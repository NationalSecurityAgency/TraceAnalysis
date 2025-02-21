use anyhow::{anyhow, Result};
use dataflow::prelude::*;
use std::collections::HashMap;
use std::io::Read;
use std::ops::ControlFlow;
use trace::{
    reader::{cont, try_break, TraceReader},
    record::{parse_unknown, FileMeta, Meta, Record},
    RuntimeError,
};

mod register_mappings;

pub fn analyze(input: Box<dyn Read>) -> Result<()> {
    let mut trace = TraceReader::new(input);

    let raw_magic_record = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw_magic_record.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }

    let raw_arch_record = trace.next().ok_or(RuntimeError::MissingArch)?;
    // NOTE: 'arch' variable gets assigned here!
    let Record::Arch(arch) = raw_arch_record.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };

    // Setup ghidra lifter for looking up native register names
    let df_arch = arch.try_into()?;
    let ghidra_lifter = GhidraLifter::new(df_arch)?;

    // Initialize translation map
    let reg_translate_map = register_mappings::get_reg_translate_map(arch)?;
    let mut reg_native_map: HashMap<u16, AddressRange> = HashMap::new();

    // Create main dataflow analysis
    let mut df = Analysis::try_from(df_arch)?;

    // Add a csv exporter. TODO: should be a command line option?
    let exporter = dataflow::export::csv::CsvExporter::new("out/");
    df.insert_exporter(exporter);

    // Setup plugins if necessary
    setup_common_plugins(&mut df)?;
    match df_arch {
        Architecture::X86_64(_) => setup_x86_64_plugins(&mut df)?,
        Architecture::X86_64Compat32(_) => setup_x86_64_plugins(&mut df)?,
        _ => {}
    };

    let mut tick: u64 = 0u64;

    let mut call_model = Call::new();
    let mut ignore_next = false;

    trace.for_each(|raw| {
        log::debug!("{raw:?}");
        let record = try_break!(arch.parse_record(raw));
        log::debug!("{record:?}");
        if ignore_next && call_model.state == CallState::NotModeling {
            ignore_next = false;
            cont!();
        }
        match record {
            Record::FileMeta(file_meta) => {
                match file_meta {
                    FileMeta::RegisterNameMap(name_map) => {
                        // TODO: Make a mapping between regnum -> SLEIGH address using register name
                        for (num, name) in name_map.iter() {
                            let regname = match std::str::from_utf8(name) {
                                Ok(name) => name,
                                Err(e) => return ControlFlow::Break(anyhow!(e)),
                            };
                            if let Some(translated_name) = reg_translate_map.get(regname) {
                                let sleigh_addr =
                                    match ghidra_lifter.register_by_name(translated_name) {
                                        Ok(addr_range) => addr_range,
                                        Err(e) => return ControlFlow::Break(e.into()),
                                    };

                                if let Some(old_addr) = reg_native_map.insert(num, sleigh_addr) {
                                    let old_val = old_addr.offset();
                                    let sleigh_offset = sleigh_addr.offset();
                                    log::warn!(
                                        "Offset for '{regname}' was updated from {old_val} to {sleigh_offset}"
                                    );
                                }
                            } else {
                                log::warn!(
                                    "{}",
                                    RuntimeError::TranslateError((num, regname.to_string()))
                                        .to_string()
                                )
                            }
                        }
                    }
                    _ => {}
                }
            }
            Record::Map(_) => {}
            Record::Unmap(_) => {}
            Record::Instruction(ins) => {
                assert_eq!(call_model.state, CallState::NotModeling);
                try_break!(df.process_instruction(ins.pc(), ins.insbytes()));
                df.end_instruction();
                tick += 1;
            }
            Record::Pc(_) => {
                assert_eq!(call_model.state, CallState::NotModeling);
                df.set_tick(tick);
                df.start_instruction();
            }
            Record::Meta(meta) => match meta {
                Meta::InstructionCount(_ins_cnt) => {
                    //tick = ins_cnt.tick();
                }
                Meta::CallBegin(call) => {
                    assert_eq!(call_model.state, CallState::NotModeling);
                    call_model.set_name(call.name());
                    call_model.set_address(call.address());
                    call_model.state = CallState::ModelingOperands;
                    df.set_tick(tick);
                }
                Meta::CallModeledOpsEnd(_) => {
                    assert_eq!(call_model.state, CallState::ModelingOperands);
                    call_model.state = CallState::ModelingSideEffects;
                }
                Meta::CallEnd(_call) => {
                    assert_ne!(call_model.state, CallState::NotModeling);
                    let (pc, name, ops) = call_model.dummy_instruction(&df);
                    try_break! {
                        df.dummy_instruction(pc, name, ops).map_err(|_| {
                            anyhow::anyhow!("failed to process dummy instruction")
                        })
                    };
                    df.end_instruction();
                    tick += 1;
                    call_model.clear();
                }
                Meta::OperandUncertain(_) => {
                    ignore_next = true;
                }
                _ => {}
            },
            Record::Interrupt(_) => {}
            Record::RegRead(reg_read) => {
                let address = df.register_space().index(reg_read.regnum() as u64);
                if call_model.state == CallState::ModelingOperands {
                    let start = reg_read.regnum() as u64;
                    let end = start + reg_read.contents().len() as u64;
                    let range = df.register_space().index(start..end);
                    call_model.inputs.push(range);
                }
                if !ignore_next {
                    df.insert_read(address, reg_read.contents());
                }
                ignore_next = false;
            }
            Record::RegWrite(reg_write) => {
                let address = df.register_space().index(reg_write.regnum() as u64);
                if call_model.state == CallState::ModelingOperands {
                    let start = reg_write.regnum() as u64;
                    let end = start + reg_write.contents().len() as u64;
                    let range = df.register_space().index(start..end);
                    call_model.outputs.push(range);
                }
                if !ignore_next {
                    df.insert_write(address, reg_write.contents());
                }
                ignore_next = false;
            }
            Record::RegWriteNative(native) => {
                assert_eq!(call_model.state, CallState::NotModeling);
                if let Some(address) = reg_native_map.get(&native.regnum()) {
                    let address = df.register_space().index(address.offset());
                    df.insert_write(address, native.contents())
                } else {
                    log::warn!(
                        "Ignoring write to unknown native register: {}",
                        &native.regnum()
                    );
                }
            }
            Record::MemRead(mem_read) => {
                for i in (0..mem_read.contents().len()).step_by(32) {
                    let address = df.default_data_space().index(mem_read.address() + i as u64);
                    let length = std::cmp::min(32, mem_read.contents().len() - i);
                    if call_model.state == CallState::ModelingOperands {
                        let end = mem_read.address() + length as u64;
                        let range = df.default_data_space().index(mem_read.address()..end);
                        call_model.inputs.push(range);
                    }
                    if !ignore_next {
                        df.insert_read(address, &mem_read.contents()[i..i+length]);
                    }
                }
                ignore_next = false;
            }
            Record::MemWrite(mem_write) => {
                for i in (0..mem_write.contents().len()).step_by(32) {
                    let address = df.default_data_space().index(mem_write.address() + i as u64);
                    let length = std::cmp::min(32, mem_write.contents().len() - i);
                    if call_model.state == CallState::ModelingOperands {
                        let end = mem_write.address() + length as u64;
                        let range = df.default_data_space().index(mem_write.address()..end);
                        call_model.outputs.push(range);
                    }
                    if !ignore_next {
                        df.insert_write(address, &mem_write.contents()[i..i+length]);
                    }
                }
                ignore_next = false;
            }
            Record::Magic => {
                return ControlFlow::Break(anyhow!(RuntimeError::DuplicateMagic));
            }
            Record::Arch(_) => {
                return ControlFlow::Break(anyhow!(RuntimeError::DuplicateArch));
            }
        }
        cont!();
    }).map_or(Ok(()), |err| Err(err.into()))
}

fn setup_common_plugins(df: &mut dataflow::analysis::Analysis) -> Result<()> {
    let plugin = dataflow::plugins::cbranch::SpeculateCBranch::new();
    df.insert_plugin(Box::new(plugin));

    let plugin = dataflow::plugins::fntrack::FnTracker::from(&*df);
    df.insert_plugin(Box::new(plugin));

    let plugin = dataflow::plugins::fpmodels::DefaultFloatModel::new();
    df.insert_plugin(Box::new(plugin));

    Ok(())
}

fn setup_x86_64_plugins(df: &mut dataflow::analysis::Analysis) -> Result<()> {
    let plugin = dataflow::plugins::syscalls::LinuxSyscallsx64::new(df);
    df.insert_plugin(Box::new(plugin));

    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CallState {
    NotModeling,
    ModelingOperands,
    ModelingSideEffects,
}

struct Call {
    pub state: CallState,
    pub name: String,
    pub address: u64,
    pub inputs: Vec<AddressRange>,
    pub outputs: Vec<AddressRange>,
    pub operations: Vec<Operation>,
}

impl Call {
    pub fn new() -> Self {
        Self {
            state: CallState::NotModeling,
            name: String::new(),
            address: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            operations: Vec::new(),
        }
    }

    pub fn set_name(&mut self, name: &str) {
        self.name.push_str(name);
    }

    pub fn set_address(&mut self, address: u64) {
        self.address = address
    }

    pub fn dummy_instruction<'a>(
        &'a mut self,
        spaces: &dyn SpaceManager,
    ) -> (u64, &'a str, impl Iterator<Item = Operation> + 'a) {
        let out_in0 = spaces
            .constant_space()
            .index(0x41414141u64..0x41414141u64 + 8);
        let out_in1 = spaces
            .constant_space()
            .index(self.inputs.len() as u64..8 + self.inputs.len() as u64);
        for output in self.outputs.drain(..) {
            for (i, input) in self.inputs.iter().copied().enumerate() {
                let in0 = spaces.constant_space().index(i as u64..8 + i as u64);
                self.operations.push(unsafe {
                    dataflow::operation::Argument::new_unchecked(in0, input).into()
                });
            }
            self.operations.push(unsafe {
                dataflow::operation::CallOther::new_unchecked(Some(output), out_in0, out_in1).into()
            });
        }
        (self.address, self.name.as_str(), self.operations.drain(..))
    }

    pub fn clear(&mut self) {
        self.state = CallState::NotModeling;
        self.name.clear();
        self.address = 0;
        self.inputs.clear();
        self.outputs.clear();
        self.operations.clear();
    }
}
