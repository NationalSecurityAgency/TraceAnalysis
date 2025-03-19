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
    let df_arch: Architecture = match arch {
        trace::Arch::X86 => dataflow::architecture::X86.into(),
        trace::Arch::X86_64 => dataflow::architecture::X86_64.into(),
        trace::Arch::X86_64Compat32 => dataflow::architecture::X86_64Compat32.into(),
        trace::Arch::PowerPc => dataflow::architecture::PPCBE32.into(),
        trace::Arch::PowerPc64 => anyhow::bail!("dataflow does not currently support PPC64"),
        trace::Arch::Arm => dataflow::architecture::ARM32.into(),
        trace::Arch::Arm64 => dataflow::architecture::AARCH64.into(),
        trace::Arch::M68k => dataflow::architecture::M68K.into(),
        trace::Arch::Mips => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mips64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mipsel => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Mipsel64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Sparc => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Sparc64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::RiscV => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::RiscV64 => anyhow::bail!("dataflow does not currently support "),
        trace::Arch::Unknown(n) => anyhow::bail!("unknown architecture: {n}"),
    };
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

    trace.for_each(|raw| {
        log::debug!("{raw:?}");
        let record = try_break!(arch.parse_record(raw));
        log::debug!("{record:?}");
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
                try_break!(df.process_instruction(ins.pc(), ins.insbytes()));
                df.end_instruction();
                tick += 1;
            }
            Record::Pc(_) => {
                df.set_tick(tick);
                df.start_instruction();
            }
            Record::Meta(meta) => match meta {
                Meta::InstructionCount(ins_cnt) => {
                    tick = ins_cnt.tick();
                }
                _ => {}
            },
            Record::Interrupt(_) => {}
            Record::RegRead(reg_read) => {
                let address = df.register_space().index(reg_read.regnum() as u64);
                df.insert_read(address, reg_read.contents());
            }
            Record::RegWrite(reg_write) => {
                let address = df.register_space().index(reg_write.regnum() as u64);
                df.insert_write(address, reg_write.contents());
            }
            Record::RegWriteNative(native) => {
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
                let address = df.default_data_space().index(mem_read.address());
                df.insert_read(address, mem_read.contents());
            }
            Record::MemWrite(mem_write) => {
                let address = df.default_data_space().index(mem_write.address());
                df.insert_write(address, mem_write.contents());
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
