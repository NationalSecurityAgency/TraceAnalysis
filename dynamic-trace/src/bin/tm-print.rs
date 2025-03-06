use anyhow::{Context, Result};
use clap::Parser;
use dataflow::architecture::Architecture;
use dataflow::prelude::{GhidraLifter, Lift, Operation, SpaceManager};
use std::fs;
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{
    record::{Meta, Record},
    RuntimeError,
};

/// Prints human readable version of the trace to stderr while continuing
/// to pipe the trace to stdout (or an output file).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Output file or '-' to use stdout.
    #[arg(short, long, default_value_t = String::from("-"))]
    output: String,

    /// Verbosity level for stderr logging.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;

    // Check that ghidra is installed before running:
    let _ = std::env::var("GHIDRA_INSTALL_DIR")
        .with_context(|| format!("GHIDRA_INSTALL_DIR is not set."))?;

    let input = open_input(args.input.as_str())?;
    let mut output = open_output(args.output.as_str())?;
    let mut trace = TraceReader::new(input);

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }
    // We don't need to print the magic record
    output.write(raw.bytes())?;

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;
    // NOTE: We define the `arch` variable in the line below!
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };
    // TODO: Print trace architecture.
    output.write(raw.bytes())?;

    let mut stderr = io::stderr();

    // Used when decoding instruction records
    let mut db = dataflow::database::Database::new(":memory:")?;
    let mut asm = String::new();
    let mut _ops = Vec::<Operation>::new();

    // Setup ghidra lifter to disasemble bytes
    let df_arch: Architecture = arch.try_into()?;
    let mut ghidra_lifter = GhidraLifter::new(df_arch)?;

    // Used for printing addresses nicely for each architecture
    let fmt_addr = match ghidra_lifter.default_code_space().addr_size() {
        4 => |data| format!("0x{:08x}", data),
        8 => |data| format!("0x{:016x}", data),
        _ => return Err(RuntimeError::UnknownArch)?,
    };

    trace
        .for_each(|raw| {
            // Pass trace bytes through to output
            try_cont!(output.write(raw.bytes()));

            let record = try_cont!(arch.parse_record(raw));
            log::debug!("{record:x?}");
            match record {
                Record::Instruction(ins) => {
                    let (pc, insbytes) = (ins.pc(), ins.insbytes());
                    try_cont!(write!(stderr, "INS {} {:02X?} ", fmt_addr(pc), insbytes));
                    if insbytes.len() == 0 {
                        log::warn!("empty instruction at {pc:#x?}");
                        cont!();
                    }

                    if let Err(e) = ghidra_lifter
                        .lift_instruction_with_cache(pc, insbytes, &mut asm, &mut _ops, &mut db)
                    {
                        // We ignore the io::Error here becuase we're already in the process of returning the
                        // LiftError which I think is more important for the end user.
                        let _ = writeln!(stderr, "");
                        return ControlFlow::Break(e.into());
                    }

                    try_cont!(writeln!(stderr, "{asm}"));

                    // NOTE: We need to clear both `asm` and `_ops` here because
                    // lift_instruction_with_cache() appends data to each variable
                    // every loop iteration.
                    asm.clear();
                    _ops.clear();
                }
                Record::Pc(pc) => {
                    try_cont!(writeln!(stderr, "PC {}", fmt_addr(pc.pc())));
                }
                Record::Meta(meta) => {
                    try_cont!(write!(stderr, "META - "));
                    match meta {
                        Meta::InstructionCount(ins_count) => {
                            try_cont!(writeln!(stderr, "InstructionCount {}", ins_count.tick()))
                        }
                        Meta::Unknown(_) => try_cont!(writeln!(stderr, "Unknown")),
                        Meta::ThreadId(threadid) => {
                            try_cont!(writeln!(stderr, "ThreadId 0x{:02x}", threadid.threadid()))
                        }
                        Meta::ProcessId(processid) => {
                            try_cont!(writeln!(
                                stderr,
                                "ProcessId {:#02x?}",
                                processid.processid()
                            ));
                        }
                        Meta::CallBegin(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "CallBegin \"{}\" ({:#02x})",
                                record.name(),
                                record.address()
                            ));
                        }
                        Meta::CallModeledOpsEnd(_) => {
                            try_cont!(writeln!(stderr, "CallModeledOpsEnd"))
                        }
                        Meta::ModelEffectsBegin(record) => {
                            try_cont!(writeln!(stderr, "ModelEffectsBegin {}", record.name()))
                        }
                        Meta::ModelEffectsEnd(_) => {
                            try_cont!(writeln!(stderr, "ModelEffectsEnd"))
                        }
                        Meta::CallEnd(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "CallEnd ({:#02x})",
                                record.call_instruction_addr()
                            ));
                        }
                        Meta::OperandUncertain(_) => {
                            try_cont!(writeln!(stderr, "OperandUncertain"));
                        }
                        Meta::AddressDependencyEdge(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "AddressDependencyEdge {:#02x}",
                                record.address()
                            ));
                        }
                        Meta::RegisterDependencyEdge(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "RegisterDependencyEdge {:#02x}",
                                record.register()
                            ));
                        }
                        Meta::MemoryAllocated(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "MemoryAllocated {:#02x} {} bytes",
                                record.address(),
                                record.size()
                            ));
                        }
                        Meta::MemoryFreed(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "MemoryFreed {:#02x} {} bytes",
                                record.address(),
                                record.size()
                            ));
                        }
                        Meta::MemoryReallocated(record) => {
                            try_cont!(writeln!(
                                stderr,
                                "MemoryReallocated {:#02x} -> {:#02x} {} bytes",
                                record.old_address(),
                                record.new_address(),
                                record.size()
                            ));
                        }
                    }
                }
                Record::FileMeta(filemeta) => {
                    try_cont!(write!(stderr, "FILEMETA - "));
                    match filemeta {
                        trace::record::FileMeta::RegisterNameMap(name_map) => {
                            for (num, name) in name_map.iter() {
                                try_cont!(write!(stderr, "RegisterNameMap {} ", num));
                                try_cont!(stderr.write(name));
                                try_cont!(writeln!(stderr, ""));
                            }
                        }
                        trace::record::FileMeta::Unknown(_) => {}
                    }
                }
                Record::RegRead(reg_read) => {
                    try_cont!(writeln!(
                        stderr,
                        "REGREAD {} {} = {:02X?}",
                        reg_read.contents().len(),
                        reg_read.regnum(),
                        reg_read.contents()
                    ));
                }
                Record::RegWrite(reg_write) => {
                    try_cont!(writeln!(
                        stderr,
                        "REGWRITE {} {} = {:02X?}",
                        reg_write.contents().len(),
                        reg_write.regnum(),
                        reg_write.contents()
                    ));
                }
                Record::RegWriteNative(native) => {
                    try_cont!(writeln!(
                        stderr,
                        "REGWRITE_NATIVE {} {} = {:02X?}",
                        native.contents().len(),
                        native.regnum(),
                        native.contents()
                    ));
                }
                Record::MemRead(mem_read) => {
                    try_cont!(writeln!(
                        stderr,
                        "MEMREAD {} = {:02X?}",
                        fmt_addr(mem_read.address()),
                        mem_read.contents()
                    ));
                }
                Record::MemWrite(mem_write) => {
                    try_cont!(writeln!(
                        stderr,
                        concat!("MEMWRITE {} = {:02X?}"),
                        fmt_addr(mem_write.address()),
                        mem_write.contents()
                    ));
                }
                Record::Magic => {
                    return ControlFlow::Break(RuntimeError::DuplicateMagic);
                }
                Record::Arch(_) => {
                    return ControlFlow::Break(RuntimeError::DuplicateArch);
                }
                _ => {
                    try_cont!(writeln!(stderr, "Unhandled Record: {record:?}"));
                }
            };

            cont!();
        })
        .map_or(Ok(()), |err| Err(err.into()))
}

fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(fs::File::open(input)?))
}

fn open_output(output: &str) -> io::Result<Box<dyn Write>> {
    if output == "-" {
        return Ok(Box::new(io::stdout().lock()));
    }
    Ok(Box::new(fs::File::create(output)?))
}
