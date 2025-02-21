use anyhow::{Error, Result};
use clap::Parser as _;
use core::ops::ControlFlow;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use trace::reader::{cont, try_break, try_cont, TraceReader};
use trace::record::{parse_unknown, Meta, Record, RecordKind};
use trace::{RawRecord, RuntimeError};

/// Splits a trace into multiple files based on thread/process IDs specified in meta-records.
#[derive(Debug, Clone, clap::Parser)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Verbosity level for logging.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut trace = TraceReader::new(input);

    // Use first two records to create the trace header.
    let mut trace_header = Vec::<u8>::with_capacity(8192);

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }
    trace_header.extend_from_slice(raw.bytes());

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };
    trace_header.extend_from_slice(raw.bytes());

    // Start Split Functionality:
    let mut cur_tid = 0;
    let mut cur_pid = 0;
    let mut out_files = HashMap::new();

    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let kind = try_cont!(raw.kind());
            match kind {
                RecordKind::Meta => {
                    let record = try_break!(arch.parse_record(raw));
                    if let Record::Meta(meta_record) = record {
                        match meta_record {
                            Meta::InstructionCount(_) => {
                                // TODO: Copy raw_record bytes to all output files
                                cont!();
                            },
                            Meta::ProcessId(ref processid) => {
                                let pid = processid.processid();
                                if pid != cur_pid {
                                    cur_pid = pid;
                                    // TODO: Emit InstructionCount record to all output files
                                }
                                cont!()
                            }
                            Meta::ThreadId(ref threadid) => {
                                let tid = threadid.threadid();
                                if tid != cur_tid {
                                    cur_tid = tid;
                                    // TODO: Emit InstructionCount record to all output files
                                }
                                cont!();
                            }
                            Meta::Unknown(unk) => {
                                log::debug!("Unknown Meta: {unk:?}");
                                let _ = try_break! {
                                    write_or_create_file(raw, &mut out_files, cur_pid, cur_tid, &trace_header)
                                };
                                cont!();
                            }
                            _ => {
                                // Do nothing (treat as any other record)
                            }
                        }
                    }

                    let _ = try_break! {
                        write_or_create_file(raw, &mut out_files, cur_pid, cur_tid, &trace_header)
                    };

                    cont!();
                }
                RecordKind::FileMeta => {
                    let record = try_break!(arch.parse_record(raw));
                    if let Record::FileMeta(file_meta) = record {
                        match file_meta {
                            trace::record::FileMeta::RegisterNameMap(_) => {
                                trace_header.extend_from_slice(raw.bytes());
                                cont!();
                            }
                            trace::record::FileMeta::Unknown(_) => {
                                let _ = try_break! {
                                    write_or_create_file(raw, &mut out_files, cur_pid, cur_tid, &trace_header)
                                };
                                cont!();
                            }
                        }
                    }
                    cont!();
                }
                _ => {
                    let _ = try_break! {
                        write_or_create_file(raw, &mut out_files, cur_pid, cur_tid, &trace_header)
                    };
                    cont!();
                }
            }
        })
        .map_or(Ok(()), |err| Err(err))?;

    Ok(())
}

/// A mapping from `(pid, tid)` tuples to file handles to write to.
type FileMap = HashMap<(u64, u32), BufWriter<File>>;

fn write_or_create_file(
    raw: RawRecord<'_>,
    files: &mut FileMap,
    pid: u64,
    tid: u32,
    hdr: &[u8],
) -> Result<()> {
    // If not a meta record, then copy the bytes to associated output file
    // creating a new file with initial magic/arch records if necessary.
    let file_obj = files.entry((pid, tid)).or_insert_with(|| {
        let filename = format!("trace.{pid:x}.{tid:x}.out");
        let mut file =
            File::create(&filename).expect(&format!("Error - Unable to create file: '{filename}'"));

        // First thing to write to the newly created file is the trace header:
        file.write(hdr)
            .expect(&format!("Error - Unable to write to '{filename}'"));

        // TODO: Emit current InstructionCount record to new file?

        eprintln!("Created {filename}");
        io::BufWriter::new(file)
    });

    let _ = file_obj.write(raw.bytes()).map_err(anyhow::Error::from)?;
    Ok(())
}

fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(File::open(input)?))
}
