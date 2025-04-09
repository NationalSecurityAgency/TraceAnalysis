use anyhow::{Error, Result};
use clap::Parser;
use goblin::elf;
use hashbrown::HashMap;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::path::Path;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{record::Record, RuntimeError};
use tracing_subscriber::EnvFilter;

/// Filters
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// path to sysroot
    #[arg(long)]
    sysroot: Option<String>,

    /// Module maps file
    #[arg(long)]
    map: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MapEntry {
    pub name: String,
    pub low: Pc,
    pub high: Pc,
}

fn get_addr_table(mapfile: String, sysroot: String) -> Result<HashMap<u64, String>> {
    let mut ans = HashMap::new();

    let mappath = Path::new(&mapfile);
    let mapf = fs::File::open(mappath)?;
    let mapreader = io::BufReader::new(mapf);
    for mapline in mapreader.lines() {
        if let Ok(mapline) = mapline {
            let mapentry = serde_json::from_str::<MapEntry>(&mapline);
            match mapentry {
                Ok(mapentry) => {
                    if let Ok(data) =
                        fs::read(Path::new(&sysroot.as_str()).join(&mapentry.name.as_str()[1..]))
                    {
                        let elf = elf::Elf::parse(&*data)?;
                        for d in elf.dynsyms.iter() {
                            if let Some(x) = elf.dynstrtab.get_at(d.st_name) {
                                // TODO: ensure that we only insert function symbols here
                                ans.insert(
                                    mapentry.low.pc + d.st_value,
                                    format!("{}.{}", mapentry.name, x),
                                );
                            }
                        }
                        let mut plt_base: Option<u64> = None;
                        let mut plt_sec_base: Option<u64> = None;
                        for shdr in elf.section_headers {
                            if let Some(x) = elf.shdr_strtab.get_at(shdr.sh_name) {
                                if x == ".plt" {
                                    plt_base = Some(shdr.sh_addr);
                                } else if x == ".plt.sec" {
                                    plt_sec_base = Some(shdr.sh_addr);
                                }
                                //println!("{}.{} @ {:x}", mapentry.name, x, shdr.sh_addr);
                            }
                        }
                        let mut plt_entry = 0;
                        for d in elf.pltrelocs.iter() {
                            if let Some(sym) = elf.dynsyms.get(d.r_sym) {
                                if let Some(x) = elf.dynstrtab.get_at(sym.st_name) {
                                    //println!("{}.{} @ {:x} + {:?} ({}) = {:x}", mapentry.name, x, d.r_offset, d.r_addend, d.r_sym, sym.st_value);
                                    if let Some(plt_base) = plt_base {
                                        ans.insert(
                                            mapentry.low.pc + plt_base + plt_entry * 0x10,
                                            format!("{}.{}@.plt", mapentry.name, x),
                                        );
                                    }
                                    if let Some(plt_sec_base) = plt_sec_base {
                                        ans.insert(
                                            mapentry.low.pc + plt_sec_base + plt_entry * 0x10,
                                            format!("{}.{}@.plt.sec", mapentry.name, x),
                                        );
                                    }
                                }
                            }
                            plt_entry += 1;
                        }
                        for d in elf.syms.iter() {
                            if let Some(x) = elf.strtab.get_at(d.st_name) {
                                // TODO: ensure that we only insert function symbols here
                                ans.insert(
                                    mapentry.low.pc + d.st_value,
                                    format!("{}.{}", mapentry.name, x),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                }
            }
        }
    }
    Ok(ans)
}

fn parse_int(s: &str) -> std::result::Result<u64, std::num::ParseIntError> {
    if let Some(s) = s.strip_prefix("0x") {
        u64::from_str_radix(s, 16)
    } else if let Some(s) = s.strip_prefix("0o") {
        u64::from_str_radix(s, 8)
    } else if let Some(s) = s.strip_prefix("0b") {
        u64::from_str_radix(s, 2)
    } else {
        u64::from_str_radix(s, 10)
    }
}

#[derive(Debug, Clone)]
pub struct Pc {
    pub pc: u64,
}

impl<'de> Deserialize<'de> for Pc {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PcVisitor;

        impl<'de> Visitor<'de> for PcVisitor {
            type Value = Pc;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or an unsigned 64-bit integer")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<Pc, E>
            where
                E: serde::de::Error,
            {
                Pc::from_str(v).map_err(|e| serde::de::Error::custom(e.to_string()))
            }

            fn visit_u64<E>(self, v: u64) -> std::result::Result<Pc, E>
            where
                E: serde::de::Error,
            {
                Ok(Pc { pc: v })
            }
        }

        deserializer.deserialize_any(PcVisitor)
    }
}

impl FromStr for Pc {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = parse_int(s)?;
        Ok(Pc { pc: x })
    }
}

struct FunctionTrackerState<'a> {
    prev_pc: Option<u64>,
    current_pc: Option<u64>,
    expected_next_pc: Option<u64>,
    live_function_runs: Vec<FunctionRunInfo<'a>>,
}

#[derive(Serialize, Debug)]
struct FunctionRunInfo<'a> {
    name: &'a str,
    pc: u64,
    start_tick: u64,
    expected_return_addr: u64,
    depth: usize,
    callsite: Option<u64>,
    end_pc: Option<u64>,
    end_tick: Option<u64>,
}

impl<'a> FunctionRunInfo<'a> {
    pub fn new(
        name: &'a str,
        pc: u64,
        start_tick: u64,
        expected_return_addr: u64,
        depth: usize,
        callsite: Option<u64>,
    ) -> Self {
        Self {
            name,
            pc,
            start_tick,
            expected_return_addr,
            depth,
            callsite,
            end_pc: None,
            end_tick: None,
        }
    }
    pub fn emit(&self) {
        println!("{}", serde_json::to_string(&self).unwrap());
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut trace = TraceReader::new(input);

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };

    let mut _stderr = io::stderr();

    let mut tick = 0 as u64;

    let mut syms = HashMap::new();
    if let Some(mapfile) = args.map {
        if let Some(sysroot) = args.sysroot {
            if let Ok(s) = get_addr_table(mapfile, sysroot) {
                syms = s;
            }
        }
    }
    let mut state = FunctionTrackerState {
        prev_pc: None,
        current_pc: None,
        expected_next_pc: None,
        live_function_runs: Vec::new(),
    };

    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));

            if let Record::Instruction(ref ins) = record {
                if let Some(pc) = state.current_pc {
                    state.expected_next_pc = Some(pc + (ins.insbytes().len() as u64));
                }
            }

            if let Record::Pc(ref pc) = record {
                tick += 1;
                if let Some(pc) = state.current_pc {
                    state.prev_pc = Some(pc);
                }
                state.current_pc = Some(pc.pc());
                let addr = pc.pc();

                if let Some(returning_idx) = state
                    .live_function_runs
                    .iter()
                    .rposition(|fnrun| fnrun.expected_return_addr == addr)
                {
                    for _ in returning_idx..state.live_function_runs.len() {
                        if let Some(mut top) = state.live_function_runs.pop() {
                            // if so, then pop the function run info, populate its last info, and emit it
                            top.end_pc = state.prev_pc;
                            top.end_tick = Some(tick - 1);
                            top.emit();
                        }
                    }
                    //state.live_function_runs.drain(returning_idx..).for_each(|top| {
                    //	top.end_pc = state.prev_pc;
                    //	top.end_tick = Some(tick-1);
                    //	top.emit();
                    //});
                    // if we are in the middle of a function run,
                    // check whether we have made it back to the
                    // return of this function:
                }

                if let Some(name) = syms.get(&addr) {
                    // we are at the first instruction of a call to
                    // the function <name>

                    // So if we have some idea as to what the next pc
                    // is supposed to be, then we can add a function
                    // run info to the callstack that awaits the
                    // return of execution to that pc
                    if let Some(retpc) = state.expected_next_pc {
                        state.live_function_runs.push(FunctionRunInfo::new(
                            name.as_str(),
                            addr,
                            tick,
                            retpc,
                            state.live_function_runs.len(),
                            state.prev_pc,
                        ));
                    }
                }
            }
            cont!();
        })
        .map_or(Ok(()), |err| Err(err))?;
    state.live_function_runs.drain(..).for_each(|fnrun| {
        fnrun.emit();
    });
    Ok(())
}

fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(fs::File::open(input)?))
}
