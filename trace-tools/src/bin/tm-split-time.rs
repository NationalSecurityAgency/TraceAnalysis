use anyhow::{Error, Result};
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{record::Record, RuntimeError};
use trace_tools::collector;
use tracing_subscriber::EnvFilter;

/// Filters
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Inclusive ranges of ticks, each of which will be collected into its own subtrace: `start:end=outfile`, `start:=outfile`, or `:end=outfile`
    #[arg(short, long)]
    ranges: Vec<IntervalFilter>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut trace = TraceReader::new(input);
    let mut header: Vec<u8> = Vec::new();

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }

    raw.bytes().iter().for_each(|x| header.push(*x));

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };
    raw.bytes().iter().for_each(|x| header.push(*x));

    let mut filters: Vec<Filter> = Vec::new();
    for ival in args.ranges {
        let filter = Filter::new(ival.clone(), arch, header.clone());
        filters.push(filter);
    }

    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));
            try_cont!(filters
                .iter_mut()
                .map(|filter| { filter.apply(record.clone()) })
                .rfold(Ok(()), |acc, res| {
                    match (acc, res) {
                        (Ok(()), Ok(())) => Ok(()),
                        _ => {
                            println!("EEE");
                            Err(())
                        }
                    }
                }));
            cont!();
        })
        .map_or(Ok(()), |err| Err(err.into()))
}

struct Filter {
    tick: u64,
    interval: IntervalFilter,
    output: io::Result<Box<dyn Write>>,
    buffer: Vec<u8>,
    collector: collector::TraceCollector,
    arch: trace::record::Arch,
    started: bool,
    done: bool,
    header: Vec<u8>,
}

impl Filter {
    fn new(interval: IntervalFilter, arch: trace::record::Arch, header: Vec<u8>) -> Self {
        Self {
            tick: 0,
            interval: interval.clone(),
            output: open_output(interval.name.as_str()),
            buffer: Vec::new(),
            collector: collector::TraceCollector::new(arch),
            arch,
            started: false,
            done: false,
            header,
        }
    }
}

impl Filter {
    fn apply(&mut self, record: Record) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let mut is_pc: bool = false;
        if let Record::Pc(_) = record {
            is_pc = true;
        }
        if self.is_starting() && !self.started {
            println!("STARTING {} -> {}", self.tick, self.interval.name);
            self.started = true;
            let _ = self.output.as_mut().unwrap().write(self.header.as_slice());
            let _ = self
                .output
                .as_mut()
                .unwrap()
                .write(self.collector.metadata.as_slice());
            self.collector.metadata.clear();
        }
        if self.tick_in_range() {
            println!("asda1 {} -> {}", self.tick, self.interval.name);
            self.arch.emit_record(record, &mut self.buffer).unwrap();
            let _ = self.output.as_mut().unwrap().write(self.buffer.as_slice());
            self.buffer.clear();
        } else {
            self.collector.update(record);
        }
        if self.is_ending() {
            self.done = true;
        }
        if is_pc {
            self.tick += 1;
        }
        Ok(())
    }

    fn tick_in_range(&self) -> bool {
        self.tick >= self.interval.start && self.tick <= self.interval.end
    }

    fn is_starting(&self) -> bool {
        self.tick == self.interval.start
    }

    fn is_ending(&self) -> bool {
        self.tick == self.interval.end + 1
    }
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
pub struct IntervalFilter {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

impl FromStr for IntervalFilter {
    type Err = ParseIntervalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ivalstr, name) = match s.split_once('=') {
            Some((r, m)) => (r, m.to_string()),
            None => {
                return Err(ParseIntervalError::Range(ParseRangeError));
            }
        };

        let Some((start, end)) = ivalstr.split_once(':') else {
            return Err(ParseRangeError)?;
        };

        let start = match start {
            "" => 0,
            n => parse_int(n)?,
        };

        let end = match end {
            "" => u64::MAX,
            n => parse_int(n)?,
        };

        if start > end {
            return Err(ParseRangeError)?;
        }

        Ok(IntervalFilter { start, end, name })
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("intervals are of the for 'start:end', ':end', or 'start:' with start <= end")]
pub struct ParseRangeError;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseIntervalError {
    #[error(transparent)]
    Range(#[from] ParseRangeError),

    #[error(transparent)]
    Int(#[from] ParseIntError),
}
