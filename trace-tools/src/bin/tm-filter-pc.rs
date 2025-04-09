use anyhow::{Error, Result};
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{
    record::{MemRead, MemWrite, Meta, ModelEffectsBegin, ModelEffectsEnd, Record, RegWrite},
    RuntimeError,
};
use trace_tools::collector;
use tracing_subscriber::EnvFilter;

/// Filters
#[derive(Parser, Debug)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Output file or '-' to use stdout.
    #[arg(short, long, default_value_t = String::from("-"))]
    output: String,

    // TODO: Filter by module name
    // Maps file
    // #[arg(long)]
    // map: Option<String>,
    /// Inclusive range of PC addresses to be filtered: `start:end`, `start:`, or `:end`
    #[arg(short, long)]
    range: Vec<IntervalFilter>,
    // TODO: Filter by module name
    // Inclusive range of PC addresses to be filtered: `start:end`, `start:`, or `:end`
    // #[arg(short, long)]
    // modules: Vec<ModuleFilter>,
}

#[derive(Debug, Clone)]
pub struct IntervalFilter {
    pub start: u64,
    pub end: u64,
    pub model: Option<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut output = open_output(args.output.as_str())?;
    let mut trace = TraceReader::new(input);

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }
    output.write(raw.bytes())?;

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };
    output.write(raw.bytes())?;

    let mut filter = Filter::new(args.range.as_slice(), arch);

    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));
            filter.apply(record);
            if filter.buffer.len() > 0 {
                try_cont!(output.write(filter.buffer.as_slice()));
                filter.buffer.clear();
            }
            cont!();
        })
        .map_or(Ok(()), |err| Err(err.into()))
}

struct Filter<'d> {
    intervals: &'d [IntervalFilter],
    buffer: Vec<u8>,
    collector: collector::TraceCollector,
    current_interval: Option<usize>,
    arch: trace::record::Arch,
}

impl<'d> Filter<'d> {
    fn new(intervals: &'d [IntervalFilter], arch: trace::record::Arch) -> Self {
        Self {
            intervals,
            buffer: Vec::new(),
            collector: collector::TraceCollector::new(arch),
            current_interval: None,
            arch,
        }
    }
}

impl Filter<'_> {
    fn apply(&mut self, record: Record) {
        if let Record::Pc(ref record) = record {
            let interval = self.address_in_range(record.pc());
            if self.current_interval != interval {
                self.update_interval(interval);
            }
        }
        if self.is_filtering() {
            self.collector.update(record);
        } else {
            self.arch.emit_record(record, &mut self.buffer).unwrap();
        }
    }

    fn address_in_range(&self, address: u64) -> Option<usize> {
        self.intervals
            .iter()
            .position(|i| address >= i.start && address <= i.end)
    }

    fn model_name(&self) -> Option<&str> {
        let index = self.current_interval?;
        let interval = self.intervals.get(index)?;
        interval.model.as_ref().map(|s| s.as_str())
    }

    fn is_filtering(&self) -> bool {
        self.current_interval.is_some()
    }

    fn update_interval(&mut self, interval: Option<usize>) {
        if self.is_filtering() {
            let name = self.model_name().unwrap_or("unnamed");
            self.arch
                .emit_record(
                    Meta::ModelEffectsBegin(ModelEffectsBegin::new(name.to_string())).into(),
                    &mut self.buffer,
                )
                .unwrap();
            self.collector
                .memory_read_effects
                .drain()
                .for_each(|(address, value)| {
                    self.arch
                        .emit_record(MemRead::new(address, &[value]).into(), &mut self.buffer)
                        .unwrap();
                });
            self.collector
                .reg_write_effects
                .drain()
                .for_each(|(regnum, value)| {
                    self.arch
                        .emit_record(
                            RegWrite::new(regnum, value.as_slice()).into(),
                            &mut self.buffer,
                        )
                        .unwrap()
                });
            self.collector
                .memory_write_effects
                .drain()
                .for_each(|(address, value)| {
                    self.arch
                        .emit_record(MemWrite::new(address, &[value]).into(), &mut self.buffer)
                        .unwrap();
                });
            self.arch
                .emit_record(
                    Meta::ModelEffectsEnd(ModelEffectsEnd::new()).into(),
                    &mut self.buffer,
                )
                .unwrap();
        }
        self.current_interval = interval;
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

impl FromStr for IntervalFilter {
    type Err = ParseIntervalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ivalstr, model) = match s.split_once('=') {
            Some((r, m)) => (r, Some(m.to_string())),
            None => (s, None),
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

        Ok(IntervalFilter { start, end, model })
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

// TODO: Filter by module name

// #[derive(Debug, Clone)]
// pub struct ModuleFilter {
//     pub start: Option<u64>,
//     pub end: Option<u64>,
//     pub name: String,
//     pub model: Option<String>,
// }

// impl FromStr for ModuleFilter {
//     type Err = ParseIntervalError;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s.split_once('=') {
//             None => Ok(ModuleFilter {
//                 start: None,
//                 end: None,
//                 name: s.to_string(),
//                 model: None,
//             }),
//             Some((module, model)) => Ok(ModuleFilter {
//                 start: None,
//                 end: None,
//                 name: module.to_string(),
//                 model: Some(model.to_string()),
//             }),
//         }
//     }
// }
