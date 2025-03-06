use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{
    record::Record,
    RuntimeError,
};

/// Filters
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

    /// Inclusive range of time intervals to be filtered: `start:end`, `start:`, or `:end`
    #[arg(short, long)]
    ranges: Vec<Interval>,
}

#[derive(Debug, Clone)]
struct Interval {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone)]
struct ParseRangeError;

impl std::error::Error for ParseRangeError {}
impl std::fmt::Display for ParseRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Intervals are of the form 'start:end' or ':end' or 'start:' with start <= end"
        )?;
        Ok(())
    }
}

impl From<ParseIntError> for ParseIntervalError {
    fn from(e: ParseIntError) -> ParseIntervalError {
        ParseIntervalError::Int(e)
    }
}

#[derive(Debug, Clone)]
enum ParseIntervalError {
    Range(ParseRangeError),
    Int(ParseIntError),
}

impl std::error::Error for ParseIntervalError {}
impl std::fmt::Display for ParseIntervalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseIntervalError::Range(e) => e.fmt(f),
            ParseIntervalError::Int(e) => e.fmt(f),
        }
    }
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

impl FromStr for Interval {
    type Err = ParseIntervalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.split_once(":");
        match t {
            None => Err(ParseIntervalError::Range(ParseRangeError {})),
            Some((xstr, ystr)) => {
                let x: u64;
                if xstr.len() == 0 {
                    x = 0 as u64;
                } else {
                    x = parse_int(xstr)?;
                }

                let y: u64;
                if ystr.len() == 0 {
                    y = u64::max_value();
                } else {
                    y = parse_int(ystr)?;
                }
                if x > y {
                    return Err(ParseIntervalError::Range(ParseRangeError {}));
                }
                Ok(Interval { start: x, end: y })
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;

    let ranges = args.ranges.as_slice();

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

    let mut tick = 0 as u64;

    let max = ranges
        .iter()
        .fold(0, |ans, ival| if ans < ival.end { ival.end } else { ans });

    trace
        .for_each(|raw| {
            let record = try_cont!(arch.parse_record(raw));
            if let Record::Pc(_pc) = record {
                tick += 1;
            }
            if tick > max {
                return ControlFlow::Break(None);
            }

            if ranges.iter().fold(false, |ans, ival| {
                ans || (ival.start <= tick && tick <= ival.end)
            }) {
                // Pass trace bytes through to output
                try_cont!(output.write(raw.bytes()));
            }
            cont!();
        })
        .map_or(Ok(()), |res: Option<io::Error>| match res {
            Some(err) => Err(err),
            None => Ok(()),
        })?;
    Ok(())
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
