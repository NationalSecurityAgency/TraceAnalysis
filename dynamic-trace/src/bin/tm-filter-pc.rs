use anyhow::{Error, Result};
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::emit_le64;
use trace::record::parse_unknown;
use trace::collector;
use trace::{
    record::{MemRead, MemWrite, Meta, ModelEffectsBegin, ModelEffectsEnd, Record, RegWrite},
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

    /// Maps file
    #[arg(long)]
    map: Option<String>,

    /// Keep only the given ranges
    #[arg(long)]
    keep: bool,
    
    /// Remove the given ranges
    #[arg(long)]
    remove: bool,

    /// Verbosity level for stderr logging.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Inclusive range of PC addresses to be filtered: `start:end`, `start:`, or `:end`
    #[arg(short, long)]
    range: Vec<IntervalFilter>,

    /// Inclusive range of PC addresses to be filtered: `start:end`, `start:`, or `:end`
    #[arg(short, long)]
    modules: Vec<ModuleFilter>,
}

#[derive(Debug, Clone)]
struct IntervalFilter {
    start: u64,
    end: u64,
    model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModuleFilter {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub name: String,
    pub model: Option<String>,
}

#[derive(Debug, Clone)]
struct ParseKeepRemoveError;

impl std::error::Error for ParseKeepRemoveError {}
impl std::fmt::Display for ParseKeepRemoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Must supply exactly one of --keep or --remove"
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ParseRangeError;

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
pub enum ParseIntervalError {
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

impl FromStr for ModuleFilter {
    type Err = ParseIntervalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
	
        let im = s.split_once("=");
	match im  {
	    None => {
		Ok(ModuleFilter { start: None, end: None, name: s.to_string(), model: None })
	    }
	    Some((module, model)) => {
		Ok(ModuleFilter { start: None, end: None, name: module.to_string(), model: Some(model.to_string()) })
	    }
	}

    }
}

impl FromStr for IntervalFilter {
    type Err = ParseIntervalError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
	
        let im = s.split_once("=");
	let ivalstr;
	let model : Option<String>;
	match im {
	    None => {
		ivalstr = s;
		model = None;
	    } 
	    Some((r, m)) => {
		ivalstr = r;
		model = Some(m.to_string());
	    }
	}
	let t = ivalstr.split_once(":");
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
		Ok(IntervalFilter { start: x, end: y, model })
	    }
	}
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;

    let mut collector = collector::TraceCollector::new();

    if args.keep != !args.remove {
	return Err(ParseKeepRemoveError {})?;
    }
    
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

    let mut was_emitting = true;
    let mut prev_model = None;
    
    let mut emit = true;
    let mut model = None;
    
    let ranges = args.range.as_slice();
    
    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));
            was_emitting = emit;
	    prev_model = model.clone();
            if let Record::Pc(ref pc) = record {
		for r in ranges.iter() {
		    if args.keep {
			emit = false;
		    } else {
			emit = true;
		    }
		    model = None;
		    if r.start <= pc.pc() && pc.pc() <= r.end {
			model = r.model.clone();
			if args.keep {
			    emit = true;
			} else {
			    emit = false;
			}
			break;
		    }
		}
            }
            if prev_model.is_some() && // if we were in the middle of modelling and...
		((model.is_none()) || // either we are done with applying the previous model...
		 (model.is_some() && (model.as_ref().unwrap() != prev_model.as_ref().unwrap()))) // or we are switching to a different model
	    {
		let mut record_bytes: Vec<u8> = vec![];
                Record::Meta(Meta::ModelEffectsBegin(ModelEffectsBegin::new(prev_model.as_ref().unwrap().clone())))
		    .emit(&mut record_bytes, emit_le64);
                try_cont!(output.write(&record_bytes));
		record_bytes.clear();
		
		// emit mem read effects
                for (key, value) in &collector.memory_read_effects {
                    Record::MemRead(MemRead::new(*key, &[*value]))
                        .emit(&mut record_bytes, emit_le64);
                    try_cont!(output.write(&record_bytes));
                    record_bytes.clear();
                }
                // emit reg write effects
                for (key, value) in &collector.reg_write_effects {
                    Record::RegWrite(RegWrite::new(*key, &value[..]))
                        .emit(&mut record_bytes, emit_le64);
                    try_cont!(output.write(&record_bytes));
                    record_bytes.clear();
                }

                // emit mem write effects
                for (key, value) in &collector.memory_write_effects {
                    Record::MemWrite(MemWrite::new(*key, &[*value]))
                        .emit(&mut record_bytes, emit_le64);
                    try_cont!(output.write(&record_bytes));
                    record_bytes.clear();
                }

		// we are done collecting...
		collector.clear();
		
                Record::Meta(Meta::ModelEffectsEnd(ModelEffectsEnd::new()))
                    .emit(&mut record_bytes, emit_le64);
                try_cont!(output.write(&record_bytes));
		record_bytes.clear();
            }
            if emit {
                // Pass trace bytes through to output
                try_cont!(output.write(raw.bytes()));
            } else if !model.is_none() {
                // we are not emitting records, but we still want to collect a summary of the effects during the elided period for inclusion with the model record
		collector.update(record);
            }
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
