use anyhow::{Error, Result};
use clap::Parser;
use goblin::elf;
use hashbrown::HashMap;
use serde::{Deserialize, Deserializer};
use serde::de::Visitor;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::num::ParseIntError;
use std::ops::ControlFlow;
use std::path::Path;
use std::str::FromStr;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{
    record::{Record},
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

    /// path to sysroot
    #[arg(long)]
    sysroot: Option<String>,

    /// Module maps file
    #[arg(long)]
    map: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MapEntry {
    name : String,
    low : Pc,
    high : Pc,
}

fn get_addr_table(mapfile : String, sysroot : String) -> Result<HashMap<u64, String>> {
    let mut ans = HashMap::new();

    let mappath = Path::new(&mapfile);
    let mapf = fs::File::open(mappath)?;
    let mapreader = io::BufReader::new(mapf);
    for mapline in mapreader.lines() {
	if let Ok(mapline) = mapline {
	    let mapentry = serde_json::from_str::<MapEntry>(&mapline);
	    match mapentry {
		Ok(mapentry) => {
		    if let Ok(data) = fs::read(Path::new(&sysroot.as_str()).join(&mapentry.name.as_str()[1..])) {
			let elf = elf::Elf::parse(&*data)?;
			for d in elf.dynsyms.iter() {
			    if let Some(x) = elf.dynstrtab.get_at(d.st_name) {
				ans.insert(mapentry.low.pc + d.st_value, format!("{}.{}", mapentry.name, x));
			    }
			}
			for d in elf.syms.iter() {
			    if let Some(x) = elf.strtab.get_at(d.st_name) {
				ans.insert(mapentry.low.pc + d.st_value, format!("{}.{}", mapentry.name, x));
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
struct Pc {
    pc: u64,
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
                Ok(Pc {pc : v})
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

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;
    
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
    
    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));
	    
	    if let Record::Pc(_) = record {
		tick += 1;
	    }
	    
	    if let Record::Pc(ref pc) = record {
		let addr = pc.pc();
		if let Some(name) = syms.get(&addr) {
		    eprintln!("{tick} {addr:x} {name}");
		}
	    }
            try_cont!(output.write(raw.bytes()));
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
