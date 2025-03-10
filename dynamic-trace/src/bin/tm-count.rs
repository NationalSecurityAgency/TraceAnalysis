use anyhow::Result;
use clap::Parser;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};

use trace::reader::{cont, try_break, TraceReader};
use trace::record::RecordKind;
use tracing_subscriber::filter::EnvFilter;

/// Counts the type of each record in the trace.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Output file or '-' to use stdout.
    #[arg(short, long, default_value_t = String::from("-"))]
    output: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut output = open_output(args.output.as_str())?;

    let mut stats: HashMap<RecordKind, u32> = HashMap::new();
    let mut unknown: u32 = 0;

    TraceReader::new(input)
        .for_each(|raw| {
            match raw.kind() {
                Ok(kind) => {
                    *stats.entry(kind).or_default() += 1;
                }
                Err(_) => {
                    unknown += 1;
                }
            }
            try_break!(output.write(raw.bytes()));
            cont!()
        })
        .map_or(Ok(()), |err: io::Error| Err(err))?;

    let mut stats: Vec<_> = stats.into_iter().collect();
    stats.sort();
    for (kind, count) in stats {
        eprintln!("{kind:?} => {count}");
    }
    if unknown > 0 {
        eprintln!("RecordKind::Unknown => {unknown}");
    }

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
