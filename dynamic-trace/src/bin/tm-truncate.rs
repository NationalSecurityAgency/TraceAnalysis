use anyhow::Result;
use clap::Parser as _;
use core::ops::ControlFlow;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use trace::reader::{cont, TraceReader};
use trace::record::{parse_unknown, Record};
use trace::RuntimeError;
use tracing_subscriber::filter::EnvFilter;

/// Splits a trace into multiple files based on thread/process IDs specified in meta-records.
#[derive(Debug, Clone, clap::Parser)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Output file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    output: String,

    #[arg(long)]
    count: usize,
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
    let Record::Arch(_arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };
    output.write(raw.bytes())?;

    let mut count = args.count;
    trace
        .for_each(move |raw| -> ControlFlow<Option<io::Error>> {
            if count == 0 {
                return ControlFlow::Break(None);
            }
            count -= 1;
            if let Err(e) = output.write(raw.bytes()) {
                return ControlFlow::Break(Some(e.into()));
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
    Ok(Box::new(File::open(input)?))
}

fn open_output(output: &str) -> io::Result<Box<dyn Write>> {
    if output == "-" {
        return Ok(Box::new(io::stdout().lock()));
    }
    Ok(Box::new(fs::File::create(output)?))
}
