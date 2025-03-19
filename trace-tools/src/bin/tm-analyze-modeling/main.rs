use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, io};

mod analyze;
mod old;

/// Analyzes a trace using the `Dataflow` engine from the traceanalysis repo.
#[derive(Debug, Clone, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Verbosity level for stderr logging.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Parse traces according to the original ("old") trace format
    #[arg(long)]
    old: bool,

    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;

    // Check that ghidra is installed before running:
    let _ = std::env::var("GHIDRA_INSTALL_DIR")
        .with_context(|| format!("GHIDRA_INSTALL_DIR is not set."))?;

    if args.old {
        old::analyze(open_input(&args.input)?)
    } else {
        analyze::analyze(open_input(&args.input)?)
    }
}

fn open_input(input: &str) -> io::Result<Box<dyn io::Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(fs::File::open(input)?))
}
