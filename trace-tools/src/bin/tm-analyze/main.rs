use anyhow::{Context, Result};
use clap::Parser;
use std::{fs, io};
use tracing_subscriber::filter::EnvFilter;

mod analyze;
mod old;

/// Analyzes a trace using the `Dataflow` engine from the traceanalysis repo.
#[derive(Debug, Clone, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Parse traces according to the original ("old") trace format
    #[arg(long)]
    old: bool,

    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Emits debug logs as JSON (TA_LOG env var is still used to determine what is logged)
    #[arg(long)]
    debug_json: bool,
}

fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr);

    let args = Args::parse();

    if args.debug_json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

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
