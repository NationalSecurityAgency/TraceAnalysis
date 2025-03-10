use anyhow::Result;
use clap::Parser;
use trace::record::Record;

use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};

use trace::{
    reader::{cont, try_break, TraceReader},
    record::parse_unknown,
    RuntimeError,
};

use dataflow::prelude::SpaceKind;
use trace::index::spacetime_index::SpacetimeIndex;
use trace::index::string_index::StringIndex;
use trace::index::{Indexer, Operation};
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

    /// String index file or '-' to skip.
    #[arg(long, default_value_t = String::from("-"))]
    str_index: String,

    /// Spacetime index file or '-' to skip.
    #[arg(long, default_value_t = String::from("-"))]
    st_index: String,
}

fn parse_ops(args: Args) -> Result<(Vec<Operation>, u64)> {
    let input = open_input(args.input.as_str())?;
    let mut output = open_output(args.output.as_str())?;

    let mut trace = TraceReader::new(input);

    let raw = trace.next().ok_or(RuntimeError::MissingMagic)?;
    if Record::Magic != raw.parse(parse_unknown)? {
        return Err(RuntimeError::MissingMagic)?;
    }

    let raw = trace.next().ok_or(RuntimeError::MissingArch)?;

    // NOTE: We define the `arch` variable in the line below!
    let Record::Arch(arch) = raw.parse(parse_unknown)? else {
        return Err(RuntimeError::MissingArch)?;
    };

    let mut ops = Vec::new();
    let mut tick = 0u64;

    trace
        .for_each(|raw| {
            match arch.parse_record(raw) {
                Err(_) => eprintln!("Error encountered during parsing"),
                Ok(Record::Pc(_)) => tick += 1,
                Ok(Record::MemRead(read)) => ops.push(Operation {
                    space: SpaceKind::Memory,
                    data: read.contents().to_vec(),
                    address: read.address(),
                    written_time: tick,
                }),
                Ok(Record::MemWrite(write)) => ops.push(Operation {
                    space: SpaceKind::Memory,
                    data: write.contents().to_vec(),
                    address: write.address(),
                    written_time: tick,
                }),
                Ok(Record::RegRead(read)) => ops.push(Operation {
                    space: SpaceKind::Register,
                    data: read.contents().to_vec(),
                    address: read.regnum() as u64,
                    written_time: tick,
                }),
                Ok(Record::RegWrite(write)) => ops.push(Operation {
                    space: SpaceKind::Register,
                    data: write.contents().to_vec(),
                    address: write.regnum() as u64,
                    written_time: tick,
                }),
                _ => {}
            }
            try_break!(output.write(raw.bytes()));
            cont!()
        })
        .map_or(Ok(()), |err: io::Error| Err(err))?;

    Ok((ops, tick + 1))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_env("TA_LOG"))
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let str_index_file = open_index_file(args.str_index.as_str())?;
    let st_index_file = open_index_file(args.st_index.as_str())?;

    let (ops, num_ticks) = parse_ops(args)?;

    let mut index = Indexer::new(num_ticks);
    if let Some(str_index_file) = str_index_file {
        index.add_index(StringIndex::new(str_index_file));
    }
    if let Some(st_index_file) = st_index_file {
        index.add_index(SpacetimeIndex::new(st_index_file, num_ticks));
    }

    for op in ops {
        index.record_op(op);
    }

    index.finalize();
    index.save_indices()?;

    Ok(())
}

fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(BufReader::new(io::stdin().lock())));
    }
    Ok(Box::new(BufReader::new(fs::File::open(input)?)))
}

fn open_output(output: &str) -> io::Result<Box<dyn Write>> {
    if output == "-" {
        return Ok(Box::new(BufWriter::new(io::stdout().lock())));
    }
    Ok(Box::new(BufWriter::new(fs::File::create(output)?)))
}

fn open_index_file(index_path: &str) -> io::Result<Option<Box<dyn Write>>> {
    if index_path == "-" {
        Ok(None)
    } else {
        Ok(Some(Box::new(BufWriter::new(fs::File::create(
            index_path,
        )?))))
    }
}
