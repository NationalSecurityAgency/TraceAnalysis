use anyhow::Result;
use clap::Parser;

use std::fs;

use dataflow::prelude::SpaceKind;
use trace_tools::index::spacetime_index::SpacetimeRTree;
use trace_tools::index::string_index::StringIndex;
use trace_tools::index::Serializable;

/// Counts the type of each record in the trace.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    str_index: Option<String>,

    #[arg(long)]
    st_index: Option<String>,

    #[arg(long)]
    searchstring: Option<String>,

    #[arg(long)]
    tick: Option<u64>,

    #[arg(long)]
    reg: bool,

    #[arg(long)]
    addr: Option<u64>,
}

/// Returns a tuple of (reg_space, mem_space)
fn get_st_index_spaces(index: &str) -> Result<(SpacetimeRTree, SpacetimeRTree)> {
    let buffer = fs::read(index)?;

    let mut offs = 0;

    let (mut reg_space, mut mem_space) = (None, None);
    while offs < buffer.len() {
        let tree = SpacetimeRTree::deserialize(&buffer[..], &mut offs);
        match tree.kind() {
            SpaceKind::Register => reg_space = Some(tree),
            SpaceKind::Memory => mem_space = Some(tree),
            _ => {}
        }
    }

    match (reg_space, mem_space) {
        (Some(r), Some(m)) => Ok((r, m)),
        _ => Err(anyhow::anyhow!(
            "Not enough 'spaces' in index file! (needs at least 2)"
        )),
    }
}

fn get_string_index(index: &str) -> Result<StringIndex<()>> {
    let buffer = fs::read(index)?;
    Ok(StringIndex::deserialize(&buffer[..]))
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(searchstring) = args.searchstring {
        let str_index_file = args.str_index.unwrap();
        let str_index = get_string_index(str_index_file.clone().as_str()).unwrap();
        let results = str_index.search(searchstring.as_bytes());
        for r in results {
            println!("{:?}", r);
        }
    }

    if let Some(tick) = args.tick {
        if let Some(addr) = args.addr {
            let st_index_file = args.st_index.unwrap();
            let (reg_index, mem_index) =
                get_st_index_spaces(&st_index_file.clone().as_str()).unwrap();
            if args.reg {
                let results = reg_index.find(tick, addr, addr + 1);
                for r in results {
                    println!("{:?}", r);
                }
            } else {
                let results = mem_index.find(tick, addr, addr + 1);
                for r in results {
                    println!("{:?}", r);
                }
            }
        }
    }

    Ok(())
}
