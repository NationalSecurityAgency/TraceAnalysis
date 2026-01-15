use anyhow::Result;

use std::fs;

use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;

use tm_api::{TmApi,InstructionSet};

use clap::{Parser, Subcommand};

#[derive(Parser, Serialize, Deserialize, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, global = true)]
    verbose: bool,
    
    #[arg(long)]
    str_index: String,

    #[arg(long)]
    st_index: String,

    #[arg(long)]
    database_path: String,

    #[arg(long)]
    init: bool,

    #[arg(long)]
    import_dynamic: Option<String>,
    
    #[arg(long)]
    import_static: Option<String>,
    
    #[arg(long)]
    import_arch: Option<String>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Serialize, Deserialize, Debug)]
enum Commands {
    GetInstructions { start_tick: u64, end_tick: u64 },
    StringSearch { string: String },
    GetModules { },
    GetMemory { tick: u64, address: u64, size: u64 },
    GetInstructionTraceTime {start_tick: u64, end_tick: u64},
    GetInstructionTracePc {start_pc: u64, end_pc: u64},
    Why {tick: u64},
    Slice {index: u64, depth: u64},
    Backslice {index: u64, depth: u64},
    Coverage {},
    MinTick {},
    MaxTick {},
    Accesses {start_addr: u64, end_addr: u64, start_tick: u64, end_tick: u64},
}


fn main() {
    let args = Args::parse();
    let mut api = TmApi::new(args.database_path.clone(), args.st_index.clone(), args.str_index.clone()).unwrap();
    if args.init {
	api.init().unwrap();
    }
    if let Some(csv_path) = args.import_dynamic {
    	api.import_dynamic(csv_path.clone()).unwrap();
    }
    if let Some(csv_path) = args.import_static {
    	api.import_static(csv_path.clone()).unwrap();
    }
    if let Some(csv_path) = args.import_arch {
    	api.import_arch(csv_path.clone()).unwrap();
    }
    
    match &args.command {
	Commands::GetInstructions{start_tick, end_tick} => {
	    let res = api.get_instructions(InstructionSet::Filter(Some((*start_tick as u64, *end_tick as u64)), None, None)).unwrap();
	    for io in res { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::GetModules{} => {
	    let res = api.get_modules().unwrap();
	    for io in res { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::StringSearch{ string } => {
	    let res = api.stringsearch((*string).clone().to_string()).unwrap();
	    for io in res { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::GetMemory { tick, address, size } => {
	    let res = api.get_memory(*tick, *address, *size as usize).unwrap();
	    println!("{}", serde_json::to_string(&res).unwrap());
	},
	Commands::GetInstructionTraceTime { start_tick, end_tick } => {
	    let res = api.get_instrace(*start_tick, *end_tick).unwrap();
	    let ie = TmApi::get_instructions_with_effects(res);
	    for io in ie { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::GetInstructionTracePc { start_pc, end_pc } => {
	    let res = api.get_instrace_by_pc(*start_pc, *end_pc).unwrap();
	    let ie = TmApi::get_instructions_with_effects(res);
	    for io in ie { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::Why {tick} => {
	    let res = api.why(*tick).unwrap();
	    if let Some(reason) = res.get(0) {
		let res2 = api.get_instrace(*reason, *reason).unwrap();
		let ie = TmApi::get_instructions_with_effects(res2);
		for io in ie { println!("{}", serde_json::to_string(&io).unwrap()); }
	    }
	},
	Commands::Slice {index, depth} => {
	    let res = api.get_forward_slice(*index, *depth).unwrap();
	    let ie = TmApi::get_instructions_with_effects(res);
	    for io in ie { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::Backslice {index, depth} => {
	    let res = api.get_backward_slice(*index, *depth).unwrap();
	    let ie = TmApi::get_instructions_with_effects(res);
	    for io in ie { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::Coverage {} => {
	    let res = api.get_coverage().unwrap();
	    for io in res { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
	Commands::MinTick {} => {
	    let res = api.get_min_tick().unwrap();
	    println!("{}", res);
	},
	Commands::MaxTick {} => {
	    let res = api.get_max_tick().unwrap();
	    println!("{}", res);
	},
	Commands::Accesses {start_addr, end_addr, start_tick, end_tick} => {
	    let res = api.get_accesses_from_rect(*start_addr, *end_addr, *start_tick, *end_tick).unwrap();
	    for io in res { println!("{}", serde_json::to_string(&io).unwrap()); }
	},
    }
}
