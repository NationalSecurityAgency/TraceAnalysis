use anyhow::Result;

use std::fs;

use std::io::{self, Read, Write};
use std::net::{TcpListener,TcpStream};
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;
use std::thread;

use trace_tools::api::{TmApi,InstructionSet,TypeInfo};

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
}

#[derive(Serialize, Deserialize, Debug)]
struct Command {
    command: Commands
}

#[derive(Serialize, Deserialize, Debug)]
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

    AddType {name: String, kind: String, count: Option<u64>, size: Option<u64>, element_type: Option<u64>},
    SetArrayCount {typename: String, count: u64},
    SetTypeName {typename: String, newname: String},
    AddStructureField {typename: String, offset: u64, fieldname: String, fieldtype: String},
    DelStructureField {typename: String, offset: u64},
    
    AddObject {name: Option<String>, base : u64, size : u64, typeid: u64, birth: u64, death: u64},
    DelObject {name: String},
    ListObjects {},
    GetObjectUses {name: String},

    AddWitness {module: String, offset: u64, obj_event_type: String, obj_typeid: u64, insn_effect: String, reg_num: Option<u64>},
    DelWitness {witnessid: u64},
    ListWitnesses {},
    GetWitnessEvents {witnessid: u64},

}


fn main() -> Result<()> {
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

    let listener = TcpListener::bind("127.0.0.1:8080")?;
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            handle_client(stream, &api);
	}
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, api: &TmApi) -> Result<()> {
    loop {
	let mut length_bytes = [0u8; 4];
	stream.read_exact(&mut length_bytes)?;
	let req_size = u32::from_le_bytes(length_bytes);
	let mut req = vec![0u8; req_size as usize];
	stream.read_exact(&mut req)?;
	let req_str = String::from_utf8(req).unwrap();
	let cmd : Command = serde_json::from_str(req_str.as_str()).unwrap();
	let mut ans : Vec<u8> = Vec::new();
	match cmd.command {
	    Commands::GetInstructions{start_tick, end_tick} => {
		let res = api.get_instructions(InstructionSet::Filter(Some((start_tick as u64, end_tick as u64)), None, None)).unwrap();
		for io in res { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::GetModules{} => {
		let res = api.get_modules().unwrap();
		for io in res { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::StringSearch{ string } => {
		let res = api.stringsearch((string).clone().to_string()).unwrap();
		for io in res { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::GetMemory { tick, address, size } => {
		let res = api.get_memory(tick, address, size as usize).unwrap();
		ans.extend_from_slice(serde_json::to_string(&res).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes());
	    },
	    Commands::GetInstructionTraceTime { start_tick, end_tick } => {
		let res = api.get_instrace(start_tick, end_tick).unwrap();
		let ie = TmApi::get_instructions_with_effects(res);
		for io in ie {  ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::GetInstructionTracePc { start_pc, end_pc } => {
		let res = api.get_instrace_by_pc(start_pc, end_pc).unwrap();
		let ie = TmApi::get_instructions_with_effects(res);
		for io in ie { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::Why {tick} => {
		let res = api.why(tick).unwrap();
		if let Some(reason) = res.get(0) {
		    let res2 = api.get_instrace(*reason, *reason).unwrap();
		    let ie = TmApi::get_instructions_with_effects(res2);
		    for io in ie { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
		}
	    },
	    Commands::Slice {index, depth} => {
		let res = api.get_forward_slice(index, depth).unwrap();
		let ie = TmApi::get_instructions_with_effects(res);
		for io in ie { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::Backslice {index, depth} => {
		let res = api.get_backward_slice(index, depth).unwrap();
		let ie = TmApi::get_instructions_with_effects(res);
		for io in ie { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::Coverage {} => {
		let res = api.get_coverage().unwrap();
		for io in res { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::MinTick {} => {
		let res = api.get_min_tick().unwrap();
		ans.extend_from_slice(serde_json::to_string(&res).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes());
	    },
	    Commands::MaxTick {} => {
		let res = api.get_max_tick().unwrap();
		ans.extend_from_slice(serde_json::to_string(&res).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes());
	    },
	    Commands::Accesses {start_addr, end_addr, start_tick, end_tick} => {
		let res = api.get_accesses_from_rect(start_addr, end_addr, start_tick, end_tick).unwrap();
		for io in res { ans.extend_from_slice(serde_json::to_string(&io).unwrap().as_bytes()); ans.extend_from_slice("\n".as_bytes()); }
	    },
	    Commands::AddType {name, kind, count, size, element_type} => {
		if kind == "array" {
		    if let Some(count) = count {
			if let Some(element_type) = element_type {
			    api.add_type(TypeInfo::Array{name, count: count as usize, element_type})?;
			}
		    }
		} else if kind == "pointer" {
		    if let Some(size) = size {
			if let Some(element_type) = element_type {
			    api.add_type(TypeInfo::Pointer{name, size: size as usize,ty:  element_type})?;
			}
		    }
		    
		} else if kind == "structure" {
		    if let Some(size) = size {
			api.add_type(TypeInfo::Structure{name, size: size as usize, fields: Vec::new()})?;
		    }
		} else if kind == "sized" {
		    if let Some(size) = size {
			api.add_type(TypeInfo::Sized{name, size: size as usize})?;
		    }
		}
	    },
	    Commands::AddStructureField {typename, offset, fieldname, fieldtype} => {},
	    Commands::DelStructureField {typename, offset} => {},
	    Commands::SetArrayCount {typename, count} => {},
	    Commands::SetTypeName {typename, newname} => {},
	    Commands::AddObject {name, base , size , typeid, birth, death} => {},
	    Commands::DelObject {name} => {},
	    Commands::ListObjects {} => {},
	    Commands::GetObjectUses {name} => {},
	    Commands::AddWitness {module, offset, obj_event_type, obj_typeid, insn_effect, reg_num} => {},
	    Commands::DelWitness {witnessid} => {},
	    Commands::ListWitnesses {} => {},
	    Commands::GetWitnessEvents {witnessid} => {},
	}
	let data = ans;
	let length_bytes = data.len().to_le_bytes();
	let mut packet = Vec::with_capacity(data.len() + length_bytes.len());
	packet.extend_from_slice(&length_bytes);
	packet.extend_from_slice(&data[..]);
	stream.write_all(&packet)?;
	stream.flush()?;
    }
    
    Ok(())
}
