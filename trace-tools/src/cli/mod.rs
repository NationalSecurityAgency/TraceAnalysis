use anyhow::{anyhow,Result};

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;

use crate::api::{TmApi, InstructionSet, InstructionRun, Object, Witness, InstructionWithEffects, OperationsWithInstructions, WitnessedEvent, Module, BufferInfo, MemoryInfo, WitnessEvent, InstructionEffectType, TypeInfo};

use clap::{Parser, Subcommand};

#[derive(Parser, Serialize, Deserialize, Debug)]
pub struct Command {
    #[command(subcommand)]
    command: Commands
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    if let Ok(x) = s.parse::<u64>() {
	return Ok(x);
    }
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16)
        .map_err(|e| format!("Invalid hex value: {}", e))
}

#[derive(Subcommand, Serialize, Deserialize, Debug)]
pub enum Commands {
    GetInstructions { start_tick: u64, end_tick: u64 },
    StringSearch { string: String },
    GetModules { },
    GetMemory {
	tick: u64,
	
	#[arg(value_parser = parse_hex_u64)]
	address: u64,
	
	size: u64
    },
    GetTrace {start_tick: u64, end_tick: u64},
    FindPc {
	#[arg(value_parser = parse_hex_u64)]
	start_pc: u64,
	
	#[arg(value_parser = parse_hex_u64)]
	end_pc: Option<u64>
    },
    Why {tick: u64},
    Slice {index: u64, depth: u64},
    Backslice {index: u64, depth: u64},
    Coverage {},
    MinTick {},
    MaxTick {},
    Accesses {
	#[arg(value_parser = parse_hex_u64)]
	start_addr: u64,
	#[arg(value_parser = parse_hex_u64)]
	end_addr: u64,
	start_tick: u64,
	end_tick: u64
    },

    AddType {name: String, kind: String, count: Option<u64>, size: Option<u64>, element_type: Option<u64>},
    DelType {name: String},
    //ResizeArrayType {typename: String, newsite: u64},
    //SetTypeName {typename: String, newname: String},
    AddStructureField {typename: String, offset: i64, fieldname: String, fieldtype: String},
    DelStructureField {typename: String, offset: i64},
    
    AddObject {
	name: String,
	
	#[arg(value_parser = parse_hex_u64)]
	base : u64,
	size : u64,
	birth: u64,
	death: u64,
	typeid: u64
    },
    DelObject {
	name: String
    },
    ListObjects {},
    GetObjectUses {
	name: String
    },

    AddWitness {
	module: String,
	#[arg(value_parser = parse_hex_u64)]
	offset: u64,
	obj_event_type: String,
	obj_typeid: u64,
	insn_effect: String,
	reg_name: Option<String>
    },
    DelWitness {
	module: String,
	#[arg(value_parser = parse_hex_u64)]
	offset: u64
    },
    ListWitnesses {},
    GetWitnessEvents {},
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Done,
    Instructions(Vec<InstructionRun>),
    Objects(Vec<Object>),
    Witnesses(Vec<Witness>),
    Instrace(Vec<InstructionWithEffects>),
    OperationIndices(Vec<u64>),
    WitnessedEvents(Vec<WitnessedEvent>),
    Ticks(Vec<u64>),
    Pcs(Vec<u64>),
    Modules(Vec<Module>),
    Buffers(Vec<BufferInfo>),
    Memory(Vec<MemoryInfo>),
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	match self {
	    Response::Done => {
		writeln!(f, "done")
	    },
	    Response::Instructions(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Objects(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Witnesses(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Instrace(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::OperationIndices(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::WitnessedEvents(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Ticks(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Pcs(v) => {
		for x in v {
		    writeln!(f, "0x{:x}", x)?;
		}
		Ok(())
	    },
	    Response::Modules(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Buffers(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	    Response::Memory(v) => {
		for x in v {
		    writeln!(f, "{}", x)?;
		}
		Ok(())
	    },
	}
    }
}
pub fn cmd_as_json(cmd: Command) -> serde_json::Result<String> {
    return serde_json::to_string(&cmd);
}

pub fn json_to_cmd(cmd_json : &str) -> serde_json::Result<Command> {
    let cmd : Command = serde_json::from_str(cmd_json)?;
    return Ok(cmd);
}

pub fn handle_cmd(cmd : Command, api: &TmApi) -> Result<Response> {

    match &cmd.command {
	Commands::GetInstructions{start_tick, end_tick} => {
	    return Ok(Response::Instructions(api.get_instructions(InstructionSet::Filter(Some((*start_tick as u64, *end_tick as u64)), None, None))?));
	},
	Commands::GetModules{} => {
	    return Ok(Response::Modules(api.get_modules()?));
	},
	Commands::StringSearch{ string } => {
	    return Ok(Response::Buffers(api.stringsearch((string).clone().to_string())?));
	},
	Commands::GetMemory { tick, address, size } => {
	    return Ok(Response::Memory(vec![api.get_memory(*tick, *address, *size as usize)?]));
	},
	Commands::GetTrace { start_tick, end_tick } => {
	    let res = api.get_instrace(*start_tick, *end_tick)?;
	    return Ok(Response::Instrace(TmApi::get_instructions_with_effects(res)));
	},
	Commands::FindPc { start_pc, end_pc } => {
	    let end : u64;
	    if let Some(end_pc) = end_pc {
		end = *end_pc;
	    } else {
		end = *start_pc;
	    }
	    let res = api.get_instrace_by_pc(*start_pc, end)?;
	    return Ok(Response::Instrace(TmApi::get_instructions_with_effects(res)));
	},
	Commands::Why {tick} => {
	    let res = api.why(*tick)?;
	    if let Some(reason) = res.get(0) {
		let res2 = api.get_instrace(*reason, *reason).unwrap();
		return Ok(Response::Instrace(TmApi::get_instructions_with_effects(res2)));
	    } else {
		return Err(anyhow!("no 'why' found for tick {}",tick));
	    }
	},
	Commands::Slice {index, depth} => {
	    let res = api.get_forward_slice(*index, *depth).unwrap();
	    return Ok(Response::Instrace(TmApi::get_instructions_with_effects(res)));
	},
	Commands::Backslice {index, depth} => {
	    let res = api.get_backward_slice(*index, *depth).unwrap();
	    return Ok(Response::Instrace(TmApi::get_instructions_with_effects(res)));
	},
	Commands::Coverage {} => {
	    return Ok(Response::Pcs(api.get_coverage()?));
	},
	Commands::MinTick {} => {
	    let res = api.get_min_tick()?;
	    return Ok(Response::Ticks(vec![res]));
	},
	Commands::MaxTick {} => {
	    let res = api.get_max_tick()?;
	    return Ok(Response::Ticks(vec![res]));
	},
	Commands::Accesses {start_addr, end_addr, start_tick, end_tick} => {
	    return Ok(Response::OperationIndices(api.get_accesses_from_rect(*start_addr, *end_addr, *start_tick, *end_tick)?));
	},
	Commands::AddType {name, kind, count, size, element_type} => {
	    if kind == "array" {
		if let Some(count) = count {
		    if let Some(element_type) = element_type {
			api.add_type(TypeInfo::Array{name:name.clone(), count: *count as usize, element_type:element_type.clone()})?;
		    }
		}
	    } else if kind == "pointer" {
		if let Some(size) = size {
		    if let Some(element_type) = element_type {
			api.add_type(TypeInfo::Pointer{name:name.clone(), size: *size as usize, ty:element_type.clone()})?;
		    }
		}
		
	    } else if kind == "structure" {
		if let Some(size) = size {
		    api.add_type(TypeInfo::Structure{name:name.clone(), size: *size as usize, fields: Vec::new()})?;
		}
	    } else if kind == "sized" {
		if let Some(size) = size {
		    api.add_type(TypeInfo::Sized{name:name.clone(), size: *size as usize})?;
		}
	    }
	    return Ok(Response::Done);
	},
	Commands::DelType {name} => {
	    api.del_type(name.clone())?;
	    return Ok(Response::Done);
	},
	Commands::AddStructureField {typename, offset, fieldname, fieldtype} => {
	    api.add_field(typename.clone(), *offset, fieldname.clone(), fieldtype.clone())?;
	    return Ok(Response::Done);
	},
	Commands::DelStructureField {typename, offset} => {
	    api.del_field(typename.clone(), *offset)?;
	    return Ok(Response::Done);
	},
	Commands::AddObject {name, base, size , typeid, birth, death} => {
	    api.add_object(name.clone(), *base, *size, *birth, *death, *typeid)?;
	    return Ok(Response::Done);
	},
	Commands::DelObject {name} => {
	    api.del_object(name.clone())?;
	    return Ok(Response::Done);
	},
	Commands::ListObjects {} => {
	    return Ok(Response::Objects(api.get_objects()?));
	},
	Commands::GetObjectUses {name} => {
	    return Ok(Response::OperationIndices(api.get_object_uses(name.clone())?));
	},
	Commands::AddWitness {module, offset, obj_event_type, obj_typeid, insn_effect, reg_name} => {
	    let we : WitnessEvent;
	    if obj_event_type == "birth" {
		we = WitnessEvent::ObjectBirth(*obj_typeid);
	    } else if obj_event_type == "death" {
		we = WitnessEvent::ObjectDeath(*obj_typeid);
	    } else if obj_event_type == "exists" {
		we = WitnessEvent::ObjectExists(*obj_typeid);
	    } else {
		return Err(anyhow!("witness event must be 'birth', 'death', or 'exists'"));
	    }
	    let eff : InstructionEffectType;
	    if insn_effect == "regwrite" {
		if let Some(reg_name) = reg_name {
		    let reg_num = api.get_reg_num(reg_name.clone())?;
		    eff = InstructionEffectType::RegWrite(reg_num);
		} else {
		    return Err(anyhow::anyhow!("regwrite instruction feature must be accompianied by a reg_name!"));
		}
	    } else if insn_effect == "memwritevalue" {
		eff = InstructionEffectType::MemWriteValue;
	    } else if insn_effect == "memwriteaddress" {
		eff = InstructionEffectType::MemWriteAddress;
	    } else if insn_effect == "memreadvalue" {
		eff = InstructionEffectType::MemReadValue;
	    } else if insn_effect == "memreadaddress" {
		eff = InstructionEffectType::MemReadAddress;
	    } else {
		return Err(anyhow::anyhow!("insn_effect must be one of 'regwrite', 'memwritevalue', memwriteaddress', 'memreadvalue', or 'memreadaddress'"))
	    }
	    api.add_witness(module.clone(), *offset, we, eff)?;
	    return Ok(Response::Done);
	},
	Commands::DelWitness {module, offset} => {
	    api.del_witness(module.clone(), *offset)?;
	    return Ok(Response::Done);
	},
	Commands::ListWitnesses {} => {
	    return Ok(Response::Witnesses(api.get_witnesses()?));
	},
	Commands::GetWitnessEvents {} => {
	    return Ok(Response::WitnessedEvents(api.get_witness_events()?));
	},
    }
}
