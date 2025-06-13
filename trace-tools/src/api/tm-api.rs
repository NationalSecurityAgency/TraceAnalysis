use anyhow::Result;
use clap::Parser;

use std::fs;

use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use trace_tools::index::spacetime_index::SpacetimeRTree;
use trace_tools::index::string_index::StringIndex;
use trace_tools::index::Serializable;
use duckdb::{params, Connection, Result};
use openapi;

#[derive(Debug)]
pub struct TmApi {
    dataflow: Connection,
    registers: SpacetimeRTree,
    memory: SpacetimeRTree,,
    strings: StringIndex,
}


type InstructionTick u64;
type OperationIndex u64;
type Pc u64;
type Address u64;
type TypeId u64;

pub enum MemorySet {
    All(InstructionTick),
    Range(InstructionTick, Address, Address),
}

pub enum AccessSet {
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Pc, Pc)>, Option<(Address, Address)>),
}

pub enum InstructionSet {
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Pc, Pc)>, Option<(Address, Address)>),
    BackwardsSlice(OperationIndex, usize),
    ForwardsSlice(OperationIndex, usize),
}

pub enum ObjectSet {
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Address, Address)>),
}

pub enum WitnessSet {
    Filter(Option<(Pc, Pc)>),
}

pub enum ModuleSet {
    Filter(Option<String>),
}

pub struct InstructionWithOperations {
    instruction : Instruction,
    ops : List<Operation>,
}

pub struct Module {
    base : Address;
    size: usize;
    name: String;
    path: String;
}

pub struct Object {
    base : Address;
    size: usize;
    birth: InstructionTick;
    death: InstructionTick;
}

pub enum InstructionEffectType {
    RegWrite(usize),
    MemWriteValue,
    MemWriteAddress,
    MemReadValue,
    MemReadAddress,
}

pub enum WitnessedEvent{ 
    ObjectBirth(TypeId),
    ObjectExists(TypeId),
    ObjectDeath(TypeId),
}

pub struct Witness {
    module_offset : Address;
    module_path: String;
    effect_type: InstructionEffectType,
    event: WitnessedEvent;
}

impl TmApi {
    pub fn new(database: String, spacetime: String, strings: String) -> Result<Self> {
	let db = duckdb::open_readonly(database)?;
	let str_index = get_string_index(args.str_index.clone().as_str()).unwrap();
	let (reg_index, mem_index) = get_st_index_spaces(&args.st_index.clone().as_str()).unwrap();
	TmApi {
	    dataflow: db,
	    registers: reg_index,
	    memory: mem_index,
	    strings: str_index,
	}
    }
    pub fn import(database: String, csv_path: String) -> Result<Self> {
	let db = duckdb::open(database)?;
	conn.execute("-- import query from file --")?;
    }
    fn get_instructions(insns InstructionSet) -> Result,Vec<InstructionWithOperations>> {
	match insns {
	    InstructionSet::Filter(ticks, pcs, addrs) => {
		if let Some(start_tick, end_tick) = ticks {
		    // ...
		}
	    }
	}
    }
    pub fn get_instructions_with_operations(start : InstructionTick, end : InstructionTick) -> Result<Vec<InstructionWithOperations>> {
	
    }
}

#[derive(Serialize, Debug)]
struct Response {
    buffer_addrs: Vec<u64>,
    buffer_creation_ticks: Vec<u64>,
    buffer_destruction_ticks: Vec<u64>,
    mem_results: Vec<u8>,
    mem_addrs: Vec<u64>,
    mem_ticks: Vec<u64>,
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

fn handle_client(
    mut stream: TcpStream,
    reg: Arc<SpacetimeRTree>,
    mem: Arc<SpacetimeRTree>,
    strs: Arc<StringIndex<()>>,
) {
    let mut msg_buffer = [0; 65536];
    let mut len_buffer = [0u8; 4];
    loop {
        match stream.read(&mut len_buffer) {
            Ok(lenlen) => {
                if lenlen != 4 {
                    return;
                }
            }
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                return;
            }
        }
        let msg_len = u32::from_le_bytes(len_buffer) as usize;
        if msg_len > std::mem::size_of_val(&msg_buffer) {
            eprintln!("Message is too large");
            return;
        }
        let mut recvd = 0 as usize;

        while recvd < msg_len as usize {
            if let Ok(sz) = stream.read(&mut msg_buffer[recvd..msg_len]) {
                if sz == 0 {
                    return;
                }
                recvd += sz;
            } else {
                // something went wrong
                return;
            }
        }

        let request_str = String::from_utf8_lossy(&msg_buffer[..msg_len]);
        eprintln!("{:?}", request_str);
        if let Ok(request) = dbg!(serde_json::from_str::<Request>(&request_str.trim())) {
            let mut response = Response {
                buffer_addrs: Vec::new(),
                buffer_creation_ticks: Vec::new(),
                buffer_destruction_ticks: Vec::new(),
                mem_results: Vec::new(),
                mem_ticks: Vec::new(),
                mem_addrs: Vec::new(),
            };
            if let Some(reqbuf) = request.buffer {
                let results = strs.search(reqbuf.as_slice());
                for i in 0..results.len() {
                    response
                        .buffer_destruction_ticks
                        .push(results[i].destroyed_at);
                    response.buffer_creation_ticks.push(results[i].created_at);
                    response.buffer_addrs.push(results[i].address);
                }
            }
            if let Some(bank) = request.mem_bank {
                if bank == 0 || bank == 1 {
                    let is_reg: bool = bank == 0;
                    if let Some(addr) = request.mem_base {
                        if let Some(len) = request.mem_len {
                            if let Some(tick) = request.mem_tick {
                                let results = match is_reg {
                                    true => reg.find(tick, addr, addr + len),
                                    false => mem.find(tick, addr, addr + len),
                                };
                                let mut ans = vec![0u8; len as usize];
                                let mut ticks = vec![0u64; len as usize];
                                let mut addrs = vec![0u64; len as usize];
                                for op in results.iter() {
                                    let mut i = 0;
                                    for x in op.data.iter() {
                                        if op.address + i >= addr && op.address + i < addr + len {
                                            let offset = (op.address + i - addr) as usize;
                                            if op.created_at > ticks[offset] {
                                                addrs[offset] = op.address + i;
                                                ticks[offset] = op.created_at;
                                                ans[offset] = *x;
                                            } else {
                                                addrs[offset] = op.address + i;
                                            }
                                        }
                                        i += 1;
                                    }
                                }
                                response.mem_results = ans;
                                response.mem_ticks = ticks;
                                response.mem_addrs = addrs;
                            }
                        }
                    }
                }
            }

            let response_str = serde_json::to_string(&response).unwrap();
            let len_bytes = u32::to_le_bytes(response_str.len() as u32);
            if let Err(e) = stream.write_all(&len_bytes) {
                eprintln!("Failed to write to socket: {}", e);
            } else {
                stream.flush().unwrap();
            }
            if let Err(e) = stream.write_all(response_str.as_bytes()) {
                eprintln!("Failed to write to socket: {}", e);
            } else {
                stream.flush().unwrap();
            }
            if request.bye == Some(true) {
                eprintln!("bye!");
                return;
            }
        } else {
            eprintln!("Failed to parse JSON request: {}", request_str);
        }
    }
}

fn main() {
    let args = Args::parse();

    let str_index = get_string_index(args.str_index.clone().as_str()).unwrap();
    let strs = Arc::new(str_index);

    let (reg_index, mem_index) = get_st_index_spaces(&args.st_index.clone().as_str()).unwrap();
    let reg = Arc::new(reg_index);
    let mem = Arc::new(mem_index);

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let reg = Arc::clone(&reg);
        let mem = Arc::clone(&mem);
        let strs = Arc::clone(&strs);
        std::thread::spawn(move || {
            handle_client(stream, reg, mem, strs);
        });
    }
}
