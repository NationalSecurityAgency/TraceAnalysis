use anyhow::Result;
use clap::Parser;

use std::fs;

use dataflow::prelude::SpaceKind;
use trace::index::spacetime_index::SpacetimeRTree;
use trace::index::string_index::StringIndex;
use trace::index::Serializable;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;


/// Counts the type of each record in the trace.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    str_index: String,

    #[arg(long)]
    st_index: String,
    
    #[arg(long)]
    port: u32,
}

#[derive(Deserialize, Debug)]
struct Request {
    buffer: Option<Vec<u8>>,
    mem_tick: Option<u64>,
    mem_base: Option<u64>,
    mem_len: Option<u64>,
}

#[derive(Serialize, Debug)]
struct Response {
    buffer_ticks: Vec<u64>,
    mem_results: Vec<u8>,
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

fn handle_client(mut stream: TcpStream, mem: Arc<SpacetimeRTree>, strs: Arc<StringIndex<()>>) {
    let mut msg_buffer = [0; 65536];
    let mut len_buffer = [0u8; 4];
    loop {
	match stream.read(&mut len_buffer) {
            Ok(lenlen) => {
		if lenlen != 4 {
		    return
		}
	    },
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                return;
            }
	}
	let msg_len = u32::from_le_bytes(len_buffer);
	let mut recvd = 0 as usize;
        match stream.read(&mut msg_buffer) {
            Ok(size) => {
                if size == 0 {
                    // Connection was closed
                    return;
                }
		recvd += size;
		while recvd < msg_len as usize {
		    if let Ok(sz) = stream.read(&mut msg_buffer[recvd..]) {
			if sz == 0 {
			    return;
			}
			recvd += sz;
			
		    } else {
			// something went wrong
			return;
		    }
		}
		
		let request_str = String::from_utf8_lossy(&msg_buffer[..size]);
		eprintln!("{:?}",request_str);
		if let Ok(request) = dbg!(serde_json::from_str::<Request>(&request_str.trim())) {
		    let mut response = Response {
			buffer_ticks: Vec::new(),
			mem_results: Vec::new(),
			mem_ticks: Vec::new(),
		    };
		    if let Some(reqbuf) = request.buffer {
			let results = strs.search(reqbuf.as_slice());
			for i in 0..results.len() {
			    response.buffer_ticks.push(results[i].created_at);
			}
		    }
		    if let Some(addr) = request.mem_base {
			if let Some(len) = request.mem_len {
			    if let Some(tick) = request.mem_tick {
				let results = mem.find(tick, addr, addr+len);
				let mut ans = vec![0u8; len as usize];
				let mut ticks = vec![0u64; len as usize];
				for op in results.iter() {
				    let mut i = 0;
				    for x in op.data.iter() {
					if op.address + i >= addr && op.address+i < addr+len {
					    let offset = (op.address+i-addr) as usize;
					    if op.created_at > ticks[offset] {
						ticks[offset] = op.created_at;
						ans[offset] = *x;
					    }
					}
					i += 1;
				    }
				}
				response.mem_results = ans;
				response.mem_ticks = ticks;
			    }
			}
		    }
		    
		    let response_str = serde_json::to_string(&response).unwrap();
		    if let Err(e) = stream.write_all(response_str.as_bytes()) {
			eprintln!("Failed to write to socket: {}", e);
		    } else {
			stream.flush().unwrap();
		    }
		} else {
		    eprintln!("Failed to parse JSON request: {}", request_str);
		}
	    },
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
                return;
            }
	    
	}
    }
}
/*
struct MyStringIndex(StringIndex<()>);
struct MySpacetimeIndex(SpacetimeRTree);

impl std::ops::Deref for MyStringIndex {
    type Target = StringIndex<()>;
    fn deref(&self) -> &Self::Target {
	&self.0
    }
}

impl std::ops::Deref for MySpacetimeIndex {
    type Target = SpacetimeRTree;
    fn deref(&self) -> &Self::Target {
	&self.0
    }
}

unsafe impl Send for MyStringIndex {}
unsafe impl Send for MySpacetimeIndex {}
*/
fn main() {
    let args = Args::parse();

    let str_index = get_string_index(args.str_index.clone().as_str()).unwrap();
    let strs = Arc::new(str_index);
    
    let (_reg_index, mem_index) = get_st_index_spaces(&args.st_index.clone().as_str()).unwrap();
    let mem = Arc::new(mem_index);

    let listener = TcpListener::bind(format!("127.0.0.1:{}", args.port)).unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let mem = Arc::clone(&mem);
        let strs = Arc::clone(&strs);
        std::thread::spawn(move || {
            handle_client(stream, mem, strs);
        });
    }
}
