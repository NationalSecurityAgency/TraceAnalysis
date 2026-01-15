use anyhow::Result;

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;

use tm_api::{TmApi,InstructionSet};

use clap::{Parser, Subcommand};

#[derive(Parser, Serialize, Deserialize, Debug)]
#[command(version, about, long_about = None)]
struct Args {
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


fn main() -> Result<()> {
    let args = Args::parse();
    let req = serde_json::to_string(&args).unwrap();
    let data = req.as_bytes();
    let length_bytes = (data.len() as u32).to_le_bytes();
    let mut packet = Vec::with_capacity(data.len() + length_bytes.len());
    packet.extend_from_slice(&length_bytes);
    packet.extend_from_slice(data);
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;
    stream.write_all(&packet)?;
    stream.flush()?;
    let mut inbound_length_bytes = [0u8; 4];
    stream.read_exact(&mut inbound_length_bytes)?;
    let inbound_size = u32::from_le_bytes(inbound_length_bytes);
    let mut res = vec![0u8; inbound_size as usize];
    stream.read_exact(&mut res)?;
    if let Ok(message) = String::from_utf8(res) {
        println!("{}", message);
    }
    Ok(())
}
