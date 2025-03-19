use anyhow::{Error, Result};
use clap::Parser;
use serde::Deserialize;
use std::fs;
use std::io::{self, Read};
use std::ops::ControlFlow;
use trace::reader::{cont, try_cont, TraceReader};
use trace::record::parse_unknown;
use trace::{
    record::Record,
    RuntimeError,
};
use dataflow::prelude::SpaceKind;
use trace_tools::index::spacetime_index::SpacetimeRTree;
use trace_tools::index::{SpacetimeBlock,Serializable};


/// Filters
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Verbosity level for stderr logging.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(long)]
    st_index: String,
    
    /// Syscall spec file
    #[arg(short, long)]
    spec: String,
}

#[derive(Debug, Deserialize)]
struct SyscallSpecStr {
    opcodes: Vec<String>,
    num_reg: u64,
    arg_regs: Vec<u64>,
    ret_reg: u64,
    reg_width: u64,
}

#[derive(Debug, Deserialize)]
struct SyscallSpec {
    opcodes: Vec<Vec<u8>>,
    num_reg: u64,
    arg_regs: Vec<u64>,
    ret_reg: u64,
    reg_width: u64,
}

fn get_syscall_spec(specfile : String) -> Result<SyscallSpec> {
    let specdata = fs::read(specfile)?;
    let specstr = serde_json::from_str::<SyscallSpecStr>(String::from_utf8(specdata).unwrap().as_str())?;
    
    Ok(SyscallSpec{
	opcodes: specstr.opcodes.iter().map(|x| {
	    x.as_bytes().chunks(2).map(|chunk| {
		u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()
	    }).collect::<Vec<u8>>()
	}).collect(),
	num_reg: specstr.num_reg,
	arg_regs: specstr.arg_regs,
	ret_reg: specstr.ret_reg,
	reg_width: specstr.reg_width,
    })
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

fn data_to_u64(data : Vec<u8>) -> u64 {
    let mut arr = [0u8; 8];
    for i in 0..data.len() {
	arr[i] = data[i];
    }
    u64::from_le_bytes(arr)
}

#[derive(Debug, Clone)]
struct TimedByte {
    val : Option<u8>,
    time : Option<u64>,
}

fn coalesce(ops : Vec<&SpacetimeBlock>, addr : u64, len : usize) -> u64 {
    let mut data : Vec<TimedByte> = vec![TimedByte{val: Some(0), time: None}; len];
    for op in ops.iter() {
	let mut i = 0;
	for x in op.data.iter() {
	    if op.address + i >= addr && op.address+i < addr+(len as u64) {
		let offset = (op.address + i - addr) as usize;
		let tb : &mut TimedByte = data.get_mut(offset).unwrap();
		if let Some(t) = tb.time {
		    if t < op.created_at {
			tb.val = Some(*x);
			tb.time = Some(op.created_at);
		    }
		} else {
		    tb.val = Some(*x);
		    tb.time = Some(op.created_at);
		}
	    }
	    i += 1;
	}
    }
    let mut ans = vec![0u8; len];
    let mut max = 0;
    for i in 0..len {
	max = i;
	if let Some(x) = data[i].val {
	    ans[i] = x;
	} else {
	    break;//ans[i] = 0;//return None;
	}
    }
    return data_to_u64(ans[0..max].to_vec());
}

fn main() -> Result<()> {
    let args = Args::parse();
    stderrlog::new().verbosity(args.verbose as usize).init()?;
    
    let input = open_input(args.input.as_str())?;
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

    let mut _stderr = io::stderr();
    
    let mut tick = 0 as u64;

    let (reg_index, mut _mem_index) = get_st_index_spaces(&args.st_index.as_str()).unwrap();
    
    let spec = get_syscall_spec(args.spec)?;
    
    trace
        .for_each(|raw| -> ControlFlow<Error> {
            let record = try_cont!(arch.parse_record(raw));
	    
	    if let Record::Pc(_) = record {
		tick += 1;
	    }
	    
	    if let Record::Instruction(ref ins) = record {
		if spec.opcodes.iter().fold(false, |acc, opc| { acc || ins.insbytes() == opc }) {
		    let args = spec.arg_regs.iter().map(|reg| {
			coalesce(reg_index.find(tick-1, *reg, *reg+spec.reg_width).iter().map(|block| { block.as_ref() }).collect::<Vec<_>>(), *reg, spec.reg_width as usize)
		    }).collect::<Vec<u64>>();
		    let mut num : Option<u64> = None;
		    let mut ret : Option<u64> = None;
		    if let Some(numblock) = reg_index.find(tick-1, spec.num_reg, spec.num_reg+spec.reg_width).first() {
			num = Some(data_to_u64(numblock.as_ref().data.clone()));
		    }
		    if let Some(retblock) = reg_index.find(tick+1, spec.ret_reg, spec.ret_reg+spec.reg_width).first() {
			if retblock.created_at >= tick {
			    ret = Some(data_to_u64(retblock.as_ref().data.clone()));
			}
		    }
		    println!("{tick} SYSCALL_{}({args:x?}) = {ret:x?}", num.unwrap())
		    //let num = data_to_u64(reg_index.find(tick, spec.num_reg, spec.num_reg+spec.reg_width).first().unwrap().as_ref().data.clone());
		    //let retval = data_to_u64(reg_index.find(tick+1, spec.ret_reg, spec.ret_reg).first().unwrap().as_ref().data.clone());
		    //println!("SYSCALL {:?} ({:x?}) = {:?}", num, args, retval)
		}
	    }
	    cont!();
        })
        .map_or(Ok(()), |err| Err(err.into()))
}

fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(fs::File::open(input)?))
}
