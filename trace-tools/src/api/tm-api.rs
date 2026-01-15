use anyhow::Result;
use std::collections::HashMap;

use std::fs;
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use duckdb::{params, Connection, Result as DuckDbResult};
use duckdb;

#[path = "../index/mod.rs"] mod index;
use crate::index::spacetime_index::SpacetimeRTree;
use crate::index::string_index::StringIndex;
use crate::index::Serializable;

pub struct TmApi {
    dataflow: Connection,
    registers: SpacetimeRTree,
    memory: SpacetimeRTree,
    strings: StringIndex<()>,
}


type InstructionTick = u64;
type OperationIndex = u64;
type Pc = u64;
type Address = u64;
type TypeId = u64;


#[derive(Serialize, Deserialize, Debug)]
pub struct BufferInfo {
    birth: InstructionTick,
    death: InstructionTick,
    addr: Address,
}
    

#[derive(Serialize, Deserialize, Debug)]
pub enum MemorySet {
    All(InstructionTick),
    Range(InstructionTick, Address, Address),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AccessSet {
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Pc, Pc)>, Option<(Address, Address)>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InstructionSet {
    // Filter(ticks, pcs, addrs) returns instructions occurring within
    // the specified range of ticks, limited to the specified range of
    // PCs
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Pc, Pc)>, Option<(Address, Address)>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum OperationTree {
    // BackwardSlice(index, depth) refers to the tree of computations
    // involved in generating the output value of the operation at the
    // given index. ForwardSlice is analogous
    BackwardsSlice(OperationIndex, u64),
    ForwardsSlice(OperationIndex, u64),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ObjectSet {
    Filter(Option<(InstructionTick, InstructionTick)>, Option<(Address, Address)>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WitnessSet {
    Filter(Option<(Pc, Pc)>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ModuleSet {
    Filter(Option<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstructionRun {
    tick : u64,
    pc : u64,
    disas : String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OperationRun {
    tick : u64,
    index : u64,
    bank : Option<u64>,
    addr : Option<u64>,
    value : Option<Vec<u8>>,
    size: Option<u64>,
    assocd_addr: Option<u64>,
    assocd_bank : Option<u64>,
    assocd_size : Option<u64>,
    deps : Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InstructionWithOperations {
    instruction : InstructionRun,
    ops : Vec<OperationRun>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OperationsWithInstructions {
    ops : Vec<OperationRun>,
    instructions : HashMap<u64, InstructionRun>, // tick -> = instruction run for that tick
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Module {
    base : Address,
    size: u64,
    name: String,
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Object {
    name : String, 
    base : Address,
    size: u64,
    type_id: TypeId,
    birth: InstructionTick,
    death: InstructionTick,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum InstructionEffectType {
    RegWrite(u64),
    MemWriteValue,
    MemWriteAddress,
    MemReadValue,
    MemReadAddress,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WitnessedEvent{ 
    ObjectBirth(Pc,InstructionTick,Address,TypeId),
    ObjectExists(Pc,InstructionTick,Address,TypeId),
    ObjectDeath(Pc,InstructionTick,Address,TypeId),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WitnessEvent{ 
    ObjectBirth(TypeId),
    ObjectExists(TypeId),
    ObjectDeath(TypeId),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Witness {
    module_offset : Address,
    module_path: String,
    effect_type: InstructionEffectType,
    event: WitnessEvent,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MemoryInfo {
    data: Vec<u8>,
    addrs: Vec<Address>,
    write_ticks: Vec<InstructionTick>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InstructionWithEffects {
    instruction: InstructionRun,
    effects: Vec<OperationEffect>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OperationEffect {
    index: OperationIndex,
    addr: Address,
    val: Vec<u8>,
    size: u64,
    effect_type: OperationEffectType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OperationEffectType {
    MemWrite,
    MemRead,
    RegWrite,
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

impl TmApi {
    pub fn new(database: String, spacetime: String, strings: String) -> Result<Self> {
	let db = Connection::open(database)?;
	let str_index = get_string_index(strings.as_str())?;
	let (reg_index, mem_index) = get_st_index_spaces(spacetime.as_str())?;
	Ok(TmApi {
	    dataflow: db,
	    registers: reg_index,
	    memory: mem_index,
	    strings: str_index,
	})
    }
    pub fn init(&self) -> Result<()> {
	let init_db : &str = include_str!("data/init.duckdb");
	self.dataflow.execute_batch(init_db)?;
	Ok(())
    }
    pub fn import_dynamic(&self, csv_path: String) -> Result<()> {
	self.dataflow.execute(format!("insert into instructionruns select _key,tick,pc,disas from '{}/ticks.csv';", csv_path).as_str(), params![])?;
	
	self.dataflow.execute(format!("insert into operationruns select _key,index,tick,opcode,size,bank,addr,cast(val as uint128) as val,raw,assocd_addr,assocd_bank,assocd_size from  read_csv('{}/deltas.csv',delim=',',columns={{'_key':'varchar','runid':'uint64','index':'uint64','tick':'uint64','opcode':'uint64','bank':'uint64','addr':'uint64','val':'varchar','raw':'varchar','size':'uint64','assocd_bank':'uint64','assocd_addr':'uint64','assocd_size':'uint64'}},strict_mode=false,header=true,null_padding=true,ignore_errors=true);", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into addrdep select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to,maybe from '{}/addr_deps.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into inputdep select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to,maybe,pos from '{}/input_deps.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into cfdep select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from '{}/cf_deps.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute_batch("load spatial;create table accesses (pt GEOMETRY, index uint64);")?;
	self.dataflow.execute_batch("load spatial;insert into accesses select ST_Point(tick,CASE WHEN opcode == 2 THEN assocd_addr ELSE addr END) as pt,index from operationruns where bank == 1 or opcode == 2;create index access_idx on accesses using RTREE(pt);")?;

	
	self.dataflow.execute(format!("insert into functionruns select startindex as _key,callsite as calliste,pc as pc,starttick as starttick,startindex as startindex,endindex as endindex,retval as retval,stackdepth as stackdepth,stackptr as stackptr from '{}/functionruns.csv';", csv_path).as_str(), params![])?;
	//self.dataflow.execute(format!("insert into syscallruns select tick as _key,tick as tick,number as number,retval as retval from '{}/syscallruns.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into infunctionrun select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from '{}/functionticks.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into calls select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from '{}/calls.csv';", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into retdep select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from '{}/retdeps.csv';", csv_path).as_str(), params![])?;
	//self.dataflow.execute(format!("insert into makessyscall select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from '{}/syscallruncalls.csv';", csv_path).as_str(), params![])?;
	
	Ok(())
    }
    pub fn import_static(&self, csv_path: String) -> Result<()> {
	self.dataflow.execute(format!("insert into functions select _key as _key, name as name, namespace as namespace, module as module, start, (CAST(\"end\" as UBIGINT)-CAST(start as UBIGINT)) as size from read_json_auto('{}/functions.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into blocks select _key as _key,module as module, addr as addr,(CAST(\"end\" as UBIGINT)-CAST(addr as UBIGINT)) as end from read_json_auto('{}/blocks.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into modules select low as _key,low as base,(CAST(high as UBIGINT)-CAST(low as UBIGINT)) as size,name as name,name as path from read_json_auto('{}/maps.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into cdg select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from read_json_auto('{}/cdg.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into blockof select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from read_json_auto('{}/blockof.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into successorof select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from read_json_auto('{}/successorof.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into callerof select 0 as _key,string_split(_from, '/')[2] as _from,string_split(_to, '/')[2] as _to from read_json_auto('{}/callerof.jsonl');", csv_path).as_str(), params![])?;
	Ok(())
    }
    
    pub fn import_arch(&self, csv_path: String) -> Result<()> {
	self.dataflow.execute(format!("insert into opcodes select _key as _key,name as name,value as value from read_json_auto('{}/opcodes.jsonl');", csv_path).as_str(), params![])?;
	self.dataflow.execute(format!("insert into registers select _key as _key,name as name,value as value,size as size,is_gp as is_gp from read_json_auto('{}/registers.jsonl');", csv_path).as_str(), params![])?;
	Ok(())
    }
    
    pub fn get_coverage(&self) -> Result<Vec<u64>> {
	let mut stmt = self.dataflow.prepare("select distinct pc from instructionruns;")?;
	let mut rows = stmt.query(params![])?;
	let mut ans = Vec::<u64>::new();
	while let Some(row) = rows.next()? {
	    let pc: u64 = row.get(0)?;
	    ans.push(pc);
	}
	return Ok(ans);
    }
    
    pub fn get_objects(&self) -> Result<Vec<Object>> {
	let mut stmt = self.dataflow.prepare("select name,base,size,birth,death,typeid from objects;")?;
	let mut rows = stmt.query(params![])?;
	let mut ans = Vec::<Object>::new();
	while let Some(row) = rows.next()? {
	    let name: String = row.get(0)?;
	    let base: u64 = row.get(1)?;
	    let size: u64 = row.get(2)?;
	    let birth: u64 = row.get(3)?;
	    let death: u64 = row.get(4)?;
	    let type_id: u64 = row.get(5)?;
	    ans.push(Object{name,base,size,type_id,birth,death});
	}
	return Ok(ans);	
    }
    
    pub fn add_object(&self, obj : Object) -> Result<()> {
	let mut stmt = self.dataflow.prepare("insert values (?, ?, ?, ?, ?, ?) into objects;")?;
	stmt.execute(params![obj.base, obj.name, obj.base, obj.size, obj.birth, obj.death])?;
	return Ok(());	
    }
    
    pub fn del_object(&self, addr : u64) -> Result<()> {
	let mut stmt = self.dataflow.prepare("delete from objects where base = ?;")?;
	stmt.execute(params![addr])?;
	return Ok(());	
    }
    

    pub fn get_witnesses(&self) -> Result<Vec<Witness>> {
	let mut stmt = self.dataflow.prepare("select moduleName,objectOffset,moduleOffset,eventType,typeId,insFeature,regNum from witnesses;")?;
	let mut rows = stmt.query(params![])?;
	let mut ans = Vec::<Witness>::new();
	while let Some(row) = rows.next()? {
	    let module_path: String = row.get(0)?;
	    let object_offset: u64 = row.get(1)?;
	    let module_offset: u64 = row.get(2)?;
	    let event_type: String = row.get(3)?;
	    let type_id: u64 = row.get(4)?;
	    let ins_feature : String = row.get(5)?;
	    let reg_num : u64 = row.get(6)?;
	    let ev : WitnessEvent;
	    if event_type == "birth" {
		ev = WitnessEvent::ObjectBirth(type_id);
	    } else if event_type == "exists" {
		ev = WitnessEvent::ObjectExists(type_id);
	    } else if event_type == "death" {
		ev = WitnessEvent::ObjectDeath(type_id);
	    } else {
		return Err(anyhow::anyhow!("invalid event_type"))
	    }
	    let eff : InstructionEffectType;
	    if ins_feature == "regwrite" {
		eff = InstructionEffectType::RegWrite(reg_num);
	    } else if ins_feature == "memwritevalue" {
		eff = InstructionEffectType::MemWriteValue;
	    } else if ins_feature == "memwriteaddress" {
		eff = InstructionEffectType::MemWriteAddress;
	    } else if ins_feature == "memreadvalue" {
		eff = InstructionEffectType::MemReadValue;
	    } else if ins_feature == "memreadaddress" {
		eff = InstructionEffectType::MemReadAddress;
	    } else {
		return Err(anyhow::anyhow!("invalid ins_feature"))
	    }
	    ans.push(Witness{module_offset, module_path, effect_type: eff, event: ev});
	}
	return Ok(ans);	
    }
    
    pub fn add_witness(&self, w : Witness) -> Result<()> {
	let type_id : u64;
	let ev = match w.event {
	    WitnessEvent::ObjectBirth(t) => {
		type_id = t;
		"birth"
	    },
	    WitnessEvent::ObjectExists(t) => {
		type_id = t;
		"exists"
	    },
	    WitnessEvent::ObjectDeath(t) => {
		type_id = t;
		"death"
	    },
	};
	let reg_num : u64;
	let ins_feature = match w.effect_type {
	    InstructionEffectType::RegWrite(r) => {
		reg_num = r;
		"regwrite"
	    },
	    InstructionEffectType::MemWriteValue => {
		reg_num = 0;
		"memwritevalue"
	    },
	    InstructionEffectType::MemWriteAddress => {
		reg_num = 0;
		"memwriteaddress"
	    },
	    InstructionEffectType::MemReadValue => {
		reg_num = 0;
		"memreadvalue"
	    },
	    InstructionEffectType::MemReadAddress => {
		reg_num = 0;
		"memreadaddress"
	    },
	};
	let mut stmt = self.dataflow.prepare("insert values (?, ?, ?, ?, ?, ?) into witnesses;")?;
	stmt.execute(params![w.module_path, 0 as u64, w.module_offset, ev, type_id, ins_feature, reg_num])?;
	return Ok(());	
    }
    
    pub fn del_witness(&self, module_name : String, module_offset : u64) -> Result<()> {
	let mut stmt = self.dataflow.prepare("delete from witnesses where moduleName = ? and moduleOffset = ?;")?;
	stmt.execute(params![module_name, module_offset])?;
	return Ok(());	
    }

    pub fn get_instructions_with_effects(instrace : OperationsWithInstructions) -> Vec<InstructionWithEffects> {
	let mut effects : HashMap<u64, Vec<OperationEffect>> = HashMap::new();
	for op in instrace.ops {
	    if !effects.contains_key(&op.tick) {
		effects.insert(op.tick, Vec::new());
	    }
	    if op.bank == Some(1) {
		if let Some(ins_effects) = effects.get_mut(&op.tick) {
		    if let Some(addr) = op.addr {
			if let Some(val) = op.value {
			    if let Some(size) = op.size {
				ins_effects.push(OperationEffect{index: op.index, addr, val, size, effect_type:OperationEffectType::MemWrite});
			    }
			}
		    }
		}
	    } else if op.assocd_bank == Some(1) {
		if let Some(ins_effects) = effects.get_mut(&op.tick) {
		    if let Some(addr) = op.assocd_addr {
			if let Some(val) = op.value {
			    if let Some(size) = op.assocd_size {
				ins_effects.push(OperationEffect{index: op.index, addr, val, size, effect_type:OperationEffectType::MemRead});
			    }
			}
		    }
		}
	    } else if op.bank == Some(0) {
		if let Some(ins_effects) = effects.get_mut(&op.tick) {
		    if let Some(addr) = op.addr {
			if let Some(val) = op.value {
			    if let Some(size) = op.size {
				ins_effects.push(OperationEffect{index: op.index, addr, val, size, effect_type:OperationEffectType::RegWrite});
			    }
			}
		    }
		}
	    }
	}

	let mut ans : Vec<InstructionWithEffects> = Vec::new();
	
	for ins in instrace.instructions.values() {
	    if let Some(ins_effects) = effects.get_mut(&ins.tick) {
		ins_effects.sort_by_key(|a| a.index);
		ans.push(InstructionWithEffects{ instruction: ins.clone(), effects: ins_effects.clone()});
	    } else {
		ans.push(InstructionWithEffects{ instruction: ins.clone(), effects: Vec::new()});
	    }
	}
	ans.sort_by_key(|a| a.instruction.tick );
	return ans;
    }
    
    pub fn get_instrace(&self, start_tick: u64, end_tick: u64) -> Result<OperationsWithInstructions> {
	let mut stmt = self.dataflow.prepare("SELECT op.tick,op.index,op.bank,op.addr,op.val,op.size,op.assocd_addr,op.assocd_bank,op.assocd_size from operationruns as op where op.tick >= ? and op.tick <= ? order by index;")?;
	let mut rows = stmt.query(params![start_tick, end_tick])?;
	let mut ops = Vec::<OperationRun>::new();
	while let Some(row) = rows.next()? {
	    let tick : u64 = row.get(0)?;
	    let index : u64 = row.get(1)?;
	    let bank : Option<u64> = row.get(2)?;
	    let addr : Option<u64> = row.get(3)?;
	    let value : Option<Vec<u8>> = row.get(4)?;
	    let size : Option<u64> = row.get(5)?;
	    let assocd_addr : Option<u64> = row.get(6)?;
	    let assocd_bank : Option<u64> = row.get(7)?;
	    let assocd_size : Option<u64> = row.get(8)?;
	    let deps: Vec<u64> = vec![];
	    ops.push(OperationRun{tick, index, bank, addr, value, size, assocd_addr, assocd_bank, assocd_size, deps});
	}
	let mut stmt2 = self.dataflow.prepare("select tick,pc,disas from instructionruns where tick >= ? and tick <= ?;")?;
	let mut rows2 = stmt2.query(params![start_tick, end_tick])?;
	let mut instructions = HashMap::<u64, InstructionRun>::new();
	while let Some(row2) = rows2.next()? {
	    let tick : u64 = row2.get(0)?;
	    let pc : u64 = row2.get(1)?;
	    let disas : String = row2.get(2)?;
	    instructions.insert(tick, InstructionRun{tick, pc, disas});
	}
	Ok(OperationsWithInstructions{ops, instructions})
    }
    
    pub fn get_instrace_by_pc(&self, start_pc: u64, end_pc: u64) -> Result<OperationsWithInstructions> {
	let mut stmt = self.dataflow.prepare("with ticks as (select tick from instructionruns where pc >= ? and pc <= ?) SELECT op.tick,op.index,op.bank,op.addr,op.val,op.size,op.assocd_addr,op.assocd_bank,op.assocd_size from operationruns as op where op.tick in (select tick from ticks) order by index;")?;
	let mut rows = stmt.query(params![start_pc, end_pc])?;
	let mut ops = Vec::<OperationRun>::new();
	while let Some(row) = rows.next()? {
	    let tick : u64 = row.get(0)?;
	    let index : u64 = row.get(1)?;
	    let bank : Option<u64> = row.get(2)?;
	    let addr : Option<u64> = row.get(3)?;
	    let value : Option<Vec<u8>> = row.get(4)?;
	    let size : Option<u64> = row.get(5)?;
	    let assocd_addr : Option<u64> = row.get(6)?;
	    let assocd_bank : Option<u64> = row.get(7)?;
	    let assocd_size : Option<u64> = row.get(8)?;
	    let deps: Vec<u64> = vec![];
	    ops.push(OperationRun{tick, index, bank, addr, value, size, assocd_addr, assocd_bank, assocd_size, deps});
	}
	let mut stmt2 = self.dataflow.prepare("select tick,pc,disas from instructionruns where pc >= ? and pc <= ?;")?;
	let mut rows2 = stmt2.query(params![start_pc, end_pc])?;
	let mut instructions = HashMap::<u64, InstructionRun>::new();
	while let Some(row) = rows2.next()? {
	    let tick : u64 = row.get(0)?;
	    let pc : u64 = row.get(1)?;
	    let disas : String = row.get(2)?;
	    instructions.insert(tick, InstructionRun{tick, pc, disas});
	}
	Ok(OperationsWithInstructions{ops, instructions})
    }
    
    pub fn get_backward_slice(&self, index: u64, depth: u64) -> Result<OperationsWithInstructions> {
	let mut stmt = self.dataflow.prepare("with recursive backward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _from as startIndex, _to as endIndex, _from as prevIndex, ARRAY[_from] as path, 1 as depth from inputdep where _from == ? UNION ALL SELECT backward_slice.startIndex as startIndex, _to as endIndex, _from as prevIndex, array_append(backward_slice.path, _to) as path, backward_slice.depth + 1 as depth from backward_slice JOIN inputdep ON backward_slice.endIndex == _from WHERE backward_slice.depth < ?) SELECT op.tick,op.index,op.bank,op.addr,op.val,op.size,op.assocd_addr,op.assocd_bank,op.assocd_size,s.prevIndex as dep from operationruns as op inner join backward_slice as s on op.index == s.endIndex order by index;")?;
	let mut rows = stmt.query(params![index, depth])?;
	let mut ops = Vec::<OperationRun>::new();
	while let Some(row) = rows.next()? {
	    let tick : u64 = row.get(0)?;
	    let index : u64 = row.get(1)?;
	    let bank : Option<u64> = row.get(2)?;
	    let addr : Option<u64> = row.get(3)?;
	    let value : Option<Vec<u8>> = row.get(4)?;
	    let size : Option<u64> = row.get(5)?;
	    let assocd_addr : Option<u64> = row.get(6)?;
	    let assocd_bank : Option<u64> = row.get(7)?;
	    let assocd_size : Option<u64> = row.get(8)?;
	    let deps: Vec<u64> = vec![row.get(9)?];
	    ops.push(OperationRun{tick, index, bank, addr, value, size, assocd_addr, assocd_bank, assocd_size, deps});
	}
	let mut stmt2 = self.dataflow.prepare("with recursive backward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _from as startIndex, _to as endIndex, _from as prevIndex, ARRAY[_from] as path, 1 as depth from inputdep where _from == ? UNION ALL SELECT backward_slice.startIndex as startIndex, _to as endIndex, _from as prevIndex, array_append(backward_slice.path, _to) as path, backward_slice.depth + 1 as depth from backward_slice JOIN inputdep ON backward_slice.endIndex == _from WHERE backward_slice.depth < ?) select tick,pc,disas from instructionruns where tick in (select tick from operationruns where index in (select endIndex from backward_slice));")?;
	let mut rows2 = stmt2.query(params![index, depth])?;
	let mut instructions = HashMap::<u64, InstructionRun>::new();
	while let Some(row) = rows2.next()? {
	    let tick : u64 = row.get(0)?;
	    let pc : u64 = row.get(1)?;
	    let disas : String = row.get(2)?;
	    instructions.insert(tick, InstructionRun{tick, pc, disas});
	}
	Ok(OperationsWithInstructions{ops, instructions})
    }
    
    pub fn get_forward_slice(&self, index: u64, depth: u64) -> Result<OperationsWithInstructions> {
	let mut stmt = self.dataflow.prepare("with recursive forward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _to as startIndex, _from as endIndex, _to as prevIndex, ARRAY[_to] as path, 1 as depth from inputdep where _to == ? UNION ALL SELECT forward_slice.startIndex as startIndex, _from as endIndex, _to as prevIndex, array_append(forward_slice.path, _to) as path, forward_slice.depth + 1 as depth from forward_slice JOIN inputdep ON forward_slice.endIndex == _to WHERE forward_slice.depth < ?) SELECT op.tick,op.index,op.bank,op.addr,op.val,op.size,op.assocd_addr,op.assocd_bank,op.assocd_size,s.prevIndex as dep from operationruns as op inner join forward_slice as s on op.index == s.endIndex order by index;")?;
	let mut rows = stmt.query(params![index, depth])?;
	let mut ops = Vec::<OperationRun>::new();
	while let Some(row) = rows.next()? {
	    let tick : u64 = row.get(0)?;
	    let index : u64 = row.get(1)?;
	    let bank : Option<u64> = row.get(2)?;
	    let addr : Option<u64> = row.get(3)?;
	    let value : Option<Vec<u8>> = row.get(4)?;
	    let size : Option<u64> = row.get(5)?;
	    let assocd_addr : Option<u64> = row.get(6)?;
	    let assocd_bank : Option<u64> = row.get(7)?;
	    let assocd_size : Option<u64> = row.get(8)?;
	    let deps: Vec<u64> = vec![row.get(9)?];
	    ops.push(OperationRun{tick, index, bank, addr, value, size, assocd_addr, assocd_bank, assocd_size, deps});
	}
	let mut stmt2 = self.dataflow.prepare("with recursive forward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _to as startIndex, _from as endIndex, _to as prevIndex, ARRAY[_to] as path, 1 as depth from inputdep where _to == ? UNION ALL SELECT forward_slice.startIndex as startIndex, _from as endIndex, _to as prevIndex, array_append(forward_slice.path, _to) as path, forward_slice.depth + 1 as depth from forward_slice JOIN inputdep ON forward_slice.endIndex == _to WHERE forward_slice.depth < ?) select tick,pc,disas from instructionruns where tick in (select tick from operationruns where index in (select endIndex from forward_slice));")?;
	let mut rows2 = stmt2.query(params![index, depth])?;
	let mut instructions = HashMap::<u64, InstructionRun>::new();
	while let Some(row) = rows2.next()? {
	    let tick : u64 = row.get(0)?;
	    let pc : u64 = row.get(1)?;
	    let disas : String = row.get(2)?;
	    instructions.insert(tick, InstructionRun{tick, pc, disas});
	}
	Ok(OperationsWithInstructions{ops, instructions})
    }
    
    pub fn get_operation_deps(&self, index: u64, depth: u64) -> Result<Vec<u64>> {
	// backward slice
	let mut stmt = self.dataflow.prepare("with recursive backward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _from as startIndex, _to as endIndex, _from as prevIndex, ARRAY[_from] as path, 1 as depth from inputdep where _from == ? UNION ALL SELECT backward_slice.startIndex as startIndex, _to as endIndex, _from as prevIndex, array_append(backward_slice.path, _to) as path, backward_slice.depth + 1 as depth from backward_slice JOIN inputdep ON backward_slice.endIndex == _from WHERE backward_slice.depth < ?) SELECT startIndex, endIndex, prevIndex, path, depth from backward_slice;")?;
	let mut rows = stmt.query(params![index, depth])?;
	let mut ans = Vec::<u64>::new();
	while let Some(row) = rows.next()? {
	    let idx: u64 = row.get(1)?;
	    ans.push(idx);
	}
	
	// forward slice
	let mut stmt2 = self.dataflow.prepare("with recursive forward_slice(startIndex, endIndex, prevIndex, path, depth) AS (select _to as startIndex, _from as endIndex, _to as prevIndex, ARRAY[_to] as path, 1 as depth from inputdep where _to == ? UNION ALL SELECT forward_slice.startIndex as startIndex, _from as endIndex, _to as prevIndex, array_append(forward_slice.path, _to) as path, forward_slice.depth + 1 as depth from forward_slice JOIN inputdep ON forward_slice.endIndex == _to WHERE forward_slice.depth < ?) SELECT startIndex, endIndex, prevIndex, path, depth from forward_slice;")?;
	let mut rows2 = stmt2.query(params![index, depth])?;
	while let Some(row) = rows2.next()? {
	    let idx: u64 = row.get(1)?;
	    ans.push(idx);
	}
	return Ok(ans);
    }

    pub fn get_object_uses(&self, obj : Object) -> Result<Vec<u64>> {
	let mut stmt = self.dataflow.prepare("load spatial;select index from accesses where ST_Within(pt, ST_MakeEnvelope(?, ?, ?, ?));")?;
	let mut rows = stmt.query(params![obj.birth, obj.base, obj.death, obj.base+obj.size])?;
	let mut ans = Vec::<u64>::new();
	while let Some(row) = rows.next()? {
	    let idx: u64 = row.get(0)?;
	    ans.push(idx);
	}
	return Ok(ans);
    }

    pub fn get_accesses_from_rect(&self, start_addr : u64, end_addr : u64, start_tick : u64, end_tick : u64) -> Result<Vec<u64>> {
	let mut stmt = self.dataflow.prepare("load spatial;select index from accesses where ST_Within(pt, ST_MakeEnvelope(?, ?, ?, ?));")?;
	let mut rows = stmt.query(params![start_tick, start_addr, end_tick, end_addr])?;
	let mut ans = Vec::<u64>::new();
	while let Some(row) = rows.next()? {
	    let idx: u64 = row.get(0)?;
	    ans.push(idx);
	}
	return Ok(ans);
    }

    pub fn get_min_tick(&self) -> Result<u64> {
	let mut stmt = self.dataflow.prepare("select min(tick) from instructionruns;")?;
	let mut rows = stmt.query(params![])?;
	match rows.next()? {
	    Some(row) => {
		Ok(row.get(0)?)
	    }
	    None => {
		Err(anyhow::anyhow!("no ticks found"))
	    }
	}
    }
    
    pub fn get_max_tick(&self) -> Result<u64> {
	let mut stmt = self.dataflow.prepare("select max(tick) from instructionruns;")?;
	let mut rows = stmt.query(params![])?;
	match rows.next()? {
	    Some(row) => {
		Ok(row.get(0)?)
	    }
	    None => {
		Err(anyhow::anyhow!("no ticks found"))
	    }
	}
    }
    
    pub fn get_instructions(&self, insns : InstructionSet) -> Result<Vec<InstructionRun>> {
	match insns {
	    InstructionSet::Filter(ticks, pcs, addrs) => {
		if let Some((start_tick, end_tick)) = ticks {
		    if let Some((start_pc, end_pc)) = pcs {
			// tick and pc filter
			let mut stmt = self.dataflow.prepare("select tick,pc,disas from instructionruns where tick >= ? and tick <= ? and pc >= ? and pc <= ?;").unwrap();
			let mut rows = stmt.query(params![start_tick, end_tick, start_pc, end_pc]).unwrap();
			let mut ans = Vec::<InstructionRun>::new();
			while let Some(row) = rows.next()? {
			    let tick: u64 = row.get(0)?;
			    let pc: u64 = row.get(1)?;
			    let disas: String = row.get(2)?;
			    ans.push(InstructionRun{tick, pc, disas});
			}
			return Ok(ans);
		    } else {
			// only tick filter
			let mut stmt = self.dataflow.prepare("select tick,pc,disas from instructionruns where tick >= ? and tick <= ?;").unwrap();
			let mut rows = stmt.query(params![start_tick, end_tick]).unwrap();
			let mut ans = Vec::<InstructionRun>::new();
			while let Some(row) = rows.next()? {
			    let tick: u64 = row.get(0)?;
			    let pc: u64 = row.get(1)?;
			    let disas: String = row.get(2)?;
			    ans.push(InstructionRun{tick, pc, disas});
			}
			return Ok(ans);
			
		    }
		} else {
		    if let Some((start_pc, end_pc)) = pcs {
			// only pc filter
			let mut stmt = self.dataflow.prepare("select tick,pc,disas from instructionruns where pc >= ? and pc <= ?;").unwrap();
			let mut rows = stmt.query(params![start_pc, end_pc]).unwrap();
			let mut ans = Vec::<InstructionRun>::new();
			while let Some(row) = rows.next()? {
			    let tick: u64 = row.get(0)?;
			    let pc: u64 = row.get(1)?;
			    let disas: String = row.get(2)?;
			    ans.push(InstructionRun{tick, pc, disas});
			}
			return Ok(ans);
		    }
		    return Ok(vec![]);
		}
	    },
	}
    }
    
    pub fn get_witness_events(&self) -> Result<Vec<WitnessedEvent>> {
	let mut stmt = self.dataflow.prepare("with wits as (select m.name as module_name,m.base + w.moduleOffset - 1048576 as pc,w.eventType as event_type,w.typeId as type_id,w.insFeature as ins_feature,w.regNum as reg_num from witnesses as w inner join modules as m on w.moduleName == m.path),
ticks as (select ws.*,ins.tick as tick from instructionruns as ins inner join wits as ws on ins.pc == ws.pc),
select ts.pc,ts.tick,ts.type_id,ts.event_type,(
  CASE WHEN ts.ins_feature == 'memwritevalue' THEN ops.val
       WHEN ts.ins_feature == 'memwriteaddress' THEN ops.addr
       WHEN ts.ins_feature == 'memreadaddress' THEN ops.val
       WHEN ts.ins_feature == 'memreadaddress' THEN ops.assocd_addr
       WHEN ts.ins_feature == 'regwrite' THEN ops.val
  END
) as witnessed_addr
from ticks as ts inner join operationruns as ops on
  CASE WHEN ts.ins_feature == 'memwritevalue' THEN ops.bank == 1 and ops.tick == ts.tick
       WHEN ts.ins_feature == 'memwriteaddress' THEN ops.bank == 1 and ops.tick == ts.tick
       WHEN ts.ins_feature == 'memreadvalue' THEN ops.assocd_bank == 1 and ops.tick == ts.tick
       WHEN ts.ins_feature == 'memreadaddress' THEN ops.assocd_bank == 1 and ops.tick == ts.tick
       WHEN ts.ins_feature == 'regwrite' THEN ops.bank == 0 and ops.addr == ts.reg_num and ops.tick == ts.tick
  END;
")?;
	let mut rows = stmt.query(params![])?;
	let mut ans = Vec::<WitnessedEvent>::new();
	while let Some(row) = rows.next()? {
	    let pc:u64 = row.get(0)?;
	    let tick:u64 = row.get(1)?;
	    let type_id:u64 = row.get(2)?;
	    let event_type:String = row.get(3)?;
	    let witnessed_addr:u64 = row.get(4)?;
	    if event_type == "birth" {
		ans.push(WitnessedEvent::ObjectBirth(pc,tick,witnessed_addr,type_id));
	    } else if event_type == "exists" {
		ans.push(WitnessedEvent::ObjectExists(pc,tick,witnessed_addr,type_id));
	    } else if event_type == "death" {
		ans.push(WitnessedEvent::ObjectDeath(pc,tick,witnessed_addr,type_id));
	    }
	}
	return Ok(ans);	
    }
    
    pub fn why(&self, tick: InstructionTick) -> Result<Vec<InstructionTick>> {
	let mut stmt = self.dataflow.prepare("
with ins as (select _key,pc,tick from instructionruns where tick == ?),
mod as (select * from modules where base < (select pc from ins) and base+size > (select pc from ins)),
mod_offset as (select (select base from mod) as base,(select pc from ins)-(select base from mod) as offset),
block as (select * from blocks where module == concat('/sysroot',(select path from mod)) and addr - 1048576 <= (select \"offset\" from mod_offset) and addr - 1048576 + size > (select \"offset\" from mod_offset)),
cdeps as (select * from blocks where _key in (select _to from cdg where _from == (select _key from block))),
cdep_ranges as (select b.addr-1048576+m.base as cdep_low,b.addr-1048576+m.base+b.size as cdep_high from cdeps as b inner join modules as m on b.module[9:]==m.path),
cdeps_insn as (select * from instructionruns as i inner join cdep_ranges as r on i.pc >= r.cdep_low and i.pc < r.cdep_high where i.tick < (select tick from ins) order by i.tick desc limit 1),
fnrun as (select * from functionruns where _key == (select _to from infunctionrun where _from == (select _key from ins))),
calls as (select max(tick) as tick from instructionruns where pc == (select callsite from fnrun) and tick < (select tick from ins))
select max(t) as tick from (select tick as t from calls union all select tick as t from cdeps_insn) as combination;")?;
	let mut rows = stmt.query(params![tick])?;
	let mut ans = Vec::<InstructionTick>::new();
	while let Some(row) = rows.next()? {
	    let tick: InstructionTick = row.get(0)?;
	    ans.push(tick);
	}
	return Ok(ans);	
    }

    pub fn get_modules(&self) -> Result<Vec<Module>> {
	let mut stmt = self.dataflow.prepare("select base,size,name,path from modules;")?;
	let mut rows = stmt.query(params![])?;
	let mut ans = Vec::<Module>::new();
	while let Some(row) = rows.next()? {
	    let base: u64 = row.get(0)?;
	    let size: u64 = row.get(1)?;
	    let name: String = row.get(2)?;
	    let path: String = row.get(3)?;
	    ans.push(Module{base,size,name,path});
	}
	return Ok(ans);	
    }
    
    pub fn stringsearch(&self, search_string: String) -> Result<Vec<BufferInfo>> {
        let results = self.strings.search(search_string.as_str().as_bytes());
	let mut ans = Vec::<BufferInfo>::new();
        for i in 0..results.len() {
	    let info = BufferInfo {
		birth: results[i].created_at,
		death: results[i].destroyed_at,
		addr: results[i].address,
	    };
	    ans.push(info);
        }
	return Ok(ans);
    }

    pub fn get_memory(&self, tick: InstructionTick, address: Address, size: usize) -> Result<MemoryInfo> {
	let results = self.memory.find(tick, address, address + size as u64);
        let mut data = vec![0u8; size];
        let mut addrs = vec![0u64; size];
        let mut write_ticks = vec![0u64; size];
        for op in results.iter() {
            let mut i = 0;
            for x in op.data.iter() {
                if op.address + i >= address && op.address + i < address + size as u64 {
                    let offset = (op.address + i - address) as usize;
                    if op.created_at > write_ticks[offset] {
                        addrs[offset] = op.address + i;
                        write_ticks[offset] = op.created_at;
                        data[offset] = *x;
                    } else {
                        addrs[offset] = op.address + i;
                    }
                }
                i += 1;
            }
        }
	Ok(MemoryInfo{data, addrs, write_ticks})
    }


    pub fn get_registers(&self, tick: InstructionTick, address: Address, size: usize) -> Result<MemoryInfo> {
	let results = self.registers.find(tick, address, address + size as u64);
        let mut data = vec![0u8; size];
        let mut addrs = vec![0u64; size];
        let mut write_ticks = vec![0u64; size];
        for op in results.iter() {
            let mut i = 0;
            for x in op.data.iter() {
                if op.address + i >= address && op.address + i < address + size as u64 {
                    let offset = (op.address + i - address) as usize;
                    if op.created_at > write_ticks[offset] {
                        addrs[offset] = op.address + i;
                        write_ticks[offset] = op.created_at;
                        data[offset] = *x;
                    } else {
                        addrs[offset] = op.address + i;
                    }
                }
                i += 1;
            }
        }
	Ok(MemoryInfo{data, addrs, write_ticks})
    }
}
