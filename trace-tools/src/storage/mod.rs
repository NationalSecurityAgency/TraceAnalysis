use anyhow::{anyhow,Result};
use std::collections::HashMap;

use std::fmt;
use std::fs;
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use duckdb::{params, Connection, Result as DuckDbResult};
use duckdb;

use crate::index;
use crate::index::Serializable;

use std::path::{Path,PathBuf};
use std::io;
use std::io::BufReader;
use std::io::BufWriter;
use std::process::Command;

use crate::index::spacetime_index::{SpacetimeRTree,SpacetimeIndex};
use crate::index::string_index::StringIndex;
use crate::index::{Indexer, Operation};
use crate::api::TmApi;

mod analyze;

use trace::{
    reader::{cont, try_break, TraceReader},
    record::{Record,parse_unknown},
    RuntimeError,
};

use walkdir::WalkDir;

pub struct ProjectData {
    pub root: PathBuf,
    pub manifest: ProjectManifest,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProjectManifest {
    pub name: String,
    pub ghidra_path: PathBuf,
    pub dynamic_info: HashMap<String, TraceInfo>,
    pub static_info: StaticInfo,
    pub arch_info: ArchInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TraceInfo {
    pub tracefile: PathBuf,
    pub mapfile: PathBuf,
    pub analysis: Option<Analysis>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Analysis {
    pub dataflow: PathBuf,
    pub db: PathBuf,
    pub strings_index: PathBuf,
    pub spacetime_index: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StaticInfo {
    pub ghidra_project: PathBuf,
    pub sysroot: PathBuf,
    pub static_info: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ArchInfo {
    pub regs: RegistersInfo,
    pub ops: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RegistersInfo {
    x86_32(PathBuf),
    x86_64(PathBuf),
    x86_64_32(PathBuf),
    aarch64(PathBuf),
    arm32(PathBuf),
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn open_input(input: PathBuf) -> io::Result<Box<dyn Read>> {
    Ok(Box::new(BufReader::new(fs::File::open(input)?)))
}

fn open_index_file(index_path: PathBuf) -> io::Result<Option<Box<dyn Write>>> {
    Ok(Some(Box::new(BufWriter::new(fs::File::create(index_path)?))))
}


impl ProjectData {

    pub fn load(path: String) -> Result<Self> {
	let root = PathBuf::from(&path);
	let manifest_str = fs::read_to_string(Path::new(&path).join("manifest.json"))?;
	let manifest : ProjectManifest = serde_json::from_str(&manifest_str)?;
	Ok(ProjectData {
	    root,
	    manifest,
	})
    }

    pub fn init(name: String, sysroot: PathBuf, arch: String, ghidra_path: PathBuf) -> Result<Self> {
	let binding = name.clone();
	let project_root = Path::new(&binding);
	fs::create_dir(project_root)?;
	
	// copy the sysroot into the project folder
	let sysroot_root = project_root.join("sysroot");
	copy_dir_all(Path::new(&sysroot), &sysroot_root)?;

	// create the arch subdir
	
	let arch_root = project_root.join("arch");
	fs::create_dir(&arch_root)?;
	let reg_path = arch_root.join("registers.jsonl");
	let maybe_reg_info = match arch.as_str() {
	    "x86_32" => Some(RegistersInfo::x86_32(PathBuf::from(reg_path.clone()))),
	    "x86_64" => Some(RegistersInfo::x86_64(PathBuf::from(reg_path.clone()))),
	    "x86_64_32" => Some(RegistersInfo::x86_64_32(PathBuf::from(reg_path.clone()))),
	    "aarch64" => Some(RegistersInfo::aarch64(PathBuf::from(reg_path.clone()))),
	    "arm32" => Some(RegistersInfo::arm32(PathBuf::from(reg_path.clone()))),
	    _ => None
	};
	let reg_info = maybe_reg_info.ok_or(anyhow!("arch must be one of x86_32, x86_64, x86_64_32, aarch64, arm32"))?;

	let reg_data = match arch.as_str() {
	    "x86_32" => Some(include_str!("./data/constants/x86_32/registers.jsonl")),
	    "x86_64" => Some(include_str!("./data/constants/x86_64/registers.jsonl")),
	    "x86_64_32" => Some(include_str!("./data/constants/x86_64_32/registers.jsonl")),
	    "aarch64" => Some(include_str!("./data/constants/aarch64/registers.jsonl")),
	    "arm32" => Some(include_str!("./data/constants/arm32/registers.jsonl")),
	    _ => None
	}.unwrap();
	
	let new_ops = arch_root.join("opcodes.jsonl");
	fs::write(&reg_path, reg_data)?;
	fs::write(&new_ops, include_str!("./data/constants/opcodes.jsonl"))?;
	
	// create the static subdir	

	let static_root = project_root.join("static");
	let script_root = static_root.join("ghidra_scripts");
	let gpr_root = static_root.join("ghidra_project");
	let extracted_root = static_root.join("extracted");
	fs::create_dir(&static_root)?;
	fs::create_dir(&script_root)?;
	fs::create_dir(&gpr_root)?;
	fs::create_dir(&extracted_root)?;
	
	fs::write(script_root.join("ExtractStatic.java"), include_str!("./data/ghidra_scripts/ExtractStatic.java"))?;
	
	let import_status = Command::new(Path::new(&ghidra_path).join("support").join("analyzeHeadless"))
	    .arg(&gpr_root)
	    .arg(&name)
	    .arg("-import")
	    .arg(&sysroot_root)
	    .arg("-recursive")
	    .status()?;
	for entry in WalkDir::new(&sysroot_root) {
	    if let Ok(entry) = entry {
		if entry.file_type().is_dir() { continue; }
		let extract_status = Command::new(Path::new(&ghidra_path).join("support").join("analyzeHeadless"))
		    .arg(&gpr_root)
		    .arg(format!("{}/{}", name, entry.path().parent().unwrap().strip_prefix(project_root).unwrap().to_str().unwrap()))
		    .arg("-process")
		    .arg(entry.path().file_name().unwrap())
		    .arg("-scriptPath")
		    .arg(&script_root)
		    .arg("-noanalysis")
		    .arg("-postScript")
		    .arg("ExtractStatic.java")
		    .arg(&extracted_root)
		    .status()?;
	    }
	}
	
	// create the ProjectManifest object
	let res = ProjectManifest {
	    name,
	    ghidra_path,
	    dynamic_info: HashMap::new(),
	    static_info: StaticInfo {
		ghidra_project: gpr_root,
		sysroot: sysroot_root,
		static_info: extracted_root,
	    },
	    arch_info: ArchInfo {
		regs: reg_info,
		ops: new_ops,
	    },
	};
	let ans = ProjectData {
	    root: fs::canonicalize(project_root)?,
	    manifest: res,
	};
	ans.save()?;
	return Ok(ans);
    }

    fn save(&self) -> Result<()> {
	fs::write(self.root.join("manifest.json"), serde_json::to_string(&self.manifest)?)?;
	Ok(())
    }

    fn generate_indices(trace_file: PathBuf, str_index: PathBuf, st_index: PathBuf) -> Result<()> {
	let str_index_file = open_index_file(str_index)?;
	let st_index_file = open_index_file(st_index)?;

	let (ops, num_ticks) = Self::parse_ops(trace_file)?;

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
    
    fn parse_ops(trace_file: PathBuf) -> Result<(Vec<Operation>, u64)> {
	let input = open_input(trace_file)?;
	
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
		cont!()
            })
            .map_or(Ok(()), |err: io::Error| Err(err))?;

	Ok((ops, tick + 1))
    }

    fn get_dynamic_folder(&self) -> PathBuf {
	self.root.join("dynamic")
    }
    fn get_trace_root(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name)
    }
    fn get_trace_strindex(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("strings.index")
    }
    fn get_trace_spacetimeindex(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("spacetime.index")
    }
    fn get_trace_dataflow(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("dataflow")
    }
    fn get_trace_db(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("dataflow.db")
    }
    fn get_trace_file(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("trace")
    }
    fn get_trace_map(&self, trace_name: &str) -> PathBuf {
	self.get_dynamic_folder().join(trace_name).join("map")
    }
    
    pub fn get_api(&self, trace_name: &str) -> Result<TmApi> {
	let trace_root = self.root.join(trace_name);
	TmApi::new(format!("{}",self.get_trace_db(trace_name).display()),
		   format!("{}",self.get_trace_spacetimeindex(trace_name).display()),
		   format!("{}",self.get_trace_strindex(trace_name).display()),
	)
    }
    
    pub fn add_trace(&mut self, name: &str, trace_file: &str, map_file: &str) -> Result<()> {
	// create the "dynamic" subdir for traces, if needed
	if !self.get_dynamic_folder().is_dir() {
	    fs::create_dir(self.get_dynamic_folder())?;
	}

	// check if the trace already exists in the manifest
	if self.manifest.dynamic_info.contains_key(name) {
	    return Err(anyhow!("trace '{}' already exists", name));
	} else if self.get_trace_root(name).is_dir() {
	    // if trace directory already existrs
	    return Err(anyhow!("trace '{}' is not in manifest, but its data directory {} does exist. please resolve manually", name, self.get_trace_root(name).display()));
	}
	
	// create trace root
	fs::create_dir(self.get_trace_root(name))?;
	let new_trace = self.get_trace_file(name);
	let new_map = self.get_trace_map(name);
	
	fs::copy(Path::new(trace_file), &new_trace)?;
	fs::copy(Path::new(map_file), &new_map)?;

	self.manifest.dynamic_info.insert(String::from(name), TraceInfo {
	    tracefile: new_trace,
	    mapfile: new_map,
	    analysis: None,
	});
	self.save()?;
	Ok(())
    }
    
    pub fn del_trace(&mut self, name: &str) -> Result<()> {
	fs::remove_dir_all(self.get_trace_root(name))?;
	
	self.manifest.dynamic_info.remove(name);
	self.save()?;
	Ok(())
    }
	
    pub fn analyse_trace(&mut self, trace_name : &str) -> Result<()> {
	
	let new_strings = self.get_trace_strindex(trace_name);
	let new_spacetime = self.get_trace_spacetimeindex(trace_name);
	let new_dataflow = self.get_trace_dataflow(trace_name);
	let new_db = self.get_trace_db(trace_name);

	// make the string and spacetime indices
	Self::generate_indices(self.get_trace_file(trace_name), new_strings.clone(), new_spacetime.clone())?;

	// make the dataflow csvs
	analyze::analyze(open_input(self.get_trace_file(trace_name))?, new_dataflow.clone())?;

	// make the db
	let mut api = TmApi::new(format!("{}",new_db.display()),
				 format!("{}",new_spacetime.display()),
				 format!("{}",new_strings.display()),
	)?;
	api.init()?;
	api.import_dynamic(format!("{}",new_dataflow.display()))?;
	api.import_arch(format!("{}",self.root.join("arch").display()))?;
	api.import_static(format!("{}",self.root.join("static").join("extracted").display()))?;
	api.import_modules(format!("{}",self.get_trace_map(trace_name).display()))?;

	let trace_info = self.manifest.dynamic_info.get_mut(trace_name).ok_or(anyhow!("failed to find trace {}", trace_name))?;
	trace_info.analysis = Some(Analysis {
	    dataflow: new_dataflow.clone(),
	    db: new_db.clone(),
	    strings_index: new_strings.clone(),
	    spacetime_index: new_spacetime.clone(),
	});
	self.save()?;
	Ok(())
    }
}
