use anyhow::{anyhow,Result};

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;
use std::collections::HashMap;

use crate::storage::{ProjectData,TraceInfo};
use std::path::{Path,PathBuf};
use clap::{Parser, Subcommand};

#[derive(Parser, Serialize, Deserialize, Debug)]
pub struct Command {
    #[command(subcommand)]
    pub command: Commands
}

#[derive(Subcommand, Serialize, Deserialize, Debug)]
pub enum Commands {
    Init { name : String, sysroot: PathBuf, arch: String, ghidra_path: PathBuf },
    AddTrace { path: String, name: String, trace_file: String, map_file: String },
    ListTraces { path: String },
    DelTrace { path: String, name: String },
    AnalyseTrace { path : String, name: String },
    Query {
	path : String,
	name: String,
	#[arg(short, long)]
	command: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    Traces(HashMap<String, TraceInfo>),
    Done,
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	match self {
	    Response::Done => {
		writeln!(f, "done")
	    },
	    Response::Traces(map) => {
		for (key, value) in map {
		    writeln!(f, "{}: {}", key, value.tracefile.display())?;
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

pub fn handle_cmd(cmd : Command) -> Result<Response> {
    match &cmd.command {
	Commands::Init{name, sysroot, arch, ghidra_path} => {
	    ProjectData::init(name.to_string(), sysroot.to_path_buf(), arch.to_string(), ghidra_path.to_path_buf())?;
	    return Ok(Response::Done);
	},
	Commands::AddTrace{path, name, trace_file, map_file} => {
	    let mut prj = ProjectData::load(path.to_string())?;
	    prj.add_trace(name, trace_file, map_file)?;
	    return Ok(Response::Done);
	},
	Commands::ListTraces{path} => {
	    let mut prj = ProjectData::load(path.to_string())?;
	    return Ok(Response::Traces(prj.manifest.dynamic_info));
	},
	Commands::DelTrace{path, name} => {
	    let mut prj = ProjectData::load(path.to_string())?;
	    prj.del_trace(&name)?;
	    return Ok(Response::Done);
	},
	Commands::AnalyseTrace{path, name} => {
	    let mut prj = ProjectData::load(path.to_string())?;
	    prj.analyse_trace(name)?;
	    return Ok(Response::Done);
	},
	_ => {
	    return Ok(Response::Done);
	}
    }
}
