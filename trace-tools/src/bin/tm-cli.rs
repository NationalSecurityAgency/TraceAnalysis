use anyhow::Result;

use std::fs;

use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;

use trace_tools::api::{TmApi,InstructionSet};
use trace_tools::cli::{Command,Commands,handle_cmd};
use trace_tools::storage::{ProjectData};
use trace_tools::mgr_cli::{Command as MgrCommand,Commands as MgrCommands,handle_cmd as mgr_handle_cmd};

use clap::{Parser, Subcommand};
use clap_repl::reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory};
use clap_repl::ClapEditor;


fn main() {
    let args = MgrCommand::parse();
    if let MgrCommands::Query{path, name, command} = args.command {
	let mut prj = ProjectData::load(path.to_string()).unwrap();
	let mut api = prj.get_api(&name).unwrap();
	if let Some(command) = command {
	    let cmd = Command::parse_from(std::iter::once("query").chain(command.split_whitespace().collect::<Vec<&str>>().into_iter()));
	    match handle_cmd(cmd, &api) {
		Ok(res) => {
		    println!("{}",res);
		},
		Err(e) => {
		    println!("Error: {:?}", e);
		},
	    }
	} else {
	    let prompt = DefaultPrompt {
		left_prompt: DefaultPromptSegment::Basic(">>".to_owned()),
		..DefaultPrompt::default()
	    };
	    let rl = ClapEditor::<Command>::builder()
		.with_prompt(Box::new(prompt))
		.with_editor_hook(|reed| {
		    reed.with_history(Box::new(FileBackedHistory::with_file(10000, "/tmp/tm-cli-history".into()).unwrap()))
		})
		.build();
	    rl.repl(|cmd| {
		match handle_cmd(cmd, &api) {
		    Ok(res) => {
			println!("{}",res);
		    },
		    Err(e) => {
			println!("Error: {:?}", e);
		    },
		}
	    });
	}
    } else {
	match mgr_handle_cmd(args) {
	    Ok(res) => {
		println!("{}",res);
	    },
	    Err(e) => {
		println!("Error: {:?}", e);
	    },
	}
    }
}
