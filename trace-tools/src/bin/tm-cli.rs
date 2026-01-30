use anyhow::Result;

use std::fs;

use dataflow::prelude::SpaceKind;
use serde::{Deserialize, Serialize};
use serde_json;
use std::sync::Arc;

use trace_tools::api::{TmApi,InstructionSet};
use trace_tools::cli::{Command,Commands,handle_cmd};

use clap::{Parser, Subcommand};
use clap_repl::reedline::{DefaultPrompt, DefaultPromptSegment, FileBackedHistory};
use clap_repl::ClapEditor;


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

fn main() {
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
