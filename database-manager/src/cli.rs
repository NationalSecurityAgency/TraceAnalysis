/// Structures for setting up DbManager's command line interface.
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "dbmanager")]
/// A CLI tool for managing databases containing dynamic trace data.
pub(crate) struct Cli {
    #[arg(long)]
    #[arg(default_value_t = url::Url::parse("http://localhost:8529").unwrap())]
    /// A url used to connect to a running database.
    pub url: url::Url,
    #[arg(long = "schema", required = true)]
    /// Path to an XML file describing the structure of the database.
    pub schema_file: std::path::PathBuf,
    #[arg(default_value_t = String::from("traceanalysis"))]
    /// Name of the database to operate on.
    pub db_name: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
/// Operations that `dbmanager` can do with a database or schema.
pub(crate) enum Command {
    /// Print information about current state of collection(s) in the database.
    // TODO: Allow the user to specify which collection(s) they want information
    // about.
    Info {
        /// If specefied, only prints information about the listed collection(s).
        collection_list: Option<Vec<String>>,
    },
    /// Initialize a database according to the specified `schema_file`.
    Init,
    // TODO: Verify database matches schema
    // /// Ensures the database at `Cli::db_name` is set up properly according to the `schema_file`.
    // Validate,
    /// Populates an initialized database data files specified by `schema_file` based at the corresponding directories.
    PopulateAll {
        /// Suppress output from arangoimport subprocess.
        #[arg(long, default_value_t = false)]
        quiet: bool,
        /// Path to a directory containing enriched trace files emitted by the TraceAnalysis dataflow engine.
        #[arg(id = "dynamic", short, long)]
        dynamic_dir: Option<std::path::PathBuf>,
        /// Path to a directory containing files describing static program information collected from Ghidra.
        #[arg(id = "static", short, long)]
        static_dir: Option<std::path::PathBuf>,
        /// Path to a directory containing files describing the register set used by TraceAnalysis.
        #[arg(id = "constant", short, long)]
        constant_dir: Option<std::path::PathBuf>,
    },
    /// Allows users to import data to individual collection(s)
    Populate {
        /// Suppress output from arangoimport subprocess.
        #[arg(long, default_value_t = false)]
        quiet: bool,
        /// Collection name to import to. (Does not get created if it doesn't exist).
        #[arg(required = true)]
        collection: String,
        /// Path to a file containing data to import.
        #[arg(required = true)]
        file: std::path::PathBuf,
    },
    /// Deletes collection(s) in the database.
    Delete {
        /// If specefied, only deletes the listed collections. Otherwise deletes the entire database.
        collection_list: Option<Vec<String>>,
    },
    /// Removes all data from collection(s) in the database.
    Truncate {
        /// If specified, only truncates the listed collections. Otherwise, truncates all collections in the databse.
        collection_list: Option<Vec<String>>,
    },
    /// Generates human readable documentation from `schema_file`.
    Doc {
        /// Format for generated documentation of database schema.
        #[arg(default_value = "html")]
        format: DocFormat,
    },
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum DocFormat {
    Html,
    Json,
    Dot,
    Md,
}

impl std::fmt::Display for DocFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}
