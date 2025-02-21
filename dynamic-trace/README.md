# Trace Management

This folder contains the rust library for working with traces, as well as a
collection of tools for manipulating them.

## Trace Format

TODO

## Pipetools

Every tool is prefixed with `tm` (for <u> **T**</u>race <u> **M**</u>anagement).
A tool should read in a trace from either a file or standard out and emit a
stream of trace records to `stdout` or a file. This way they can be composed
using unix pipes (hence the name) to execute complex operations on traces.

|     Tool     | Description                                                                                                           |
| :----------: | :-------------------------------------------------------------------------------------------------------------------- |
|  `tm-count`  | Counts the number of each type of record in a trace and prints the results to `stderr`.                               |
|  `tm-print`  | Prints a human readable version of the trace to `stderr`.                                                             |
|  `tm-split`  | Splits a trace into separate files based on process id and thread id. NOTE: Cannot be composed with other pipe tools. |
| `tm-analyze` | Analyzes a trace using the `Dataflow` engine from this repo.                                                          |

### Writing Your Own Pipe Tool

Below is a template for writing your own pipe tool:

```Rust
use anyhow::Result;
use clap::Parser;
use std::fs;
use std::io::{self, Read, Write};
use trace::reader::{cont, try_break, TraceReader};

/// Description of the pipe tool
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or '-' to use stdin.
    #[arg(short, long, default_value_t = String::from("-"))]
    input: String,

    /// Output file or '-' to use stdout.
    #[arg(short, long, default_value_t = String::from("-"))]
    output: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = open_input(args.input.as_str())?;
    let mut output = open_output(args.output.as_str())?;
    let mut trace = TraceReader::new(input);

    // Initial set up goes here. For example, checking that the first two records
    // of a trace are a `Magic` and `Arch` records.

    trace.for_each(
        // This is a function that takes in `raw` records and returns
        // a `std::ops::ControlFlow` type. Use the `cont!` and `try_break!` 
        // macros imported above to continue to the next record or bail and
        // return an `Error`.
        // 
        // Using a closure is helpful because it will capture any variables
        // initialized above.
        |raw| {
            // Always make sure to write the records back to `stdout`
            try_break!(output.write(raw.bytes()));
            cont!();
        }
    )
    .map_or(Ok(()), |err| Err(err.into()))
}


fn open_input(input: &str) -> io::Result<Box<dyn Read>> {
    if input == "-" {
        return Ok(Box::new(io::stdin().lock()));
    }
    Ok(Box::new(fs::File::open(input)?))
}

fn open_output(output: &str) -> io::Result<Box<dyn Write>> {
    if output == "-" {
        return Ok(Box::new(io::stdout().lock()));
    }
    Ok(Box::new(fs::File::create(output)?))
}
```
