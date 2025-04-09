use anyhow::Result;
use dataflow::prelude::*;

use super::{Event, InsEvent, Parser};

pub fn analyze(reader: Box<dyn std::io::Read>) -> Result<()> {
    let mut app = Analysis::try_from(Architecture::X86_64(X86_64))?;

    let exporter = dataflow::export::csv::CsvExporter::new("out/");
    app.insert_exporter(exporter);

    let plugin = dataflow::plugins::syscalls::LinuxSyscallsx64::new(&app);
    app.insert_plugin(Box::new(plugin));

    let plugin = dataflow::plugins::cbranch::SpeculateCBranch::new();
    app.insert_plugin(Box::new(plugin));

    let plugin = dataflow::plugins::fntrack::FnTracker::from(&app);
    app.insert_plugin(Box::new(plugin));

    let plugin = dataflow::plugins::fpmodels::DefaultFloatModel::new();
    app.insert_plugin(Box::new(plugin));

    let mut tick: u64 = 0u64;
    let mut prev_ins: Option<InsEvent> = None;

    app.set_tick(0);
    for event in Parser::new(reader).into_iter() {
        let event = event?;
        match event {
            Event::Ins(e) => {
                if let Some(ins) = prev_ins {
                    app.process_instruction(ins.pc(), ins.insbytes())?;
                    app.end_instruction();
                }
                tick += 1;
                app.set_tick(tick);
                app.start_instruction();
                prev_ins = Some(e);
            }

            Event::RegWrite(e) => {
                let sleigh_reg = app.register_space().index(e.register().sleigh());
                app.insert_write(sleigh_reg, e.register().bytes());
            }

            Event::MemRead(e) => {
                let address = app.default_data_space().index(e.addr());
                app.insert_read(address, e.bytes());
            }

            Event::MemWrite(e) => {
                let address = app.default_data_space().index(e.addr());
                app.insert_write(address, e.bytes());
            } /* _ => {}, */
        }
    }
    app.save();

    Ok(())
}
