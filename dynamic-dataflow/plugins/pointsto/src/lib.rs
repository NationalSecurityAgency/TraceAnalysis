#![allow(unused_variables)]
use dataflow_core::address::Address;
use dataflow_core::datastore::Datastore;
use dataflow_core::delta::Delta;
use dataflow_core::operation::OperationKind;
use dataflow_core::plugins::DataflowPlugin;
use dataflow_core::space::{Space, SpaceManager};
use dataflow_core::{Index, Tick};

use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

mod writers;

use writers::Message;

pub struct PointsToPlugin {
    threads: Vec<JoinHandle<()>>,
    pointsto_writer: Sender<Message>,
    context_size: u64,
    memory: Space,
}

impl From<&'_ dataflow_core::analysis::Analysis> for PointsToPlugin {
    fn from(analysis: &dataflow_core::analysis::Analysis) -> Self {
        let memory = analysis.default_data_space();
        let context_size = memory.addr_size() as u64 * 4;
        Self::new(memory, context_size)
    }
}

impl PointsToPlugin {
    pub fn new(memory: Space, context_size: u64) -> Self {
        let mut threads = Vec::with_capacity(1);

        let (pointsto_writer, chan) = mpsc::channel();
        threads.push(thread::spawn(move || {
            writers::write_pointsto(chan, "out/");
        }));
        Self {
            threads,
            pointsto_writer,
            memory,
            context_size,
        }
    }

    pub fn write_pointsto(&mut self, from: Index, to: Index, offset: u64) {
        let _ = self
            .pointsto_writer
            .send(Message::PointsTo((from, to, offset)));
    }

    fn memory(&self, offset: u64) -> Address {
        Address::new(self.memory, offset)
    }

    #[inline]
    fn address_size(&self) -> u64 {
        self.memory.addr_size() as u64
    }
}

impl DataflowPlugin for PointsToPlugin {
    fn on_delta(
        &mut self,
        store: &Datastore,
        tick: Tick,
        opcode: OperationKind,
        index: Index,
        delta: Delta,
    ) {
        if delta.size == self.address_size() {
            if let Some(sized_addr) = delta.as_complete() {
                let mut current_target: Option<usize> = None;
                for off in 0..self.context_size {
                    let address = self.memory(sized_addr.as_usize() as u64 + off);
                    if let Some(target) = store.last_modified(&address) {
                        if current_target.is_none() || *target != current_target.unwrap() {
                            current_target = Some(*target);
                            if *target <= index {
                                self.write_pointsto(index, *target, off);
                            }
                        }
                    }
                }
            }
        }
    }

    fn on_fini(&mut self) {
        self.pointsto_writer.send(Message::Done).unwrap();
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}
