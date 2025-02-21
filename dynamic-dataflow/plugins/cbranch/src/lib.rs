use dataflow_core::analysis::{EmulatorOutput, Step};
use dataflow_core::datastore::Datastore;
use dataflow_core::operation::Operation;
use dataflow_core::oplog::OpLog;
use dataflow_core::plugins::DataflowPlugin;
use dataflow_core::slot::Slot;
use dataflow_core::space::SpaceKind;
use dataflow_core::value::PartialValue;
use dataflow_core::{Index, Tick};

use log::trace;

pub struct SpeculateCBranch {
    speculating: bool,
}

impl SpeculateCBranch {
    pub fn new() -> Self {
        Self { speculating: false }
    }

    fn resolve_input(&self, store: &Datastore, oplog: &OpLog, slot: &mut Slot) {
        if slot.space.kind() == SpaceKind::Constant {
            slot.value = PartialValue::from(slot.offset);
        }

        slot.value = PartialValue::default();
        let mut deps: [Option<Index>; 16] = [None; 16];

        for (i, address) in slot.as_range().iter().enumerate() {
            if let Some(index) = store.last_modified(&address) {
                if let Some((_, _, delta)) = store.delta(*index) {
                    deps[i] = Some(*index);
                    slot.value.set_or_unset(i, delta.value_at(address));
                }
            }
        }

        if deps.iter().any(|x| x.is_some()) {
            return;
        }

        if slot.space.kind() == SpaceKind::Memory {
            oplog.fill_with_reads(slot);
        }
    }
}

impl DataflowPlugin for SpeculateCBranch {
    fn on_operation(
        &mut self,
        store: &Datastore,
        oplog: &OpLog,
        op: Operation,
        output: &mut EmulatorOutput,
    ) {
        if self.speculating {
            // Validate via write records: If a write to unique space,
            // emit unconditionally. Otherwise, if a register or memory write, verify that
            if let Some(delta) = output.delta {
                let kind = delta.space.kind();
                if kind != SpaceKind::Register && kind != SpaceKind::Memory {
                    return;
                }
                trace!("[SpeculateCBranch] speculating addr or mem!");
                let mut num_writes = 0;
                let mut ok = true;
                for (address, value) in oplog.writes_in_range(&delta.as_range()) {
                    num_writes += 1;
                    if let Some(v) = delta.value_at(address) {
                        if v != value {
                            trace!(
                                "[SpeculateCBranch] {} value mismatch at {:?}: {:?} != {:?}",
                                store.instruction_index(),
                                address,
                                v,
                                value
                            );
                            ok = false;
                            break;
                        }
                    } else {
                        trace!(
                            "[SpeculateCBranch] {} written value unavailable at {:?}",
                            store.instruction_index(),
                            address
                        );
                        ok = false;
                        break;
                    }
                }
                // this analysis breaks down somewhat if we can have
                // more than one write record in our oplog for the
                // same byte
                if !ok || num_writes < delta.size {
                    trace!(
                        "[SpeculateCBranch] {} wrong number of writes {} < {}",
                        store.instruction_index(),
                        num_writes,
                        delta.size
                    );
                    // If we could not corroborate this operation with a record,
                    output.delta = None;
                } else {
                    trace!(
                        "[SpeculateCBranch] {} speculation success",
                        store.instruction_index()
                    );
                }
            }
        }

        match output.step {
            Step::Break => {}
            _ => {
                return;
            }
        }

        if let Operation::CondBranch(op) = op {
            let [iaddr0, iaddr1] = op.inputs();
            let mut input1 = Slot::from(iaddr1);
            self.resolve_input(store, oplog, &mut input1);

            // Are we taking the branch or not?
            let branch_taken = match input1.value.as_bool() {
                Some(v) => v,
                None => {
                    return;
                }
            };

            // We're speculating now, even if we branch out of instruction
            // that will just flip speculation off.
            self.speculating = true;

            match (branch_taken, iaddr0.space().kind()) {
                (true, SpaceKind::Constant) => {
                    output.step = Step::Continue(iaddr0.offset() as isize);
                }
                (false, _) => {
                    output.step = Step::Continue(1);
                }
                _ => {
                    // We break, could flip speculating but again
                    // that will happen automatically
                }
            }
        }
    }

    fn on_instruction(
        &mut self,
        _store: &Datastore,
        _tick: Tick,
        _pc: u64,
        _insbytes: &[u8],
        _assembly: &str,
    ) {
        self.speculating = false;
    }
}
