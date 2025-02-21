use crate::analysis::EmulatorOutput;
use crate::datastore::Datastore;
use crate::delta::Delta;
use crate::operation::{Operation, OperationKind};
use crate::oplog::OpLog;
use crate::{Index, Tick};

pub trait DataflowPlugin {
    fn on_instruction(
        &mut self,
        store: &Datastore,
        tick: Tick,
        pc: u64,
        insbytes: &[u8],
        assembly: &str,
    ) {
        let _ = (store, tick, pc, insbytes, assembly);
    }
    fn on_delta(
        &mut self,
        store: &Datastore,
        tick: Tick,
        opcode: OperationKind,
        index: Index,
        delta: Delta,
    ) {
        let _ = (store, tick, opcode, index, delta);
    }
    fn on_operation(
        &mut self,
        store: &Datastore,
        oplog: &OpLog,
        op: Operation,
        output: &mut EmulatorOutput,
    ) {
        let _ = (store, oplog, op, output);
    }
    fn on_init(&mut self) {}
    fn on_fini(&mut self) {}
}
