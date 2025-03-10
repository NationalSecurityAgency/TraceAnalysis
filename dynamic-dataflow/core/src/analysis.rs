use crate::address::{Address, AddressRange};
use crate::architecture::Architecture;
use crate::datastore::Datastore;
use crate::delta::{AddressDep, ConstAddressDep, ConstValueDep, Delta, DeltaDep, ValueDep};
use crate::error::DataflowError;
use crate::export::DataflowExport;
use crate::operation::{Operation, OperationKind};
use crate::oplog::OpLog;
#[cfg(feature = "plugins")]
use crate::plugins::*;
use crate::slot::Slot;
use crate::space::{Space, SpaceAttributes, SpaceKind};
use crate::value::{Bool, PartialValue, Signed, SizedValue, Unsigned};
use crate::Tick;

use hashbrown::HashMap;
use tracing::{trace, warn};

trait LiftAndSpaceManager: crate::lifter::Lift + crate::space::SpaceManager {}
impl<T> LiftAndSpaceManager for T where T: crate::lifter::Lift + crate::space::SpaceManager {}

/// The `Analysis` type is the primary iterface for the dataflow tracking
/// algorithm.
///
/// # General Usage
///
/// `Analysis` provides a public API for handling events from a trace.
/// An example workflow may look like the following:
///
/// ```ignore
/// # use dataflow_core::prelude::*;
/// # use dataflow_core::error::DataflowError;
///
/// # fn main() -> Result<(), DataflowError> {
/// let mut app = Analysis::try_from(Architecture::X86(X86)).unwrap();
/// app.set_tick(1000);
/// app.start_instruction();
/// let eax = app.register_space().index(0);
/// app.insert_write(eax, &[0x37, 0x13, 0, 0]);
/// let pc = 0x800000;
/// app.process_instruction(pc, &[0xb8, 0x37, 0x13, 0x00, 0x00])?;
/// app.end_instruction();
/// app.save();
/// # Ok(())
/// # }
/// ```
///
/// In this example, the dataflow analysis engine will track the writes that
/// occured during a given instruction ("write 0x1337 to eax"), lift the
/// instruction that executed ("mov eax, 0x1337") into an IR, and use
/// historical instructions along with current write records to track the flow
/// of values through successive instruction. It will then save a copy of all
/// the outputs on each of the ticks the engine analyzed along with their
/// dependencies to a series of CSV files prefixed by the path provided.
///
/// # Warning:
///
/// This API is under active development and is quite unstable at the moment.
/// Some fields that are exposed now are likely to be private in the future,
/// Many method signatures will change in the future until we reach "1.0".
///
pub struct Analysis {
    tick: Tick,
    // This is public to cache index to register mapping
    pub reg_addrs: HashMap<usize, AddressRange>,
    oplog: OpLog,
    operations: Vec<Operation>,
    // This is public so that ZApplication can convert register indices to
    // AddressRanges
    lifter: Box<dyn LiftAndSpaceManager>,
    store: Datastore,

    // Cache of the emulator's output so that we do not have to reallocate for each instruction
    output: EmulatorOutput,

    arch: Architecture,
    stack: Vec<AddressRange>,

    #[cfg(feature = "plugins")]
    plugins: Vec<Box<dyn DataflowPlugin>>,
}

impl std::convert::TryFrom<Architecture> for Analysis {
    type Error = DataflowError;
    fn try_from(arch: Architecture) -> Result<Self, Self::Error> {
        Ok(Self {
            tick: 0,
            reg_addrs: HashMap::default(),
            oplog: OpLog::new(),
            operations: Vec::new(),
            lifter: Box::new(crate::lifter::GhidraLifter::new(arch)?),
            store: Datastore::new(),
            output: EmulatorOutput::new(),
            arch,
            stack: Vec::new(),

            #[cfg(feature = "plugins")]
            plugins: Vec::new(),
        })
    }
}

impl Analysis {
    //#[inline]
    //pub fn big_endian(&self) -> bool {
    //    self.lifter.big_endian()
    //}

    #[cfg(feature = "plugins")]
    pub fn insert_plugin(&mut self, mut plugin: Box<dyn DataflowPlugin>) {
        plugin.on_init();
        self.plugins.push(plugin);
    }

    pub fn insert_exporter(&mut self, exporter: impl DataflowExport + 'static) {
        self.store.exporters.push(Box::new(exporter))
    }

    /// Right now this method does nothing.
    ///
    /// Eventually this method will probably track the starting tick of an
    /// instruction to compare it with the ending tick of an instruction
    /// in order to determine if the instruction was interrupted.
    ///
    /// Additionally, this method will likely return a handle of some sort
    /// to indicate which thread this instruction is being executed on so that
    /// the `Analysis` engine can track multiple threads simultaneously.
    pub fn start_instruction(&mut self) {
        // Do nothing
    }

    /// This method should be called whenever an instruction is finished
    /// executing.
    ///
    /// Most of the heavy-weight analysis is started by this method.
    /// In summary, this method lifts the instruction bytes into a series of
    /// IR operations and iterates through the series of operations performing
    /// the following steps:
    ///
    /// - Attempt to resolve the values for all the inputs to the operation
    ///   by searching through historical operation outputs and current
    ///   instruction read records.
    /// - Emulate the operation to calculate the expected output of the
    ///   operation.
    /// - Inserts the output into the datastore along with the indices of
    ///   the outputs that were used to derive its address and value.
    ///
    /// After all outputs were emulated, the analysis will iterate through
    /// write records to ensure that emulated values were correct and create
    /// "pseudo-ops" for writes that were not generated by emulation.
    ///
    /// # TODO
    ///
    /// - Write unit tests
    ///
    pub fn process_instruction(&mut self, pc: u64, insbytes: &[u8]) -> Result<(), DataflowError> {
        let _span = tracing::trace_span!("process_instruction", tick = self.tick).entered();

        let mut assembly = String::new();

        let tindex =
            self.store
                .lookup_tcache_or_else::<_, DataflowError>(pc, insbytes, |disasm, ops| {
                    self.lifter
                        .lift_instruction(pc, insbytes, disasm, ops)
                        .map(|_| ())
                        .map_err(|e| e.into())
                });

        match tindex {
            Ok(tindex) => {
                assembly.push_str(self.store.disassembly_for(tindex).unwrap());
                self.operations
                    .extend_from_slice(self.store.operations_for(tindex).unwrap());
            }

            Err(_) => {
                warn!("unable to get assembly for instruction");
                assembly.push_str("BAD INSTRUCTION");
            }
        }

        trace!(pc = %crate::Hex(pc), bytes = %crate::Hex(insbytes), assembly = assembly);

        // Checks if there are any potential controlflows in this
        // instruction. Optimization: we use "rev" b/c it is most
        // likely that controlflow ops occur toward the end and
        // "any" will shortcut on first true.

        self.store.start_tick(self.tick, pc, assembly.clone());

        for (address, value) in self.oplog.reads() {
            trace! {
                space = address.space().id(),
                offset = %crate::Hex(address.offset()),
                value = %crate::Hex(value),
                "processing read record",
            };
        }

        let mut index = 0;
        'emuloop: while let Some(op) = self.operations.get(index) {
            let mut output = std::mem::replace(&mut self.output, EmulatorOutput::new());
            std::mem::swap(&mut self.stack, &mut output.stack);
            self.emulate(op, &mut output);
            std::mem::swap(&mut output.stack, &mut self.stack);

            #[cfg(feature = "plugins")]
            for p in self.plugins.iter_mut() {
                p.on_operation(&self.store, &self.oplog, op.clone(), &mut output);
            }

            let EmulatorOutput {
                delta,
                mut deps,
                mut clear_ranges,
                side_effect,
                step,
                ..
            } = output;

            if let Some(delta) = delta {
                #[cfg(feature = "plugins")]
                for p in self.plugins.iter_mut() {
                    p.on_delta(
                        &self.store,
                        self.tick,
                        op.kind(),
                        self.store.next_index(),
                        delta,
                    );
                }

                match &delta {
                    Delta::Controlflow(slot, assc) => {
                        trace! {
                            kind = "controlflow",
                            space = slot.space.id(),
                            offset = %crate::Hex(slot.offset),
                            size = slot.size,
                            value = %PrettyPrintPartial(slot.value, slot.size as usize),
                            assoc_space = assc.map(|v| v.space().id()),
                            assoc_offset = %crate::Hex(assc.map(|v| v.offset())),
                            assoc_size = assc.map(|v| v.size()),
                            "generated delta",
                        };
                    }
                    Delta::Dataflow(slot, assc) => {
                        trace! {
                            kind = "dataflow",
                            space = slot.space.id(),
                            offset = %crate::Hex(slot.offset),
                            size = slot.size,
                            value = %PrettyPrintPartial(slot.value, slot.size as usize),
                            assoc_space = assc.map(|v| v.space().id()),
                            assoc_offset = %crate::Hex(assc.map(|v| v.offset())),
                            assoc_size = assc.map(|v| v.size()),
                            "generated delta",
                        };
                    }
                }

                self.store
                    .insert_delta(self.tick, op.kind(), delta, deps.drain(..));
            }

            deps.clear();

            // SideEffect::Clear will likely be deprecated as it makes
            // the preceeding analysis useless
            if let Some(effect) = side_effect {
                match effect {
                    SideEffect::Clear => {
                        self.store.forget();
                    }
                    SideEffect::Blame => {
                        self.store.blame();
                    }
                }
            }

            // `clear_ranges` is likely going to completely replace `SideEffect::Clear` as it gives
            // more fine-grained control as to which regions get cleared.
            for range in clear_ranges.drain(..) {
                self.store.forget_range(&range);
            }

            std::mem::swap(&mut deps, &mut self.output.deps);
            std::mem::swap(&mut clear_ranges, &mut self.output.clear_ranges);

            match step {
                Step::Continue(i) => {
                    index = index.wrapping_add(i as usize);
                }
                Step::Break => {
                    break 'emuloop;
                }
            }
        }

        // This procedure may move to end_instruction to support different
        // types of traces (i.e. traces whose write records occur "after"
        // an instruction execution)
        //
        // Note: This CANNOT be done any earlier than now to remain sound.
        // Consider multiple writes per instruction.
        let mut writes = self.oplog.writes();

        while let Some((address, value)) = writes.next() {
            trace! {
                space = address.space().id(),
                offset = %crate::Hex(address.offset()),
                value = %crate::Hex(value),
                "processing write record",
            };

            // Template for psuedo-op if one needs to be added
            let opc = OperationKind::Unknown;
            let pseudo_delta = Delta::Dataflow(
                Slot {
                    space: address.space(),
                    offset: address.offset(),
                    size: 1,
                    value: value.into(),
                },
                None,
            );

            // Get index of last delta to touch this address
            // If this address has never been touched insert pseudo-op
            let index = match self.store.last_modified(&address) {
                Some(index) => *index,
                None => {
                    #[cfg(feature = "plugins")]
                    for p in self.plugins.iter_mut() {
                        p.on_delta(
                            &self.store,
                            self.tick,
                            opc,
                            self.store.next_index(),
                            pseudo_delta,
                        );
                    }
                    self.store
                        .insert_delta(self.tick, opc, pseudo_delta, std::iter::empty());
                    continue;
                }
            };
            // Get the tick and delta at that index
            // Cannot be none if the index is in the last_modified store
            let (tick, delta) = match self.store.delta_mut(index) {
                Some((tick, _, delta)) => (*tick, delta),
                None => {
                    unreachable!()
                }
            };
            // If the last delta to touch this address did not occur during
            // this instruction, make a pseudo-op for the write
            if self.tick != tick {
                #[cfg(feature = "plugins")]
                for p in self.plugins.iter_mut() {
                    p.on_delta(
                        &self.store,
                        self.tick,
                        opc,
                        self.store.next_index(),
                        pseudo_delta,
                    );
                }
                self.store
                    .insert_delta(self.tick, opc, pseudo_delta, std::iter::empty());
                continue;
            }
            // If the delta corresponding to this write record does not
            // have a concrete value, fill it in with the write record
            let old = match delta.value_at(address) {
                Some(old) => old,
                None => {
                    delta.set_value(address, value);
                    continue;
                }
            };
            // The delta occured during this instruction and had a concrete
            // value that did not match the write record. Correct the
            // value, and blame the mistake on the last source of
            // uncertainty.
            if old != value {
                warn! {
                    calculated = old,
                    recorded = value,
                    "calculated value did not match write record"
                };
                delta.set_value(address, value);
                self.store.blame_on_other(index);
            }
        }

        #[cfg(feature = "plugins")]
        for p in self.plugins.iter_mut() {
            p.on_instruction(&self.store, self.tick, pc, insbytes, assembly.as_str());
        }

        Ok(())
    }

    /// This method is called to simulate "manual dataflow".
    ///
    /// Instead of lifting the instruction, the user provides a prelifted list of operations and a
    /// dummy name for the instruction.
    ///
    /// # TODO:
    ///
    /// - Dedup the common code between this method and ['Analysis::process_instruction']
    ///
    pub fn dummy_instruction<N, I>(&mut self, pc: u64, name: N, ops: I) -> Result<(), ()>
    where
        N: AsRef<str>,
        I: IntoIterator<Item = Operation>,
    {
        let _span = tracing::trace_span!("dummy_instruction", tick = self.tick).entered();

        let assembly = name.as_ref();

        self.operations.clear();
        self.operations.extend(ops);

        trace!(pc = %crate::Hex(pc), assembly = assembly);

        // Checks if there are any potential controlflows in this
        // instruction. Optimization: we use "rev" b/c it is most
        // likely that controlflow ops occur toward the end and
        // "any" will shortcut on first true.

        self.store.start_tick(self.tick, pc, assembly.to_owned());

        for (address, value) in self.oplog.reads() {
            trace! {
                space = address.space().id(),
                offset = %crate::Hex(address.offset()),
                value = %crate::Hex(value),
                "processing read record",
            };
        }

        let mut index = 0;
        'emuloop: while let Some(op) = self.operations.get(index) {
            let mut output = std::mem::replace(&mut self.output, EmulatorOutput::new());
            std::mem::swap(&mut output.stack, &mut self.stack);
            self.emulate(op, &mut output);
            std::mem::swap(&mut output.stack, &mut self.stack);

            #[cfg(feature = "plugins")]
            for p in self.plugins.iter_mut() {
                p.on_operation(&self.store, &self.oplog, op.clone(), &mut output);
            }

            let EmulatorOutput {
                delta,
                mut deps,
                mut clear_ranges,
                side_effect,
                step,
                ..
            } = output;

            if let Some(delta) = delta {
                #[cfg(feature = "plugins")]
                for p in self.plugins.iter_mut() {
                    p.on_delta(
                        &self.store,
                        self.tick,
                        op.kind(),
                        self.store.next_index(),
                        delta,
                    );
                }

                match &delta {
                    Delta::Controlflow(slot, assc) => {
                        trace! {
                            kind = "controlflow",
                            space = slot.space.id(),
                            offset = %crate::Hex(slot.offset),
                            size = slot.size,
                            value = %PrettyPrintPartial(slot.value, slot.size as usize),
                            assoc_space = assc.map(|v| v.space().id()),
                            assoc_offset = %crate::Hex(assc.map(|v| v.offset())),
                            assoc_size = assc.map(|v| v.size()),
                            "generated delta",
                        };
                    }
                    Delta::Dataflow(slot, assc) => {
                        trace! {
                            kind = "dataflow",
                            space = slot.space.id(),
                            offset = %crate::Hex(slot.offset),
                            size = slot.size,
                            value = %PrettyPrintPartial(slot.value, slot.size as usize),
                            assoc_space = assc.map(|v| v.space().id()),
                            assoc_offset = %crate::Hex(assc.map(|v| v.offset())),
                            assoc_size = assc.map(|v| v.size()),
                            "generated delta",
                        };
                    }
                }

                self.store
                    .insert_delta(self.tick, op.kind(), delta, deps.drain(..));
            }

            // Uncertain if this is necessary for the case where there is no delta output as there
            // probably wouldn't be any deps to clear.
            deps.clear();

            // SideEffect::Clear will likely be deprecated as it makes
            // the preceeding analysis useless
            if let Some(effect) = side_effect {
                match effect {
                    SideEffect::Clear => {
                        self.store.forget();
                    }
                    SideEffect::Blame => {
                        self.store.blame();
                    }
                }
            }

            // `clear_ranges` is likely going to completely replace `SideEffect::Clear` as it gives
            // more fine-grained control as to which regions get cleared.
            for range in clear_ranges.drain(..) {
                self.store.forget_range(&range);
            }

            std::mem::swap(&mut deps, &mut self.output.deps);
            std::mem::swap(&mut clear_ranges, &mut self.output.clear_ranges);

            match step {
                Step::Continue(i) => {
                    index = index.wrapping_add(i as usize);
                }
                Step::Break => {
                    break 'emuloop;
                }
            }
        }

        // This procedure may move to end_instruction to support different
        // types of traces (i.e. traces whose write records occur "after"
        // an instruction execution)
        //
        // Note: This CANNOT be done any earlier than now to remain sound.
        // Consider multiple writes per instruction.
        let mut writes = self.oplog.writes();

        while let Some((address, value)) = writes.next() {
            trace! {
                space = address.space().id(),
                offset = %crate::Hex(address.offset()),
                value = %crate::Hex(value),
                "processing write record",
            };

            // Template for psuedo-op if one needs to be added
            let opc = OperationKind::Unknown;
            let pseudo_delta = Delta::Dataflow(
                Slot {
                    space: address.space(),
                    offset: address.offset(),
                    size: 1,
                    value: value.into(),
                },
                None,
            );

            // Get index of last delta to touch this address
            // If this address has never been touched insert pseudo-op
            let index = match self.store.last_modified(&address) {
                Some(index) => *index,
                None => {
                    trace! {
                        space = address.space().id(),
                        offset = %crate::Hex(address.offset()),
                        "address not found in last modified table"
                    };
                    #[cfg(feature = "plugins")]
                    for p in self.plugins.iter_mut() {
                        p.on_delta(
                            &self.store,
                            self.tick,
                            opc,
                            self.store.next_index(),
                            pseudo_delta,
                        );
                    }
                    self.store
                        .insert_delta(self.tick, opc, pseudo_delta, std::iter::empty());
                    continue;
                }
            };
            // Get the tick and delta at that index
            // Cannot be none if the index is in the last_modified store
            let (tick, delta) = match self.store.delta_mut(index) {
                Some((tick, _, delta)) => (*tick, delta),
                None => {
                    unreachable!()
                }
            };
            // If the last delta to touch this address did not occur during
            // this instruction, make a pseudo-op for the write
            if self.tick != tick {
                trace! {
                    space = address.space().id(),
                    offset = %crate::Hex(address.offset()),
                    last_modified_tick = tick,
                    last_modified_index = index,
                    "address found in last modified table"
                };
                #[cfg(feature = "plugins")]
                for p in self.plugins.iter_mut() {
                    p.on_delta(
                        &self.store,
                        self.tick,
                        opc,
                        self.store.next_index(),
                        pseudo_delta,
                    );
                }
                self.store
                    .insert_delta(self.tick, opc, pseudo_delta, std::iter::empty());
                continue;
            }
            // If the delta corresponding to this write record does not
            // have a concrete value, fill it in with the write record
            let old = match delta.value_at(address) {
                Some(old) => old,
                None => {
                    trace! {
                        space = address.space().id(),
                        offset = %crate::Hex(address.offset()),
                        value = %crate::Hex(value),
                        index = index,
                        "backfilling missing value from recent delta with write record",
                    }
                    delta.set_value(address, value);
                    continue;
                }
            };
            // The delta occured during this instruction and had a concrete
            // value that did not match the write record. Correct the
            // value, and blame the mistake on the last source of
            // uncertainty.
            if old != value {
                warn! {
                    calculated = old,
                    recorded = value,
                    "calculated value did not match write record"
                };
                delta.set_value(address, value);
                self.store.blame_on_other(index);
            }
        }

        #[cfg(feature = "plugins")]
        for p in self.plugins.iter_mut() {
            p.on_instruction(&self.store, self.tick, pc, &[], assembly);
        }

        Ok(())
    }

    /// This method ends the analysis of a single instruction.
    ///
    /// Right now, it just clears all of the records and the lifted IR nodes.
    /// In the future, the resolve output procedure will likely get moved to
    /// here and the alogorithm will proceed as follows:
    ///
    /// - For each write record, check if the value of the output who last
    ///   modified the corresponding address has a matching value.
    /// - (Optionally) reverse emulate to fill in the missing values of
    ///   intermediate calculations. <-- Very unlikely
    /// - For each write record with no corresponding output, create a pseudo
    ///   operation to represent an external output.
    pub fn end_instruction(&mut self) {
        self.oplog.clear();
        self.operations.clear();
    }

    /// This method stores a write record to an address for each byte in the
    /// data buffer.
    ///
    /// This method should be called prior to calling `process_instruction`
    /// (eventually will be relaxed to `end_instruction`) in order to capture
    /// the record in the analysis.
    pub fn insert_write(&mut self, base: Address, data: &[u8]) {
        for (i, val) in data.iter().enumerate() {
            let address = Address::new(base.space(), base.offset() + i as u64);
            self.oplog.insert_write(&address, *val);
        }
    }

    /// This method store a read record to an address for each byte in the
    /// data buffer.
    ///
    /// This method should be called prior to calling `process_instruction`
    /// in order to capture the record in the analysis.
    pub fn insert_read(&mut self, base: Address, data: &[u8]) {
        for (i, val) in data.iter().enumerate() {
            let address = Address::new(base.space(), base.offset() + i as u64);
            self.oplog.insert_read(&address, *val);
        }
    }

    /// This method returns the last seen tick.
    pub fn tick(&self) -> Tick {
        self.tick
    }

    /// This method updates the last seen tick.
    ///
    /// # Warning
    ///
    /// This method is likely to be deprecated in the future in favor of
    /// providing the current tick on each event method.
    pub fn set_tick(&mut self, tick: Tick) {
        self.tick = tick;
    }

    /// This method sets the namespace under which proceeding events are perceived.
    ///
    /// The context in its current implementation acts as a thread id. By setting the thread id
    /// before processing an instruction, the analysis will assume that writes to (and reads from)
    /// register space occured under the given thread and will be able to track independent
    /// dataflow chains between thread swaps.
    ///
    /// In the future this API will enable the ability to set a process id that allows analysis to
    /// track dataflow chains across process swaps.
    ///
    /// # Warning
    ///
    /// This api is under active development and should not be used outside of internal tools.
    pub fn set_context(&mut self, tid: u16) {
        self.store.current_thread = tid;
    }

    /// This method used to save the datastore to CSV files. This is being
    /// done concurrently now, so this function just flushes the buffers.
    pub fn save(&mut self) {
        self.store.flush();

        #[cfg(feature = "plugins")]
        for p in self.plugins.iter_mut() {
            p.on_fini();
        }
    }

    pub fn arch(&self) -> Architecture {
        self.arch
    }
}

impl crate::lifter::Lift for Analysis {
    fn lift_instruction(
        &mut self,
        pc: u64,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
    ) -> std::result::Result<i32, crate::lifter::LiftError> {
        let tindex = self
            .store
            .lookup_tcache_or_else(pc, insbytes, |disasm, ops| {
                self.lifter
                    .lift_instruction(pc, insbytes, disasm, ops)
                    .map(|_| ())
            })?;

        assembly.push_str(self.store.disassembly_for(tindex).unwrap());
        operations.extend_from_slice(self.store.operations_for(tindex).unwrap());
        let length = self.store.instruction_bytes_for(tindex).unwrap().len();
        Ok(length as i32)
    }
}

impl crate::space::SpaceManager for Analysis {
    fn register_space(&self) -> Space {
        self.lifter.register_space()
    }

    fn default_data_space(&self) -> Space {
        self.lifter.default_data_space()
    }

    fn default_code_space(&self) -> Space {
        self.lifter.default_code_space()
    }

    fn unique_space(&self) -> Space {
        self.lifter.unique_space()
    }

    fn constant_space(&self) -> Space {
        self.lifter.constant_space()
    }

    fn space_by_name(&self, name: &str) -> Option<Space> {
        self.lifter.space_by_name(name)
    }

    fn space_by_id(&self, id: u16) -> Option<Space> {
        self.lifter.space_by_id(id)
    }
}

// PRIVATE API

pub enum SideEffect {
    Clear,
    Blame,
}

pub enum Step {
    Continue(isize),
    Break,
}

pub struct EmulatorOutput {
    pub delta: Option<Delta>,
    pub deps: Vec<DeltaDep>,
    /// Depractation warning: `side_effect` is likely to be removed in future versions of dataflow
    /// in favor of `clear_ranges`
    pub side_effect: Option<SideEffect>,
    pub clear_ranges: Vec<AddressRange>,
    pub stack: Vec<AddressRange>,
    pub step: Step,
}

impl EmulatorOutput {
    fn new() -> Self {
        Self {
            delta: None,
            deps: Vec::new(),
            side_effect: None,
            clear_ranges: Vec::new(),
            step: Step::Continue(1),
            stack: Vec::new(),
        }
    }

    fn insert_dep(&mut self, dep: DeltaDep) {
        if self.deps.iter().any(|&d| dep == d) {
            return;
        }
        self.deps.push(dep)
    }
}

impl Analysis {
    // A little hacky but I'm overloading the usage of the pos argument to determine whether the
    // dependency is an address dep or a value dep
    fn resolve_deps(&self, slot: &Slot, pos: Option<u8>, emu_out: &mut EmulatorOutput) {
        if slot.space.kind() == SpaceKind::Constant {
            // slot.as_complete() will fail if the size is greater than 16 bytes, but in that case
            // we cannot produce a concrete value for the database anyways so we will currently
            // just drop the dependency.
            if let Some(value) = slot.as_complete() {
                emu_out.deps.push(match pos {
                    Some(n) => DeltaDep::ConstValue(ConstValueDep { value, pos: n }),
                    None => DeltaDep::ConstAddress(ConstAddressDep { value }),
                });
            }
            return;
        }

        for address in slot.as_range().iter() {
            if let Some(index) = self.store.last_modified(&address) {
                emu_out.insert_dep(match pos {
                    Some(n) => DeltaDep::Value(ValueDep {
                        index: *index,
                        pos: n,
                    }),
                    None => DeltaDep::Address(AddressDep { index: *index }),
                });
            }
        }
    }

    fn resolve_input(&self, slot: &mut Slot) {
        if slot.space.kind() == SpaceKind::Constant {
            // Maximum value of a constant is u64::MAX, but the size can still be arbitrarily
            // large. We have at least seen 16 byte constants so we cast to u128.
            slot.value = PartialValue::from(slot.offset as u128);
            return;
        }

        slot.value = PartialValue::default();
        let mut has_value = false;

        for (i, address) in slot.as_range().iter().enumerate() {
            if let Some(index) = self.store.last_modified(&address) {
                if let Some((_, _, delta)) = self.store.delta(*index) {
                    has_value = true;
                    slot.value.set_or_unset(i, delta.value_at(address));
                }
            }
        }

        if has_value {
            return;
        }

        if slot.space.kind() == SpaceKind::Memory {
            self.oplog.fill_with_reads(slot);
        }
    }

    fn emulate(&self, op: &Operation, emu_out: &mut EmulatorOutput) {
        const MAX_PRIMITIVE: u64 = std::mem::size_of::<u128>() as u64;

        trace! {
            kind = ?op.kind(),
            inputs = %PrettyPrintInputs(op.inputs()),
            output = %PrettyPrintOutput(op.outputs()),
            "emulating operation"
        };

        match op {
            Operation::Copy(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                let mut output = Slot::from(out);
                output.value = input0.value;
                if output.space.big_endian() {
                    output.byte_swap();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::Load(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                /* let mut input0 = Slot::from(iaddr0); */
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);
                if input1.space.big_endian() {
                    input1.byte_swap();
                }
                let mut loadaddr = None;

                let mut output = Slot::from(out);
                if let Some(v) = input1.as_complete() {
                    let mut input2 = Slot {
                        space: iaddr0.space(),
                        offset: v.as_usize() as _,
                        size: output.size,
                        value: Default::default(),
                    };
                    loadaddr = Some(input2.as_range());
                    self.resolve_input(&mut input2);
                    output.value = input2.value;
                    self.resolve_deps(&input2, Some(0), emu_out);
                }

                self.resolve_deps(&input1, None, emu_out);
                emu_out.delta = Some(Delta::Dataflow(output, loadaddr));
            }

            Operation::Store(op) => {
                let [iaddr0, iaddr1, iaddr2] = op.inputs();
                /* let mut input0 = Slot::from(iaddr0); */
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);
                if input1.space.big_endian() {
                    input1.byte_swap();
                }
                let mut input2 = Slot::from(iaddr2);
                self.resolve_input(&mut input2);
                if iaddr0.space().big_endian() != iaddr2.space().big_endian() {
                    input2.byte_swap();
                }

                if let Some(address) = input1.as_complete() {
                    let output = Slot {
                        space: iaddr0.space(),
                        offset: address.as_usize() as _,
                        size: input2.size,
                        value: input2.value,
                    };

                    self.resolve_deps(&input1, None, emu_out);
                    self.resolve_deps(&input2, Some(0), emu_out);

                    emu_out.delta = Some(Delta::Dataflow(output, None));
                }
            }

            Operation::Branch(_) => {
                emu_out.step = Step::Break;
            }
            Operation::CondBranch(op) => {
                let [iaddr0, iaddr1] = op.inputs();
                if iaddr0.space().kind() != SpaceKind::Constant {
                    let mut input = Slot::from(iaddr1);
                    self.resolve_input(&mut input);

                    self.resolve_deps(&input, Some(0), emu_out);

                    emu_out.delta = Some(Delta::Controlflow(Slot::default(), Some(*iaddr1)));
                }
                emu_out.step = Step::Break;
            }
            Operation::BranchInd(op) => {
                let [iaddr] = op.inputs();
                let mut input = Slot::from(iaddr);
                self.resolve_input(&mut input);

                self.resolve_deps(&input, Some(0), emu_out);

                emu_out.delta = Some(Delta::Controlflow(Slot::default(), Some(*iaddr)));

                emu_out.step = Step::Break;
            }
            Operation::Call(_) => {
                emu_out.step = Step::Break;
            }
            Operation::CallInd(op) => {
                let [iaddr] = op.inputs();
                let mut input = Slot::from(iaddr);
                self.resolve_input(&mut input);

                self.resolve_deps(&input, Some(0), emu_out);

                emu_out.delta = Some(Delta::Controlflow(Slot::default(), Some(*iaddr)));

                emu_out.step = Step::Break;
            }
            Operation::CallOther(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1] = op.inputs();
                let mut stack = std::mem::replace(&mut emu_out.stack, Vec::new());
                for (i, iaddr) in stack.iter().copied().enumerate() {
                    let input = Slot::from(iaddr);
                    self.resolve_deps(&input, Some((i + 1) as _), emu_out);
                }
                std::mem::swap(&mut stack, &mut emu_out.stack);
                emu_out.stack.clear();
                //for i in ix {
                //    let mut input = Slot::from(i);
                //    self.resolve_input(&mut input);
                //    self.resolve_deps(&input, Some(0), emu_out);
                //}
                let output = match out {
                    Some(out) => Slot::from(out),
                    None => Slot {
                        space: Space::new(255, SpaceAttributes(0b0101), 8, 1),
                        offset: 0,
                        size: 0,
                        value: Default::default(),
                    },
                };
                emu_out.delta = Some(Delta::Dataflow(output, None));
                emu_out.side_effect = Some(SideEffect::Blame);
            }
            Operation::Return(_) => {
                emu_out.step = Step::Break;
            }

            Operation::IntEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(true);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = (Unsigned(v0) == Unsigned(v1)).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntNotEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(false);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = (Unsigned(v0) != Unsigned(v1)).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedLess(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(false);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Signed(v0) < Signed(v1)).into();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedLessEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(true);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Signed(v0) <= Signed(v1)).into();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntLess(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(true);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Unsigned(v0) < Unsigned(v1)).into();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntLessEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(true);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Unsigned(v0) <= Unsigned(v1)).into();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntZeroExtend(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                let mut output = Slot::from(out);

                if let Some(v0) = input0.as_complete() {
                    output.value = v0.int_zext(output.size as _).into();
                    if output.space.big_endian() {
                        output.byte_swap();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignExtend(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                let mut output = Slot::from(out);

                if let Some(v0) = input0.as_complete() {
                    output.value = v0.int_sext(output.size as _).into();
                    if output.space.big_endian() {
                        output.byte_swap();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntAdd(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 + v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSub(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for clear operation
                if iaddr0 == iaddr1 {
                    output.value = SizedValue::new(0, output.size as _).into();
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 - v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntCarry(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = v0.int_carry(&v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedCarry(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = v0.int_scarry(&v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedBorrow(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for irrefutable comparison
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(false);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = v0.int_sborrow(&v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntNeg(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if let Some(v0) = input0.as_complete() {
                    if input0.size <= MAX_PRIMITIVE {
                        output.value = (-Signed(v0)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntNot(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                let mut output = Slot::from(out);

                if let Some(v0) = input0.as_complete() {
                    if input0.size <= MAX_PRIMITIVE {
                        output.value = (!Unsigned(v0)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntXor(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for clear operation
                if iaddr0 == iaddr1 {
                    output.value = SizedValue::new(0, output.size as _).into();
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 ^ v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntAnd(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for clear operation
                if iaddr0.first().map(|a| a.is_const_zero()).unwrap_or(false)
                    || iaddr1.first().map(|a| a.is_const_zero()).unwrap_or(false)
                {
                    output.value = SizedValue::new(0, output.size as _).into();
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 & v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntOr(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 | v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntLeft(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 << v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntRight(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Unsigned(v0) >> Unsigned(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedRight(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Signed(v0) >> Signed(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntMult(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (v0 * v1).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntDiv(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Unsigned(v0) / Unsigned(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedDiv(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Signed(v0) / Signed(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntRem(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Unsigned(v0) % Unsigned(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntSignedRem(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    if input0.size <= MAX_PRIMITIVE && input1.size <= MAX_PRIMITIVE {
                        output.value = (Signed(v0) % Signed(v1)).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::BoolNot(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let mut output = Slot::from(out);

                if let Some(v0) = input0.as_complete() {
                    output.value = (!Bool(v0)).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::BoolXor(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for clear operation
                if iaddr0 == iaddr1 {
                    output.value = PartialValue::from(false);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = (Bool(v0) ^ Bool(v1)).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::BoolAnd(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                // Heuristic for clear operation
                if iaddr0.first().map(|a| a.is_const_zero()).unwrap_or(false)
                    || iaddr1.first().map(|a| a.is_const_zero()).unwrap_or(false)
                {
                    output.value = PartialValue::from(false);
                    emu_out.delta = Some(Delta::Dataflow(output, None));
                    return;
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = (v0 & v1).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::BoolOr(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = (Bool(v0) | Bool(v1)).into();
                }

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::FloatEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNotEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatLess(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatLessEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNaN(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatAdd(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatDiv(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatMult(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatSub(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNeg(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatAbs(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatSqrt(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::IntToFloat(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatToFloat(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatToInt(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatCeil(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatFloor(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatRound(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::Multiequal(op) => {
                let out = op.output();
                let [_iaddr0] = op.inputs();
                let output = Slot::from(out);
                emu_out.stack.clear();
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::Indirect(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1] = op.inputs();
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::Piece(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let output = Slot::from(out);

                self.resolve_deps(&input0, Some(0), emu_out);
                self.resolve_deps(&input1, Some(1), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::Subpiece(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(&mut input1);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if input1.space.big_endian() {
                    input1.byte_swap();
                }

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(v0), Some(v1)) = inputs {
                    output.value = v0.subpiece(&v1, output.size as _).into();
                    if output.space.big_endian() {
                        output.byte_swap();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::Cast(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let input0 = Slot::from(iaddr0);
                self.resolve_deps(&input0, Some(0), emu_out);
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::AddressOfIndex(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1, _iaddr2] = op.inputs();
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::AddressOfField(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1] = op.inputs();
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::SegmentOp(_) => {
                emu_out.side_effect = Some(SideEffect::Clear);
            }
            Operation::ConstPoolRef(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1, _iaddr2] = op.inputs();
                let output = Slot::from(out);
                emu_out.stack.clear();
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::New(op) => {
                let out = op.output();
                let [_iaddr0] = op.inputs();
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::NewCount(op) => {
                let out = op.output();
                let [_iaddr0, _iaddr1] = op.inputs();
                let output = Slot::from(out);
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::Insert(_) => {
                unimplemented!()
            }
            Operation::Extract(_) => {
                unimplemented!()
            }
            Operation::Popcount(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if let Some(v0) = input0.as_complete() {
                    if input0.size <= MAX_PRIMITIVE {
                        output.value = v0.popcount(output.size as _).into();
                        if output.space.big_endian() {
                            output.byte_swap();
                        }
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::Lzcount(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(&mut input0);

                let mut output = Slot::from(out);

                if input0.space.big_endian() {
                    input0.byte_swap();
                }

                if let Some(v0) = input0.as_complete() {
                    output.value = v0.lzcount(output.size as _).into();
                    if output.space.big_endian() {
                        output.byte_swap();
                    }
                }

                self.resolve_deps(&input0, Some(0), emu_out);

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }

            Operation::IntCmp(_) => {
                todo!()
            }

            Operation::IntSignedCmp(_) => {
                todo!()
            }

            Operation::Argument(op) => {
                let &[_iaddr0, iaddr1] = op.inputs();
                emu_out.stack.push(iaddr1);
                // TODO: Push argument to interpreter stack
            }

            Operation::Unknown(_) => {
                emu_out.side_effect = Some(SideEffect::Clear);
            }
        };
    }
}

struct PrettyPrintPartial(PartialValue, usize);

impl std::fmt::Display for PrettyPrintPartial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_list();
        for i in 0..self.1 {
            match self.0.get(i) {
                Some(&b) => {
                    f.entry(&HEX_BYTES[b as usize]);
                }
                None => {
                    f.entry(&UnknownByte);
                }
            }
        }
        f.finish()
    }
}

struct UnknownByte;

impl std::fmt::Debug for UnknownByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "??")
    }
}

const fn generate_hex_bytes() -> [crate::Hex<u8>; 256] {
    let mut arr = [crate::Hex(0); 256];
    let mut i = 0;
    while i < 256 {
        arr[i] = crate::Hex(i as u8);
        i += 1;
    }
    arr
}

static HEX_BYTES: [crate::Hex<u8>; 256] = generate_hex_bytes();

struct PrettyPrintInputs<'a>(&'a [AddressRange]);

impl std::fmt::Display for PrettyPrintInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for (i, address) in self.0.iter().enumerate() {
            write! {
                f,
                "{}({}, {}, {})",
                if i == 0 { "" } else { ", " },
                address.space().id(),
                crate::Hex(address.offset()),
                address.size(),
            }?;
        }
        write!(f, "]")
    }
}

struct PrettyPrintOutput(Option<AddressRange>);

impl std::fmt::Display for PrettyPrintOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(address) => write!(
                f,
                "Some(({}, {}, {}))",
                address.space().id(),
                crate::Hex(address.offset()),
                address.size()
            ),
            None => write!(f, "None"),
        }
    }
}
