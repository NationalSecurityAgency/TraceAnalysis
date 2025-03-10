use crate::address::{Address, AddressRange};
use crate::delta::{Delta, DeltaDep};
use crate::export::*;
use crate::lifter::cache::*;
use crate::operation::{Operation, OperationKind};
use crate::slot::Slot;
use crate::space::SpaceKind;
use crate::{Index, Tick};
use hashbrown::HashMap;
use std::ops::Deref;

pub struct Datastore {
    deltas: Vec<(Tick, OperationKind, Delta)>,
    last_modified: HashMap<Address, Index>,
    last_modified_registers: HashMap<(u16, u64), Index>,
    value_deps: Vec<(Edge, u8)>,
    addr_deps: Vec<Edge>,
    const_value_deps: Vec<(ConstEdge, u8)>,
    const_addr_deps: Vec<ConstEdge>,
    cf_deps: Vec<Edge>,

    last_cf: Index,                 // Index of the last controlflow
    start_index: Index,             // Index at the start of the instruction
    blamed: Index,                  // Index of the last delta w/ side-effects
    pub(crate) current_thread: u16, // Thread id used to namespace register changes

    pub(crate) exporters: Vec<Box<dyn DataflowExport>>,

    translation_cache: Tcache,
    disasm_buffer: String,
    ops_buffer: Vec<Operation>,
}

impl Datastore {
    pub fn new() -> Self {
        let opc = OperationKind::Unknown;
        let delta = Delta::Dataflow(Slot::default(), None);
        let deltas = vec![(0, opc, delta)];

        Self {
            deltas,
            last_modified: HashMap::new(),
            last_modified_registers: HashMap::new(),
            addr_deps: Vec::new(),
            value_deps: Vec::new(),
            const_value_deps: Vec::new(),
            const_addr_deps: Vec::new(),
            cf_deps: Vec::new(),
            last_cf: 0,
            start_index: 0,
            blamed: 0,
            current_thread: 0,
            exporters: Vec::new(),
            translation_cache: Tcache::new(),
            disasm_buffer: String::new(),
            ops_buffer: Vec::new(),
        }
    }

    pub fn flush(&mut self) {
        //trace!("Datastore::flush()");
        let deltas = Message::Deltas(self.start_index, &self.deltas[self.start_index..]);
        let addr_deps = Message::AddrDeps(self.addr_deps.as_slice());
        let value_deps = Message::ValueDeps(self.value_deps.as_slice());
        let const_value_deps = Message::ConstValueDeps(self.const_value_deps.as_slice());
        let const_addr_deps = Message::ConstAddrDeps(self.const_addr_deps.as_slice());
        let cf_deps = Message::ControlflowDeps(self.cf_deps.as_slice());

        for exporter in self.exporters.iter_mut() {
            exporter.write(deltas).unwrap();
            exporter.write(addr_deps).unwrap();
            exporter.write(value_deps).unwrap();
            exporter.write(const_value_deps).unwrap();
            exporter.write(const_addr_deps).unwrap();
            exporter.write(cf_deps).unwrap();
            exporter.flush().unwrap();
        }

        self.addr_deps.clear();
        self.value_deps.clear();
        self.const_value_deps.clear();
        self.const_addr_deps.clear();
        self.cf_deps.clear();
        self.start_index = self.deltas.len();
    }

    pub fn start_tick(&mut self, tick: Tick, pc: u64, asm: String) {
        //trace!("Datastore::start_tick({}, {:x?}, {})", tick, pc, asm);
        self.flush();
        let message = Message::Tick(tick, pc, asm.as_str());
        for exporter in self.exporters.iter_mut() {
            exporter.write(message).unwrap();
        }
    }

    pub fn insert_delta<D>(&mut self, tick: Tick, opc: OperationKind, delta: Delta, deps: D)
    where
        D: IntoIterator<Item = DeltaDep>,
    {
        let delta_idx = self.deltas.len();
        let _span = tracing::trace_span!("insert_delta", index = delta_idx).entered();

        if Delta::is_dataflow(&delta) {
            match delta.deref().space.kind() {
                SpaceKind::Register => {
                    for address in delta.as_range().iter() {
                        let key = (self.current_thread, address.offset());
                        self.last_modified_registers.insert(key, delta_idx);
                    }
                }
                _ => {
                    for address in delta.as_range().iter() {
                        self.last_modified.insert(address, delta_idx);
                    }
                }
            }
        }

        self.deltas.push((tick, opc, delta));

        deps.into_iter().for_each(|dep| match dep {
            DeltaDep::Address(dep) => {
                tracing::trace!(from = delta_idx, to = dep.index, "address dep");
                self.addr_deps.push(Edge::Certain(delta_idx, dep.index));
            }
            DeltaDep::Value(dep) => {
                tracing::trace! {
                    from = delta_idx,
                    to = dep.index,
                    position = dep.pos,
                    "value dep"
                };
                self.value_deps
                    .push((Edge::Certain(delta_idx, dep.index), dep.pos));
            }
            DeltaDep::ConstAddress(dep) => {
                self.const_addr_deps.push(ConstEdge(delta_idx, dep.value));
            }
            DeltaDep::ConstValue(dep) => {
                self.const_value_deps
                    .push((ConstEdge(delta_idx, dep.value), dep.pos));
            }
        });

        self.cf_deps.push(Edge::Certain(delta_idx, self.last_cf));

        if Delta::is_controlflow(&delta) {
            self.last_cf = delta_idx;
        }

        // Deciding whether deps should be deduped by the datastore
        // or ahead of time

        //let mut unique: HashSet<Index> = HashSet::new();
        //
        //for i in vdeps {
        //    if let None = unique.get(&i) {
        //        self.value_deps.push((delta_idx, i));
        //        unique.insert(i);
        //    }
        //}
    }

    pub fn instruction_index(&self) -> Index {
        //trace!("Datastore::instruction_index() = {}", self.start_index);
        self.start_index
    }

    pub fn next_index(&self) -> Index {
        //trace!("Datastore::next_index() = {}", self.next_index);
        self.deltas.len()
    }

    pub fn instruction_deltas(&self) -> impl Iterator<Item = &(Tick, OperationKind, Delta)> {
        self.deltas[self.start_index..].iter()
    }

    pub fn delta(&self, index: Index) -> Option<&(Tick, OperationKind, Delta)> {
        self.deltas.get(index)
    }

    pub fn delta_mut(&mut self, index: Index) -> Option<&mut (Tick, OperationKind, Delta)> {
        self.deltas.get_mut(index)
    }

    pub fn last_modified(&self, address: &Address) -> Option<&Index> {
        match address.space().kind() {
            SpaceKind::Register => {
                let key = (self.current_thread, address.offset());
                self.last_modified_registers.get(&key)
            }
            _ => self.last_modified.get(address),
        }
    }

    pub fn last_modified_with_context(&self, address: &Address, tid: u16) -> Option<&Index> {
        match address.space().kind() {
            SpaceKind::Register => {
                let key = (tid, address.offset());
                self.last_modified_registers.get(&key)
            }
            _ => self.last_modified.get(address),
        }
    }

    pub fn forget(&mut self) {
        self.last_modified.clear();
        self.last_modified_registers.clear();
    }

    pub fn forget_range(&mut self, range: &AddressRange) {
        tracing::trace! {
            space = range.space().id(),
            offset = %crate::Hex(range.offset()),
            size = range.size(),
            "terminating dataflow in range"
        };

        match range.space().kind() {
            SpaceKind::Register => {
                for address in range.iter() {
                    let key = (self.current_thread, address.offset());
                    self.last_modified_registers.remove(&key);
                }
            }
            _ => {
                for address in range.iter() {
                    self.last_modified.remove(&address);
                }
            }
        }
    }

    pub fn blame(&mut self) {
        self.blamed = self.deltas.len() - 1;
    }

    pub fn blame_on_other(&mut self, index: Index) {
        // Convert all certain edges into maybe edges
        // Assumption: "certain" edges are never created after maybe edges.
        // So if a maybe edge is encountered, all certain edges have been
        // converted and a newly blamed edge does not need to be created
        // to avoid duplication

        for (edge, _) in self.value_deps.iter_mut() {
            match edge {
                &mut Edge::Certain(src, dst) if src == index => {
                    *edge = Edge::Maybe(src, dst);
                }
                &mut Edge::Maybe(src, _) if src == index => {
                    return ();
                }
                _ => {}
            }
        }

        self.value_deps.push((Edge::Maybe(index, self.blamed), 255));
    }

    pub(crate) fn lookup_tcache_or_else<F, E>(
        &mut self,
        pc: u64,
        insbytes: &[u8],
        f: F,
    ) -> std::result::Result<TcacheIndex, E>
    where
        F: FnOnce(&mut String, &mut Vec<Operation>) -> std::result::Result<(), E>,
    {
        if let Some(&idx) = self.translation_cache.get(&(pc, insbytes)) {
            return Ok(idx);
        }

        self.disasm_buffer.clear();
        self.ops_buffer.clear();
        f(&mut self.disasm_buffer, &mut self.ops_buffer)?;

        Ok(self.translation_cache.insert(
            pc,
            insbytes,
            self.disasm_buffer.as_str(),
            self.ops_buffer.as_slice(),
        ))
    }

    pub(crate) fn disassembly_for(&self, idx: TcacheIndex) -> Option<&str> {
        self.translation_cache.disassembly_for(idx)
    }

    pub(crate) fn operations_for(&self, idx: TcacheIndex) -> Option<&[Operation]> {
        self.translation_cache.operations_for(idx)
    }

    pub(crate) fn instruction_bytes_for(&self, idx: TcacheIndex) -> Option<&[u8]> {
        self.translation_cache.instruction_bytes_for(idx)
    }
}

impl Drop for Datastore {
    fn drop(&mut self) {}
}
