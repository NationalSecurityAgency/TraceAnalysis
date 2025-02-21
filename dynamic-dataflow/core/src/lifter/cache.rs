#![allow(dead_code)]

use crate::operation::Operation;
use crate::seqcache;
use hashbrown::HashMap;
use std::fmt::Write;

pub(crate) struct Tcache {
    bytes: InsBytesCache,
    disasm: DisasmCache,
    ops: OpCache,
    instructions: HashMap<TcacheIndex, (usize, TcacheEntry)>,
}

impl Tcache {
    pub fn new() -> Self {
        Self {
            bytes: InsBytesCache::new(),
            disasm: DisasmCache::new(),
            ops: OpCache::new(),
            instructions: HashMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        pc: u64,
        bytes: &[u8],
        disasm: &str,
        ops: &[Operation],
    ) -> TcacheIndex {
        let bytesidx = self.bytes.get_or_intern(bytes);
        let index = TcacheIndex(pc, bytesidx);
        if self.instructions.contains_key(&index) {
            return index;
        }
        let disasmidx = self.disasm.get_or_intern(disasm);
        let opsidx = self.ops.get_or_intern(ops);
        let order = self.instructions.len();
        self.instructions
            .insert(index, (order, TcacheEntry(disasmidx, opsidx)));
        index
    }

    pub fn iter_indices_for<'a>(&'a self, pc: u64) -> impl Iterator<Item = TcacheIndex> + 'a {
        self.instructions
            .keys()
            .filter_map(move |&index| (index.0 == pc).then(|| index))
    }

    pub fn iter_disasm<'a>(&'a self) -> impl Iterator<Item = &'a str> + 'a {
        self.disasm.iter()
    }

    pub fn iter_ops<'a>(&'a self) -> impl Iterator<Item = &'a [Operation]> + 'a {
        self.ops.iter()
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = (usize, u64, &'a [u8], usize, usize)> + 'a {
        self.instructions
            .iter()
            .map(|(&index, &(order, ref entry))| {
                let pc = index.0;
                let bytes = self.instruction_bytes_for(index).unwrap();
                let disas_idx: DisasmIndex = entry.0;
                let disas_id = disas_idx.0.to_usize();
                let oplist_idx: OpIndex = entry.1;
                let oplist_id = oplist_idx.0.to_usize();
                (order, pc, bytes, disas_id, oplist_id)
            })
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn stats(&self, s: &mut String) {
        let _ = write!(
            s,
            "{},{},{},{},{},{},{}",
            self.instructions.len(),
            self.disasm.0.len(),
            self.disasm.0.size(),
            self.ops.0.len(),
            self.ops.0.size(),
            self.bytes.0.len(),
            self.bytes.0.size()
        );
    }

    #[inline]
    pub(crate) fn contains_key<K: Key>(&self, key: &K) -> bool {
        K::contains(key, self)
    }

    #[inline]
    pub(crate) fn get<'a, K: Key>(&'a self, key: &K) -> Option<&'a K::Value> {
        K::get(key, self)
    }

    #[inline]
    pub fn disassembly_for(&self, idx: TcacheIndex) -> Option<&str> {
        self.get(&idx)
            .and_then(|&(_, ref entry)| self.get(&entry.0))
    }

    #[inline]
    pub fn operations_for(&self, idx: TcacheIndex) -> Option<&[Operation]> {
        self.get(&idx)
            .and_then(|&(_, ref entry)| self.get(&entry.1))
    }

    #[inline]
    pub fn instruction_bytes_for(&self, idx: TcacheIndex) -> Option<&[u8]> {
        self.get(&idx.1)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcacheIndex(u64, InsBytesIndex);

pub struct TcacheEntry(DisasmIndex, OpIndex);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InsBytesIndex(seqcache::Index);

struct InsBytesCache(seqcache::SeqCache<u8>);

impl InsBytesCache {
    fn new() -> Self {
        Self(seqcache::SeqCache::new())
    }

    fn get_or_intern<T>(&mut self, s: T) -> InsBytesIndex
    where
        T: AsRef<[u8]>,
    {
        InsBytesIndex(self.0.get_or_intern(s.as_ref()))
    }

    fn resolve(&self, s: InsBytesIndex) -> Option<&[u8]> {
        self.0.resolve(s.0)
    }

    fn get<T>(&self, s: T) -> Option<InsBytesIndex>
    where
        T: AsRef<[u8]>,
    {
        self.0.get(s.as_ref()).map(InsBytesIndex)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct DisasmIndex(seqcache::Index);

struct DisasmCache(seqcache::SeqCache<u8>);

impl DisasmCache {
    fn new() -> Self {
        Self(seqcache::SeqCache::new())
    }

    fn get_or_intern<T>(&mut self, s: T) -> DisasmIndex
    where
        T: AsRef<str>,
    {
        DisasmIndex(self.0.get_or_intern(s.as_ref().as_bytes()))
    }

    fn resolve(&self, s: DisasmIndex) -> Option<&str> {
        self.0
            .resolve(s.0)
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .map(|seq| unsafe { std::str::from_utf8_unchecked(seq) })
    }

    //#[allow(dead_code)]
    //fn get<T>(&self, s: T) -> Option<DisasmIndex>
    //where
    //    T: AsRef<str>
    //{
    //    self.0.get(s.as_ref().as_bytes()).map(DisasmIndex)
    //}
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OpIndex(seqcache::Index);

struct OpCache(seqcache::SeqCache<Operation>);

impl OpCache {
    fn new() -> Self {
        Self(seqcache::SeqCache::new())
    }

    fn get_or_intern<T>(&mut self, s: T) -> OpIndex
    where
        T: AsRef<[Operation]>,
    {
        OpIndex(self.0.get_or_intern(s.as_ref()))
    }

    fn resolve(&self, s: OpIndex) -> Option<&[Operation]> {
        self.0.resolve(s.0)
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &'a [Operation]> + 'a {
        self.0.iter()
    }
}

pub(crate) trait Key {
    type Value: ?Sized;
    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value>;
    fn contains(&self, tcache: &Tcache) -> bool;
}

impl Key for (u64, &'_ [u8]) {
    type Value = TcacheIndex;

    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value> {
        let &(pc, bytes) = self;
        tcache
            .bytes
            .get(bytes)
            .and_then(|bytesidx| {
                let key = TcacheIndex(pc, bytesidx);
                tcache.instructions.raw_entry().from_key(&key)
            })
            .map(|(key, _)| key)
    }

    fn contains(&self, tcache: &Tcache) -> bool {
        let &(pc, bytes) = self;
        if let Some(bytesidx) = tcache.bytes.get(bytes) {
            return tcache.instructions.contains_key(&TcacheIndex(pc, bytesidx));
        }
        false
    }
}

impl Key for TcacheIndex {
    type Value = (usize, TcacheEntry);

    #[inline]
    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value> {
        tcache.instructions.get(self)
    }

    #[inline]
    fn contains(&self, tcache: &Tcache) -> bool {
        tcache.instructions.contains_key(self)
    }
}

impl Key for InsBytesIndex {
    type Value = [u8];

    #[inline]
    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value> {
        tcache.bytes.resolve(*self)
    }

    #[inline]
    fn contains(&self, tcache: &Tcache) -> bool {
        tcache.bytes.resolve(*self).is_some()
    }
}

impl Key for DisasmIndex {
    type Value = str;

    #[inline]
    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value> {
        tcache.disasm.resolve(*self)
    }

    #[inline]
    fn contains(&self, tcache: &Tcache) -> bool {
        tcache.disasm.resolve(*self).is_some()
    }
}

impl Key for OpIndex {
    type Value = [Operation];

    #[inline]
    fn get<'a>(&self, tcache: &'a Tcache) -> Option<&'a Self::Value> {
        tcache.ops.resolve(*self)
    }

    #[inline]
    fn contains(&self, tcache: &Tcache) -> bool {
        tcache.ops.resolve(*self).is_some()
    }
}
