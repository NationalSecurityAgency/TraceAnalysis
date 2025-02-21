use crate::operation::Operation;
use crate::seqcache;
use hashbrown::hash_map::{DefaultHashBuilder, HashMap, RawEntryMut};
use std::borrow::Cow;
use std::hash::{BuildHasher, Hash, Hasher};

use super::sql;

pub struct Cache {
    ibytes_cache: seqcache::SeqCache<u8>,
    disasm_cache: seqcache::SeqCache<u8>,
    oplist_cache: seqcache::SeqCache<Operation>,
    dedup_instru: HashMap<InstructionIndex, (), ()>,
    instructions: Vec<(u64, InsBytesIndex, DisasmIndex, OpListIndex)>,
    hasher: DefaultHashBuilder,
    //instructions: HashMap<InstructionIndex, (usize, DisasmIndex, OpListIndex)>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            ibytes_cache: seqcache::SeqCache::new(),
            disasm_cache: seqcache::SeqCache::new(),
            oplist_cache: seqcache::SeqCache::new(),
            dedup_instru: HashMap::default(),
            instructions: Vec::new(),
            hasher: DefaultHashBuilder::default(),
        }
    }

    /// Returns the corresponding values for a given index into the cache.
    ///
    /// There are a number of different indices into the cache and each correspond to different
    /// types. The trait bounds on the input map a given index to the type of values it returns.
    ///
    /// For quick reference, the following indices exist for this cache:
    ///
    /// - `(u64, &[u8])` -> [`InstructionIndex`]
    /// - [`InstructionIndex`] -> `(usize, DisasmIndex, OpListIndex)`
    /// - [`InsBytesIndex`] -> `&[u8]`
    /// - [`DisasmIndex`] -> `&str`
    /// - [`OpListIndex`] -> `&[Operation]`
    #[inline]
    pub fn get<T: CacheLookup>(&self, index: T) -> Option<&T::Output> {
        T::get(index, self)
    }

    /// Inserts data into the cache to get a new index.
    ///
    /// If the data already exists in the cache, the index will be returned for the existing
    /// entry.
    ///
    /// The index is inferred from the type of data being inserted via the trait bounds. For quick
    /// reference, the following mappings exist for this cache:
    ///
    /// - `(u64, &[u8], &str, &[Operation])` -> [`InstructionIndex`]
    /// - `&[u8]` -> [`InsBytesIndex`]
    /// - `&str` -> [`DisasmIndex`]
    /// - `&[Operation]` -> [`OpListIndex`]
    #[inline]
    pub fn insert<T: CacheInsert + ?Sized>(&mut self, t: &T) -> T::Output {
        T::insert(t, self)
    }

    pub(super) fn flush(
        &mut self,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), super::DatabaseError> {
        let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();

        ////////////////////
        // diassembly
        ////////////////////

        let tx = conn.transaction()?;

        let mut param_str = " (?, ?),".repeat(50);
        param_str.pop();
        let mut stmt = tx.prepare_cached(
            format!("INSERT INTO disassembly (id, text) VALUES {}", param_str).as_str(),
        )?;
        let records: Vec<sql::Disassembly> = self
            .disasm_cache
            .iter()
            .map(|text| unsafe { std::str::from_utf8_unchecked(text) })
            .enumerate()
            .map(|(id, text)| sql::Disassembly {
                id: id as i64,
                text: Cow::from(text),
            })
            .collect();
        for batch in records.chunks(50) {
            params.clear();
            if batch.len() == 50 {
                params.extend(batch.iter().flat_map(|record| {
                    [
                        &record.id as &dyn rusqlite::ToSql,
                        &record.text as &dyn rusqlite::ToSql,
                    ]
                }));
                stmt.execute(params.as_slice())?;
                continue;
            }
            param_str = " (?, ?),".repeat(batch.len());
            param_str.pop();
            let mut stmt = tx.prepare_cached(
                format!("INSERT INTO disassembly (id, text) VALUES {}", param_str).as_str(),
            )?;
            params.extend(batch.iter().flat_map(|record| {
                [
                    &record.id as &dyn rusqlite::ToSql,
                    &record.text as &dyn rusqlite::ToSql,
                ]
            }));
            stmt.execute(params.as_slice())?;
        }

        std::mem::drop(stmt);
        tx.commit()?;

        ////////////////////
        // operations
        ////////////////////

        let tx = conn.transaction()?;

        param_str = " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),".repeat(50);
        param_str.pop();
        let mut stmt = tx.prepare_cached(
            format!(
                "INSERT INTO operations (\
                    id, oplist, seqnum, opcode, \
                    arg0_space, arg0_offset, arg0_size, \
                    arg1_space, arg1_offset, arg1_size, \
                    arg2_space, arg2_offset, arg2_size, \
                    arg3_space, arg3_offset, arg3_size\
                ) VALUES {}",
                param_str
            )
            .as_str(),
        )?;
        let records: Vec<sql::Operation> = self
            .oplist_cache
            .iter()
            .enumerate()
            .flat_map(|(oplist, ops)| {
                ops.iter()
                    .enumerate()
                    .map(move |(seqnum, op)| (oplist, seqnum, op))
            })
            .enumerate()
            .map(|(id, (oplist, seqnum, op))| {
                let (opcode, arg0, arg1, arg2, arg3) = op.unpack();
                sql::Operation {
                    id: id as i64,
                    oplist: oplist as i64,
                    seqnum: seqnum as i64,
                    opcode: opcode as u8,

                    arg0_space: arg0.map(|a| a.space().id()),
                    arg0_offset: arg0.map(|a| a.offset() as i64),
                    arg0_size: arg0.map(|a| a.size() as i64),

                    arg1_space: arg1.map(|a| a.space().id()),
                    arg1_offset: arg1.map(|a| a.offset() as i64),
                    arg1_size: arg1.map(|a| a.size() as i64),

                    arg2_space: arg2.map(|a| a.space().id()),
                    arg2_offset: arg2.map(|a| a.offset() as i64),
                    arg2_size: arg2.map(|a| a.size() as i64),

                    arg3_space: arg3.map(|a| a.space().id()),
                    arg3_offset: arg3.map(|a| a.offset() as i64),
                    arg3_size: arg3.map(|a| a.size() as i64),
                }
            })
            .collect();
        for batch in records.chunks(50) {
            params.clear();
            if batch.len() == 50 {
                params.extend(batch.iter().flat_map(|record| {
                    [
                        &record.id as &dyn rusqlite::ToSql,
                        &record.oplist as &dyn rusqlite::ToSql,
                        &record.seqnum as &dyn rusqlite::ToSql,
                        &record.opcode as &dyn rusqlite::ToSql,
                        &record.arg0_space as &dyn rusqlite::ToSql,
                        &record.arg0_offset as &dyn rusqlite::ToSql,
                        &record.arg0_size as &dyn rusqlite::ToSql,
                        &record.arg1_space as &dyn rusqlite::ToSql,
                        &record.arg1_offset as &dyn rusqlite::ToSql,
                        &record.arg1_size as &dyn rusqlite::ToSql,
                        &record.arg2_space as &dyn rusqlite::ToSql,
                        &record.arg2_offset as &dyn rusqlite::ToSql,
                        &record.arg2_size as &dyn rusqlite::ToSql,
                        &record.arg3_space as &dyn rusqlite::ToSql,
                        &record.arg3_offset as &dyn rusqlite::ToSql,
                        &record.arg3_size as &dyn rusqlite::ToSql,
                    ]
                }));
                stmt.execute(params.as_slice())?;
                continue;
            }
            param_str = " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),".repeat(batch.len());
            param_str.pop();
            let mut stmt = tx.prepare_cached(
                format!(
                    "INSERT INTO operations (\
                        id, oplist, seqnum, opcode, \
                        arg0_space, arg0_offset, arg0_size, \
                        arg1_space, arg1_offset, arg1_size, \
                        arg2_space, arg2_offset, arg2_size, \
                        arg3_space, arg3_offset, arg3_size\
                    ) VALUES {}",
                    param_str
                )
                .as_str(),
            )?;
            params.extend(batch.iter().flat_map(|record| {
                [
                    &record.id as &dyn rusqlite::ToSql,
                    &record.oplist as &dyn rusqlite::ToSql,
                    &record.seqnum as &dyn rusqlite::ToSql,
                    &record.opcode as &dyn rusqlite::ToSql,
                    &record.arg0_space as &dyn rusqlite::ToSql,
                    &record.arg0_offset as &dyn rusqlite::ToSql,
                    &record.arg0_size as &dyn rusqlite::ToSql,
                    &record.arg1_space as &dyn rusqlite::ToSql,
                    &record.arg1_offset as &dyn rusqlite::ToSql,
                    &record.arg1_size as &dyn rusqlite::ToSql,
                    &record.arg2_space as &dyn rusqlite::ToSql,
                    &record.arg2_offset as &dyn rusqlite::ToSql,
                    &record.arg2_size as &dyn rusqlite::ToSql,
                    &record.arg3_space as &dyn rusqlite::ToSql,
                    &record.arg3_offset as &dyn rusqlite::ToSql,
                    &record.arg3_size as &dyn rusqlite::ToSql,
                ]
            }));
            stmt.execute(params.as_slice())?;
        }

        std::mem::drop(stmt);
        tx.commit()?;

        ////////////////////
        // instructions
        ////////////////////

        let tx = conn.transaction()?;

        param_str = " (?, ?, ?, ?, ?),".repeat(50);
        param_str.pop();
        let mut stmt = tx.prepare_cached(
            format!(
                "INSERT INTO instructions (\
                    id, pc, bytes, disasm_id, oplist_id\
                ) VALUES {}",
                param_str
            )
            .as_str(),
        )?;
        let records: Vec<sql::Instruction> = self
            .instructions
            .iter()
            .map(|&(pc, ibytes_idx, disasm_idx, oplist_idx)| {
                let bytes = Cow::from(self.get(ibytes_idx).unwrap());
                (pc, bytes, disasm_idx, oplist_idx)
            })
            .enumerate()
            .map(
                |(id, (pc, bytes, disasm_idx, oplist_idx))| sql::Instruction {
                    id: id as i64,
                    pc: pc as i64,
                    bytes,
                    disasm_id: disasm_idx.0.to_usize() as i64,
                    oplist_id: oplist_idx.0.to_usize() as i64,
                },
            )
            .collect();
        for batch in records.chunks(50) {
            params.clear();
            if batch.len() == 50 {
                params.extend(batch.iter().flat_map(|record| {
                    [
                        &record.id as &dyn rusqlite::ToSql,
                        &record.pc as &dyn rusqlite::ToSql,
                        &record.bytes as &dyn rusqlite::ToSql,
                        &record.disasm_id as &dyn rusqlite::ToSql,
                        &record.oplist_id as &dyn rusqlite::ToSql,
                    ]
                }));
                stmt.execute(params.as_slice())?;
                continue;
            }
            param_str = " (?, ?, ?, ?, ?),".repeat(batch.len());
            param_str.pop();
            let mut stmt = tx.prepare_cached(
                format!(
                    "INSERT INTO instructions (\
                        id, pc, bytes, disasm_id, oplist_id\
                    ) VALUES {}",
                    param_str
                )
                .as_str(),
            )?;
            params.extend(batch.iter().flat_map(|record| {
                [
                    &record.id as &dyn rusqlite::ToSql,
                    &record.pc as &dyn rusqlite::ToSql,
                    &record.bytes as &dyn rusqlite::ToSql,
                    &record.disasm_id as &dyn rusqlite::ToSql,
                    &record.oplist_id as &dyn rusqlite::ToSql,
                ]
            }));
            stmt.execute(params.as_slice())?;
        }

        std::mem::drop(stmt);
        tx.commit()?;

        Ok(())
    }
}

/// Index into the lift cache that corresponds to a specific lifted instruction.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructionIndex(seqcache::Index);

impl CacheLookup for (u64, &'_ [u8]) {
    type Output = InstructionIndex;

    fn get(self, cache: &Cache) -> Option<&Self::Output> {
        let hash = make_hash(&cache.hasher, &self);
        let (pc, bytes) = self;
        cache
            .dedup_instru
            .raw_entry()
            .from_hash(hash, |index| {
                // SAFETY: This is safe because we are only using indices that are internally
                // stored which guarentees the existence of an entry at that point.
                let &(entry_pc, entry_ibytes_index, _, _) =
                    unsafe { cache.instructions.get_unchecked(index.0.to_usize()) };
                entry_pc == pc && cache.get(entry_ibytes_index) == Some(bytes)
            })
            .map(|(index, _)| index)
    }
}

impl CacheInsert for (u64, &'_ [u8], &'_ str, &[Operation]) {
    type Output = (InstructionIndex, DisasmIndex, OpListIndex);

    #[inline]
    fn insert(&self, cache: &mut Cache) -> Self::Output {
        let &(pc, bytes, disasm, ops) = self;
        let ibytes_idx = cache.insert(bytes);
        let disasm_idx = cache.insert(disasm);
        let oplist_idx = cache.insert(ops);
        let hash = make_hash(&cache.hasher, &(pc, bytes));

        let entry = cache.dedup_instru.raw_entry_mut().from_hash(hash, |index| {
            let &(e_pc, e_ibytes_idx, e_disasm_idx, e_oplist_idx) =
                unsafe { cache.instructions.get_unchecked(index.0.to_usize()) };
            let is_match = e_pc == pc && e_ibytes_idx == ibytes_idx;
            if is_match {
                assert! {
                    e_disasm_idx == disasm_idx,
                    "cannot update disassembly for existing instruction"
                };
                assert! {
                    e_oplist_idx == oplist_idx,
                    "cannot update operations for existing instruction"
                };
            }
            is_match
        });

        let (&mut ins_idx, &mut ()) = match entry {
            RawEntryMut::Occupied(occupied) => occupied.into_key_value(),
            RawEntryMut::Vacant(vacant) => {
                let index = InstructionIndex(
                    seqcache::Index::try_from_usize(cache.instructions.len())
                        .expect("out of indices"),
                );
                cache
                    .instructions
                    .push((pc, ibytes_idx, disasm_idx, oplist_idx));
                vacant.insert_with_hasher(hash, index, (), |index| {
                    let &(entry_pc, entry_ibytes_idx, _, _) =
                        unsafe { cache.instructions.get_unchecked(index.0.to_usize()) };
                    let entry_ibytes = cache.ibytes_cache.resolve(entry_ibytes_idx.0).unwrap();
                    make_hash(&cache.hasher, &(entry_pc, entry_ibytes))
                })
            }
        };

        (ins_idx, disasm_idx, oplist_idx)
    }
}

impl CacheLookup for InstructionIndex {
    type Output = (u64, InsBytesIndex, DisasmIndex, OpListIndex);

    #[inline]
    fn get(self, cache: &Cache) -> Option<&Self::Output> {
        cache.instructions.get(self.0.to_usize())
    }
}

/// Index into the lift cache that corresponds to the set of bytes for an instruction.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InsBytesIndex(seqcache::Index);

impl CacheLookup for InsBytesIndex {
    type Output = [u8];

    #[inline]
    fn get(self, cache: &Cache) -> Option<&Self::Output> {
        cache.ibytes_cache.resolve(self.0)
    }
}

impl CacheInsert for [u8] {
    type Output = InsBytesIndex;
    fn insert(&self, cache: &mut Cache) -> Self::Output {
        InsBytesIndex(cache.ibytes_cache.get_or_intern(self))
    }
}

/// Index into the lift cache that corresponds to the disassembly for an instruction.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DisasmIndex(seqcache::Index);

impl CacheLookup for DisasmIndex {
    type Output = str;

    #[inline]
    fn get(self, cache: &Cache) -> Option<&Self::Output> {
        cache
            .disasm_cache
            .resolve(self.0)
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) })
    }
}

impl CacheInsert for str {
    type Output = DisasmIndex;

    #[inline]
    fn insert(&self, cache: &mut Cache) -> Self::Output {
        DisasmIndex(cache.disasm_cache.get_or_intern(self.as_bytes()))
    }
}

/// Index into the lift cache that corresponds to the pcode operations for an instruction.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpListIndex(seqcache::Index);

impl CacheLookup for OpListIndex {
    type Output = [Operation];

    #[inline]
    fn get(self, cache: &Cache) -> Option<&Self::Output> {
        cache.oplist_cache.resolve(self.0)
    }
}

impl CacheInsert for [Operation] {
    type Output = OpListIndex;

    #[inline]
    fn insert(&self, cache: &mut Cache) -> Self::Output {
        OpListIndex(cache.oplist_cache.get_or_intern(self))
    }
}

pub trait CacheInsert: private::Sealed {
    type Output;
    fn insert(&self, cache: &mut Cache) -> Self::Output;
}

pub trait CacheLookup: private::Sealed {
    type Output: ?Sized;
    fn get(self, cache: &Cache) -> Option<&Self::Output>;
}

fn make_hash<T>(builder: &impl BuildHasher, value: &T) -> u64
where
    T: ?Sized + Hash,
{
    let state = &mut builder.build_hasher();
    value.hash(state);
    state.finish()
}

mod private {
    pub trait Sealed {}
    impl Sealed for (u64, &'_ [u8]) {}
    impl Sealed for (u64, &'_ [u8], &'_ str, &'_ [super::Operation]) {}
    impl Sealed for [u8] {}
    impl Sealed for str {}
    impl Sealed for [super::Operation] {}
    impl Sealed for super::InstructionIndex {}
    impl Sealed for super::InsBytesIndex {}
    impl Sealed for super::DisasmIndex {}
    impl Sealed for super::OpListIndex {}
}
