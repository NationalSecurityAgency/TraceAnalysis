use std::collections::BTreeMap;
use std::path::Path;

mod cache;
mod sql;

pub use cache::{DisasmIndex, InsBytesIndex, InstructionIndex, OpListIndex};

#[allow(dead_code)]
pub struct Database {
    conn: rusqlite::Connection,
    last_modified: BTreeMap<(u16, u64), (Option<u8>, Option<u64>)>,
    cache: cache::Cache,
}

impl Database {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let conn = rusqlite::Connection::open(path)?;

        conn.execute_batch(
            "BEGIN;
        CREATE TABLE instructions (\
            id INTEGER PRIMARY KEY, \
            pc INTEGER NOT NULL, \
            bytes BLOB NOT NULL, \
            disasm_id INTEGER, \
            oplist_id INTEGER\
        );
        CREATE TABLE disassembly (\
            id INTEGER PRIMARY KEY, \
            text TEXT NOT NULL\
        ); 
        CREATE TABLE operations (\
            id INTEGER PRIMARY KEY, \
            oplist INTEGER NOT NULL, \
            seqnum INTEGER NOT NULL, \
            opcode INTEGER NOT NULL, \
            arg0_space INTEGER, \
            arg0_offset INTEGER, \
            arg0_size INTEGER, \
            arg1_space INTEGER, \
            arg1_offset INTEGER, \
            arg1_size INTEGER, \
            arg2_space INTEGER, \
            arg2_offset INTEGER, \
            arg2_size INTEGER, \
            arg3_space INTEGER, \
            arg3_offset INTEGER, \
            arg3_size INTEGER\
        );
        CREATE TABLE instructionruns (\
            id INTEGER PRIMARY KEY, \
            tick INTEGER NOT NULL, \
            ins_id INTEGER NOT NULL\
        );
        CREATE TABLE operationruns (\
            id INTEGER PRIMARY KEY, \
            tick INTEGER NOT NULL, \
            op_id INTEGER NOT NULL, \
            ins_run_id INTEGER\
        );
        CREATE TABLE deltas (\
            id INTEGER PRIMARY KEY, \
            op_run_id INTEGER NOT NULL, \
            space INTEGER NOT NULL, \
            offset INTEGER NOT NULL, \
            size INTEGER NOT NULL, \
            value BLOB NOT NULL, \
            bitmask BLOB NOT NULL\
        );
        COMMIT;",
        )?;

        Ok(Self {
            conn,
            last_modified: BTreeMap::new(),
            cache: cache::Cache::new(),
        })
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
    pub fn cache_lookup<T: cache::CacheLookup>(&self, index: T) -> Option<&T::Output> {
        T::get(index, &self.cache)
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
    pub fn cache_insert<T: cache::CacheInsert + ?Sized>(&mut self, t: &T) -> T::Output {
        T::insert(t, &mut self.cache)
    }

    pub fn save(&mut self) -> Result<(), DatabaseError> {
        self.cache.flush(&mut self.conn)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DatabaseError(#[from] rusqlite::Error);
