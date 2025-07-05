//! A table for tracking the last known value stored at an [`Address`] in memory as well as the
//! index of the last [`Operation`] known to have written to that [`Address`].
//!
//! Conceptually, this should be thought of as being laid out as follows:
//!
//! ```text
//! +-------+--------+----------------+---------------+
//! | Space | Offset | Option<Source> | Option<Value> |
//! +-------+--------+----------------+---------------+
//! | Regs  | 0      | Some(1)        | Some(0xbe)    |
//! | Regs  | 1      | Some(1)        | Some(0xef)    |
//! | Mem   | 1000   | Some(2)        | None          |
//! | Mem   | 1001   | Some(2)        | None          |
//! | Mem   | 1002   | None           | Some(0xc0)    |
//! | Mem   | 1003   | None           | Some(0xde)    |
//! | Mem   | 1004   | None           | None          |
//! | Mem   | 1005   | None           | None          |
//! | ...   | ...    | ...            | ...           |
//! +-------+--------+----------------+---------------+
//! ```
//!
//! This illustrates a couple of key facts:
//!
//! - There are instances where a source is known, but the corresponding value is not. This often
//!   occurs when analysis is insufficient to determine the results of intermediate computations,
//!   or some non-deterministic event occurs that was not captured by a trace. The operation will
//!   be able to tell as that a particular address was written to, but not its value.
//! - There are instances where a value is known, but its corresponding source is not. This will
//!   only occur is certain setups where analysis is able to query the live state of a running
//!   program. In this case, we can fallback on reading from a process to determine the value at
//!   an address, but we will not know what historical operation produced that value.
//! - Range queries across continuous addresses are relatively cheap. The public API should reflect
//!   that this is going to be the most common use.
//!
//! # Examples
//!
//! ```
//! # use crate::beta::lastmodified::LastModified;
//! # use crate::space::{Space, SpaceAttributes};
//! /// Make a new set of spaces for memory and registers
//! let mem = Space::new(1, SpaceAttributes::MEMORY, 8, 1);
//! let regs = Space::new(2, SpaceAttributes::REGISTER, 8, 1);
//! let mut table = LastModified::new();
//! let mut results: Vec<(Option<u8>, Option<u64>)> = Vec::new();
//!
//! /// By default, values and sources are None
//! table.resolve(&mem.index(0..4));
//! assert_eq!(results, vec![(None, None); 4]);
//! results.clear()
//!
//! /// We can add a range of values with an Address range and a set of iterators
//! table.add_value(
//!   &mem.index(0..4),
//!   u32::to_le_bytes(0x1337c0de).into_iter().map(Some),
//!   std::iter::repeat(Some(0)));
//!
//! /// We can query on portions of that range
//! table.resolve(&mem.index(2..4), &mut results);
//! assert_eq!(results, vec![(Some(0x37), Some(0)), (Some(0x13), Some(0))]);
//! results.clear();
//!
//! /// Spaces are non-overlapping (writes to memory do not effect writes to registers)
//! table.resolve(&reg.index(2..4), &mut results);
//! assert_eq!(results, vec![(None, None), (None, None)]);
//! results.clear();
//!
//! /// We can update portions of an existing range and they will cascade
//! table.add_value(&mem.index(2..3), std::iter::once(Some(0x41)), std::iter::once(Some(1)));
//! table.resolve(&mem.index(2..4), &mut results);
//! assert_eq!(results, vec![(Some(0x41), Some(1)), (Some(0x13), Some(0))]);
//! ```

use std::collections::HashMap;

use crate::address::AddressRange;

const HAS_VALUE: u64 = i64::MIN as u64;
const HAS_SOURCE: u64 = i64::MIN as u64 >> 1;
const SOURCE_MASK: u64 = (u64::MAX >> 2) ^ 0xff;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: u64 = u64::MAX ^ (PAGE_SIZE as u64 - 1);


#[derive(Debug, Clone, Default)]
pub struct LastModified(HashMap<LastModifiedKey, LastModifiedPage>);

impl LastModified {
    /// Constructs a new, empty [`LastModified`] table
    pub fn new() -> Self {
        Self::default()
    }

    /// Queries the table for values and sources stored within a given address range.
    pub fn resolve<V>(&self, address: &AddressRange, value: &mut V)
    where
        V: Extend<(Option<u8>, Option<u64>)>,
    {
        let Some(first) = address.first().map(|a| a.offset()) else {
            return;
        };

        let Some(last) = address.last().map(|a| a.offset()) else {
            return;
        };

        let space = address.space();

        if last < first {
            self.resolve(&space.index(first..=space.mask()), value);
            self.resolve(&space.index(0..=last), value);
            return;
        }

        let space_id = space.id() as u64 & 0xfff;

        let inner = self.inner();

        let first_page = first & PAGE_MASK;
        let last_page = last & PAGE_MASK;

        // This is both an optimization of the most likely path (copies within a single page), and
        // an optimization for more complicated paths below (copies that span multiple pages). By
        // handling the single page case here, we can elide several bounds checks below that would
        // have to make sure that we don't duplicate copies.
        if first_page == last_page {
            let start = (first - first_page) as usize;
            let size = address.size() as usize;
            let Some(page) = inner.get(&LastModifiedKey(first_page | space_id)) else {
                value.extend(std::iter::repeat((None, None)).take(size));
                return;
            };
            // SAFETY: The bitmasks ensure that start is clamped between 0..=0xfff, and we know
            // that we do not cross a page boundary so the addition of size will not exceed 0xfff.
            let data = unsafe { page.get_unchecked(start..start + size) };
            value.extend(data.iter().copied().map(LastModifiedEntry::into_parts));
            return;
        }

        // Given the above check, we are guarenteed to cross a page boundary, so we handle the
        // first page uniquely since it has the potential to be a partial page
        {
            let start = (first - first_page) as usize;
            if let Some(page) = inner.get(&LastModifiedKey(first_page | space_id)) {
                // SAFETY: The bitmasking calculations clamp start to be in the range 0..=0xfff
                // which guarantees that start will be within the page
                let data = unsafe { page.get_unchecked(start..) };
                value.extend(data.iter().copied().map(LastModifiedEntry::into_parts));
            } else {
                value.extend(std::iter::repeat((None, None)).take(PAGE_SIZE - start));
            }
        }

        // This loop almost certainly never runs b/c memory accesses rarely span three+ pages.
        // But in the case it does run, we all of the middle pages can handled without any bounds
        // checkeding.
        for base in (first_page + PAGE_SIZE as u64..last_page).step_by(PAGE_SIZE) {
            if let Some(page) = inner.get(&LastModifiedKey(base | space_id)) {
                value.extend(page.iter().copied().map(LastModifiedEntry::into_parts));
            } else {
                value.extend(std::iter::repeat((None, None)).take(PAGE_SIZE));
            }
        }

        // Given that we were guaranteed to cross a page boundary at least once, we can safely copy
        // from the beginning of the page w/o accidently copying twice. So this last copy handles
        // the last, potentially partial page.
        {
            let end = (last - last_page) as usize;
            if let Some(page) = inner.get(&LastModifiedKey(last_page | space_id)) {
                // SAFETY: The bitmasking calculations clamp end to be in the range 0..=0xfff
                // which guarantees that end will be within the page
                let data = unsafe { page.get_unchecked(..=end) };
                value.extend(data.iter().copied().map(LastModifiedEntry::into_parts));
            } else {
                value.extend(std::iter::repeat((None, None)).take(end));
            }
        }
    }

    /// Adds the given values and sources to the table at the given address range.
    ///
    /// This function is primarily driven by the supplied address range. That means that if the
    /// value or source iterators are exhausted before all of the addresses have been iterated
    /// over, they will be implicitly extended with their None variants.
    pub fn add_value<V, S>(&mut self, address: &AddressRange, value: V, source: S)
    where
        V: IntoIterator<Item = Option<u8>>,
        S: IntoIterator<Item = Option<u64>>,
    {
        let mut value = value.into_iter().chain(std::iter::repeat(None));
        let mut source = source.into_iter().chain(std::iter::repeat(None));
        self.add_value_internal(address, &mut value, &mut source);
    }
}



impl LastModified {
    #[inline]
    fn inner(&self) -> &HashMap<LastModifiedKey, LastModifiedPage> {
        &self.0
    }

    #[inline]
    fn inner_mut(&mut self) -> &mut HashMap<LastModifiedKey, LastModifiedPage> {
        &mut self.0
    }

    // This is a hack to avoid hitting the recursion limit in the trait solver b/c Rust is unable
    // to determine that we can only recursively call ourself with a depth of one (if our address
    // range wraps), we split the range in two and call ourselves twice.
    #[inline]
    fn add_value_internal<V, S>(&mut self, address: &AddressRange, value: &mut V, source: &mut S)
    where
        V: Iterator<Item = Option<u8>>,
        S: Iterator<Item = Option<u64>>,
    {
        let Some(first) = address.first().map(|a| a.offset()) else {
            return;
        };

        let Some(last) = address.last().map(|a| a.offset()) else {
            return;
        };

        let space = address.space();
        let space_id = space.id() as u64 & 0xfff;

        if last < first {
            self.add_value_internal(&space.index(first..=space.mask()), value, source);
            self.add_value_internal(&space.index(0..=last), value, source);
            return;
        }

        let mut iter = value.zip(source);

        let inner = self.inner_mut();

        let first_page = first & PAGE_MASK;
        let last_page = last & PAGE_MASK;

        if first_page == last_page {
            let start = (first - first_page) as usize;
            let size = address.size() as usize;
            let page = inner
                .entry(LastModifiedKey(first_page | space_id))
                .or_default();
            let data = unsafe { page.get_unchecked_mut(start..start + size) };
            data.iter_mut().zip(iter).for_each(|(dst, (val, src))| {
                *dst = LastModifiedEntry(
                    src.map(|s| HAS_SOURCE | s).unwrap_or(0) |
                    val.map(|v| HAS_VALUE | (v as u64)).unwrap_or(0)
                );
            });
            return;
        }

        {
            let start = (first - first_page) as usize;
            let page = inner
                .entry(LastModifiedKey(first_page | space_id))
                .or_default();
            let data = unsafe { page.get_unchecked_mut(start..) };
            data.iter_mut().zip(&mut iter).for_each(|(dst, (val, src))| {
                *dst = LastModifiedEntry(
                    src.map(|s| HAS_SOURCE | s).unwrap_or(0) |
                    val.map(|v| HAS_VALUE | (v as u64)).unwrap_or(0)
                );
            });
        }

        for base in (first_page + PAGE_SIZE as u64..last_page).step_by(PAGE_SIZE) {
            let page = inner
                .entry(LastModifiedKey(base | space_id))
                .or_default();
            page.iter_mut().zip(&mut iter).for_each(|(dst, (val, src))| {
                *dst = LastModifiedEntry(
                    src.map(|s| HAS_SOURCE | s).unwrap_or(0) |
                    val.map(|v| HAS_VALUE | (v as u64)).unwrap_or(0)
                );
            });
        }

        {
            let end = (last - last_page) as usize;
            let page = inner
                .entry(LastModifiedKey(last_page | space_id))
                .or_default();
            let data = unsafe { page.get_unchecked_mut(..end) };
            data.iter_mut().zip(&mut iter).for_each(|(dst, (val, src))| {
                *dst = LastModifiedEntry(
                    src.map(|s| HAS_SOURCE | s).unwrap_or(0) |
                    val.map(|v| HAS_VALUE | (v as u64)).unwrap_or(0)
                );
            });
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct LastModifiedEntry(u64);

impl LastModifiedEntry {
    #[inline]
    pub fn value(&self) -> Option<u8> {
        (self.0 | HAS_VALUE != 0).then_some(self.0 as u8)
    }

    #[inline]
    pub fn source(&self) -> Option<u64> {
        (self.0 | HAS_SOURCE != 0).then_some((self.0 & SOURCE_MASK) >> 8)
    }

    #[inline]
    pub fn into_parts(self) -> (Option<u8>, Option<u64>) {
        (self.value(), self.source())
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct LastModifiedKey(u64);

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct LastModifiedPage(Box<[LastModifiedEntry; PAGE_SIZE]>);

impl Default for LastModifiedPage {
    fn default() -> Self {
        Self(Box::new([Default::default(); PAGE_SIZE]))
    }
}

impl std::ops::Deref for LastModifiedPage {
    type Target = [LastModifiedEntry; PAGE_SIZE];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl std::ops::DerefMut for LastModifiedPage {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}


