pub mod merge_set;
pub mod segment_tree;
pub mod spacetime_index;
pub mod string_index;

use core::fmt;
use std::{any::Any, fmt::Debug, io::Result};

use dataflow::prelude::SpaceKind;
use merge_set::{MergeSet, OverlapComparable, OverlapComparison};

/// Trait representing the ability to serialize and deserialize an object.
pub trait Serializable {
    /// Serializes [self] to `bytes`, extending `bytes` as necessary
    fn serialize_to(&self, bytes: &mut Vec<u8>);
    /// Deserializes [self] from `bytes[start..]`, updating `start` to point to the end of
    /// [self] in the byte stream.
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized;
}

impl Serializable for u64 {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let size = std::mem::size_of::<Self>();
        *start += size;
        return Self::from_le_bytes(bytes[*start - size..*start].try_into().unwrap());
    }
}
impl Serializable for u32 {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let size = std::mem::size_of::<Self>();
        *start += size;
        return Self::from_le_bytes(bytes[*start - size..*start].try_into().unwrap());
    }
}
impl Serializable for SpaceKind {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        bytes.push(match self {
            SpaceKind::Constant => 0,
            SpaceKind::Memory => 1,
            SpaceKind::Register => 2,
            SpaceKind::Unique => 3,
            SpaceKind::Other => 4,
        });
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let kind = match bytes[*start] {
            0 => SpaceKind::Constant,
            1 => SpaceKind::Memory,
            2 => SpaceKind::Register,
            3 => SpaceKind::Unique,
            4 => SpaceKind::Other,
            _ => panic!("Unsupported space kind"),
        };
        *start += 1;
        kind
    }
}
impl Serializable for u8 {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.clone());
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        *start += 1;
        return bytes[*start - 1];
    }
}
impl Serializable for usize {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.to_le_bytes());
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let size = std::mem::size_of::<Self>();
        *start += size;
        return Self::from_le_bytes(bytes[*start - size..*start].try_into().unwrap());
    }
}
impl Serializable for SpacetimeBlock {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.space.serialize_to(bytes);
        self.address.serialize_to(bytes);
        self.len.serialize_to(bytes);
        self.created_at.serialize_to(bytes);
        self.destroyed_at.serialize_to(bytes);
        bytes.extend_from_slice(&self.data);
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let space = SpaceKind::deserialize(bytes, start);
        let address = u64::deserialize(bytes, start);
        let len = usize::deserialize(bytes, start);
        let this = Self {
            space,
            address,
            len,
            created_at: u64::deserialize(bytes, start),
            destroyed_at: u64::deserialize(bytes, start),
            data: bytes[*start..*start + len].to_vec(),
        };
        *start += len;
        this
    }
}
impl<T> Serializable for Vec<T>
where
    T: Serializable,
{
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.len().serialize_to(bytes);
        for elem in self {
            elem.serialize_to(bytes);
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let len = usize::deserialize(bytes, start);
        let mut this = Vec::new();
        for _ in 0..len {
            this.push(T::deserialize(bytes, start));
        }
        this
    }
}
impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        if self.is_none() {
            0u8.serialize_to(bytes);
        } else {
            1u8.serialize_to(bytes);

            if let Some(elem) = self {
                elem.serialize_to(bytes);
            }
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let is_present = u8::deserialize(bytes, start) == 1;
        if is_present {
            Some(T::deserialize(bytes, start))
        } else {
            None
        }
    }
}
impl<T> Serializable for Box<T>
where
    T: Serializable,
{
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        Box::new(T::deserialize(bytes, start))
    }
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        (**self).serialize_to(bytes);
    }
}

///
/// Describes a value that exists in spacetime
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpacetimeBlock {
    /// The kind of space in which the spacetime block was found
    pub space: SpaceKind,

    /// Where the value begins in space
    pub address: u64,
    /// How large the value is in space
    pub len: usize,

    /// When the value begins in time
    pub created_at: u64,
    /// When the value ends in time
    pub destroyed_at: u64,

    /// The bytes associated with the value
    pub data: Vec<u8>,
}

/// A trait describing the ability to record an index over [SpacetimeBlock]s.
pub trait Index {
    /// Records that `block` existed at some point in spacetime
    fn record(&mut self, block: SpacetimeBlock);
    /// Indicates that no more records will be added and any finalization actions can begin.
    fn finalize(&mut self);
    /// Saves the index as defined by the implementing type.
    fn save(&mut self) -> Result<()>;
}

/// Describes either a read or write. Note that there is no distinction between the two; an
/// operation is considered a "write" if it reveals data previously unknown or contains data
/// different from what used to be at an address.
///
/// Therefore, a read would be considered a write if it shows that memory changed or shows
/// previously unknown memory, and a write would not be considered a write if it contained
/// the same data that already existed in memory.
pub struct Operation {
    /// The kind of the space in which the operation occured
    pub space: SpaceKind,
    /// The data associated with the operation
    pub data: Vec<u8>,
    /// The location in space where the operation occured
    pub address: u64,
    /// The location in time where the operation occured
    pub written_time: u64,
}
impl Operation {
    /// Splits [self] into two [Operation]s, updating [self] to only describe the first
    /// `offset` bytes and creating another [Operation] that describes all bytes after
    /// `offset`.
    fn partition(&mut self, offset: usize) -> Self {
        Operation {
            space: self.space,
            data: self.data.drain(offset..).collect(),
            address: self.address + offset as u64,
            written_time: self.written_time,
        }
    }
    /// Provided `self` partially overlaps `other` in memory, updates self to only describe the
    /// portion of memory not overlapping `other`, recording the discarded portion in each [Index]
    /// within `indices`.
    fn retract_from(&mut self, other: &Self, indices: &mut Vec<Box<dyn Index>>) {
        let my_end = self.address as usize + self.data.len();
        let other_end = other.address as usize + other.data.len();

        let overlap_len = my_end.min(other_end) - self.address.max(other.address) as usize;

        let to_retire = if self.address > other.address {
            let mut other = self.partition(overlap_len);
            std::mem::swap(self, &mut other);
            other
        } else {
            self.partition(self.data.len() - overlap_len)
        };

        to_retire.retire(other.written_time, indices);
    }
    /// Constructs a [SpacetimeBlock] indicating that the value described by [self] was destroyed
    /// at `destroyed_at` and records it in each [Index] within `indices`.
    fn retire(&self, destroyed_at: u64, indices: &mut Vec<Box<dyn Index>>) {
        for index in indices {
            index.record(SpacetimeBlock {
                space: self.space,
                address: self.address,
                len: self.data.len(),
                created_at: self.written_time,
                destroyed_at: destroyed_at,
                data: self.data.to_vec(),
            });
        }
    }
    /// Determines whether `other` is completely contained within the region described by [self]
    /// (in space only).
    fn covers(&self, other: &Self) -> bool {
        return self.address <= other.address
            && self.address + self.data.len() as u64 >= other.address + other.data.len() as u64;
    }
    /// Determines whether `self` is a read or not.
    fn matches(&self, other: &Self) -> bool {
        let my_end = self.address as usize + self.data.len();
        let other_end = other.address as usize + other.data.len();

        let overlap_len = my_end.min(other_end) - self.address.max(other.address) as usize;
        if overlap_len == 0 {
            return false;
        }

        let my_base = (other.address.max(self.address) - self.address) as usize;
        let other_base = (self.address.max(other.address) - other.address) as usize;

        for byte_idx in 0..overlap_len {
            if self.data[my_base + byte_idx] != other.data[other_base + byte_idx] {
                return false;
            }
        }

        true
    }
}
impl Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}:{:x}", self.address, self.data.len())
    }
}
impl OverlapComparable for Operation {
    fn cmp(&self, other: &Self) -> OverlapComparison {
        let (my_addr, my_size) = (self.address, self.data.len() as u64);
        let (other_addr, other_size) = (other.address, other.data.len() as u64);

        if my_addr < other_addr + other_size && other_addr < my_addr + my_size {
            OverlapComparison::Overlap
        } else if my_addr < other_addr {
            OverlapComparison::Less
        } else {
            OverlapComparison::Greater
        }
    }
    fn combine(self, mut overlapping: Vec<Self>, combine_ctx: &mut dyn Any) -> Vec<Self> {
        /*
         * Not all writes are recorded, so if a read contains information inconsistent with what
         * we expected to be in memory, we pretend as though it's a write that also counts as a
         * read. On the other hand, not all recorded writes change the contents of memory, and in
         * such cases, we'll pretend it didn't happen.
         */
        let mut is_update = false;

        /* `overlapping` is sorted ascending. `tracked_offset` refers to the highest offset
         * into `self` overlapping an operation encountered so far. */
        let mut tracked_offset = 0;

        for elem in overlapping.iter() {
            if !self.matches(&elem) {
                is_update = true;
                break;
            } else if tracked_offset < elem.address.max(self.address) - self.address {
                /* We skipped at least one byte */
                is_update = true;
                break;
            } else {
                tracked_offset = elem.address + elem.data.len() as u64 - self.address;
            }
        }

        if is_update {
            let indices = combine_ctx.downcast_mut().unwrap();

            overlapping.retain_mut(|op| {
                if self.covers(op) {
                    op.retire(self.written_time, indices);
                    false
                } else {
                    op.retract_from(&self, indices);
                    true
                }
            });

            overlapping.push(self);
        }

        overlapping
    }
}

/// An object that, given the [Operation]s that occured during a program's runtime,
/// constructs [SpacetimeBlock]s from them as appropriate and feeds them into every [Index]
/// registered with it.
pub struct Indexer {
    /// The number of tick in program execution
    end_tick: u64,
    /// A list of the [Index]es to build.
    indices: Vec<Box<dyn Index>>,
    /// Describes memory at a given point in time.
    active_mem_tree: MergeSet<Operation>,
}
impl Indexer {
    /// Constructs a new, empty [Indexer].
    pub fn new(end_tick: u64) -> Self {
        Self {
            end_tick: end_tick,
            indices: Vec::new(),
            active_mem_tree: MergeSet::new(),
        }
    }

    /// Adds `index` to [self]'s list of indices.
    pub fn add_index<I: Index + 'static>(&mut self, index: I) {
        self.indices.push(Box::new(index));
    }

    /// Records that `op` occured. This must be called in time order; if `a` occurs before `b`,
    /// then `record_op(a)` must be called before `record_op(b)`.
    pub fn record_op(&mut self, op: Operation) {
        self.active_mem_tree.insert(op, &mut self.indices);
    }

    /// Indicates that no more [Operation]s will be recorded.
    pub fn finalize(&mut self) {
        // Empty all `Operation` from `self.active_mem_tree` into the indices.
        for entry in self.active_mem_tree.extract_members() {
            let block = SpacetimeBlock {
                space: entry.space,
                address: entry.address,
                len: entry.data.len(),
                created_at: entry.written_time,
                destroyed_at: self.end_tick,
                data: entry.data,
            };

            for index in &mut self.indices {
                index.record(block.clone());
            }
        }

        for index in &mut self.indices {
            index.finalize();
        }
    }

    /// Instructs each index to save itself.
    pub fn save_indices(&mut self) -> Result<()> {
        for index in &mut self.indices {
            index.save()?
        }

        Ok(())
    }
}
