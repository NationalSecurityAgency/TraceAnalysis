use std::io;
use std::ops::Add;
use std::{fmt::Debug, io::Write};

use crate::space::SpaceKind;

use super::{Index, Serializable, SpacetimeBlock};

pub const DENSE_SIZE: usize = std::mem::size_of::<DenseByteTrieRNode>();
pub const SPARSE_SIZE: usize = std::mem::size_of::<SparseByteTrieRNode>();
pub const VERY_SPARSE_SIZE: usize = std::mem::size_of::<VerySparseByteTrieRNode>();

// Constants for use in serializing and deserializing trie nodes
const NODE_TYPE_NONE: u8 = 0;
const NODE_TYPE_DENSE: u8 = 1;
const NODE_TYPE_SPARSE: u8 = 2;
const NODE_TYPE_VERY_SPARSE: u8 = 3;

// This is subject to tuning.
/// The maximum number of elements that a very sparse trie node may hold before being promoted to
/// a sparse trie node. Very sparse space complexity, query time, and retrieval time scale linearly
/// with this.
const SPARSE_THRESHOLD: usize = 8;

// This is subject to tuning.
/// The maximum number of elements that a sparse trie node may hold before being promoted to a
/// dense trie node. Sparse trie node space complexity scales linearly with this.
const DENSE_THRESHOLD: usize = 96;

// This is subject to tuning.
/// The number of characters in the longest string a byte trie may hold before being split up.
/// Trie depth scales linearly with this. The lower this is, the higher the density of the trie.
const MAX_ENTRY_SIZE: usize = 16;

///
/// Represents a particular location within spacetime.
///
/// That this does not have a length is deliberate and allows for more efficient (log vs linear)
/// computation during lookups.
///
#[derive(Copy, Clone, Eq, PartialEq, Ord)]
pub struct SpacetimeLocation {
    /// The address where the object this is describing began in memory
    pub address: u64,
    /// The tick at which the specified object first appeared at this address.
    /// Note that parts of this object may have been present before this tick, but
    /// at least one byte was not.
    pub created_at: u64,
    /// The tick at which the specified object was destroyed
    /// Note that parts of this object may have been present after this tick, but
    /// at least one byte was not.
    pub destroyed_at: u64,
}
impl SpacetimeLocation {
    /// Constructs a new `SpacetimeLocation` describing a `SpacetimeBlock` if the block describes
    /// memory space.
    pub(crate) fn new_from_block(block: &SpacetimeBlock) -> Option<Self> {
        if block.space == SpaceKind::Memory {
            Some(Self {
                address: block.address,
                created_at: block.created_at,
                destroyed_at: block.destroyed_at,
            })
        } else {
            None
        }
    }
    pub(crate) fn overlap(&self, other: &SpacetimeLocation) -> Option<Self> {
        if self.created_at < other.destroyed_at && self.destroyed_at > other.created_at {
            Some(Self {
                address: self.address.min(other.address),
                created_at: self.created_at.max(other.created_at),
                destroyed_at: self.destroyed_at.min(other.destroyed_at),
            })
        } else {
            None
        }
    }
}
impl Serializable for SpacetimeLocation {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.address.serialize_to(bytes);
        self.created_at.serialize_to(bytes);
        self.destroyed_at.serialize_to(bytes);
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        Self {
            address: u64::deserialize(bytes, start),
            created_at: u64::deserialize(bytes, start),
            destroyed_at: u64::deserialize(bytes, start),
        }
    }
}
impl PartialOrd for SpacetimeLocation {
    /// Compares two `SpacetimeLocation`s, ordering first by address, then by creation time.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.address.partial_cmp(&other.address) {
            // No two `SpacetimeLocation`s should have the same address and lifetime, so no
            // need to check `destroyed_at` if `created_at` was equal.
            Some(std::cmp::Ordering::Equal) => self.created_at.partial_cmp(&other.created_at),
            cmp => cmp,
        }
    }
}
impl Debug for SpacetimeLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SpacetimeLocation(0x{:x} from {} to {})",
            self.address, self.created_at, self.destroyed_at
        )
    }
}
impl Add<usize> for &SpacetimeLocation {
    type Output = SpacetimeLocation;
    fn add(self, other: usize) -> SpacetimeLocation {
        SpacetimeLocation {
            address: self.address + other as u64,
            created_at: self.created_at,
            destroyed_at: self.destroyed_at,
        }
    }
}

///
/// A dense node in a byte trie that allows for insertions
///
/// Compared to a very sparse or sparse byte trie node, this node has a higher memory
/// and storage footprint with only a relatively minor performance increase. The main
/// benefit to a dense node is its capacity; it holds a reference to a child for each
/// byte value. Close to the root of the trie, there will likely be a number of dense
/// byte tries, but should be comparatively lower than very sparse or sparse byte tries.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
///
/// This node does not support query operations; call See
/// [DenseByteTrieWNode::finalize] to retrieve a node that does.
///
struct DenseByteTrieWNode {
    /// The branches of this node; `trie[i]` represents the child for byte `i`.
    trie: [Option<Box<ByteTrieWNode>>; 256],
}

///
/// A sparse node in a byte trie that allows for insertions.
///
/// [SparseByteTrieWNode] is slightly faster than a [VerySparseByteTrieWNode] at a significant
/// cost in memory and storage. It is slightly slower than a [DenseByteTrieWNode], but
/// significantly less expensive in memory and storage. The main benefit to a [SparseByteTrieWNode]
/// over a [VerySparseByteTrieWNode] is its increased storage capacity; while the very sparse node
/// may store only a few sub-trees, a [SparseByteTrieWNode] can hold significantly more.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
///
/// This node does not support query operations; call See
/// [SparseByteTrieWNode::finalize] to retrieve a node that does.
///
struct SparseByteTrieWNode {
    /// The number of [ByteTrieWNode]s used in [Self::tries].
    head: usize,
    /// A mapping of bytes to the index within [Self::tries] at which the child associated
    /// with that byte can be found; `tries[trie_indices[i]]` represents the child associated
    /// with `i`.
    trie_indices: [u8; 256],
    /// The subtrees associated with [self].
    tries: [Option<Box<ByteTrieWNode>>; DENSE_THRESHOLD],
}

///
/// A very sparse node in a byte trie that allows for insertions.
///
/// [VerySparseByteTrieWNode] is slightly slower than a [VerySparseByteTrieWNode] or a
/// [DenseByteTrieWNode], but it is vastly more space efficient. When a node in a byte trie is
/// expected to only have a few children, a [VerySparseByteTrieWNode] should be used.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
///
/// This node does not support query operations; call See
/// [VerySparseByteTrieWNode::finalize] to retrieve a node that does.
///
struct VerySparseByteTrieWNode {
    /// The number of elements in [Self::trie] that are currently used
    head: usize,
    /// A list of key-value pairs of bytes and their associated children.
    trie: [(u8, Option<Box<ByteTrieWNode>>); SPARSE_THRESHOLD],
}

///
/// A dense node in a byte trie that allows for queries.
///
/// See [DenseByteTrieWNode] for members and a detailed description.
///
/// This node does not support update operations.
///
struct DenseByteTrieRNode {
    trie: [Option<Box<ByteTrieRNode>>; 256],
}

///
/// A sparse node in a byte trie that allows for queries.
///
/// See [SparseByteTrieWNode] for members and a detailed description.
///
/// This node does not support update operations.
///
struct SparseByteTrieRNode {
    head: usize,
    trie_indices: [u8; 256],
    tries: [Option<Box<ByteTrieRNode>>; DENSE_THRESHOLD],
}

///
/// A very sparse node in a byte trie that allows for queries.
///
/// See [VerySparseByteTrieWNode] for members and a detailed description.
///
/// This node does not support update operations.
///
struct VerySparseByteTrieRNode {
    head: usize,
    trie: [(u8, Option<Box<ByteTrieRNode>>); SPARSE_THRESHOLD],
}

/// Container type for either a very sparse, a sparse, or a dense byte trie node that supports
/// update operations.
enum WNodeType {
    VerySparse(VerySparseByteTrieWNode),
    Sparse(SparseByteTrieWNode),
    Dense(DenseByteTrieWNode),
}

/// Container type for either a very sparse, a sparse, or a dense byte trie node that supports
/// query operations.
enum RNodeType {
    VerySparse(VerySparseByteTrieRNode),
    Sparse(SparseByteTrieRNode),
    Dense(DenseByteTrieRNode),
}

///
/// Represents a node in a byte trie that supports update operations.
///
/// The distinction between [ByteTrieWNode] and [ByteTrieRNode] is that in [ByteTrieWNode],
/// [Self::prefixes], [Self::chunks], and [Self::suffixes] are not sorted in any particular
/// order or fashion, whereas in [ByteTrieRNode], they are. These are treated as distinct
/// types to ensure safety.
///
/// The traversal to reach this node describes a string; further documentation for this struct
/// will refer to this string as "the string represented by this node".
///
/// There are three types of strings stored in this byte trie:
///
///  - Prefixes
///
///        A prefix is a string that may make up the start of a query term, but only the start.
///        When processing a query term, a prefix may only be used to match a substring of the
///        query term if the substring starts at the beginning of the query term.
///
///        When a string is added to the byte trie, all substrings ending at the string's end are
///        added as prefixes.
///
///  - Chunks
///
///        A chunk is a string that may make up any part of a query term. When processing a query
///        term, any strict substring of the query term may be matched by a chunk.
///
///        When a string is added to the byte trie, the whole string is added as a chunk.
///
///  - Suffixes
///
///        A suffix is a string that may make up the end of a query term, but only the end. When
///        processing a query term, a suffix may only be used to match a substring of the query
///        term if the substring ends at the end of the query term.
///
///        When a string is added to the byte trie, all substrings beginning at the string's start
///        are added as suffixes.
///
/// Note that in the above descriptions, before a string longer than `MAX_ENTRY_SIZE` is added, it
/// is first split into smaller strings of at most `MAX_ENTRY_SIZE` bytes.
///
/// The distinction between these three is, strictly speaking, unnecessary. However, for a string
/// of length `N`, it is expected that `N` prefixes and `N` suffixes but only 1 chunk will be added
/// to the trie. It follows, then, that if the average length of a string in the trie is `K`, the
/// average node in the trie will have `K` times as many prefixes and suffixes as chunks. Since
/// the process of evaluating a query involves identifying the possible sets of prefixes, chunks,
/// and suffixes that compose the term, being able to *only* query chunks when looking for a chunk
/// offers a significant speedup.
///
/// Consider the example of a query term that contains a byte in the middle. Every address written
/// to memory throughout the program's execution will have a null byte added to the trie as a
/// prefix. By distinguishing between chunks and prefixes, we can exclude such writes from
/// consideration when trying to evaluate how the query term could have been composed.
///
/// See [ReadStringIndex::search]'s inline comment for more details on query evaluation.
///
struct ByteTrieWNode {
    /// Describes locations where the string represented by [self] can be found as a prefix
    prefixes: Vec<SpacetimeLocation>,
    /// Describes locations where the string represented by [self] can be found as a chunk
    chunks: Vec<SpacetimeLocation>,
    /// Describes locations where the string represented by [self] can be found as a suffix
    suffixes: Vec<SpacetimeLocation>,
    /// Describes [self]'s children
    node: Option<Box<WNodeType>>,
}

///
/// Represents a node in a byte trie that supports query operations. See [ByteTrieWNode] for
/// more information and members.
///
struct ByteTrieRNode {
    prefixes: Vec<SpacetimeLocation>,
    chunks: Vec<SpacetimeLocation>,
    suffixes: Vec<SpacetimeLocation>,
    node: Option<Box<RNodeType>>,
}

impl Serializable for DenseByteTrieRNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        let table_offset = bytes.len();
        bytes.extend_from_slice(&[0x00; 0x100 * std::mem::size_of::<usize>()]);
        for i in 0..0x100 {
            let subtable_offset = bytes.len();
            self.trie[i].serialize_to(bytes);
            let offset_slice = &mut bytes[table_offset + i * std::mem::size_of::<usize>()
                ..table_offset + (i + 1) * std::mem::size_of::<usize>()];
            offset_slice.copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let mut this = DenseByteTrieRNode {
            trie: [const { None }; 0x100],
        };

        for i in 0..0x100 {
            let mut subtrie_offset = usize::deserialize(bytes, start);
            this.trie[i] = Option::deserialize(bytes, &mut subtrie_offset);
        }

        this
    }
}
impl Serializable for SparseByteTrieRNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.head.serialize_to(bytes);

        let table_offset = bytes.len();
        bytes.resize(
            bytes.len() + self.head * (std::mem::size_of::<usize>() + 1),
            0x00,
        );
        for i in 0..256 {
            if self.trie_indices[i] == u8::MAX {
                continue;
            }

            let idx = self.trie_indices[i] as usize;

            let subtable_offset = bytes.len();
            self.tries[idx].serialize_to(bytes);
            let entry_slice = &mut bytes[table_offset + idx * (std::mem::size_of::<usize>() + 1)
                ..table_offset + (idx + 1) * (std::mem::size_of::<usize>() + 1)];
            entry_slice[0] = i as u8;
            entry_slice[1..].copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let mut this = Self::new();
        this.head = usize::deserialize(bytes, start);

        for i in 0..this.head {
            let subtrie_char = u8::deserialize(bytes, start);
            this.trie_indices[subtrie_char as usize] = i as u8;

            let mut subtrie_offset = usize::deserialize(bytes, start);

            this.tries[i] = Option::deserialize(bytes, &mut subtrie_offset);
        }

        this
    }
}
impl Serializable for VerySparseByteTrieRNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.head.serialize_to(bytes);

        let table_offset = bytes.len();
        bytes.resize(
            bytes.len() + self.head * (std::mem::size_of::<usize>() + 1),
            0x00,
        );
        for i in 0..self.head {
            let (char, subtrie) = &self.trie[i];
            let subtable_offset = bytes.len();
            subtrie.serialize_to(bytes);
            let entry_slice = &mut bytes[table_offset + i * (std::mem::size_of::<usize>() + 1)
                ..table_offset + (i + 1) * (std::mem::size_of::<usize>() + 1)];
            entry_slice[0] = *char;
            entry_slice[1..].copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let mut this = Self::new();
        this.head = usize::deserialize(bytes, start);

        for i in 0..this.head {
            let subtrie_char = bytes[*start];
            *start += 1;

            let mut subtrie_offset = usize::from_le_bytes(
                bytes[*start..*start + std::mem::size_of::<usize>()]
                    .try_into()
                    .unwrap(),
            );
            *start += std::mem::size_of::<usize>();

            this.trie[i] = (
                subtrie_char,
                Option::deserialize(bytes, &mut subtrie_offset),
            );
        }

        this
    }
}
impl Serializable for ByteTrieRNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        let type_id = if let Some(node) = &self.node {
            match &**node {
                RNodeType::Dense(_) => NODE_TYPE_DENSE,
                RNodeType::Sparse(_) => NODE_TYPE_SPARSE,
                RNodeType::VerySparse(_) => NODE_TYPE_VERY_SPARSE,
            }
        } else {
            NODE_TYPE_NONE
        };

        type_id.serialize_to(bytes);
        self.prefixes.serialize_to(bytes);
        self.chunks.serialize_to(bytes);
        self.suffixes.serialize_to(bytes);

        if let Some(node) = &self.node {
            match &**node {
                RNodeType::Dense(node) => node.serialize_to(bytes),
                RNodeType::Sparse(node) => node.serialize_to(bytes),
                RNodeType::VerySparse(node) => node.serialize_to(bytes),
            }
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let mut this = ByteTrieRNode {
            prefixes: Vec::new(),
            chunks: Vec::new(),
            suffixes: Vec::new(),
            node: None::<Box<RNodeType>>,
        };

        let kind = u8::deserialize(bytes, start);
        this.prefixes = Vec::deserialize(bytes, start);
        this.chunks = Vec::deserialize(bytes, start);
        this.suffixes = Vec::deserialize(bytes, start);

        let node_type = match kind {
            NODE_TYPE_DENSE => Some(Box::new(
                DenseByteTrieRNode::deserialize(bytes, start).into(),
            )),
            NODE_TYPE_SPARSE => Some(Box::new(
                SparseByteTrieRNode::deserialize(bytes, start).into(),
            )),
            NODE_TYPE_VERY_SPARSE => Some(Box::new(
                VerySparseByteTrieRNode::deserialize(bytes, start).into(),
            )),
            _ => None,
        };

        this.node = node_type;

        this
    }
}

impl DenseByteTrieWNode {
    /// Constructs a new, empty [DenseByteTrieWNode]
    fn new() -> Self {
        Self {
            trie: [const { None }; 256],
        }
    }
    ///
    /// Passes the request to record the given `string` and `data` to the correct child
    /// sub-tree.
    ///
    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) {
        let node = if let Some(node) = &mut self.trie[string[depth] as usize] {
            node
        } else {
            self.trie[string[depth] as usize] = Some(Box::new(ByteTrieWNode::new()));
            self.trie[string[depth] as usize].as_mut().unwrap()
        };

        node.insert_str(depth + 1, string, data, is_prefix);
    }
    /// Irrevocably converts [self] to a [DenseByteTrieRNode].
    fn finalize(self) -> DenseByteTrieRNode {
        DenseByteTrieRNode {
            trie: self.trie.map(|o| o.map(|t| Box::new(t.finalize()))),
        }
    }
}
impl DenseByteTrieRNode {
    /// Calls [ByteTrieRNode::collect_all_substrings] on all child sub-trees.
    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        for elem in self.trie.iter() {
            if let Some(node) = elem {
                node.collect_all_substrings(values);
            }
        }
    }
    /// Retrieves the sub-tree associated with byte `char`
    fn get_child_node(&self, char: u8) -> Option<&ByteTrieRNode> {
        self.trie[char as usize].as_ref().map(|b| &**b)
    }
}
impl SparseByteTrieWNode {
    /// Creates a new, empty [SparseByteTrieWNode].
    fn new() -> Self {
        Self {
            head: 0,
            trie_indices: [u8::MAX; 256],
            tries: [const { None }; DENSE_THRESHOLD],
        }
    }

    ///
    /// Passes the request to record the given `string` and `data` to the correct child
    /// sub-tree.
    ///
    /// If doing so would require that a new sub-tree be created, this instead returns
    /// `Err(())`; it is then the caller's responsibility to [Self::upgrade] this node
    /// and call [DenseByteTrieWNode::insert_str] on the new, upgraded node.
    ///
    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), ()> {
        let char = string[depth] as usize;

        // Check if full and insertion requires a new sub-tree.
        let requires_new_entry = self.trie_indices[char] == u8::MAX;
        if self.head == DENSE_THRESHOLD && requires_new_entry {
            return Err(());
        }

        // If insertion requires a new sub-tree, claim the first unused one.
        if requires_new_entry {
            self.trie_indices[char] = self.head as u8;
            self.head += 1;
        }

        let node = if let Some(node) = &mut self.tries[self.trie_indices[char] as usize] {
            node
        } else {
            self.tries[self.trie_indices[char] as usize] = Some(Box::new(ByteTrieWNode::new()));
            self.tries[self.trie_indices[char] as usize]
                .as_mut()
                .unwrap()
        };

        node.insert_str(depth + 1, string, data, is_prefix);

        Ok(())
    }
    /// Converets [self] into a [DenseByteTrieWNode].
    fn upgrade(&mut self) -> DenseByteTrieWNode {
        let mut this = DenseByteTrieWNode::new();

        for i in 0..256 {
            if self.trie_indices[i] < u8::MAX {
                std::mem::swap(
                    &mut this.trie[i],
                    &mut self.tries[self.trie_indices[i] as usize],
                );
            }
        }

        this
    }
    /// Irrevocably converts [self] to a [SparseByteTrieRNode].
    fn finalize(self) -> SparseByteTrieRNode {
        SparseByteTrieRNode {
            head: self.head,
            trie_indices: self.trie_indices,
            tries: self.tries.map(|o| o.map(|t| Box::new(t.finalize()))),
        }
    }
}
impl SparseByteTrieRNode {
    /// Creates a new, empty [SparseByteTrieRNode]
    fn new() -> Self {
        Self {
            head: 0,
            trie_indices: [u8::MAX; 256],
            tries: [const { None }; DENSE_THRESHOLD],
        }
    }
    /// Calls [ByteTrieRNode::collect_all_substrings] on all child sub-trees.
    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        for i in 0..self.head {
            if let Some(node) = &self.tries[i] {
                node.collect_all_substrings(values);
            }
        }
    }
    /// Retrieves the sub-tree associated with byte `char`
    fn get_child_node(&self, char: u8) -> Option<&ByteTrieRNode> {
        if self.trie_indices[char as usize] != u8::MAX {
            self.tries[self.trie_indices[char as usize] as usize]
                .as_ref()
                .map(|b| &**b)
        } else {
            None
        }
    }
}
impl VerySparseByteTrieWNode {
    /// Constructs a new, empty [VerySparseByteTrieWNode]
    fn new() -> Self {
        Self {
            head: 0,
            trie: [const { (0, None) }; SPARSE_THRESHOLD],
        }
    }
    ///
    /// Passes the request to record the given `string` and `data` to the correct child
    /// sub-tree.
    ///
    /// If doing so would require that a new sub-tree be created, this instead returns
    /// `Err(())`; it is then the caller's responsibility to [Self::upgrade] this node
    /// and call [SparseByteTrieWNode::insert_str] on the new, upgraded node.
    ///
    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), ()> {
        let char = string[depth];

        // If a sub-tree for `char` already exists, pass the update request on to it.
        for i in 0..self.head {
            let (trie_char, Some(trie)) = &mut self.trie[i] else {
                break;
            };
            if *trie_char == char {
                trie.insert_str(depth + 1, string, data, is_prefix);
                return Ok(());
            }
        }

        // If the required subtree doesn't exist and we're out of space, error out.
        if self.head == SPARSE_THRESHOLD {
            Err(())
        } else {
            // Build a new sub-tree for the string, insert this string into it, then
            // add it to `self`.
            let mut trie = ByteTrieWNode::new();
            trie.insert_str(depth + 1, string, data, is_prefix);
            self.trie[self.head] = (char, Some(Box::new(trie)));
            self.head += 1;
            Ok(())
        }
    }
    /// Converts [self] into a [SparseByteTrieWNode].
    fn upgrade(&mut self) -> SparseByteTrieWNode {
        let mut this = SparseByteTrieWNode::new();

        for (trie_char, trie) in self.trie[..self.head].iter_mut() {
            this.trie_indices[*trie_char as usize] = this.head as u8;
            std::mem::swap(&mut this.tries[this.head], trie);
            this.head += 1;
        }

        this
    }
    /// Irrevocably converts [self] to a [VerySparseByteTrieRNode].
    fn finalize(self) -> VerySparseByteTrieRNode {
        VerySparseByteTrieRNode {
            head: self.head,
            trie: self
                .trie
                .map(|(c, o)| (c, o.map(|t| Box::new(t.finalize())))),
        }
    }
}
impl VerySparseByteTrieRNode {
    /// Constructs a new [VerySparseByteTrieRNode].
    fn new() -> Self {
        Self {
            head: 0,
            trie: [const { (0, None) }; SPARSE_THRESHOLD],
        }
    }
    /// Calls [ByteTrieRNode::collect_all_substrings] on all child sub-trees.
    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        for i in 0..self.head {
            if let Some(node) = self.trie[i].1.as_ref() {
                node.collect_all_substrings(values);
            }
        }
    }
    /// Retrieves the sub-tree associated with byte `char`
    fn get_child_node(&self, char: u8) -> Option<&ByteTrieRNode> {
        for i in 0..self.head {
            let (trie_char, Some(trie)) = &self.trie[i] else {
                break;
            };
            if *trie_char == char {
                return Some(&*trie);
            }
        }

        None
    }
}

impl Into<WNodeType> for DenseByteTrieWNode {
    fn into(self) -> WNodeType {
        WNodeType::Dense(self)
    }
}
impl Into<WNodeType> for SparseByteTrieWNode {
    fn into(self) -> WNodeType {
        WNodeType::Sparse(self)
    }
}
impl Into<WNodeType> for VerySparseByteTrieWNode {
    fn into(self) -> WNodeType {
        WNodeType::VerySparse(self)
    }
}
impl Into<RNodeType> for DenseByteTrieRNode {
    fn into(self) -> RNodeType {
        RNodeType::Dense(self)
    }
}
impl Into<RNodeType> for SparseByteTrieRNode {
    fn into(self) -> RNodeType {
        RNodeType::Sparse(self)
    }
}
impl Into<RNodeType> for VerySparseByteTrieRNode {
    fn into(self) -> RNodeType {
        RNodeType::VerySparse(self)
    }
}

impl ByteTrieWNode {
    /// Constructs a new, empty [ByteTrieWNode].
    const fn new() -> Self {
        Self {
            prefixes: Vec::new(),
            chunks: Vec::new(),
            suffixes: Vec::new(),
            node: None,
        }
    }
    ///
    /// Records that `string` was present at `data`.
    ///
    /// The traversal to [self] is `string[..depth]`; thus, this function is responsible for either
    /// marking the end of a traversal (`depth == string.len()`) or continuing the traversal.
    ///
    /// If this function is marking the end of a traversal, then the string represented by [self]
    /// is a chunk (see [ByteTrieWNode]), and `data` is recorded in `self.chunks`. Otherwise,
    /// the string represented by [self] is a suffix (see [ByteTrieWNode]), and `data` is recorded
    /// in `self.suffixes`.
    ///
    /// However, if `is_prefix` is `true`, this serves as a hint that `string` actually refers to a
    /// prefix (see [ByteTrieWNode]). In such a case, `suffixes` and `chunks` are left alone, and
    /// only when `depth == string.len()` is `data` added to `self.prefixes`.
    ///
    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) {
        if is_prefix {
            if depth == string.len() {
                self.prefixes.push(data);
                return;
            }
        } else if depth < string.len() {
            self.suffixes.push(data.clone());
        } else {
            self.chunks.push(data);
            return;
        }

        self.node = Some(Box::new(if let Some(node) = &mut self.node {
            match &mut **node {
                WNodeType::Dense(node) => {
                    let _ = node.insert_str(depth, string, data, is_prefix);
                    return;
                }
                WNodeType::Sparse(node) => {
                    if node
                        .insert_str(depth, string, data.clone(), is_prefix)
                        .is_err()
                    {
                        let mut upgraded = node.upgrade();
                        let _ = upgraded.insert_str(depth, string, data, is_prefix);
                        upgraded.into()
                    } else {
                        return;
                    }
                }
                WNodeType::VerySparse(node) => {
                    if node
                        .insert_str(depth, string, data.clone(), is_prefix)
                        .is_err()
                    {
                        let mut upgraded = node.upgrade();
                        let _ = upgraded.insert_str(depth, string, data, is_prefix);
                        upgraded.into()
                    } else {
                        return;
                    }
                }
            }
        } else {
            let mut upgraded = VerySparseByteTrieWNode::new();
            let _ = upgraded.insert_str(depth, string, data, is_prefix);
            upgraded.into()
        }));
    }
    /// Irrevocably converts [self] into a [ByteTrieRNode] by sorting its location vectors, then
    /// converting all children into [ByteTrieRNode]s.
    fn finalize(mut self) -> ByteTrieRNode {
        self.prefixes.sort_unstable();
        self.chunks.sort_unstable();
        self.suffixes.sort_unstable();

        ByteTrieRNode {
            prefixes: self.prefixes,
            chunks: self.chunks,
            suffixes: self.suffixes,

            node: if let Some(node) = self.node {
                Some(Box::new(match *node {
                    WNodeType::Dense(node) => node.finalize().into(),
                    WNodeType::Sparse(node) => node.finalize().into(),
                    WNodeType::VerySparse(node) => node.finalize().into(),
                }))
            } else {
                None
            },
        }
    }
}
impl ByteTrieRNode {
    ///
    /// Collects all locations where the string represented by [self] in any form.
    /// This includes as a prefix, as a chunk, as a suffix, or as a substring of any
    /// prefix, chunk, or suffix.
    ///
    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        // Get all the locations of the prefix represented by `self`
        values.extend(self.prefixes.clone());
        // Get all the locations of the chunk represented by `self`
        values.extend(self.chunks.clone());

        // Every non-prefix substring `s` of string `str` can be found at the start of at least
        // one prefix present within `str` or at the start of `str`. Take `str` "abcd", for
        // example. The non-prefix substrings are "abc", "ab", "bc", "a", "b", and "c".
        // "abc", "ab", and "a" are found at the start of `str`, "bc" and "b" are found at the
        // start of prefix "bcd", and "c" is found at the start of prefix "cd".
        //
        // If `self` represents `s`, then it follows that `str` or one of `str`'s prefixes can
        // be reached via a traversal of `self`'s children. Thus, to find where `s` can be
        // found in spacetime, it suffices to find where all chunks and prefixes represented by
        //  `self`'s children can be found.
        if let Some(node) = &self.node {
            match &**node {
                RNodeType::Dense(node) => node.collect_all_substrings(values),
                RNodeType::Sparse(node) => node.collect_all_substrings(values),
                RNodeType::VerySparse(node) => node.collect_all_substrings(values),
            }
        }
    }
    /// Retrieves a reference to the child of this node associated with `byte`, if any.
    fn get_child_node(&self, byte: u8) -> Option<&ByteTrieRNode> {
        if let Some(node) = &self.node {
            match &**node {
                RNodeType::Dense(node) => node.get_child_node(byte),
                RNodeType::Sparse(node) => node.get_child_node(byte),
                RNodeType::VerySparse(node) => node.get_child_node(byte),
            }
        } else {
            None
        }
    }
}

/// Describes the root of a byte trie that supports update operations
struct WriteStringIndex {
    /// The root node of the trie
    underlying: ByteTrieWNode,
}
/// Describes the root of a byte trie that supports query operations
pub struct ReadStringIndex {
    /// The root node of the trie
    underlying: ByteTrieRNode,
}

impl WriteStringIndex {
    /// Constructs a new, empty [WriteStringIndex].
    fn new() -> Self {
        Self {
            underlying: ByteTrieWNode::new(),
        }
    }
    /// Records all prefixes, chunks, and suffixes within `string` as appearing at the location
    /// described by `data`.
    fn insert_str(&mut self, mut string: &[u8], data: SpacetimeLocation) {
        if string.len() > MAX_ENTRY_SIZE {
            self.insert_str(&string[MAX_ENTRY_SIZE..], &data + MAX_ENTRY_SIZE);
            string = &string[..MAX_ENTRY_SIZE];
        }

        // Add all prefixes present within `string`
        for i in 1..string.len() {
            self.underlying.insert_str(0, &string[i..], &data + i, true);
        }

        // Add `string` as a chunk, and add all suffixes
        self.underlying.insert_str(0, string, data, false);
    }
    /// Irrevocable converts [self] into a [ReadStringIndex]
    fn finalize(self) -> ReadStringIndex {
        ReadStringIndex {
            underlying: self.underlying.finalize(),
        }
    }
}
impl ReadStringIndex {
    /// Searches [self] for records where `string` was written. This does not consider
    /// aggregate writes (i.e. if "abc" was written at 0x100 and "def" was written at
    /// 0x103, this would not find "abcdef"; it could only find "abc" OR "def").
    fn search_raw_str<'a>(&'a self, string: &[u8]) -> Option<&'a ByteTrieRNode> {
        let mut node_ref = &self.underlying;
        for c in string {
            node_ref = match node_ref.get_child_node(*c) {
                Some(node_ref) => node_ref,
                None => return None,
            };
        }

        Some(&node_ref)
    }

    ///
    /// Filters the entries of `to_filter` by finding which locations have corresponding locations
    /// whose address is exactly `offset` bytes *lower* in `filter_keys`. The filtered results then
    /// have their creation and destruction times updated to be only the overlap between their
    /// original ranges and the range in the matching location in `filter_keys`.
    ///
    /// **This function requires that `filter_keys` be sorted.**.
    ///
    /// Time complexity: `O(b log a)`, where `a` is `filter_keys.len()` and `b` is
    /// `to_filter.len()`
    ///
    fn filter_results(
        filter_keys: &Vec<SpacetimeLocation>,
        offset: usize,
        to_filter: &Vec<SpacetimeLocation>,
    ) -> Vec<SpacetimeLocation> {
        if to_filter.is_empty() || filter_keys.is_empty() {
            return Vec::new();
        }

        let mut filtered = Vec::new();

        let idxs: Vec<_> = to_filter
            .iter()
            .enumerate()
            .filter_map(|(loc_idx, location)| {
                let key = location.address - offset as u64;
                filter_keys
                    .binary_search_by_key(&key, |location| location.address)
                    .ok()
                    .map(|key_idx| (loc_idx, key_idx))
            })
            .collect();

        for (loc_idx, mut key_idx) in idxs {
            let addr = filter_keys[key_idx].address;

            while key_idx < filter_keys.len() && filter_keys[key_idx].address == addr {
                if let Some(overlap) = to_filter[loc_idx].overlap(&filter_keys[key_idx]) {
                    filtered.push(overlap);
                }

                key_idx += 1;
            }
        }

        filtered
    }

    ///
    /// Filters the entries of `to_filter` by finding which locations have corresponding locations
    /// whose address is exactly `offset` bytes *higher* in any element of `filter_keys`. The
    /// filtered results then have their creation and destruction times updated to be only the
    /// overlap between their original ranges and the range in the matching location from an element
    /// of `filter_keys`.
    ///
    /// **This function requires that each element of `filter_keys` be sorted.**
    ///
    /// Time complexity: `O(b SUM(log a_i))`, where `a_i` is `filter_keys[i].len()` and `b` is
    /// `to_filter.len()`
    ///
    fn multi_filter(
        filter_keys: &Vec<&Vec<SpacetimeLocation>>,
        offset: usize,
        to_filter: &Vec<SpacetimeLocation>,
    ) -> Vec<SpacetimeLocation> {
        if to_filter.is_empty() || filter_keys.is_empty() {
            return Vec::new();
        }

        let mut filtered = Vec::new();

        let idxs: Vec<_> = to_filter
            .iter()
            .enumerate()
            .filter_map(|(loc_idx, location)| {
                let key = location.address + offset as u64;
                filter_keys
                    .iter()
                    .enumerate()
                    .filter_map(|(list_idx, keys)| {
                        keys.binary_search_by_key(&key, |location| location.address)
                            .ok()
                            .map(|entry_idx| (loc_idx, list_idx, entry_idx))
                    })
                    .next()
            })
            .collect();

        for (loc_idx, list_idx, mut entry_idx) in idxs {
            let addr = filter_keys[list_idx][entry_idx].address;

            while entry_idx < filter_keys[list_idx].len()
                && filter_keys[list_idx][entry_idx].address == addr
            {
                if let Some(overlap) = to_filter[loc_idx].overlap(&filter_keys[list_idx][entry_idx])
                {
                    filtered.push(overlap);
                }

                entry_idx += 1;
            }
        }

        filtered
    }

    ///
    /// Identifies locations in spacetime whose associated prefix matches strict substrings of the
    /// query term `string`.
    ///
    /// Prefixes may only match substrings of a query term if the substring starts at the beginning
    /// of the query term.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    ///
    /// Returns a list containing tuples mapping prefix length to a list of locations where the
    /// prefix can be found in spacetime.
    ///
    fn find_prefixes(&self, string: &[u8]) -> Vec<(usize, &Vec<SpacetimeLocation>)> {
        (1..MAX_ENTRY_SIZE.min(string.len()))
            .filter_map(|end| {
                self.search_raw_str(&string[..end])
                    .map(|node| (end, &node.prefixes))
            })
            .collect()
    }

    ///
    /// Identifies locations in spacetime whose associated chunk matches strict substrings of the
    /// query term `string` that end at offset `end`.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    ///
    /// Returns a list containing tuples mapping chunk length to a list of locations where the
    /// chunk can be found in spacetime.
    ///
    fn find_chunks_ending_at(
        &self,
        string: &[u8],
        end: usize,
    ) -> Vec<(usize, &Vec<SpacetimeLocation>)> {
        // Do not query chunks that match `string` exactly.
        let offset = if end == string.len() { 1 } else { 0 };

        (end - MAX_ENTRY_SIZE.min(end - offset)..end)
            .filter_map(|start| {
                self.search_raw_str(&string[start..end])
                    .map(|node| (end - start, &node.chunks))
            })
            .collect()
    }

    ///
    /// Finds the locations of all strings present in the trie that containing `string` in any
    /// form, including prefixes, chunks, and suffixes.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    ///
    fn find_substrings(&self, string: &[u8]) -> Vec<SpacetimeLocation> {
        self.search_raw_str(string)
            .map(|node| {
                let mut sub_chunks = Vec::new();
                node.collect_all_substrings(&mut sub_chunks);
                sub_chunks
            })
            .unwrap_or_else(Vec::new)
    }

    ///
    /// Identifies locations in spacetime whose associated suffixes match strict substrings of the
    /// query term `string`.
    ///
    /// Suffixes may only match substrings of a query term if the substring ends at the end of the
    /// query term.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    ///
    /// Returns a list containing tuples mapping suffix length to a list of locations where the
    /// suffix can be found in spacetime.
    ///
    fn find_suffixes(&self, string: &[u8]) -> Vec<(usize, &Vec<SpacetimeLocation>)> {
        let end = string.len();

        (end - MAX_ENTRY_SIZE.min(end - 1)..end)
            .filter_map(|start| {
                self.search_raw_str(&string[start..end])
                    .map(|node| (end - start, &node.suffixes))
            })
            .collect()
    }

    ///
    /// Combines [SpacetimeLocation]s that occupy the same space and are directly adjacent in
    /// time.
    ///
    fn combine_split_times(mut locations: Vec<SpacetimeLocation>) -> Vec<SpacetimeLocation> {
        let mut combined = Vec::new();

        // `SpacetimeLocation`s are ordered first by address, then by time, so elements we'd
        // want to combined will be made adjacent by this.
        locations.sort_unstable();
        let mut locations_itr = locations.into_iter().peekable();

        while let Some(mut location) = locations_itr.next() {
            // While the next location occupies the same space and is adjacent in time to our
            // current location, extend the current location's lifetime and forget the next
            // location.
            while let Some(next) = locations_itr.peek() {
                if location.address == next.address && location.destroyed_at == next.created_at {
                    location.destroyed_at = next.destroyed_at;
                    let _ = locations_itr.next();
                } else {
                    break;
                }
            }

            combined.push(location);
        }

        combined
    }

    ///
    /// Searches for `string` within all of spacetime, including across write boundaries.
    ///
    pub fn search(&self, string: &[u8]) -> Vec<SpacetimeLocation> {
        // Simple cases requiring no aggregation of entries
        if string.len() == 0 {
            return Vec::new();
        } else if string.len() == 1 {
            return Self::combine_split_times(self.find_substrings(string));
        }

        // `chunks[i]` describes the set of all `SpacetimeLocation` containing `string[i..]`
        let mut chunks = Vec::new();
        chunks.resize_with(string.len() - 1, || Vec::new());

        // Serves effectively as `chunks[-1]`. Rather than being a list of all locations where
        // the last byte can be found, though, it is a list of sorted lists of such locations. This
        // is because it is expected that there will be a significant number of one byte suffixes,
        // whose locations will be retrieved as a reference to a sorted list. By maintaining a list
        // of such references, we can avoid the costly O(n) clone operation required to add a list
        // to `chunks` and use binary searches to find desired locations rather than the more
        // costly linear scan we use for `chunks`.
        let mut last_byte_locations = Vec::new();

        // `string` was written to memory in one or more writes. This computes the locations where
        // `string` appeared as a result of exactly one write.
        chunks[0].extend(self.find_substrings(string));

        //
        // At this point, we are searching for locations in memory where `string` was written in
        // two or more writes. That is to say, `string` is composed of up to 1 prefix, and number
        // of chunks, and up to 1 suffix, provided there are at least two parts to it. In
        // particular, we can say that all appearances of `string` ends with either a chunk or a
        // suffix and begins with a either a chunk or a prefix.
        //
        // We use dynamic programming to evaluate the various ways in which `string` could have
        // been constructed. As stated above, `chunks[i]` contains the list of locations in which
        // `string[i..]` can be found. We will iterate from the back of the string towards the
        // front and build `chunks` as we go.
        //
        // We start by recording the locations of the suffixes of `string` into `chunk`. From
        // there, we work our way from the back of `string` towards the front using the logic
        // that if we have the list of locations of `string[i..]` and the locations of
        // `string[j..i]`, we can say that the locations of `string[j..]` are the locations shared
        // between those two lists.
        //
        // Once we have worked our way backwards through first suffixes, then chunks, then
        // prefixes, we have that `chunks[0]` contains the locations of `string`.
        //

        // Search for all suffixes of `string`. Any location each suffix can be found is, by
        // definition, a location where `string[-suffix_len ..]` can be found. Record that in
        // `chunks`.
        for (suffix_len, locations) in self.find_suffixes(string) {
            if suffix_len == 1 {
                last_byte_locations.push(locations);
            } else {
                chunks[string.len() - suffix_len].extend(locations.clone());
            }
        }

        // Search all chunks that are `string`. This is an `O(n^3)` operation for small `n`,
        // which becomes linear for `n` greater than `MAX_ENTRY_SIZE`, where `n` is the length
        // of `string`.
        //
        // If we find a chunk describing `string[i..j]`, we may record its locations in
        // `chunks[i]` if and only if they are also found in `chunks[j]` offset by `j - i`
        // ir `j` is the length of `string`. For example, if `string[4 .. 8] is found at
        // `0xABC0`, it may only be recorded in `chunks[4]` if `chunks[8]` contains `0xABC4`
        // or `string` is 8 bytes long.
        //
        // Since whether we can add an try to `chunks[i]` or not may depend on `chunks[j]`
        // for `j > i`, we iterate backwards so that the final value of `chunks[j]` is known
        // before trying to add things to `chunks[i]`.
        for end in (1..string.len() + 1).rev() {
            // Get locations where (chunks of `string` that end at offset `end`) can be found
            let sub_chunks = self.find_chunks_ending_at(string, end);

            for (sub_chunk_len, locations) in sub_chunks {
                let filtered = if end == string.len() {
                    if sub_chunk_len == 1 {
                        last_byte_locations.push(locations);
                        continue;
                    } else {
                        locations.clone()
                    }
                } else if end == string.len() - 1 {
                    // `last_byte_locations`'s elements are expected to be vastly bigger than
                    // `locations` because it contains suffixes, so I've defined `multi_filter`
                    // to filter `locations` against each element of it.
                    Self::multi_filter(&last_byte_locations, sub_chunk_len, locations)
                } else {
                    // Take only locations from `locations` with matching locations in
                    // `chunks[end]`
                    Self::filter_results(locations, sub_chunk_len, &chunks[end])
                };

                chunks[end - sub_chunk_len].extend(filtered);
            }
        }

        // Now we find the prefixes
        for (prefix_len, locations) in self.find_prefixes(string) {
            let filtered = if prefix_len == string.len() - 1 {
                Self::multi_filter(&last_byte_locations, prefix_len, &locations)
            } else {
                Self::filter_results(locations, prefix_len, &chunks[prefix_len])
            };
            chunks[0].extend(filtered);
        }

        let mut drain = chunks.drain(..);

        // If I have a string "abcdefg", and "efg" gets overwritten, a query for "abcd" would show
        // two results: before the overwrite and after. Yet, the "abcd" is not affected. This
        // combines this split location records in such cases.
        //
        // `chunks[0]` (aka `drain.next()`) is the set of all `SpacetimeLocations` containing
        // `string[0..]`; i.e. the locations we want.
        Self::combine_split_times(drain.next().unwrap_or_else(Vec::new))
    }
}
impl Serializable for ReadStringIndex {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.underlying.serialize_to(bytes);
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        Self {
            underlying: ByteTrieRNode::deserialize(bytes, start),
        }
    }
}

enum InternalStringIndex {
    Write(WriteStringIndex),
    Read(ReadStringIndex),
}
pub struct StringIndex<W: Write> {
    trie: Option<InternalStringIndex>,
    pub file: W,
}
impl<W: Write> StringIndex<W> {
    pub fn new(out_file: W) -> Self {
        Self {
            trie: Some(InternalStringIndex::Write(WriteStringIndex::new())),
            file: out_file,
        }
    }
    pub fn get_read_index(&self) -> Option<&ReadStringIndex> {
        match self.trie.as_ref() {
            Some(InternalStringIndex::Read(read_index)) => Some(read_index),
            _ => None,
        }
    }
}
impl<W: Write> Index for StringIndex<W> {
    fn record(&mut self, block: SpacetimeBlock) {
        let location = SpacetimeLocation::new_from_block(&block);
        match (location, &mut self.trie) {
            (Some(location), Some(InternalStringIndex::Write(trie))) => {
                trie.insert_str(&block.data, location)
            }
            (None, _) => {}
            _ => panic!("Unable to add record to finalized index!"),
        }
    }
    fn finalize(&mut self) {
        match self.trie.take() {
            Some(InternalStringIndex::Write(trie)) => {
                self.trie = Some(InternalStringIndex::Read(trie.finalize()));
            }
            _ => {}
        };
    }
    fn save(&mut self) -> io::Result<()> {
        match &mut self.trie {
            Some(InternalStringIndex::Read(trie)) => {
                let mut bytes = Vec::new();
                trie.underlying.serialize_to(&mut bytes);
                self.file.write_all(&bytes)?;
            }
            _ => panic!("Unable to serialize non-finalized index!"),
        }

        Ok(())
    }
}
