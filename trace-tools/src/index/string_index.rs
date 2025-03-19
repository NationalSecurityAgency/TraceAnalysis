use super::{Index, Serializable, SpacetimeBlock};
use dataflow::prelude::SpaceKind;
use std::{fmt::Display, io::Write, ops::Add};

const NODE_TYPE_DENSE: u8 = 1;
const NODE_TYPE_SPARSE: u8 = 2;
const NODE_TYPE_VERY_SPARSE: u8 = 3;

/// The maximum number of elements that a very sparse trie node may hold before being promoted to
/// a sparse trie node. Very sparse space complexity, query time, and retrieval time scale linearly
/// with this.
const SPARSE_THRESHOLD: usize = 8;

/// The maximum number of elements that a sparse trie node may hold before being promoted to a
/// dense trie node. Sparse trie node space complexity scales linearly with this.
const DENSE_THRESHOLD: usize = 96;

/// The number of characters in the longest string a byte trie may hold before being split up.
/// Trie depth scales linearly with this. The lower this is, the higher the density of the trie.
const MAX_ENTRY_SIZE: usize = 16;

pub struct StringIndex<W> {
    trie: StringIndexInner,
    writer: W,
}

impl StringIndex<()> {
    pub fn deserialize(bytes: &[u8]) -> Self {
        Self {
            trie: Serializable::deserialize(bytes, &mut 0),
            writer: (),
        }
    }
}

impl<W: Write> StringIndex<W> {
    pub fn new(writer: W) -> Self {
        Self {
            trie: StringIndexInner::new(),
            writer,
        }
    }
}

impl<W> StringIndex<W> {
    pub fn search(&self, string: &[u8]) -> Vec<SpacetimeLocation> {
        self.trie.search(string)
    }
}

impl<W: Write> Index for StringIndex<W> {
    fn record(&mut self, block: super::SpacetimeBlock) {
        if let Some(location) = SpacetimeLocation::new_from_block(&block) {
            self.trie.insert_str(&block.data, location)
        }
    }

    fn finalize(&mut self) {
        self.trie.finalize();
    }

    fn save(&mut self) -> std::io::Result<()> {
        let mut bytes = Vec::new();
        self.trie.serialize_to(&mut bytes);
        self.writer.write_all(&bytes)
    }
}

///
/// Represents a particular location within spacetime.
///
/// That this does not have a length is deliberate and allows for more efficient (log vs linear)
/// computation during lookups.
///
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord)]
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
    fn new_from_block(block: &SpacetimeBlock) -> Option<Self> {
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

    fn overlap(&self, other: &SpacetimeLocation) -> Option<Self> {
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

impl Display for SpacetimeLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SpacetimeLocation(0x{:x} from {} to {})",
            self.address, self.created_at, self.destroyed_at
        )
    }
}

impl Add<usize> for SpacetimeLocation {
    type Output = Self;
    fn add(self, other: usize) -> Self::Output {
        Self {
            address: self.address + other as u64,
            created_at: self.created_at,
            destroyed_at: self.destroyed_at,
        }
    }
}

struct StringIndexInner {
    head: Option<Box<dyn ByteTrieNode + Send + Sync + 'static>>,
}

impl StringIndexInner {
    fn new() -> Self {
        Self { head: None }
    }

    fn finalize(&mut self) {
        if let Some(node) = self.head.as_mut() {
            node.finalize();
        }
    }

    fn insert_str(&mut self, mut string: &[u8], data: SpacetimeLocation) {
        if string.len() > MAX_ENTRY_SIZE {
            self.insert_str(&string[MAX_ENTRY_SIZE..], data + MAX_ENTRY_SIZE);
            string = &string[..MAX_ENTRY_SIZE];
        }

        let mut node = self
            .head
            .take()
            .unwrap_or_else(|| Box::new(VerySparseByteTrieNode::new()));

        for i in 1..string.len() {
            insert_str(&mut node, 0, &string[i..], data + i, true);
        }

        insert_str(&mut node, 0, string, data, false);
        self.head = Some(node);
    }

    /// Searches [self] for records where `string` was written. This does not consider
    /// aggregate writes (i.e. if "abc" was written at 0x100 and "def" was written at
    /// 0x103, this would not find "abcdef"; it could only find "abc" OR "def").
    fn search_raw_str<'a>(
        &'a self,
        string: &[u8],
    ) -> Option<&'a (dyn ByteTrieNode + Send + Sync + 'static)> {
        let mut node_ref: &(dyn ByteTrieNode + Send + Sync + 'static) =
            self.head.as_ref().map(AsRef::as_ref)?;
        for c in string {
            node_ref = match node_ref.child(*c) {
                Some(node_ref) => node_ref,
                None => return None,
            };
        }
        Some(node_ref)
    }

    /// Filters the entries of `to_filter` by finding which locations have corresponding locations
    /// whose address is exactly `offset` bytes *lower* in `filter_keys`. The filtered results then
    /// have their creation and destruction times updated to be only the overlap between their
    /// original ranges and the range in the matching location in `filter_keys`.
    ///
    /// **This function requires that `filter_keys` be sorted.**.
    ///
    /// Time complexity: `O(b log a)`, where `a` is `filter_keys.len()` and `b` is
    /// `to_filter.len()`
    fn filter_results(
        filter_keys: &[SpacetimeLocation],
        offset: usize,
        to_filter: &[SpacetimeLocation],
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
    fn multi_filter(
        filter_keys: &Vec<&[SpacetimeLocation]>,
        offset: usize,
        to_filter: &[SpacetimeLocation],
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
    fn find_prefixes(&self, string: &[u8]) -> Vec<(usize, &[SpacetimeLocation])> {
        (1..MAX_ENTRY_SIZE.min(string.len()))
            .filter_map(|end| {
                self.search_raw_str(&string[..end])
                    .map(|node| (end, node.data().prefixes()))
            })
            .collect()
    }

    /// Identifies locations in spacetime whose associated chunk matches strict substrings of the
    /// query term `string` that end at offset `end`.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    ///
    /// Returns a list containing tuples mapping chunk length to a list of locations where the
    /// chunk can be found in spacetime.
    fn find_chunks_ending_at(
        &self,
        string: &[u8],
        end: usize,
    ) -> Vec<(usize, &[SpacetimeLocation])> {
        // Do not query chunks that match `string` exactly.
        let offset = if end == string.len() { 1 } else { 0 };

        (end - MAX_ENTRY_SIZE.min(end - offset)..end)
            .filter_map(|start| {
                self.search_raw_str(&string[start..end])
                    .map(|node| (end - start, node.data().chunks()))
            })
            .collect()
    }

    /// Finds the locations of all strings present in the trie that containing `string` in any
    /// form, including prefixes, chunks, and suffixes.
    ///
    /// This only considers strings in spacetime recorded in the trie as a single entry.
    fn find_substrings(&self, string: &[u8]) -> Vec<SpacetimeLocation> {
        self.search_raw_str(string)
            .map(|node| {
                let mut sub_chunks = Vec::new();
                node.collect_all_substrings(&mut sub_chunks);
                sub_chunks
            })
            .unwrap_or_else(Vec::new)
    }

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
    fn find_suffixes(&self, string: &[u8]) -> Vec<(usize, &[SpacetimeLocation])> {
        let end = string.len();

        (end - MAX_ENTRY_SIZE.min(end - 1)..end)
            .filter_map(|start| {
                self.search_raw_str(&string[start..end])
                    .map(|node| (end - start, node.data().suffixes()))
            })
            .collect()
    }

    /// Combines [SpacetimeLocation]s that occupy the same space and are directly adjacent in
    /// time.
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

    /// Searches for `string` within all of spacetime, including across write boundaries.
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
                chunks[string.len() - suffix_len].extend(locations);
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
                        locations.into()
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

impl Serializable for StringIndexInner {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        //self.head.serialize_to(bytes)
        if let Some(ref node) = self.head {
            node.serialize_to(bytes);
        } else {
            0u8.serialize_to(bytes);
            0usize.serialize_to(bytes);
            0usize.serialize_to(bytes);
            0usize.serialize_to(bytes);
        }
    }

    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized,
    {
        match bytes[*start] {
            0u8 => Self { head: None },
            _ => Self {
                head: Some(deserialize_node(bytes, start)),
            },
        }
    }
}

/// Data for a node in the byte trie.
///
/// The traversal to reach this node describes a string; further documentation for this struct
/// will refer to this string as "the string represented by this node".
///
/// There are three types of strings stored in this byte trie:
///
/// - Prefixes: A prefix is a string that may make up the start of a query term, but only the start.
/// When processing a query term, a prefix may only be used to match a substring of the
/// query term if the substring starts at the beginning of the query term.
/// When a string is added to the byte trie, all substrings ending at the string's end are
/// added as prefixes.
///
/// - Chunks: A chunk is a string that may make up any part of a query term. When processing a query
/// term, any strict substring of the query term may be matched by a chunk.
/// When a string is added to the byte trie, the whole string is added as a chunk.
///
/// - Suffixes: A suffix is a string that may make up the end of a query term, but only the end. When
/// processing a query term, a suffix may only be used to match a substring of the query
/// term if the substring ends at the end of the query term.
/// When a string is added to the byte trie, all substrings beginning at the string's start
/// are added as suffixes.
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
#[derive(Clone)]
struct ByteTrieNodeData {
    /// Describes locations where the string represented by [self] can be found as a prefix
    prefixes: Vec<SpacetimeLocation>,
    /// Describes locations where the string represented by [self] can be found as a chunk
    chunks: Vec<SpacetimeLocation>,
    /// Describes locations where the string represented by [self] can be found as a suffix
    suffixes: Vec<SpacetimeLocation>,
}

impl ByteTrieNodeData {
    fn new() -> Self {
        Self {
            prefixes: Vec::new(),
            chunks: Vec::new(),
            suffixes: Vec::new(),
        }
    }

    fn prefixes(&self) -> &[SpacetimeLocation] {
        self.prefixes.as_slice()
    }

    fn chunks(&self) -> &[SpacetimeLocation] {
        self.chunks.as_slice()
    }

    fn suffixes(&self) -> &[SpacetimeLocation] {
        self.suffixes.as_slice()
    }

    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> bool {
        if is_prefix {
            if depth == string.len() {
                self.prefixes.push(data);
                return true;
            }
        } else if depth < string.len() {
            self.suffixes.push(data);
        } else {
            self.chunks.push(data);
            return true;
        }
        false
    }

    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        values.extend_from_slice(self.prefixes.as_slice());
        values.extend_from_slice(self.chunks.as_slice());
    }

    fn finalize(&mut self) {
        self.prefixes.sort_unstable();
        self.chunks.sort_unstable();
        self.suffixes.sort_unstable();

        self.prefixes.dedup();
        self.chunks.dedup();
        self.suffixes.dedup();
    }
}

impl Serializable for ByteTrieNodeData {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.prefixes.serialize_to(bytes);
        self.chunks.serialize_to(bytes);
        self.suffixes.serialize_to(bytes);
    }

    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized,
    {
        Self {
            prefixes: Serializable::deserialize(bytes, start),
            chunks: Serializable::deserialize(bytes, start),
            suffixes: Serializable::deserialize(bytes, start),
        }
    }
}

trait ByteTrieNode: Serializable {
    fn data(&self) -> &ByteTrieNodeData;

    /// Records that `string` was present at `data`.
    ///
    /// The traversal to [self] is `string[..depth]`; thus, this function is responsible for either
    /// marking the end of a traversal (`depth == string.len()`) or continuing the traversal.
    ///
    /// If this function is marking the end of a traversal, then the string represented by [self]
    /// is a chunk (see [ByteTrieNodeData]), and `data` is recorded in `self.chunks`. Otherwise,
    /// the string represented by [self] is a suffix (see [ByteTrieNodeData]), and `data` is
    /// recorded in `self.suffixes`.
    ///
    /// However, if `is_prefix` is `true`, this serves as a hint that `string` actually refers to a
    /// prefix (see [ByteTrieNodeData]). In such a case, `suffixes` and `chunks` are left alone, and
    /// only when `depth == string.len()` is `data` added to `self.prefixes`.
    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), NeedsUpgrade>;
    fn upgrade(self: Box<Self>) -> Box<dyn ByteTrieNode + Send + Sync + 'static>;
    fn finalize(&mut self);

    /// Collects all locations where the string represented by [self] in any form.
    /// This includes as a prefix, as a chunk, as a suffix, or as a substring of any
    /// prefix, chunk, or suffix.
    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>);

    /// Retrieves a reference to the child of this node associated with `byte`, if any.
    fn child(&self, byte: u8) -> Option<&(dyn ByteTrieNode + Send + Sync + 'static)>;
}

/// A dense node in a byte trie
///
/// Compared to a very sparse or sparse byte trie node, this node has a higher memory
/// and storage footprint with only a relatively minor performance increase. The main
/// benefit to a dense node is its capacity; it holds a reference to a child for each
/// byte value. Close to the root of the trie, there will likely be a number of dense
/// byte tries, but should be comparatively lower than very sparse or sparse byte tries.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
struct DenseByteTrieNode {
    data: ByteTrieNodeData,
    trie: [Option<Box<dyn ByteTrieNode + Send + Sync + 'static>>; 256],
}

impl DenseByteTrieNode {
    fn new() -> Self {
        Self {
            data: ByteTrieNodeData::new(),
            trie: [const { None }; 256],
        }
    }
}

impl ByteTrieNode for DenseByteTrieNode {
    fn data(&self) -> &ByteTrieNodeData {
        &self.data
    }

    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), NeedsUpgrade> {
        if self.data.insert_str(depth, string, data, is_prefix) {
            return Ok(());
        }

        let index = string[depth] as usize;
        let mut node = self.trie[index]
            .take()
            .unwrap_or_else(|| Box::new(VerySparseByteTrieNode::new()));
        insert_str(&mut node, depth + 1, string, data, is_prefix);
        self.trie[index] = Some(node);

        Ok(())
    }

    fn upgrade(self: Box<Self>) -> Box<dyn ByteTrieNode + Send + Sync + 'static> {
        self
    }

    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        self.data.collect_all_substrings(values);
        for elem in self.trie.iter() {
            if let Some(node) = elem {
                node.collect_all_substrings(values);
            }
        }
    }

    fn child(&self, byte: u8) -> Option<&(dyn ByteTrieNode + Send + Sync + 'static)> {
        self.trie[byte as usize].as_ref().map(AsRef::as_ref)
    }

    fn finalize(&mut self) {
        self.data.finalize();
        self.trie
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .for_each(|i| i.finalize());
    }
}

impl Serializable for DenseByteTrieNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        NODE_TYPE_DENSE.serialize_to(bytes);
        self.data.serialize_to(bytes);

        let table_offset = bytes.len();
        bytes.extend_from_slice(&[0x00; 0x100 * std::mem::size_of::<usize>()]);
        for i in 0..0x100 {
            let subtable_offset = bytes.len();
            // Two blanket impls + a subtrait relationship results a failure of the trait solver to
            // determine that Option<Box<dyn ByteTrieNode>> must impl Serializable
            //self.trie[i].serialize_to(bytes);
            if let Some(ref node) = self.trie[i] {
                1u8.serialize_to(bytes);
                node.serialize_to(bytes);
            } else {
                0u8.serialize_to(bytes);
            }
            let offset_slice = &mut bytes[table_offset + i * std::mem::size_of::<usize>()
                ..table_offset + (i + 1) * std::mem::size_of::<usize>()];
            offset_slice.copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }

    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized,
    {
        assert_eq!(u8::deserialize(bytes, start), NODE_TYPE_DENSE);
        Self {
            data: ByteTrieNodeData::deserialize(bytes, start),
            trie: std::array::from_fn(|_| {
                let mut offset = usize::deserialize(bytes, start);
                if bytes[offset] == 0 {
                    return None;
                }
                offset += 1;
                Some(deserialize_node(bytes, &mut offset))
            }),
        }
    }
}

/// A sparse node in a byte trie that allows for insertions.
///
/// [SparseByteTrieNode] is slightly faster than a [VerySparseByteTrieNode] at a significant
/// cost in memory and storage. It is slightly slower than a [DenseByteTrieWNode], but
/// significantly less expensive in memory and storage. The main benefit to a [SparseByteTrieNode]
/// over a [VerySparseByteTrieNode] is its increased storage capacity; while the very sparse node
/// may store only a few sub-trees, a [SparseByteTrieNode] can hold significantly more.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
struct SparseByteTrieNode {
    data: ByteTrieNodeData,
    head: usize,
    trie_indices: [u8; 256],
    tries: [Option<Box<dyn ByteTrieNode + Send + Sync + 'static>>; DENSE_THRESHOLD],
}

impl SparseByteTrieNode {
    fn new() -> Self {
        Self {
            data: ByteTrieNodeData::new(),
            head: 0,
            trie_indices: [u8::MAX; 256],
            tries: [const { None }; DENSE_THRESHOLD],
        }
    }
}

impl ByteTrieNode for SparseByteTrieNode {
    fn data(&self) -> &ByteTrieNodeData {
        &self.data
    }

    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), NeedsUpgrade> {
        if self.data.insert_str(depth, string, data, is_prefix) {
            return Ok(());
        }

        let char = string[depth] as usize;

        let requires_new_entry = self.trie_indices[char] == u8::MAX;
        if self.head == DENSE_THRESHOLD && requires_new_entry {
            return Err(NeedsUpgrade);
        }

        if requires_new_entry {
            self.trie_indices[char] = self.head as u8;
            self.head += 1;
        }

        let index = self.trie_indices[char] as usize;
        let mut node = self.tries[index]
            .take()
            .unwrap_or_else(|| Box::new(VerySparseByteTrieNode::new()));
        insert_str(&mut node, depth + 1, string, data, is_prefix);
        self.tries[index] = Some(node);
        Ok(())
    }

    fn upgrade(mut self: Box<Self>) -> Box<dyn ByteTrieNode + Send + Sync + 'static> {
        let mut upgraded = DenseByteTrieNode::new();
        std::mem::swap(&mut self.data, &mut upgraded.data);

        for i in 0..256 {
            if self.trie_indices[i] < u8::MAX {
                std::mem::swap(
                    &mut upgraded.trie[i],
                    &mut self.tries[self.trie_indices[i] as usize],
                );
            }
        }

        Box::new(upgraded)
    }

    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        self.data.collect_all_substrings(values);
        for i in 0..self.head {
            if let Some(node) = &self.tries[i] {
                node.collect_all_substrings(values);
            }
        }
    }

    fn child(&self, byte: u8) -> Option<&(dyn ByteTrieNode + Send + Sync + 'static)> {
        if self.trie_indices[byte as usize] != u8::MAX {
            self.tries[self.trie_indices[byte as usize] as usize]
                .as_ref()
                .map(|b| &**b)
        } else {
            None
        }
    }

    fn finalize(&mut self) {
        self.data.finalize();
        self.tries
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .for_each(|i| i.finalize());
    }
}

impl Serializable for SparseByteTrieNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        NODE_TYPE_SPARSE.serialize_to(bytes);
        self.data.serialize_to(bytes);
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
            //self.tries[idx].serialize_to(bytes);
            if let Some(ref node) = self.tries[idx] {
                1u8.serialize_to(bytes);
                node.serialize_to(bytes);
            } else {
                0u8.serialize_to(bytes);
            }
            let entry_slice = &mut bytes[table_offset + idx * (std::mem::size_of::<usize>() + 1)
                ..table_offset + (idx + 1) * (std::mem::size_of::<usize>() + 1)];
            entry_slice[0] = i as u8;
            entry_slice[1..].copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }

    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized,
    {
        assert_eq!(u8::deserialize(bytes, start), NODE_TYPE_SPARSE);
        let data = ByteTrieNodeData::deserialize(bytes, start);
        let head = usize::deserialize(bytes, start);
        let mut tries = std::array::from_fn(|_| None);
        let mut trie_indices = [u8::MAX; 256];
        for i in 0..head {
            let subtrie_char = u8::deserialize(bytes, start);
            trie_indices[subtrie_char as usize] = i as u8;
            let mut offset = usize::deserialize(bytes, start);
            tries[i] = match bytes[offset] {
                0 => None,
                _ => {
                    offset += 1;
                    Some(deserialize_node(bytes, &mut offset))
                }
            };
        }
        Self {
            data,
            head,
            tries,
            trie_indices,
        }
    }
}

/// A very sparse node in a byte trie that allows for insertions.
///
/// [VerySparseByteTrieNode] is slightly slower than a [SparseByteTrieNode] or a
/// [DenseByteTrieNode], but it is vastly more space efficient. When a node in a byte trie is
/// expected to only have a few children, a [VerySparseByteTrieNode] should be used.
///
/// Nodes start out as very sparse, and if they require more space than is available in
/// a very sparse node, it is promoted to sparse, then to dense.
struct VerySparseByteTrieNode {
    data: ByteTrieNodeData,
    head: usize,
    trie: [(u8, Option<Box<dyn ByteTrieNode + Send + Sync + 'static>>); SPARSE_THRESHOLD],
}

impl VerySparseByteTrieNode {
    fn new() -> Self {
        Self {
            data: ByteTrieNodeData::new(),
            head: 0,
            trie: [const { (0, None) }; SPARSE_THRESHOLD],
        }
    }
}

impl ByteTrieNode for VerySparseByteTrieNode {
    fn data(&self) -> &ByteTrieNodeData {
        &self.data
    }

    fn insert_str(
        &mut self,
        depth: usize,
        string: &[u8],
        data: SpacetimeLocation,
        is_prefix: bool,
    ) -> Result<(), NeedsUpgrade> {
        if self.data.insert_str(depth, string, data, is_prefix) {
            return Ok(());
        }

        let char = string[depth];

        for i in 0..self.head {
            if self.trie[i].0 == char {
                let mut node = self.trie[i]
                    .1
                    .take()
                    .unwrap_or_else(|| Box::new(VerySparseByteTrieNode::new()));
                insert_str(&mut node, depth + 1, string, data, is_prefix);
                self.trie[i].1 = Some(node);
                return Ok(());
            }

            if self.trie[i].1.is_none() {
                break;
            }
        }

        if self.head == SPARSE_THRESHOLD {
            return Err(NeedsUpgrade);
        }

        let mut node: Box<dyn ByteTrieNode + Send + Sync + 'static> =
            Box::new(VerySparseByteTrieNode::new());
        insert_str(&mut node, depth + 1, string, data, is_prefix);
        self.trie[self.head] = (char, Some(node));
        self.head += 1;
        Ok(())
    }

    fn upgrade(mut self: Box<Self>) -> Box<dyn ByteTrieNode + Send + Sync + 'static> {
        let mut upgraded = SparseByteTrieNode::new();
        std::mem::swap(&mut self.data, &mut upgraded.data);

        for (trie_char, trie) in self.trie[..self.head].iter_mut() {
            upgraded.trie_indices[*trie_char as usize] = upgraded.head as u8;
            std::mem::swap(&mut upgraded.tries[upgraded.head], trie);
            upgraded.head += 1;
        }

        Box::new(upgraded)
    }

    fn collect_all_substrings(&self, values: &mut Vec<SpacetimeLocation>) {
        self.data.collect_all_substrings(values);
        for i in 0..self.head {
            if let Some(node) = self.trie[i].1.as_ref() {
                node.collect_all_substrings(values);
            }
        }
    }

    fn child(&self, byte: u8) -> Option<&(dyn ByteTrieNode + Send + Sync + 'static)> {
        for i in 0..self.head {
            let (trie_char, Some(trie)) = &self.trie[i] else {
                break;
            };
            if *trie_char == byte {
                return Some(trie.as_ref());
            }
        }

        None
    }

    fn finalize(&mut self) {
        self.data.finalize();
        self.trie
            .iter_mut()
            .filter_map(|(_, i)| i.as_mut())
            .for_each(|i| i.finalize());
    }
}

impl Serializable for VerySparseByteTrieNode {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        NODE_TYPE_VERY_SPARSE.serialize_to(bytes);
        self.data.serialize_to(bytes);
        self.head.serialize_to(bytes);

        let table_offset = bytes.len();
        bytes.resize(
            bytes.len() + self.head * (std::mem::size_of::<usize>() + 1),
            0x00,
        );
        for i in 0..self.head {
            let (char, subtrie) = &self.trie[i];
            let subtable_offset = bytes.len();
            //subtrie.serialize_to(bytes);
            if let Some(node) = subtrie {
                1u8.serialize_to(bytes);
                node.serialize_to(bytes);
            } else {
                0u8.serialize_to(bytes);
            }
            let entry_slice = &mut bytes[table_offset + i * (std::mem::size_of::<usize>() + 1)
                ..table_offset + (i + 1) * (std::mem::size_of::<usize>() + 1)];
            entry_slice[0] = *char;
            entry_slice[1..].copy_from_slice(&subtable_offset.to_le_bytes());
        }
    }

    fn deserialize(bytes: &[u8], start: &mut usize) -> Self
    where
        Self: Sized,
    {
        assert_eq!(u8::deserialize(bytes, start), NODE_TYPE_VERY_SPARSE);
        let data = ByteTrieNodeData::deserialize(bytes, start);
        let head = usize::deserialize(bytes, start);
        let mut trie: [_; SPARSE_THRESHOLD] = std::array::from_fn(|_| (0u8, None));
        for i in 0..head {
            let subtrie_char = u8::deserialize(bytes, start);
            let mut offset = usize::deserialize(bytes, start);
            trie[i] = match bytes[offset] {
                0 => (subtrie_char, None),
                _ => {
                    offset += 1;
                    (subtrie_char, Some(deserialize_node(bytes, &mut offset)))
                }
            };
        }
        Self { data, head, trie }
    }
}

#[derive(Debug, Copy, Clone)]
struct NeedsUpgrade;

fn deserialize_node(
    bytes: &[u8],
    start: &mut usize,
) -> Box<dyn ByteTrieNode + Send + Sync + 'static> {
    match bytes[*start] {
        NODE_TYPE_DENSE => Box::new(DenseByteTrieNode::deserialize(bytes, start)),
        NODE_TYPE_SPARSE => Box::new(SparseByteTrieNode::deserialize(bytes, start)),
        NODE_TYPE_VERY_SPARSE => Box::new(VerySparseByteTrieNode::deserialize(bytes, start)),
        _ => unimplemented!(),
    }
}

/// This is a dummy trie node only meant for temporary storage.
///
/// Because all trie nodes are allocated on the heap, a dummy node is used to allow an upgrade in
/// place without the cost of a larger allocation. When a real trie node needs to be upgraded, its
/// place in the the trie is swapped with this dummy node, so that the upgrade can consume the old
/// node before it is swapped back.
struct DummyNode;

impl ByteTrieNode for DummyNode {
    fn insert_str(
        &mut self,
        _depth: usize,
        _string: &[u8],
        _data: SpacetimeLocation,
        _is_prefix: bool,
    ) -> Result<(), NeedsUpgrade> {
        todo!()
    }

    fn upgrade(self: Box<Self>) -> Box<dyn ByteTrieNode + Send + Sync + 'static> {
        todo!()
    }

    fn collect_all_substrings(&self, _values: &mut Vec<SpacetimeLocation>) {
        todo!()
    }

    fn child(&self, _byte: u8) -> Option<&(dyn ByteTrieNode + Send + Sync + 'static)> {
        todo!()
    }

    fn finalize(&mut self) {
        todo!()
    }

    fn data(&self) -> &ByteTrieNodeData {
        todo!()
    }
}

impl Serializable for DummyNode {
    fn serialize_to(&self, _bytes: &mut Vec<u8>) {
        todo!()
    }

    fn deserialize(_bytes: &[u8], _start: &mut usize) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
}

fn insert_str(
    node: &mut Box<dyn ByteTrieNode + Send + Sync + 'static>,
    depth: usize,
    string: &[u8],
    data: SpacetimeLocation,
    is_prefix: bool,
) {
    if node.insert_str(depth, string, data, is_prefix).is_ok() {
        return;
    }
    let mut dummy: Box<dyn ByteTrieNode + Send + Sync + 'static> = Box::new(DummyNode);
    std::mem::swap(node, &mut dummy);
    dummy = dummy.upgrade();
    std::mem::swap(node, &mut dummy);
    node.insert_str(depth, string, data, is_prefix).unwrap();
}
