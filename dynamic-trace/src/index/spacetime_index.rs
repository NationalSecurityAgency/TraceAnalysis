/*

# The Problem
During the execution of the program, memory accesses of all sorts occur. This information - the
accesses - is all we have; if we want to know what was in memory at a specific location at a
specific time, we need to find the most recent access(es) there and retrieve it/them.

## Constraints
This is a computation that occurs with some degree of frequency. As traces can be large (billions
of records), it is important that it can be answered in O(log n) time and with O(n log n) or
better space complexity.

## Framing the Problem
With some amount of post-processing, we can compute each time memory is changed and how long it
remains before it is changed again. For example, we may find that "abcd" was written at address
0x1234 at tick 100 and remained "abcd" until tick 300, at which point it was changed.

We may regard a location in memory at a specific tick as a location in "space-time". It follows,
then, that each change (as described above), can be regarded as a rectangle in space-time. In the
example above, "abcd" would be the tag applied to a rectange at (0x1234, 100), (0x1238, 300).
The process of examining a range of memory at a specific time, then, can be reduced to finding
the space-time rectangles (henceforce referred to as `SpacetimeBlock`s) that overlap a line in
space-time from (`<start address>`, `<time>`) to (`<end address>`, `<time>`).

## Solution
The canonical solution is to use an "r-tree" data structure. However, r-trees can be challenging
to efficiently build, and our queries have a useful property that allows a modified segment tree
to solve the problem. Since they are flat along the time axis, we can approach the problem by
finding `SpacetimeBlock`s that overlap the line `time = <query_time>`. Each node in the segment
tree will contain some number of `SpacetimeBlock`s, some of which will overlap our requested
address range, and some of which will not. Because these blocks are non-overlapping, a sorted
vector is capable of storing them such that we may retrieve an interval in `O(log k + s)` time,
where `k` is the number of blocks stored at the node, and `s` is the number of blocks in our
desired interval (basically serving as a faster and easier to implement interval tree).

We store these blocks sorted by address so that, in `O(log k + s)` time, we can retrieve the
relevant blocks, where `k` is the total number of blocks stored at the node.
*/

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Result;
use std::io::Write;
use std::rc::Rc;

use super::segment_tree::{RSegmentTree, SegmentTreeEntry, WSegmentTree};
use dataflow::prelude::SpaceKind;

use super::Index;
use super::Serializable;
use super::SpacetimeBlock;

struct SpacetimeWTree {
    space: SpaceKind,
    trunk: WSegmentTree<SpacetimeBlock>,
}
pub struct SpacetimeRTree {
    space: SpaceKind,
    trunk: RSegmentTree<SpacetimeBlock>,
}

enum SpacetimeTree {
    Write(SpacetimeWTree),
    Read(SpacetimeRTree),
}

pub struct SpacetimeIndex<W: Write> {
    max_ticks: u64,
    trees: HashMap<SpaceKind, SpacetimeTree>,
    pub file: W,
}

impl SpacetimeWTree {
    fn new(num_ticks: u64, space: SpaceKind) -> Self {
        Self {
            space: space,
            trunk: WSegmentTree::new(0, num_ticks),
        }
    }
    fn insert(&mut self, data: SpacetimeBlock) {
        let (creation, destruction) = (data.created_at, data.destroyed_at);
        let entry = SegmentTreeEntry {
            sort_key: data.address,
            data: Rc::new(data),
        };

        self.trunk.add_location(entry, creation, destruction);
    }
    fn finalize(self) -> SpacetimeRTree {
        SpacetimeRTree {
            space: self.space,
            trunk: self.trunk.finalize(),
        }
    }
}
impl SpacetimeRTree {
    pub fn find(&mut self, time: u64, addr_start: u64, addr_end: u64) -> Vec<Rc<SpacetimeBlock>> {
        let mut results = Vec::new();
        self.trunk.search(time, addr_start, addr_end, &mut results);
        results
    }

    pub fn last_tick(&self) -> u64 {
        self.trunk.max
    }
}

fn begin_rtree_serialization<T>(tree: &RSegmentTree<T>, bytes: &mut Vec<u8>) {
    1u8.serialize_to(bytes);
    tree.min.serialize_to(bytes);
    tree.max.serialize_to(bytes);
    tree.mid.serialize_to(bytes);
    tree.elements.len().serialize_to(bytes);
}
fn begin_rtree_deserialization<T>(
    bytes: &[u8],
    start: &mut usize,
) -> Option<(Box<RSegmentTree<T>>, usize)> {
    let is_present = u8::deserialize(bytes, start);
    if is_present == 0 {
        None
    } else {
        Some((
            Box::new(RSegmentTree {
                min: u64::deserialize(bytes, start),
                max: u64::deserialize(bytes, start),
                mid: u64::deserialize(bytes, start),
                left: None,
                right: None,
                elements: Vec::new(),
            }),
            usize::deserialize(bytes, start),
        ))
    }
}

impl Serializable for SpacetimeRTree {
    fn serialize_to(&self, bytes: &mut Vec<u8>) {
        self.space.serialize_to(bytes);

        let mut blocks = BTreeMap::new();
        let mut branch_stack = VecDeque::new();

        self.trunk.retrieve_entries(&mut blocks);
        branch_stack.push_front(Some(&self.trunk));

        blocks.len().serialize_to(bytes);

        let mut block_ids = BTreeMap::new();
        for (idx, (addr, block)) in blocks.iter().enumerate() {
            block_ids.insert(addr, idx);
            block.serialize_to(bytes);
        }

        while let Some(front) = branch_stack.pop_front() {
            if let Some(front) = front {
                begin_rtree_serialization(front, bytes);

                for elem in &front.elements {
                    let block_addr: *const SpacetimeBlock = elem.data.as_ref();
                    let block_id = block_ids.get(&block_addr).unwrap();
                    block_id.serialize_to(bytes);
                }

                branch_stack.push_front(front.right.as_ref().map_or(None, |b| Some(b.as_ref())));
                branch_stack.push_front(front.left.as_ref().map_or(None, |b| Some(b.as_ref())));
            } else {
                0u8.serialize_to(bytes);
            }
        }
    }
    fn deserialize(bytes: &[u8], start: &mut usize) -> Self {
        let space = SpaceKind::deserialize(bytes, start);
        let num_entries = usize::deserialize(bytes, start);
        let block_map = (0..num_entries)
            .map(|n| {
                let block = SpacetimeBlock::deserialize(bytes, start);
                (
                    n,
                    SegmentTreeEntry {
                        sort_key: block.address,
                        data: Rc::new(block),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut branch_stack = VecDeque::new();
        let mut root_branch = Some(Box::new(RSegmentTree::new_empty()));
        branch_stack.push_front(&mut root_branch);

        while let Some(branch) = branch_stack.pop_front() {
            if let Some((new_branch, num_elems)) = begin_rtree_deserialization(bytes, start) {
                *branch = Some(new_branch);

                let branch_ref = branch.as_mut().unwrap();

                for _ in 0..num_elems {
                    let block_id = usize::deserialize(bytes, start);
                    branch_ref
                        .elements
                        .push(block_map.get(&block_id).unwrap().clone())
                }

                branch_stack.push_front(&mut branch_ref.right);
                branch_stack.push_front(&mut branch_ref.left);
            }
        }

        Self {
            space,
            trunk: *root_branch.unwrap(),
        }
    }
}

impl<W: Write> SpacetimeIndex<W> {
    pub fn new(file: W, num_ticks: u64) -> Self {
        Self {
            file: file,
            max_ticks: num_ticks,
            trees: HashMap::new(),
        }
    }
}
impl<W: Write> Index for SpacetimeIndex<W> {
    fn record(&mut self, block: SpacetimeBlock) {
        let tree = if let Some(tree) = self.trees.get_mut(&block.space) {
            tree
        } else {
            self.trees.insert(
                block.space,
                SpacetimeTree::Write(SpacetimeWTree::new(self.max_ticks, block.space)),
            );
            self.trees.get_mut(&block.space).unwrap()
        };
        match tree {
            SpacetimeTree::Write(tree) => tree.insert(block),
            _ => panic!("Cannot record into finalized Index"),
        }
    }
    fn finalize(&mut self) {
        self.trees = self
            .trees
            .drain()
            .map(|(key, value)| {
                (
                    key,
                    match value {
                        SpacetimeTree::Write(tree) => SpacetimeTree::Read(tree.finalize()),
                        other => other,
                    },
                )
            })
            .collect();
    }
    fn save(&mut self) -> Result<()> {
        for tree in self.trees.values() {
            match tree {
                SpacetimeTree::Read(tree) => {
                    let mut data = Vec::new();
                    tree.serialize_to(&mut data);
                    self.file.write_all(&data)?
                }
                _ => panic!("Cannot save non-finalized index!"),
            }
        }

        Ok(())
    }
}
