use std::{any::Any, fmt::Debug};

///
/// [OverlapComparable] defines a special sort of partial ordering wherein two objects have have
/// one "greater" or "less" than another, or they could be not exactly equal but not greater than
/// or less than each other, and in this third case, the two objects can be combined into one.
/// This third case is referred to as "overlap".
///
/// Standard associativity apply with [OverlapComparison::Less] and [OverlapComparison::Greater],
/// but not with [OverlapComparison::Overlap].
///
#[derive(PartialEq, Eq)]
pub enum OverlapComparison {
    /// "A and B overlap" implies A and B are not equal but are also not greater than or less than
    /// one another
    Overlap,
    /// In the partial ordering where A comes before B, A is [OverlapComparison::Less] than B.
    Less,
    /// In the partial ordering where A comes after B, A is [OverlapComparison::Greater]  than B.
    Greater,
}

///
/// [OverlapComparable] defines a special sort of partial ordering wherein two objects have have
/// one "greater" or "less" than another, or they could be not exactly equal but not greater than
/// or less than each other, and in this third case, the two objects can be combined into one.
/// This third case is referred to as "overlap".
///
/// Any type which implements [OverlapComparable] must have some concept of overlapping instances
/// and must have a way to combine said instances.
///
pub trait OverlapComparable: Sized {
    /// Compares [self] to another instance of this kind of [OverlapComparable], where
    /// returning [OverlapComparison::Less] implies [self] is less than `other`.
    fn cmp(&self, other: &Self) -> OverlapComparison;
    /// Combines [self] with a list of this kind of [OverlapComparable] which have been
    /// determined to overlap [self]. Returns the result from the combination.
    fn combine(self, overlaps: Vec<Self>, combine_ctx: &mut dyn Any) -> Vec<Self>;
}

/// Describes a node in an AVL tree whose members are [OverlapComparable]
struct MergeSetNode<T>
where
    T: Sized + OverlapComparable + Debug,
{
    /// Non-optional option; exists so that I may .take() it.
    /// Contains the data associated with this AVL node.
    element: Option<T>,
    ///
    /// The depth of either [Self::left] or [Self::right], whichever is greater.
    ///
    /// # Example
    ///
    /// A [MergeSetNode] with no children on left or right would have a depth of 0.
    ///
    /// A [MergeSetNode] with an empty left child but no right child would have a depth of 1.
    ///
    /// A [MergeSetNode] with an empty left and right child would have a depth of 1.
    ///
    child_depth: usize,
    ///
    /// The difference in depth of between [Self::right] and [Self::left]. A positive [Self::skew]
    /// indicates that the right child has a higher depth, and a negative [Self::skew] indicates
    /// that the left child has a higher depth.
    ///
    /// # Example
    ///
    /// A [MergeSetNode] with no children on left or right would have a skew of 0.
    ///
    /// A [MergeSetNode] with an empty left child but no right child would have a skew of -1.
    ///
    /// A [MergeSetNode] with no left child but an empty right child would have a skew of 1.
    ///
    /// A [MergeSetNode] with an empty left and right child would have a skew of 0.
    ///
    skew: i32,
    /// The left child (i.e. the child representing elements [OverlapComparison::Less] than
    /// [Self::element]).
    left: Option<Box<MergeSetNode<T>>>,
    /// The left child (i.e. the child representing elements [OverlapComparison::Greater] than
    /// [Self::element]).
    right: Option<Box<MergeSetNode<T>>>,
}

///
/// A user-friendly wrapper around [MergeSetNode]s, implementing standard AVL tree operations.
///
pub struct MergeSet<T>
where
    T: Sized + OverlapComparable + Debug,
{
    /// The root node of the AVL tree
    root: Option<Box<MergeSetNode<T>>>,
}

impl<T> MergeSetNode<T>
where
    T: Sized + OverlapComparable + Debug,
{
    /// Instantiates a new [MergeSetNode] containing the specified element.
    fn new(elem: T) -> Self {
        Self {
            element: Some(elem),
            child_depth: 0,
            skew: 0,
            left: None,
            right: None,
        }
    }

    /// Rotates elements to the left around [self] ([self]'s right child becomes [self], and
    /// the old [self] becomes the new [self]'s left child)
    fn rotate_left(&mut self) {
        let old_right = self.right.take().unwrap();

        let mut new_left = Box::new(Self::new(self.element.take().unwrap()));
        new_left.left = self.left.take();
        new_left.right = old_right.left;
        new_left.update();

        self.left = Some(new_left);
        self.element = old_right.element;
        self.right = old_right.right;

        self.update();
    }

    /// Rotates elements to the right around [self] ([self]'s left child becomes [self], and
    /// the old [self] becomes the new [self]'s right child)
    fn rotate_right(&mut self) {
        let old_left = self.left.take().unwrap();

        let mut new_right = Box::new(Self::new(self.element.take().unwrap()));
        new_right.left = old_left.right;
        new_right.right = self.right.take();
        new_right.update();

        self.right = Some(new_right);
        self.element = old_left.element;
        self.left = old_left.left;

        self.update();
    }

    /// Updates the [Self::child_depth] and [Self::skew] of [self], and if a rebalance is needed,
    /// performs the rebalance.
    ///
    /// This must *ONLY* be called after the [Self::left] and [Self::right] children have been
    /// updated.
    fn update(&mut self) {
        let left_depth = self.left.as_ref().map_or(0, |c| c.child_depth);
        let right_depth = self.right.as_ref().map_or(0, |c| c.child_depth);

        self.child_depth = left_depth.max(right_depth) + 1;
        self.skew = right_depth as i32 - left_depth as i32;

        if self.skew > 1 {
            if let Some(right) = self.right.as_mut() {
                if right.skew < 0 {
                    right.rotate_right();
                }
            }
            self.rotate_left()
        } else if self.skew < -1 {
            if let Some(left) = self.left.as_mut() {
                if left.skew > 0 {
                    left.rotate_left();
                }
            }
            self.rotate_right()
        }
    }
    /// Inserts a new element into the tree under [self], rebalancing if needed.
    fn insert(&mut self, elem: T, combine_ctx: &mut dyn Any) {
        let comparison = elem.cmp(self.element.as_mut().unwrap());

        match comparison {
            OverlapComparison::Greater => {
                match self.right.as_mut() {
                    Some(node) => node.insert(elem, combine_ctx),
                    None => self.right = Some(Box::new(Self::new(elem))),
                };
            }
            OverlapComparison::Less => {
                match self.left.as_mut() {
                    Some(node) => node.insert(elem, combine_ctx),
                    None => self.left = Some(Box::new(Self::new(elem))),
                };
            }
            OverlapComparison::Overlap => {
                let mut overlapping = vec![];

                if self
                    .left
                    .as_mut()
                    .map_or(false, |n| n.remove_overlapping(&elem, &mut overlapping))
                {
                    self.left = None;
                }

                overlapping.push(self.element.take().unwrap());

                if self
                    .right
                    .as_mut()
                    .map_or(false, |n| n.remove_overlapping(&elem, &mut overlapping))
                {
                    self.right = None;
                }

                let mut replacements = elem.combine(overlapping, combine_ctx).into_iter();

                self.element = Some(
                    replacements
                        .next()
                        .expect("Combination must result in at least one element"),
                );
                self.update();

                for elem in replacements {
                    self.insert(elem, combine_ctx);
                }

                return;
            }
        };

        self.update();
    }
    /// Consumes [self] to move all elements into `vec`.
    fn extract_all(self, vec: &mut Vec<T>) {
        self.left.map(|node| node.extract_all(vec));
        vec.push(self.element.unwrap());
        self.right.map(|node| node.extract_all(vec));
    }
    /// Consumes all children that overlap with `elem`, and if [self] also overlaps,
    /// finds a child to replace the current [Self::element]. If no such child could
    /// be found, returns `true`. In this case, the caller should either remove [self]
    /// as a child from its parent or replace [Self::element]. Removed elements are
    /// placed into `removed`.
    fn remove_overlapping(&mut self, elem: &T, removed: &mut Vec<T>) -> bool {
        let comparison = elem.cmp(self.element.as_mut().unwrap());

        match comparison {
            OverlapComparison::Greater => {
                let prune_right = self
                    .right
                    .as_mut()
                    .map_or(false, |n| n.remove_overlapping(elem, removed));
                if prune_right {
                    self.right = None;
                }
                self.update();
                false
            }
            OverlapComparison::Less => {
                let prune_left = self
                    .left
                    .as_mut()
                    .map_or(false, |n| n.remove_overlapping(elem, removed));
                if prune_left {
                    self.left = None;
                }
                self.update();
                false
            }
            OverlapComparison::Overlap => {
                let prune_left = self
                    .left
                    .as_mut()
                    .map_or(true, |n| n.remove_overlapping(elem, removed));

                removed.push(self.element.take().unwrap());

                let prune_right = self
                    .right
                    .as_mut()
                    .map_or(true, |n| n.remove_overlapping(elem, removed));

                if prune_left {
                    self.left = None;
                }
                if prune_right {
                    self.right = None;
                }

                /* `remove_overlapping` is only ever called from `insert` when `self` overlaps
                 * the element being inserted. `remove_overlapping` is then called on the left
                 * and right child of `self`. In this case, one of the children - or one of the
                 * children's children (or so on) - also overlaps the element being inserted.
                 * Given that the tree is sorted, every element between `self` and the node on
                 * which `insert` was called must necessarily overlap `elem`. Therefore, one of
                 * `prune_left` or `prune_right` must be true. This will only ever fail if the
                 * comparison function violates transitivity. */
                match (prune_left, prune_right) {
                    (true, true) => true,
                    (true, false) => {
                        let old_right = self.right.take().unwrap();
                        let _ = std::mem::replace(self, *old_right);
                        false
                    }
                    (false, true) => {
                        let old_left = self.left.take().unwrap();
                        let _ = std::mem::replace(self, *old_left);
                        false
                    }
                    (false, false) => panic!("Mass removal invariants violated."),
                }
            }
        }
    }
}

impl<T> MergeSet<T>
where
    T: Sized + OverlapComparable + Debug,
{
    /// Instantiates a new, empty [MergeSet]
    pub fn new() -> Self {
        Self { root: None }
    }
    /// Adds an element to [self], combining with existing overlapping elements.
    pub fn insert(&mut self, elem: T, combine_ctx: &mut dyn Any) {
        if let Some(node) = self.root.as_mut() {
            node.insert(elem, combine_ctx);
        } else {
            self.root = Some(Box::new(MergeSetNode::new(elem)));
        }
    }
    /// Extracts a [Vec] of all non-overlapping members, where overlapping members have
    /// been combined.
    pub fn extract_members(&mut self) -> Vec<T> {
        let mut vec = Vec::new();
        self.root.take().map(|node| node.extract_all(&mut vec));
        vec
    }
}
