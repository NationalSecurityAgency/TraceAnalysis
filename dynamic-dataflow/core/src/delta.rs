use std::fmt;
use std::iter::FromIterator;
use std::mem::MaybeUninit;

use crate::address::AddressRange;
use crate::slot::Slot;
use crate::value::SizedValue;
use crate::Index;

/// This type represents a change of state to the system.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Delta {
    Controlflow(Slot, Option<AddressRange>),
    Dataflow(Slot, Option<AddressRange>),
}

impl Delta {
    pub fn associated_range(delta: &Delta) -> Option<AddressRange> {
        match delta {
            Self::Controlflow(_, a) => *a,
            Self::Dataflow(_, a) => *a,
        }
    }

    pub fn is_controlflow(delta: &Delta) -> bool {
        match delta {
            Self::Controlflow(_, _) => true,
            _ => false,
        }
    }

    pub fn is_dataflow(delta: &Delta) -> bool {
        match delta {
            Self::Dataflow(_, _) => true,
            _ => false,
        }
    }
}

impl std::ops::Deref for Delta {
    type Target = Slot;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Controlflow(s, _) => s,
            Self::Dataflow(s, _) => s,
        }
    }
}

impl std::ops::DerefMut for Delta {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Controlflow(s, _) => s,
            Self::Dataflow(s, _) => s,
        }
    }
}

impl fmt::Display for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Controlflow(_, _) => {
                write!(f, "Controlflow")?;
            }
            Self::Dataflow(_, _) => {
                write!(f, "Dataflow")?;
            }
        }
        <Slot as fmt::Display>::fmt(self, f)
    }
}

//pub type Delta = Slot;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct AddressDep {
    pub index: Index,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ValueDep {
    pub index: Index,
    pub pos: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConstAddressDep {
    pub value: SizedValue,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConstValueDep {
    pub value: SizedValue,
    pub pos: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeltaDep {
    Address(AddressDep),
    Value(ValueDep),
    ConstAddress(ConstAddressDep),
    ConstValue(ConstValueDep),
}

/// This type represents an adjacency list for a `Delta`.
///
/// A `Delta::Dataflow` can depend on another `Delta` either for the `Value`
/// it writes, or for the `AddressRange` it writes to. In the case of the
/// `Value`, this is true even if the `Value` the previous `Delta` wrote
/// is unknown. This is not true for the `AddressRange` of a `Delta` because
/// if the `AddressRange` is not known, then the `Delta` serves no purpose
/// in analysis.
///
/// This data structure acts like a fixed sized Vec to avoid constant heap
/// allocation. It's size is tunable at compile time.
#[derive(Clone)]
pub struct DeltaDeps {
    data: [MaybeUninit<Index>; Self::MAX_DEPS],
    pos: [u8; Self::MAX_DEPS],
    length: usize,
}

impl DeltaDeps {
    const MAX_DEPS: usize = 128;

    /// Constructs a new, empty adjacency list.
    ///
    /// This method will not allocate.
    pub fn new() -> Self {
        Self {
            data: unsafe { MaybeUninit::uninit().assume_init() },
            pos: [0; Self::MAX_DEPS],
            length: 0,
        }
    }

    /// Adds a new dependency to the adjacency list.
    ///
    /// # Notes
    ///
    /// - This method currently dedups the dependencies added, but may avoid
    ///   doing so in the future.
    /// - This method will panic if dependencies exceed a pre-set maximum
    ///   (currently 24)
    pub fn push(&mut self, index: Index, pos: u8) {
        if self.iter().any(|(x, p)| x == index && p == pos) {
            return ();
        }

        assert!(
            self.length < Self::MAX_DEPS,
            "exceeding max dependencies for delta"
        );

        self.data[self.length] = MaybeUninit::new(index);
        self.pos[self.length] = pos;
        self.length += 1;
    }

    /// This method is an alias for `extend_left` still present for backwards compatibility.
    pub fn extend<'a, I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = &'a Option<Index>>,
    {
        Self::extend_left(self, iter)
    }

    /// This method fills the adjacency list with items from the `Iterator` and records them in the
    /// 0th position.
    #[inline]
    pub fn extend_left<'a, I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = &'a Option<Index>>,
    {
        self.extend_with_pos(iter.into_iter().filter_map(|&x| Some((x?, 0))))
    }

    /// This method fills the adjacency list with items from the `Iterator` and records them in the
    /// 1st position.
    pub fn extend_right<'a, I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = &'a Option<Index>>,
    {
        self.extend_with_pos(iter.into_iter().filter_map(|&x| Some((x?, 1))))
    }

    /// This method fills the adjacency list with items from the `Iterator`.
    #[inline]
    pub fn extend_with_pos<'a, I>(&mut self, iter: I)
    where
        I: Iterator<Item = (Index, u8)>,
    {
        iter.for_each(|(i, p)| self.push(i, p))
    }

    /// This method rreturns an `Iterator` to all of the depencies in the list.
    pub fn iter<'a>(&'a self) -> DeltaDepsIter<'a> {
        DeltaDepsIter::new(self)
    }
}

impl fmt::Debug for DeltaDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = unsafe { std::mem::transmute::<_, &[Index]>(&self.data[..self.length]) };
        //let value: Vec<Index> = self.iter().collect();
        f.debug_tuple("DeltaDeps")
            .field(&value)
            .field(&&self.pos[..self.length])
            .finish()
    }
}

impl<'a> FromIterator<&'a Option<Index>> for DeltaDeps {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a Option<Index>>,
    {
        let mut this = Self::new();
        this.extend(iter);
        this
    }
}

/// This type is an `Iterator` on the dependencies of an adjacency list.
pub struct DeltaDepsIter<'a> {
    deps: &'a DeltaDeps,
    pos: usize,
}

impl<'a> DeltaDepsIter<'a> {
    fn new(deps: &'a DeltaDeps) -> Self {
        Self { deps, pos: 0 }
    }
}

impl Iterator for DeltaDepsIter<'_> {
    type Item = (Index, u8);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.deps.length {
            let item = unsafe { self.deps.data[self.pos].assume_init() };
            self.pos += 1;
            return Some((item, self.deps.pos[self.pos]));
        }

        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_delta_deps() {
        let a: [Option<Index>; 4] = [Some(1), Some(2), None, None];

        let deps: DeltaDeps = a.iter().collect();
        let mut iter = deps.iter();

        assert_eq!(iter.next(), Some((1, 0)));
        assert_eq!(iter.next(), Some((2, 0)));
        assert_eq!(iter.next(), None);
    }
}
