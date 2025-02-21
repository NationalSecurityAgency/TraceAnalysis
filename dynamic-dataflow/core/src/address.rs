use crate::space::{Space, SpaceKind};

/// Location in an abstract memory space.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    space: Space,
    offset: u64,
}

impl Address {
    #[inline]
    pub const fn new(space: Space, offset: u64) -> Self {
        Self {
            space,
            offset: offset & space.mask(),
        }
    }

    #[inline]
    pub const fn space(&self) -> Space {
        self.space
    }

    #[inline]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[inline]
    pub fn is_const_zero(&self) -> bool {
        self.offset == 0 && self.space().kind() == SpaceKind::Constant
    }
}

impl std::ops::Add<u64> for Address {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self {
            space: self.space(),
            offset: self.offset.wrapping_add(rhs) & self.space.mask(),
        }
    }
}

impl std::ops::AddAssign<u64> for Address {
    fn add_assign(&mut self, rhs: u64) {
        self.offset = self.offset.wrapping_add(rhs) & self.space.mask();
    }
}

impl std::ops::Sub<u64> for Address {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self {
            space: self.space(),
            offset: self.offset.wrapping_sub(rhs) & self.space.mask(),
        }
    }
}

impl std::ops::SubAssign<u64> for Address {
    fn sub_assign(&mut self, rhs: u64) {
        self.offset = self.offset.wrapping_sub(rhs) & self.space.mask();
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct AddressRange {
    space: Space,
    offset: u64,
    size: u64,
}

impl AddressRange {
    #[inline]
    pub const fn new(space: Space, offset: u64, size: u64) -> Self {
        Self {
            space,
            offset: offset & space.mask(),
            size,
        }
    }

    #[inline]
    pub const fn space(&self) -> Space {
        self.space
    }

    #[inline]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[inline]
    pub const fn first(&self) -> Option<Address> {
        if self.size == 0 {
            return None;
        }
        Some(Address {
            space: self.space,
            offset: self.offset,
        })
    }

    #[inline]
    pub fn last(&self) -> Option<Address> {
        if self.size == 0 {
            return None;
        }
        Some(Address {
            space: self.space,
            offset: self.offset.wrapping_add(self.size).wrapping_sub(1) & self.space.mask(),
        })
    }

    #[inline]
    pub fn contains(&self, address: Address) -> bool {
        if self.space != address.space {
            return false;
        }

        let Some((start, end)) = self.first().and_then(|s| self.last().map(|e| (s, e))) else {
            return false;
        };

        if start.offset > end.offset {
            return address.offset >= start.offset || address.offset <= end.offset;
        }

        address.offset >= start.offset && address.offset <= end.offset
    }

    #[inline]
    pub fn iter(&self) -> AddressRangeIter {
        AddressRangeIter(*self)
    }
}

pub struct AddressRangeIter(AddressRange);

impl Iterator for AddressRangeIter {
    type Item = Address;
    fn next(&mut self) -> Option<Self::Item> {
        let address = self.0.first()?;
        self.0.size -= 1;
        self.0.offset = self.0.offset.wrapping_add(1) & self.0.space.mask();
        Some(address)
    }
}

impl DoubleEndedIterator for AddressRangeIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        let address = self.0.last()?;
        self.0.size -= 1;
        Some(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::SpaceAttributes;

    #[test]
    fn ensure_range_increments() {
        let space = Space::new(0, SpaceAttributes::CONSTANT, 8, 1);
        let range = space.index(0..4);
        let mut iter = range.iter();
        assert_eq!(iter.next(), Some(space.index(0)));
        assert_eq!(iter.next(), Some(space.index(1)));
    }

    #[test]
    fn ensure_range_wraps() {
        let space = Space::new(0, SpaceAttributes::CONSTANT, 2, 1);
        let range = space.index(u16::MAX as u64..3);
        let mut iter = range.iter();
        assert_eq!(iter.next(), Some(space.index(u16::MAX as u64)));
        assert_eq!(iter.next(), Some(space.index(0)));
    }

    #[test]
    fn ensure_range_decrements() {
        let space = Space::new(0, SpaceAttributes::CONSTANT, 8, 1);
        let range = space.index(0..4);
        let mut iter = range.iter();
        assert_eq!(iter.next_back(), Some(space.index(3)));
        assert_eq!(iter.next_back(), Some(space.index(2)));
    }
}
