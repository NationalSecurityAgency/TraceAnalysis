use crate::address::{Address, AddressRange};
use crate::slot::Slot;

/// This type is a log of all the read and write operations that happened in
/// a given instruction.
pub struct OpLog(Vec<OpType>);

impl OpLog {
    /// Creates a new `OpLog`.
    ///
    /// Allocates a fairly large space upfront to avoid any allocations again
    /// in the future.
    pub fn new() -> Self {
        Self(Vec::with_capacity(8192))
    }

    pub fn writes<'a>(&'a self) -> impl Iterator<Item = (Address, u8)> + 'a {
        self.0.iter().filter_map(move |&op| {
            if let OpType::Write(address, value) = op {
                return Some((address, value));
            }
            None
        })
    }

    pub fn reads<'a>(&'a self) -> impl Iterator<Item = (Address, u8)> + 'a {
        self.0.iter().filter_map(move |&op| {
            if let OpType::Read(address, value) = op {
                return Some((address, value));
            }
            None
        })
    }

    /// Returns an iterator to all writes that occured within a given
    /// `AddressRange`
    pub fn writes_in_range<'a>(
        &'a self,
        range: &AddressRange,
    ) -> impl Iterator<Item = (Address, u8)> + 'a {
        let range = *range;
        self.0.iter().filter_map(move |&op| {
            if let OpType::Write(address, value) = op {
                if range.contains(address) {
                    return Some((address, value));
                }
            }
            None
        })
    }

    /// Returns an iterator to all reads that occured within a given
    /// `AddressRange`
    pub fn reads_in_range<'a>(
        &'a self,
        range: &AddressRange,
    ) -> impl Iterator<Item = (Address, u8)> + 'a {
        let range = *range;
        self.0.iter().filter_map(move |&op| {
            if let OpType::Read(address, value) = op {
                if range.contains(address) {
                    return Some((address, value));
                }
            }
            None
        })
    }

    pub fn fill_with_writes(&self, slot: &mut Slot) {
        let range = slot.as_range();
        self.writes_in_range(&range).for_each(|op| {
            let (address, byte) = op;
            let offset = address.offset() - range.offset();
            slot.value.set(offset as _, byte);
        });
    }

    pub fn fill_with_reads(&self, slot: &mut Slot) {
        let range = slot.as_range();
        self.reads_in_range(&range).for_each(|op| {
            let (address, byte) = op;
            let offset = address.offset() - range.offset();
            slot.value.set(offset as _, byte);
        });
    }

    /// Record that a write occured at an `Address` with a particular value.
    pub fn insert_write(&mut self, address: &Address, value: u8) {
        self.0.push(OpType::Write(*address, value));
    }

    /// Record that a read occured at an `Address` with a particular value.
    pub fn insert_read(&mut self, address: &Address, value: u8) {
        self.0.push(OpType::Read(*address, value));
    }

    /// Clears the `OpLog` without deallocating memory.
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Copy, Clone)]
enum OpType {
    Write(Address, u8),
    Read(Address, u8),
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::space::{Space, SpaceAttributes};

    #[test]
    fn test_check_writes() {
        let mut oplog = OpLog::new();
        let space = Space::new(0, SpaceAttributes::MEMORY, 8, 1);
        let range = space.index(0x100..0x104);
        for (i, a) in range.iter().enumerate() {
            oplog.insert_write(&a, i as u8);
            oplog.insert_read(&a, i as u8);
        }

        let mut writes = oplog.writes_in_range(&range);
        let mut address = space.index(0x100);

        assert_eq!(writes.next(), Some((address, 0x0)));
        address += 1;
        assert_eq!(writes.next(), Some((address, 0x1)));
        address += 1;
        assert_eq!(writes.next(), Some((address, 0x2)));
        address += 1;
        assert_eq!(writes.next(), Some((address, 0x3)));
        assert_eq!(writes.next(), None);
    }
}
