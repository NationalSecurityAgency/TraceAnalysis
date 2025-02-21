use crate::address::{Address, AddressRange};
use crate::space::{Space, SpaceAttributes};
use crate::value::{PartialValue, SizedValue};
use std::fmt;

/// This type represents an `AddressRange` along with the `Value`
/// at that range.
///
/// It may not always be possible to know what the `Value` is at a given
/// `Address` so the `Value` may be `None`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Slot {
    pub space: Space,
    pub offset: u64,
    pub size: u64,
    pub value: PartialValue,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            space: Space::new(255, SpaceAttributes(0b0101), 8, 1),
            offset: 0,
            size: 0,
            value: PartialValue::new(),
        }
    }
}

impl Slot {
    /// Returns this `Slot` as an `AddressRange`.
    pub fn as_range(&self) -> AddressRange {
        AddressRange::new(self.space, self.offset, self.size)
    }

    /// Returns the byte value of a particular `Address` within this `Slot`
    /// if the `Address` is within the `Slot` and the `Value` is known.
    pub fn value_at(&self, address: Address) -> Option<u8> {
        let range = self.as_range();
        if !range.contains(address) {
            return None;
        }
        let offset = address.offset() - self.offset;
        self.value.get(offset as usize).map(|b| *b)
    }

    /// Sets the byte-value of an address within this slot's range
    pub fn set_value(&mut self, address: Address, value: u8) {
        let range = self.as_range();
        if !range.contains(address) {
            return ();
        }
        let offset = address.offset() - self.offset;
        self.value.set(offset as usize, value);
    }

    /// Returns the correctly sized-value of this slot if all
    /// of the bytes have been set within the slot's range.
    pub fn as_complete(&self) -> Option<SizedValue> {
        self.value.as_sized(self.size as usize)
    }

    pub fn byte_swap(&mut self) {
        let mut value = PartialValue::new();
        let size = self.size as usize;
        for i in 0..size {
            let i = i as usize;
            value.set_or_unset(i, self.value.get(size - i - 1).map(|&v| v));
        }
        self.value = value;
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sized = self.value.as_sized(self.size as _);
        write!(
            f,
            "({:?}, {:#x}, {}, {:x?})",
            self.space, self.offset, self.size, sized
        )
    }
}

impl From<AddressRange> for Slot {
    fn from(v: AddressRange) -> Self {
        Self {
            space: v.space(),
            offset: v.offset(),
            size: v.size(),
            value: Default::default(),
        }
    }
}

impl From<&AddressRange> for Slot {
    fn from(v: &AddressRange) -> Self {
        Self::from(*v)
    }
}

impl From<(&AddressRange, PartialValue)> for Slot {
    fn from((range, value): (&AddressRange, PartialValue)) -> Self {
        Self {
            space: range.space(),
            offset: range.offset(),
            size: range.size(),
            value: value,
        }
    }
}
