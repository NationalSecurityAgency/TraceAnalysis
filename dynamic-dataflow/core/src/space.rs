use crate::address::{Address, AddressRange};

use std::ops::{Range, RangeInclusive};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Space {
    index: u16,
    attrs: u16,
    addr_size: u8,
    word_size: u8,
}

impl Space {
    pub const fn new(index: u16, attrs: SpaceAttributes, addr_size: u8, word_size: u8) -> Self {
        Self {
            index,
            attrs: attrs.0,
            addr_size,
            word_size,
        }
    }

    #[inline]
    pub const fn mask(&self) -> u64 {
        let word_size = self.word_size as u64;
        let n: u64 = match self.addr_size {
            0 => 0x0000_0000_0000_0000,
            1 => 0x0000_0000_0000_00ff,
            2 => 0x0000_0000_0000_ffff,
            3 => 0x0000_0000_00ff_ffff,
            4 => 0x0000_0000_ffff_ffff,
            5 => 0x0000_00ff_ffff_ffff,
            6 => 0x0000_ffff_ffff_ffff,
            7 => 0x00ff_ffff_ffff_ffff,
            _ => 0xffff_ffff_ffff_ffff,
        };
        n.wrapping_mul(word_size)
            .wrapping_add(word_size.wrapping_sub(1))
    }

    #[inline]
    pub fn id(&self) -> u16 {
        self.index & 0xfff
    }

    #[inline]
    pub fn kind(&self) -> SpaceKind {
        match self.attrs & 0b111 {
            0b000 => SpaceKind::Register,
            0b001 => SpaceKind::Constant,
            0b010 => SpaceKind::Memory,
            0b011 => SpaceKind::Unique,
            _ => SpaceKind::Other,
        }
    }

    #[inline]
    pub fn addr_size(&self) -> u8 {
        self.addr_size
    }

    #[inline]
    pub fn word_size(&self) -> u8 {
        self.word_size
    }

    #[inline]
    pub fn big_endian(&self) -> bool {
        self.attrs & 0b1000 != 0
    }

    #[inline]
    pub fn index<I>(&self, index: I) -> I::Output
    where
        I: SpaceIndex,
    {
        I::index(index, self)
    }
}

pub trait SpaceIndex {
    type Output;
    fn index(self, space: &Space) -> Self::Output;
}

impl SpaceIndex for u64 {
    type Output = Address;
    fn index(self, space: &Space) -> Self::Output {
        Address::new(*space, self & space.mask())
    }
}

impl SpaceIndex for Range<u64> {
    type Output = AddressRange;
    fn index(self, space: &Space) -> Self::Output {
        let std::ops::Range { start, end } = self;
        AddressRange::new(*space, start & space.mask(), end.wrapping_sub(start))
    }
}

impl SpaceIndex for RangeInclusive<u64> {
    type Output = AddressRange;
    fn index(self, space: &Space) -> Self::Output {
        let (start, end) = self.into_inner();
        AddressRange::new(
            *space,
            start & space.mask(),
            end.wrapping_sub(start).wrapping_add(1),
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SpaceKind {
    Constant = 3, // These numbers are being kept for compatibilty but will be deprecated soon
    Register = 0,
    Memory = 1,
    Unique = 2,
    Other = 4,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SpaceAttributes(pub u16);

impl SpaceAttributes {
    pub const REGISTER: Self = Self(0b00);
    pub const CONSTANT: Self = Self(0b01);
    pub const MEMORY: Self = Self(0b10);
    pub const UNIQUE: Self = Self(0b11);
    pub const BIG_ENDIAN: Self = Self(0b1000);
}

impl std::ops::BitOr for SpaceAttributes {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

pub trait SpaceManager {
    fn register_space(&self) -> Space;
    fn default_data_space(&self) -> Space;
    fn default_code_space(&self) -> Space;
    fn unique_space(&self) -> Space;
    fn constant_space(&self) -> Space;

    fn space_by_name(&self, name: &str) -> Option<Space>;
    fn space_by_id(&self, id: u16) -> Option<Space>;
}
