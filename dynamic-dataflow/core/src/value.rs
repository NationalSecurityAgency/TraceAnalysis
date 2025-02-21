use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Index, IndexMut, Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub,
    SubAssign,
};

/// New API for working with value making it more ergonomic to perform
/// calculations and represent incomplete value.
///
/// Specifically, it is benficial to be able to represent an incomplete
/// value without it being an all-or-nothing `Option<Value>`. More on
/// that later.
///
/// Likewise, we would like to perform all possible arithmetic operations
/// on values via operators without resorting to calling methods.
/// Previously, that was done by assuming if the value was a `SizedValue`
/// then it was also signed. This time, `SizedValue` makes no assumptions
/// on signed-ness, it only represents a complete value. To distinguish
/// signed types and unsigned type, transparent wrapper types are
/// introduced. This way, when signed-ness does not matter for an operation
/// it can be performed on `SizedValue`. However, for the handful of
/// operations where signed-ness does matter, the type is just wrapped
/// with the correct wrapper.
///

/// Represents a partially initialized value
///
/// This type keeps track of which bytes are set within its value so that
/// it can safely expose concrete values if the correct layout is set.
///
/// This type is not useful for most arithmetic operations since the size
/// is relavant for those operations. Therefore, most calculation will
/// require a conversion to `SizedValue`.
#[derive(Default, Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct PartialValue {
    data: RawValue,
    bitmap: u32,
}

impl PartialValue {
    /// Default value is completely uninitialized
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns an initialized `u64` if the proper values are set
    pub fn as_u64(&self) -> Option<u64> {
        if self.bitmap.trailing_ones() as usize >= size_of::<u64>() {
            return Some(self.data.as_u64());
        }
        None
    }

    /// Returns an initialized `u32` if the proper values are set
    pub fn as_u32(&self) -> Option<u32> {
        if self.bitmap.trailing_ones() as usize >= size_of::<u32>() {
            return Some(self.data.as_u32());
        }
        None
    }

    /// Returns an initialized `u16` if the proper values are set
    pub fn as_u16(&self) -> Option<u16> {
        if self.bitmap.trailing_ones() as usize >= size_of::<u16>() {
            return Some(self.data.as_u16());
        }
        None
    }

    /// Returns an initialized `u8` if the proper values are set
    pub fn as_u8(&self) -> Option<u8> {
        if self.bitmap.trailing_ones() as usize >= size_of::<u8>() {
            return Some(self.data.as_u8());
        }
        None
    }

    /// Returns an initialized `i64` if the proper values are set
    pub fn as_i64(&self) -> Option<i64> {
        if self.bitmap.trailing_ones() as usize >= size_of::<i64>() {
            return Some(self.data.as_i64());
        }
        None
    }

    /// Returns an initialized `i32` if the proper values are set
    pub fn as_i32(&self) -> Option<i32> {
        if self.bitmap.trailing_ones() as usize >= size_of::<i32>() {
            return Some(self.data.as_i32());
        }
        None
    }

    /// Returns an initialized `i16` if the proper values are set
    pub fn as_i16(&self) -> Option<i16> {
        if self.bitmap.trailing_ones() as usize >= size_of::<i16>() {
            return Some(self.data.as_i16());
        }
        None
    }

    /// Returns an initialized `i8` if the proper values are set
    pub fn as_i8(&self) -> Option<i8> {
        if self.bitmap.trailing_ones() as usize >= size_of::<i8>() {
            return Some(self.data.as_i8());
        }
        None
    }

    /// Returns an initialized `bool` if the proper values are set
    ///
    /// # Note
    ///
    /// A boolean MUST have a value of 0 or 1 in it's least significant
    /// byte. Any other bit pattern is invalid
    pub fn as_bool(&self) -> Option<bool> {
        if let Some(byte) = self.as_u8() {
            return match byte {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            };
        }
        None
    }

    /// Returns a byte array of all the byte values
    ///
    /// Values will be `Some(u8)` if unitialized and `None` otherwise.
    pub fn as_raw(&self) -> [Option<u8>; RawValue::SIZE] {
        let mut result = [None; RawValue::SIZE];
        for (i, &byte) in self.data.as_raw().iter().enumerate() {
            if self.bitmap & (1u32 << i as u32) != 0 {
                result[i] = Some(byte);
            }
        }
        result
    }

    /// Returns a concrete `SizedValue` if the correct amount of bytes are
    /// initialized.
    pub fn as_sized(&self, size: usize) -> Option<SizedValue> {
        if self.bitmap.trailing_ones() as usize >= size {
            let mut value = SizedValue {
                value: Default::default(),
                size,
            };
            let raw = unsafe { &mut value.value.raw };
            raw[..size].copy_from_slice(&self.data.as_raw()[..size]);
            return Some(value);
        }
        None
    }

    /// Gets a byte value within this value or `None` if uninitialized
    pub fn get(&self, i: usize) -> Option<&u8> {
        if i >= RawValue::SIZE {
            return None;
        }
        if self.bitmap & (1u32 << i as u32) != 0 {
            return Some(&self.data[i]);
        }
        None
    }

    /// Get's a mutable byte value within this value or `None` if uninitialized
    pub fn get_mut(&mut self, i: usize) -> Option<&mut u8> {
        if i >= RawValue::SIZE {
            return None;
        }
        if self.bitmap & (1u32 << i as u32) != 0 {
            return Some(&mut self.data[i]);
        }
        None
    }

    /// Sets a byte value within this value
    pub fn set(&mut self, i: usize, value: u8) {
        assert!(i < RawValue::SIZE);
        self.bitmap |= 1u32 << i as u32;
        self.data[i] = value;
    }

    /// Sets or unsets a byte value within this value
    pub fn set_or_unset(&mut self, i: usize, value: Option<u8>) {
        assert!(i < RawValue::SIZE);
        if let Some(value) = value {
            self.bitmap |= 1u32 << i as u32;
            self.data[i] = value;
        } else {
            self.bitmap &= (1u32 << i as u32) ^ u32::MAX;
            self.data[i] = 0; // Should be unnecessary
        }
    }

    /// Returns true if no bytes have been set
    pub fn is_empty(&self) -> bool {
        self.bitmap == 0b0000_0000_0000_0000
    }
}

impl From<u128> for PartialValue {
    fn from(v: u128) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b1111_1111_1111_1111,
        }
    }
}

impl From<u64> for PartialValue {
    fn from(v: u64) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_1111_1111,
        }
    }
}

impl From<u32> for PartialValue {
    fn from(v: u32) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_1111,
        }
    }
}

impl From<u16> for PartialValue {
    fn from(v: u16) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_0011,
        }
    }
}

impl From<u8> for PartialValue {
    fn from(v: u8) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_0001,
        }
    }
}

impl From<i128> for PartialValue {
    fn from(v: i128) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b1111_1111_1111_1111,
        }
    }
}

impl From<i64> for PartialValue {
    fn from(v: i64) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_1111_1111,
        }
    }
}

impl From<i32> for PartialValue {
    fn from(v: i32) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_1111,
        }
    }
}

impl From<i16> for PartialValue {
    fn from(v: i16) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_0011,
        }
    }
}

impl From<i8> for PartialValue {
    fn from(v: i8) -> Self {
        Self {
            data: v.into(),
            bitmap: 0b0000_0000_0000_0001,
        }
    }
}

impl From<bool> for PartialValue {
    fn from(v: bool) -> Self {
        match v {
            true => Self::from(1u8),
            false => Self::from(0u8),
        }
    }
}

impl From<SizedValue> for PartialValue {
    fn from(v: SizedValue) -> Self {
        let SizedValue { value, size } = v;
        assert!(size <= RawValue::SIZE);
        let bitmap = u32::MAX >> (RawValue::SIZE as u32 - size as u32);
        Self {
            data: value,
            bitmap,
        }
    }
}

/// This type represents a variable sized integer
///
/// Arithmetic operations are safe to perform on this type so long
/// as the operands have matching sizes. Other operations outside of the
/// standard unary and binary operations are defined for this type
/// such as checking for flags.
///
/// In general, most operations are exposed with operators; however, some
/// are not as the implementation would vary based on signed-ness. In these
/// cases, wrapper types are used to dispatch to the correct functions.
///
/// These are not actually as flexible as a true variable sized integer, since
/// they currently only support sized that can be lowered into primitive types.
/// That may change in the future to support slow paths for weird sizes.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SizedValue {
    value: RawValue,
    size: usize,
}

// PRIVATE API
//
// These functions are not "safe" to expose b/c they don't tell you what you
// think they should. For example, a signed value with size 1 would expect to
// be sign extended when the `as_i16` function is called. However, that is not
// what happens with these functions.
//
// These functions exist solely to lower the type into a primitive for fast
// operations. Thus, there is limited use for these outside of the public
// api, and so they are kept private.
//
// I believe this also assists inlining if the compiler knows that they cannot
// be used outside of this module.

impl SizedValue {
    #[inline]
    fn as_u128(&self) -> u128 {
        self.value.as_u128()
    }

    #[inline]
    fn as_u64(&self) -> u64 {
        self.value.as_u64()
    }

    #[inline]
    fn as_u32(&self) -> u32 {
        self.value.as_u32()
    }

    #[inline]
    fn as_u16(&self) -> u16 {
        self.value.as_u16()
    }

    #[inline]
    fn as_u8(&self) -> u8 {
        self.value.as_u8()
    }

    #[inline]
    fn as_i128(&self) -> i128 {
        self.value.as_i128()
    }

    #[inline]
    fn as_i64(&self) -> i64 {
        self.value.as_i64()
    }

    #[inline]
    fn as_i32(&self) -> i32 {
        self.value.as_i32()
    }

    #[inline]
    fn as_i16(&self) -> i16 {
        self.value.as_i16()
    }

    #[inline]
    fn as_i8(&self) -> i8 {
        self.value.as_i8()
    }

    #[inline]
    pub fn as_usize(&self) -> usize {
        match self.size {
            1 => self.value.as_u8() as usize,
            2 => self.value.as_u16() as usize,
            4 => self.value.as_u32() as usize,
            8 => self.value.as_u64() as usize,
            16 => self.value.as_u128() as usize,
            _ => unimplemented!(),
        }
    }
}

const fn true_helper<const N: usize>() -> [u8; N] {
    let mut raw = [0u8; N];
    raw[0] = 1;
    raw
}

impl SizedValue {
    // Short hands for canonical true and false values
    const TRUE: Self = Self {
        value: RawValue { raw: true_helper() },
        size: 1,
    };
    const FALSE: Self = Self {
        value: RawValue {
            raw: [0; RawValue::SIZE],
        },
        size: 1,
    };

    pub fn new(value: isize, size: usize) -> Self {
        match size {
            1 => Self::from(value as i8),
            2 => Self::from(value as i16),
            4 => Self::from(value as i32),
            8 => Self::from(value as i64),
            16 => Self::from(value as i128),
            _ => unimplemented!(),
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn int_equal(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.value == other.value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_notequal(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.value != other.value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_less(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let value = match self.size {
            1 => self.as_u8() < other.as_u8(),
            2 => self.as_u16() < other.as_u16(),
            4 => self.as_u32() < other.as_u32(),
            8 => self.as_u64() < other.as_u64(),
            16 => self.as_u128() < other.as_u128(),
            _ => unimplemented!(),
        };
        match value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_sless(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let value = match self.size {
            1 => self.as_i8() < other.as_i8(),
            2 => self.as_i16() < other.as_i16(),
            4 => self.as_i32() < other.as_i32(),
            8 => self.as_i64() < other.as_i64(),
            16 => self.as_i128() < other.as_i128(),
            _ => unimplemented!(),
        };
        match value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_lessequal(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let value = match self.size {
            1 => self.as_u8() <= other.as_u8(),
            2 => self.as_u16() <= other.as_u16(),
            4 => self.as_u32() <= other.as_u32(),
            8 => self.as_u64() <= other.as_u64(),
            16 => self.as_u128() <= other.as_u128(),
            _ => unimplemented!(),
        };
        match value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_slessequal(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let value = match self.size {
            1 => self.as_i8() <= other.as_i8(),
            2 => self.as_i16() <= other.as_i16(),
            4 => self.as_i32() <= other.as_i32(),
            8 => self.as_i64() <= other.as_i64(),
            16 => self.as_i128() <= other.as_i128(),
            _ => unimplemented!(),
        };
        match value {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_zext(&self, size: usize) -> Self {
        assert!(size > self.size);
        let mut extended = Self {
            value: RawValue::default(),
            size,
        };
        let value = unsafe { &mut extended.value.raw[..self.size] };
        value.copy_from_slice(&self.value.as_raw()[..self.size]);
        extended
    }

    pub fn int_sext(&self, size: usize) -> Self {
        assert!(size > self.size);
        let negative = self.value[self.size - 1] & 0x80 == 0x80;
        let mut extended = match negative {
            true => Self {
                value: RawValue {
                    raw: [0xff; RawValue::SIZE],
                },
                size,
            },
            false => Self {
                value: Default::default(),
                size,
            },
        };
        let value = unsafe { &mut extended.value.raw[..self.size] };
        value.copy_from_slice(&self.value.as_raw()[..self.size]);
        extended
    }

    pub fn int_add(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8().wrapping_add(other.as_u8())),
            2 => Self::from(self.as_u16().wrapping_add(other.as_u16())),
            4 => Self::from(self.as_u32().wrapping_add(other.as_u32())),
            8 => Self::from(self.as_u64().wrapping_add(other.as_u64())),
            16 => Self::from(self.as_u128().wrapping_add(other.as_u128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_sub(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8().wrapping_sub(other.as_u8())),
            2 => Self::from(self.as_u16().wrapping_sub(other.as_u16())),
            4 => Self::from(self.as_u32().wrapping_sub(other.as_u32())),
            8 => Self::from(self.as_u64().wrapping_sub(other.as_u64())),
            16 => Self::from(self.as_u128().wrapping_sub(other.as_u128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_carry(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let flag = match self.size {
            1 => self.as_u8().overflowing_add(other.as_u8()).1,
            2 => self.as_u16().overflowing_add(other.as_u16()).1,
            4 => self.as_u32().overflowing_add(other.as_u32()).1,
            8 => self.as_u64().overflowing_add(other.as_u64()).1,
            16 => self.as_u128().overflowing_add(other.as_u128()).1,
            _ => unimplemented!(),
        };
        match flag {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_scarry(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        let flag = match self.size {
            1 => self.as_i8().overflowing_add(other.as_i8()).1,
            2 => self.as_i16().overflowing_add(other.as_i16()).1,
            4 => self.as_i32().overflowing_add(other.as_i32()).1,
            8 => self.as_i64().overflowing_add(other.as_i64()).1,
            16 => self.as_i128().overflowing_add(other.as_i128()).1,
            _ => unimplemented!(),
        };
        match flag {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_sborrow(&self, other: &Self) -> Self {
        let flag = match self.size {
            1 => self.as_i8().overflowing_sub(other.as_i8()).1,
            2 => self.as_i16().overflowing_sub(other.as_i16()).1,
            4 => self.as_i32().overflowing_sub(other.as_i32()).1,
            8 => self.as_i64().overflowing_sub(other.as_i64()).1,
            _ => unimplemented!(),
        };
        match flag {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }

    pub fn int_2comp(&self) -> Self {
        match self.size {
            1 => Self::from(self.as_i8().neg()),
            2 => Self::from(self.as_i16().neg()),
            4 => Self::from(self.as_i32().neg()),
            8 => Self::from(self.as_i64().neg()),
            16 => Self::from(self.as_i128().neg()),
            _ => unimplemented!(),
        }
    }

    pub fn int_negate(&self) -> Self {
        match self.size {
            1 => Self::from(self.as_u8().not()),
            2 => Self::from(self.as_u16().not()),
            4 => Self::from(self.as_u32().not()),
            8 => Self::from(self.as_u64().not()),
            16 => Self::from(self.as_u128().not()),
            _ => unimplemented!(),
        }
    }

    pub fn int_xor(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8() ^ other.as_u8()),
            2 => Self::from(self.as_u16() ^ other.as_u16()),
            4 => Self::from(self.as_u32() ^ other.as_u32()),
            8 => Self::from(self.as_u64() ^ other.as_u64()),
            16 => Self::from(self.as_u128() ^ other.as_u128()),
            _ => unimplemented!(),
        }
    }

    pub fn int_and(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8() & other.as_u8()),
            2 => Self::from(self.as_u16() & other.as_u16()),
            4 => Self::from(self.as_u32() & other.as_u32()),
            8 => Self::from(self.as_u64() & other.as_u64()),
            16 => Self::from(self.as_u128() & other.as_u128()),
            _ => unimplemented!(),
        }
    }

    pub fn int_or(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8() | other.as_u8()),
            2 => Self::from(self.as_u16() | other.as_u16()),
            4 => Self::from(self.as_u32() | other.as_u32()),
            8 => Self::from(self.as_u64() | other.as_u64()),
            16 => Self::from(self.as_u128() | other.as_u128()),
            _ => unimplemented!(),
        }
    }

    pub fn int_left(&self, other: &Self) -> Self {
        let shift = match other.size {
            1 => other.as_u8() as u32,
            2 => other.as_u16() as u32,
            4 => other.as_u32(),
            8 => other.as_u32(),
            16 => other.as_u32(),
            _ => unimplemented!(),
        };
        match self.size {
            1 => match self.as_u8().overflowing_shl(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u8),
            },
            2 => match self.as_u16().overflowing_shl(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u16),
            },
            4 => match self.as_u32().overflowing_shl(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u32),
            },
            8 => match self.as_u64().overflowing_shl(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u64),
            },
            16 => match self.as_u128().overflowing_shl(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u128),
            },
            _ => unimplemented!(),
        }
    }

    pub fn int_right(&self, other: &Self) -> Self {
        let shift = match other.size {
            1 => other.as_u8() as u32,
            2 => other.as_u16() as u32,
            4 => other.as_u32(),
            8 => other.as_u32(),
            _ => unimplemented!(),
        };
        match self.size {
            1 => match self.as_u8().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u8),
            },
            2 => match self.as_u16().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u16),
            },
            4 => match self.as_u32().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u32),
            },
            8 => match self.as_u64().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u64),
            },
            16 => match self.as_u128().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => Self::from(0u128),
            },
            _ => unimplemented!(),
        }
    }

    pub fn int_sright(&self, other: &Self) -> Self {
        let shift = match other.size {
            1 => other.as_u8() as u32,
            2 => other.as_u16() as u32,
            4 => other.as_u32(),
            8 => other.as_u32(),
            _ => unimplemented!(),
        };
        let negative = self.value[self.size - 1] & 0x80 == 0x80;
        let overflow = match (self.size, negative) {
            (1, true) => Self::from(-1i8),
            (1, false) => Self::from(0i8),
            (2, true) => Self::from(-1i16),
            (2, false) => Self::from(0i16),
            (4, true) => Self::from(-1i32),
            (4, false) => Self::from(0i32),
            (8, true) => Self::from(-1i64),
            (8, false) => Self::from(0i64),
            (16, true) => Self::from(-1i128),
            (16, false) => Self::from(0i128),
            _ => unimplemented!(),
        };
        match self.size {
            1 => match self.as_i8().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => overflow,
            },
            2 => match self.as_i16().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => overflow,
            },
            4 => match self.as_i32().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => overflow,
            },
            8 => match self.as_i64().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => overflow,
            },
            16 => match self.as_i128().overflowing_shr(shift) {
                (value, false) => Self::from(value),
                (_, true) => overflow,
            },
            _ => unimplemented!(),
        }
    }

    pub fn int_mult(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8().wrapping_mul(other.as_u8())),
            2 => Self::from(self.as_u16().wrapping_mul(other.as_u16())),
            4 => Self::from(self.as_u32().wrapping_mul(other.as_u32())),
            8 => Self::from(self.as_u64().wrapping_mul(other.as_u64())),
            16 => Self::from(self.as_u128().wrapping_mul(other.as_u128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_div(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8().wrapping_div(other.as_u8())),
            2 => Self::from(self.as_u16().wrapping_div(other.as_u16())),
            4 => Self::from(self.as_u32().wrapping_div(other.as_u32())),
            8 => Self::from(self.as_u64().wrapping_div(other.as_u64())),
            16 => Self::from(self.as_u128().wrapping_div(other.as_u128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_rem(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_u8().wrapping_rem(other.as_u8())),
            2 => Self::from(self.as_u16().wrapping_rem(other.as_u16())),
            4 => Self::from(self.as_u32().wrapping_rem(other.as_u32())),
            8 => Self::from(self.as_u64().wrapping_rem(other.as_u64())),
            16 => Self::from(self.as_u128().wrapping_rem(other.as_u128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_sdiv(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_i8().wrapping_div_euclid(other.as_i8())),
            2 => Self::from(self.as_i16().wrapping_div_euclid(other.as_i16())),
            4 => Self::from(self.as_i32().wrapping_div_euclid(other.as_i32())),
            8 => Self::from(self.as_i64().wrapping_div_euclid(other.as_i64())),
            16 => Self::from(self.as_i128().wrapping_div_euclid(other.as_i128())),
            _ => unimplemented!(),
        }
    }

    pub fn int_srem(&self, other: &Self) -> Self {
        assert!(self.size == other.size);
        match self.size {
            1 => Self::from(self.as_i8().wrapping_rem_euclid(other.as_i8())),
            2 => Self::from(self.as_i16().wrapping_rem_euclid(other.as_i16())),
            4 => Self::from(self.as_i32().wrapping_rem_euclid(other.as_i32())),
            8 => Self::from(self.as_i64().wrapping_rem_euclid(other.as_i64())),
            16 => Self::from(self.as_i128().wrapping_rem_euclid(other.as_i128())),
            _ => unimplemented!(),
        }
    }

    pub fn bool_negate(&self) -> Self {
        assert!(self.size == 1);
        match self.value.as_u8() {
            0 => Self::TRUE,
            1 => Self::FALSE,
            _ => panic!("value is not boolean"),
        }
    }

    pub fn bool_xor(&self, other: &Self) -> Self {
        assert!(self.size == 1 && other.size == 1);
        match (self.as_u8(), other.as_u8()) {
            (1, 1) => Self::FALSE,
            (1, 0) => Self::TRUE,
            (0, 1) => Self::TRUE,
            (0, 0) => Self::FALSE,
            _ => panic!("value is not boolean"),
        }
    }

    pub fn bool_and(&self, other: &Self) -> Self {
        assert!(self.size == 1 && other.size == 1);
        match (self.as_u8(), other.as_u8()) {
            (1, 1) => Self::TRUE,
            (1, 0) => Self::FALSE,
            (0, 1) => Self::FALSE,
            (0, 0) => Self::FALSE,
            _ => panic!("value is not boolean"),
        }
    }

    pub fn bool_or(&self, other: &Self) -> Self {
        assert!(self.size == 1 && other.size == 1);
        match (self.as_u8(), other.as_u8()) {
            (1, 1) => Self::TRUE,
            (1, 0) => Self::TRUE,
            (0, 1) => Self::TRUE,
            (0, 0) => Self::FALSE,
            _ => panic!("value is not boolean"),
        }
    }

    pub fn subpiece(&self, other: &Self, size: usize) -> Self {
        assert!(other.size < RawValue::SIZE);
        assert!(size <= RawValue::SIZE);
        assert!(other.size + size <= RawValue::SIZE);
        let start = other.as_usize();
        let mut result = Self {
            value: Default::default(),
            size: size,
        };
        let value = unsafe { &mut result.value.raw };
        value[..size].copy_from_slice(&self.value.as_raw()[start..start + size]);
        result
    }

    pub fn popcount(&self, size: usize) -> Self {
        assert!(size <= RawValue::SIZE);
        let mut result = Self {
            value: Default::default(),
            size: size,
        };
        let value = match self.size {
            1 => self.as_u8().count_ones(),
            2 => self.as_u16().count_ones(),
            4 => self.as_u32().count_ones(),
            8 => self.as_u64().count_ones(),
            16 => self.as_u128().count_ones(),
            _ => unimplemented!(),
        };
        result.value = value.into();
        result
    }

    pub fn lzcount(&self, size: usize) -> Self {
        assert!(size <= RawValue::SIZE);
        let mut result = Self {
            value: Default::default(),
            size: size,
        };
        let value = match self.size {
            1 => self.as_u8().leading_zeros(),
            2 => self.as_u16().leading_zeros(),
            4 => self.as_u32().leading_zeros(),
            8 => self.as_u64().leading_zeros(),
            16 => self.as_u128().leading_zeros(),
            _ => unimplemented!(),
        };
        result.value = value.into();
        result
    }
}

impl From<u128> for SizedValue {
    fn from(v: u128) -> Self {
        Self {
            value: v.into(),
            size: size_of::<u128>(),
        }
    }
}

impl From<u64> for SizedValue {
    fn from(v: u64) -> Self {
        Self {
            value: v.into(),
            size: size_of::<u64>(),
        }
    }
}

impl From<u32> for SizedValue {
    fn from(v: u32) -> Self {
        Self {
            value: v.into(),
            size: size_of::<u32>(),
        }
    }
}

impl From<u16> for SizedValue {
    fn from(v: u16) -> Self {
        Self {
            value: v.into(),
            size: size_of::<u16>(),
        }
    }
}

impl From<u8> for SizedValue {
    fn from(v: u8) -> Self {
        Self {
            value: v.into(),
            size: size_of::<u8>(),
        }
    }
}

impl From<i128> for SizedValue {
    fn from(v: i128) -> Self {
        Self {
            value: v.into(),
            size: size_of::<i128>(),
        }
    }
}

impl From<i64> for SizedValue {
    fn from(v: i64) -> Self {
        Self {
            value: v.into(),
            size: size_of::<i64>(),
        }
    }
}

impl From<i32> for SizedValue {
    fn from(v: i32) -> Self {
        Self {
            value: v.into(),
            size: size_of::<i32>(),
        }
    }
}

impl From<i16> for SizedValue {
    fn from(v: i16) -> Self {
        Self {
            value: v.into(),
            size: size_of::<i16>(),
        }
    }
}

impl From<i8> for SizedValue {
    fn from(v: i8) -> Self {
        Self {
            value: v.into(),
            size: size_of::<i8>(),
        }
    }
}

impl From<bool> for SizedValue {
    fn from(v: bool) -> Self {
        match v {
            true => Self::TRUE,
            false => Self::FALSE,
        }
    }
}

impl fmt::Debug for SizedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SizedValue");
        match self.size {
            1 => f.field(&self.as_u8()).finish(),
            2 => f.field(&self.as_u16()).finish(),
            4 => f.field(&self.as_u32()).finish(),
            8 => f.field(&self.as_u64()).finish(),
            16 => f.field(&self.as_u128()).finish(),
            _ => f.field(&self.value.as_raw()).finish(),
        }
    }
}

impl Add for SizedValue {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        self.int_add(&other)
    }
}

impl AddAssign for SizedValue {
    fn add_assign(&mut self, other: Self) {
        *self = self.int_add(&other);
    }
}

impl BitAnd for SizedValue {
    type Output = Self;
    fn bitand(self, other: Self) -> Self::Output {
        self.int_and(&other)
    }
}

impl BitAndAssign for SizedValue {
    fn bitand_assign(&mut self, other: Self) {
        *self = self.int_and(&other);
    }
}

impl BitOr for SizedValue {
    type Output = Self;
    fn bitor(self, other: Self) -> Self::Output {
        self.int_or(&other)
    }
}

impl BitOrAssign for SizedValue {
    fn bitor_assign(&mut self, other: Self) {
        *self = self.int_or(&other);
    }
}

impl BitXor for SizedValue {
    type Output = Self;
    fn bitxor(self, other: Self) -> Self::Output {
        self.int_xor(&other)
    }
}

impl BitXorAssign for SizedValue {
    fn bitxor_assign(&mut self, other: Self) {
        *self = self.int_xor(&other);
    }
}

impl Mul for SizedValue {
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        self.int_mult(&other)
    }
}

impl MulAssign for SizedValue {
    fn mul_assign(&mut self, other: Self) {
        *self = self.int_mult(&other);
    }
}

impl Shl for SizedValue {
    type Output = Self;
    fn shl(self, other: Self) -> Self::Output {
        self.int_left(&other)
    }
}

impl ShlAssign for SizedValue {
    fn shl_assign(&mut self, other: Self) {
        *self = self.int_left(&other);
    }
}
impl Sub for SizedValue {
    type Output = Self;
    fn sub(self, other: Self) -> Self::Output {
        self.int_sub(&other)
    }
}

impl SubAssign for SizedValue {
    fn sub_assign(&mut self, other: Self) {
        *self = self.int_sub(&other);
    }
}

/// Wrapper type for `SizedValue` that automatically dispatches to
/// unsigned operations for operations where that makes a difference.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Unsigned<T>(pub T);

impl<T> Unsigned<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl PartialOrd for Unsigned<SizedValue> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let lt = self.0.int_less(&other.0) == SizedValue::TRUE;
        if lt {
            Some(Ordering::Less)
        } else if self.eq(other) {
            Some(Ordering::Equal)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl PartialEq for Unsigned<SizedValue> {
    fn eq(&self, other: &Self) -> bool {
        self.0.int_equal(&other.0) == SizedValue::TRUE
    }
}

impl From<Unsigned<SizedValue>> for PartialValue {
    fn from(v: Unsigned<SizedValue>) -> Self {
        Self::from(v.into_inner())
    }
}

impl Div for Unsigned<SizedValue> {
    type Output = Self;
    fn div(self, other: Self) -> Self::Output {
        Self(self.0.int_div(&other.0))
    }
}

impl DivAssign for Unsigned<SizedValue> {
    fn div_assign(&mut self, other: Self) {
        *self = Self(self.0.int_div(&other.0));
    }
}

impl Not for Unsigned<SizedValue> {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0.int_negate())
    }
}

impl Rem for Unsigned<SizedValue> {
    type Output = Self;
    fn rem(self, other: Self) -> Self::Output {
        Self(self.0.int_rem(&other.0))
    }
}

impl RemAssign for Unsigned<SizedValue> {
    fn rem_assign(&mut self, other: Self) {
        *self = Self(self.0.int_rem(&other.0));
    }
}

impl Shr for Unsigned<SizedValue> {
    type Output = Self;
    fn shr(self, other: Self) -> Self::Output {
        Self(self.0.int_right(&other.0))
    }
}

impl ShrAssign for Unsigned<SizedValue> {
    fn shr_assign(&mut self, other: Self) {
        *self = Self(self.0.int_right(&other.0));
    }
}

/// Wrapper type for `SizedValue` that automatically dispatches to
/// signed operations for operations where that makes a difference.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Signed<T>(pub T);

impl<T> Signed<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl PartialOrd for Signed<SizedValue> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let lt = self.0.int_sless(&other.0) == SizedValue::TRUE;
        if lt {
            Some(Ordering::Less)
        } else if self.eq(other) {
            Some(Ordering::Equal)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl PartialEq for Signed<SizedValue> {
    fn eq(&self, other: &Self) -> bool {
        self.0.int_equal(&other.0) == SizedValue::TRUE
    }
}

impl From<Signed<SizedValue>> for PartialValue {
    fn from(v: Signed<SizedValue>) -> Self {
        Self::from(v.into_inner())
    }
}

impl Div for Signed<SizedValue> {
    type Output = Self;
    fn div(self, other: Self) -> Self::Output {
        Self(self.0.int_sdiv(&other.0))
    }
}

impl DivAssign for Signed<SizedValue> {
    fn div_assign(&mut self, other: Self) {
        *self = Self(self.0.int_sdiv(&other.0));
    }
}

impl Neg for Signed<SizedValue> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(self.0.int_2comp())
    }
}

impl Rem for Signed<SizedValue> {
    type Output = Self;
    fn rem(self, other: Self) -> Self::Output {
        Self(self.0.int_srem(&other.0))
    }
}

impl RemAssign for Signed<SizedValue> {
    fn rem_assign(&mut self, other: Self) {
        *self = Self(self.0.int_srem(&other.0));
    }
}

impl Shr for Signed<SizedValue> {
    type Output = Self;
    fn shr(self, other: Self) -> Self::Output {
        Self(self.0.int_sright(&other.0))
    }
}

impl ShrAssign for Signed<SizedValue> {
    fn shr_assign(&mut self, other: Self) {
        *self = Self(self.0.int_sright(&other.0));
    }
}

/// Wrapper type for `SizedValue` that automatically dispatches to
/// boolean operations for operations where that makes a difference.
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct Bool<T>(pub T);

impl<T> Bool<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl From<Bool<SizedValue>> for PartialValue {
    fn from(v: Bool<SizedValue>) -> Self {
        Self::from(v.into_inner())
    }
}

impl Not for Bool<SizedValue> {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(self.0.bool_negate())
    }
}

impl BitAnd for Bool<SizedValue> {
    type Output = Self;
    fn bitand(self, other: Self) -> Self::Output {
        Self(self.0.bool_and(&other.0))
    }
}

impl BitAndAssign for Bool<SizedValue> {
    fn bitand_assign(&mut self, other: Self) {
        *self = Self(self.0.bool_and(&other.0));
    }
}

impl BitOr for Bool<SizedValue> {
    type Output = Self;
    fn bitor(self, other: Self) -> Self::Output {
        Self(self.0.bool_or(&other.0))
    }
}

impl BitOrAssign for Bool<SizedValue> {
    fn bitor_assign(&mut self, other: Self) {
        *self = Self(self.0.bool_or(&other.0));
    }
}

impl BitXor for Bool<SizedValue> {
    type Output = Self;
    fn bitxor(self, other: Self) -> Self::Output {
        Self(self.0.bool_xor(&other.0))
    }
}

impl BitXorAssign for Bool<SizedValue> {
    fn bitxor_assign(&mut self, other: Self) {
        *self = Self(self.0.bool_xor(&other.0));
    }
}

// PRIVATE API
//
// RawValue is the underlying value for Partial and Sized values. It allows
// easy access to primitive types. All functions on RawValues are technically
// safe because RawValues are initialized to a known good value and all
// bit patterns are safe for each of the union variants. However, not all
// functions are inherently meaningful in every context.
//
// For example, the RawValue behind a SizedValue can technically be casted
// to a larger primitive type than the SizedValue represents without being
// memory unsafe. However, that could produce unexpected results because
// the value may have come from PartialValue that had higher bytes set.
//
// Most, if not all, of these patterns are guarded against by the code in
// PartialValue and SizedValue. However, this type will not be public for
// that reason.

#[derive(Copy, Eq)]
#[repr(C)]
union RawValue {
    uint8_t: u8,
    uint16_t: u16,
    uint32_t: u32,
    uint64_t: u64,
    uint128_t: u128,
    int8_t: i8,
    int16_t: i16,
    int32_t: i32,
    int64_t: i64,
    int128_t: i128,
    raw: [u8; Self::SIZE],
}

impl RawValue {
    const SIZE: usize = std::mem::size_of::<[u8; 32]>();
    #[inline]
    fn as_u8(&self) -> u8 {
        unsafe { self.uint8_t }
    }
    #[inline]
    fn as_u16(&self) -> u16 {
        unsafe { self.uint16_t }
    }
    #[inline]
    fn as_u32(&self) -> u32 {
        unsafe { self.uint32_t }
    }
    #[inline]
    fn as_u64(&self) -> u64 {
        unsafe { self.uint64_t }
    }
    #[inline]
    fn as_u128(&self) -> u128 {
        unsafe { self.uint128_t }
    }
    #[inline]
    fn as_i8(&self) -> i8 {
        unsafe { self.int8_t }
    }
    #[inline]
    fn as_i16(&self) -> i16 {
        unsafe { self.int16_t }
    }
    #[inline]
    fn as_i32(&self) -> i32 {
        unsafe { self.int32_t }
    }
    #[inline]
    fn as_i64(&self) -> i64 {
        unsafe { self.int64_t }
    }
    #[inline]
    fn as_i128(&self) -> i128 {
        unsafe { self.int128_t }
    }
    #[inline]
    fn as_raw(&self) -> [u8; Self::SIZE] {
        unsafe { self.raw }
    }
}

impl Default for RawValue {
    fn default() -> Self {
        Self {
            raw: [0; Self::SIZE],
        }
    }
}

impl Clone for RawValue {
    fn clone(&self) -> Self {
        Self { raw: self.as_raw() }
    }
}

impl PartialEq for RawValue {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw() == other.as_raw()
    }
}

impl Hash for RawValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw().hash(state);
    }
}

impl fmt::Debug for RawValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RawValue").field(&self.as_raw()).finish()
    }
}

impl From<u8> for RawValue {
    fn from(v: u8) -> Self {
        let mut this = Self::default();
        this.uint8_t = v;
        this
    }
}

impl From<u16> for RawValue {
    fn from(v: u16) -> Self {
        let mut this = Self::default();
        this.uint16_t = v;
        this
    }
}

impl From<u32> for RawValue {
    fn from(v: u32) -> Self {
        let mut this = Self::default();
        this.uint32_t = v;
        this
    }
}

impl From<u64> for RawValue {
    fn from(v: u64) -> Self {
        let mut this = Self::default();
        this.uint64_t = v;
        this
    }
}

impl From<u128> for RawValue {
    fn from(v: u128) -> Self {
        let mut this = Self::default();
        this.uint128_t = v;
        this
    }
}

impl From<i8> for RawValue {
    fn from(v: i8) -> Self {
        let mut this = Self::default();
        this.int8_t = v;
        this
    }
}

impl From<i16> for RawValue {
    fn from(v: i16) -> Self {
        let mut this = Self::default();
        this.int16_t = v;
        this
    }
}

impl From<i32> for RawValue {
    fn from(v: i32) -> Self {
        let mut this = Self::default();
        this.int32_t = v;
        this
    }
}

impl From<i64> for RawValue {
    fn from(v: i64) -> Self {
        let mut this = Self::default();
        this.int64_t = v;
        this
    }
}

impl From<i128> for RawValue {
    fn from(v: i128) -> Self {
        let mut this = Self::default();
        this.int128_t = v;
        this
    }
}

impl From<bool> for RawValue {
    fn from(v: bool) -> Self {
        match v {
            true => Self::from(1u8),
            false => Self::from(0u8),
        }
    }
}

impl Index<usize> for RawValue {
    type Output = u8;
    fn index(&self, i: usize) -> &Self::Output {
        unsafe { &self.raw[i] }
    }
}

impl IndexMut<usize> for RawValue {
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        unsafe { &mut self.raw[i] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_addition() {
        // u8, no wrap

        let v1 = SizedValue::from(45u8);
        let v2 = SizedValue::from(54u8);

        assert!(SizedValue::from(99u8) == v1 + v2, "45 + 54 != 99");

        // u8, wrap

        let v1 = SizedValue::from(254u8);
        let v2 = SizedValue::from(50u8);

        assert!(SizedValue::from(48u8) == v1 + v2, "254 + 50 != 48");
    }
}

pub(crate) trait PrimitiveExt {
    fn read_le_bytes(bytes: &[u8]) -> Self;
    fn write_le_bytes(self, bytes: &mut [u8]);
}

pub(crate) trait ToPrimitive<T> {
    fn to_primitive(&self) -> T;
}

impl<T> ToPrimitive<T> for [u8]
where
    T: PrimitiveExt,
{
    #[inline]
    fn to_primitive(&self) -> T {
        T::read_le_bytes(self)
    }
}

macro_rules! impl_primitive_ext {
    ($ty:ty) => {
        impl PrimitiveExt for $ty {
            #[inline]
            fn read_le_bytes(bytes: &[u8]) -> Self {
                let mut buffer = [0u8; ::std::mem::size_of::<$ty>()];
                (&mut buffer[..bytes.len()]).copy_from_slice(bytes);
                <$ty>::from_le_bytes(buffer)
            }

            #[inline]
            fn write_le_bytes(self, bytes: &mut [u8]) {
                let size = bytes.len();
                bytes.copy_from_slice(&(self.to_le_bytes()[..size]))
            }
        }
    };
}

impl PrimitiveExt for u8 {
    #[inline]
    fn read_le_bytes(bytes: &[u8]) -> Self {
        bytes[0]
    }

    #[inline]
    fn write_le_bytes(self, bytes: &mut [u8]) {
        bytes[0] = self
    }
}

impl_primitive_ext!(u16);
impl_primitive_ext!(u32);
impl_primitive_ext!(u64);
impl_primitive_ext!(u128);
impl_primitive_ext!(usize);

impl PrimitiveExt for i8 {
    #[inline]
    fn read_le_bytes(bytes: &[u8]) -> Self {
        bytes[0] as Self
    }

    #[inline]
    fn write_le_bytes(self, bytes: &mut [u8]) {
        bytes[0] = self as u8
    }
}

impl_primitive_ext!(i16);
impl_primitive_ext!(i32);
impl_primitive_ext!(i64);
impl_primitive_ext!(i128);
impl_primitive_ext!(isize);

impl_primitive_ext!(f32);
impl_primitive_ext!(f64);
