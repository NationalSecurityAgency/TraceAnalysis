//! Definitions and implementations of p-code operations.
//!
//! The overall goal here is to modularize each operation into its own type that is responsible for
//! validation, implementation, and transformations. All of these operations are then grouped up in
//! a single `enum` that can unify some of their common methods.
//!
//! All operations should remain `Copy`, and to facilitate this, operations with a variable amount
//! of parameters utilize the [`Argument`] operation to store additional parameters with the
//! interpreter to be provided back to the operation during execution.
//!
//! # Notes on Implementation
//!
//! One of the weird quirks about the implementation of the operations is the prevalence of arrays
//! for single elements. As an explanation, this is an attempt to simplify the unified method for
//! getting the input parameters for an operation. In order to return a variable number of inputs,
//! the method returns a slice. However, that slice has to have some backing storage, so all input
//! parameters are stored as arrays, even when they are single elements. To offset some of the
//! clunkiness of this, the methods that return the input parameters specialized to the individual
//! operations them self (i.e. `Copy::inputs` vs. `Operation::inputs`) return a borrow of a fixed
//! array instead of a slice. This you write the following code since the length of the array is
//! fixed and known at compile time:
//!
//! ```ignore
//! let op: IntAdd;
//! let &[in0, in1] = op.inputs();
//! ```
//!

use crate::address::AddressRange;
use crate::space::SpaceKind;
use crate::value::{PrimitiveExt, ToPrimitive};

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("operation failed validation")]
    Validate(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

type Out = AddressRange;
type In = AddressRange;
type UnpackedOp = (
    OperationKind,
    Option<AddressRange>,
    Option<AddressRange>,
    Option<AddressRange>,
    Option<AddressRange>,
);

macros::operations! {
    {
        name = Copy,
        opcode = 1,
        signature = (out,in),
        validate = [OutIsNotConst, OutSizeInOneSizeMatch],
        description = ""
    }
    {
        name = Load,
        opcode = 2,
        signature = (out,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Store,
        opcode = 3,
        signature = (in,in,in),
        validate = [],
        description = ""
    }
    {
        name = Branch,
        opcode = 4,
        signature = (in),
        validate = [],
        description = ""
    }
    {
        name = CondBranch,
        opcode = 5,
        signature = (in,in),
        validate = [InTwoSizeOne],
        description = ""
    }
    {
        name = BranchInd,
        opcode = 6,
        signature = (in),
        validate = [],
        description = ""
    }
    {
        name = Call,
        opcode = 7,
        signature = (in),
        validate = [],
        description = ""
    }
    {
        name = CallInd,
        opcode = 8,
        signature = (in),
        validate = [],
        description = ""
    }
    {
        name = CallOther,
        opcode = 9,
        signature = (?out,in,*in),
        validate = [OutIsNotConst, InOneIsConst, InTwoIsConst],
        description = ""
    }
    {
        name = Return,
        opcode = 10,
        signature = (in),
        validate = [],
        description = ""
    }
    {
        name = IntEqual,
        opcode = 11,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = IntNotEqual,
        opcode = 12,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne,AllInSizesMatch],
        description = ""
    }
    {
        name = IntSignedLess,
        opcode = 13,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne,AllInSizesMatch],
        description = ""
    }
    {
        name = IntSignedLessEqual,
        opcode = 14,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne,AllInSizesMatch],
        description = ""
    }
    {
        name = IntLess,
        opcode = 15,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne,AllInSizesMatch],
        description = ""
    }
    {
        name = IntLessEqual,
        opcode = 16,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne,AllInSizesMatch],
        description = ""
    }
    {
        name = IntZeroExtend,
        opcode = 17,
        signature = (out,in),
        validate = [OutIsNotConst, OutSizeGreaterThanInSize],
        description = ""
    }
    {
        name = IntSignExtend,
        opcode = 18,
        signature = (out,in),
        validate = [OutIsNotConst, OutSizeGreaterThanInSize],
        description = ""
    }
    {
        name = IntAdd,
        opcode = 19,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntSub,
        opcode = 20,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntCarry,
        opcode = 21,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = IntSignedCarry,
        opcode = 22,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = IntSignedBorrow,
        opcode = 23,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = IntNeg,
        opcode = 24,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntNot,
        opcode = 25,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntXor,
        opcode = 26,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntAnd,
        opcode = 27,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntOr,
        opcode = 28,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntLeft,
        opcode = 29,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeInOneSizeMatch],
        description = ""
    }
    {
        name = IntRight,
        opcode = 30,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeInOneSizeMatch],
        description = ""
    }
    {
        name = IntSignedRight,
        opcode = 31,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeInOneSizeMatch],
        description = ""
    }
    {
        name = IntMult,
        opcode = 32,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntDiv,
        opcode = 33,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntSignedDiv,
        opcode = 34,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntRem,
        opcode = 35,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntSignedRem,
        opcode = 36,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = BoolNot,
        opcode = 37,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesAreOne],
        description = ""
    }
    {
        name = BoolXor,
        opcode = 38,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesAreOne],
        description = ""
    }
    {
        name = BoolAnd,
        opcode = 39,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesAreOne],
        description = ""
    }
    {
        name = BoolOr,
        opcode = 40,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesAreOne],
        description = ""
    }
    {
        name = FloatEqual,
        opcode = 41,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = FloatNotEqual,
        opcode = 42,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = FloatLess,
        opcode = 43,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = FloatLessEqual,
        opcode = 44,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = FloatNaN,
        opcode = 46,
        signature = (out,in),
        validate = [OutIsNotConst, OutSizeIsOne],
        description = ""
    }
    {
        name = FloatAdd,
        opcode = 47,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatDiv,
        opcode = 48,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatMult,
        opcode = 49,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatSub,
        opcode = 50,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatNeg,
        opcode = 51,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatAbs,
        opcode = 52,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatSqrt,
        opcode = 53,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = IntToFloat,
        opcode = 54,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = FloatToFloat,
        opcode = 55,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = FloatToInt,
        opcode = 56,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = FloatCeil,
        opcode = 57,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatFloor,
        opcode = 58,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = FloatRound,
        opcode = 59,
        signature = (out,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = Multiequal,
        opcode = 60,
        signature = (out,*in),
        validate = [OutIsNotConst, InOneIsConst],
        description = ""
    }
    {
        name = Indirect,
        opcode = 61,
        signature = (out,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Piece,
        opcode = 62,
        signature = (out,in,in),
        validate = [OutIsNotConst, InSizesSumToOutSize],
        description = ""
    }
    {
        name = Subpiece,
        opcode = 63,
        signature = (out,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Cast,
        opcode = 64,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = AddressOfIndex,
        opcode = 65,
        signature = (out,in,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = AddressOfField,
        opcode = 66,
        signature = (out,in,in),
        validate = [OutIsNotConst, AllSizesMatch],
        description = ""
    }
    {
        name = SegmentOp,
        opcode = 67,
        signature = (?out),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = ConstPoolRef,
        opcode = 68,
        signature = (out,in,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = New,
        opcode = 69,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Insert,
        opcode = 70,
        signature = (out,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Extract,
        opcode = 71,
        signature = (out,in,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Popcount,
        opcode = 72,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = Lzcount,
        opcode = 73,
        signature = (out,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = NewCount,
        opcode = 251,
        signature = (out,in,in),
        validate = [OutIsNotConst],
        description = ""
    }
    {
        name = IntCmp,
        opcode = 252,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = IntSignedCmp,
        opcode = 253,
        signature = (out,in,in),
        validate = [OutIsNotConst, OutSizeIsOne, AllInSizesMatch],
        description = ""
    }
    {
        name = Argument,
        opcode = 254,
        signature = (in,in),
        validate = [InOneIsConst],
        description = ""
    }
    {
        name = Unknown,
        opcode = 255,
        signature = (?out,in,*in),
        validate = [OutIsNotConst, InOneIsConst],
        description = ""
    }
}

macros::validators! {
    (
        OutIsNotConst "output of an operation must not be a constant"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            let Some(kind) = args.maybe_output().map(|out| out.space().kind()) else {
                return Ok(());
            };
            if kind == SpaceKind::Constant {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        InOneIsConst "first input must be a constant"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.input(0).space().kind() != SpaceKind::Constant {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        InTwoIsConst "second input must be a constant"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.input(1).space().kind() != SpaceKind::Constant {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        InTwoSizeOne "second input must have a size of one"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.input(1).size() != 1 {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        OutSizeIsOne "output must have a size of one"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.output().size() != 1 {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        OutSizeGreaterThanInSize "output size must be strictly greater than input size"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.output().size() <= args.input(0).size() {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        OutSizeInOneSizeMatch "output size must match first input size"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.output().size() != args.input(0).size() {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        InSizesSumToOutSize "input sizes must sum to output size"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if Some(args.output().size()) !=
                args.input(0).size().checked_add(args.input(1).size())
            {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        AllInSizesMatch "all input sizes must match"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            let Some(sz) = args.inputs().get(0).map(|p| p.size()) else {
                return Ok(());
            };
            if args.inputs().iter().skip(1).any(|p| p.size() != sz) {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        AllSizesAreOne "all sizes must be one"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            if args.all().any(|p| p.size() != 1) {
                return Err(Self);
            }
            Ok(())
        }
    )
    (
        AllSizesMatch "all sizes must match"
        fn validate(args: Args) -> std::result::Result<(), Self> {
            let mut all = args.all();
            let Some(sz) = all.next().map(|p| p.size()) else {
                return Ok(());
            };
            if all.any(|p| p.size() != sz) {
                return Err(Self);
            }
            Ok(())
        }
    )
}

#[derive(Copy, Clone)]
struct Args<'a>(&'a [Out], &'a [In]);

impl Args<'_> {
    fn output(&self) -> Out {
        self.0[0]
    }

    fn maybe_output(&self) -> Option<Out> {
        self.0.get(0).map(|&out| out)
    }

    fn inputs(&self) -> &[In] {
        self.1
    }

    fn input(&self, n: usize) -> In {
        self.1[n]
    }

    fn all<'a>(&'a self) -> impl Iterator<Item = AddressRange> + 'a {
        self.0.iter().copied().chain(self.1.iter().copied())
    }
}

impl Branch {
    pub fn set_target(&mut self, target: AddressRange) {
        self.0[0] = target;
    }
}

impl CondBranch {
    pub fn set_target(&mut self, target: AddressRange) {
        self.0[0] = target;
    }
}

impl IntZeroExtend {
    /// Performs a zero extension of `b` and stores the result in `a` (i.e. `a = zext(b)`).
    ///
    /// # Panics
    ///
    /// Panics if `b.len() > a.len()`.
    pub fn _impl(a: &mut [u8], b: &[u8]) {
        a.fill(0);
        (&mut a[..b.len()]).copy_from_slice(b)
    }
}

impl IntSignExtend {
    /// Performs signed extension of `b` and stores the result in `a` (i.e. `a = sext(b)`).
    ///
    /// # Panics
    ///
    /// Panics if `b.len() == 0`.
    pub fn _impl(a: &mut [u8], b: &[u8]) {
        let sign = b[b.len().wrapping_sub(1)] & 0x80 != 0;
        a.fill(if sign { 0xff } else { 0x00 });
        (&mut a[..b.len()]).copy_from_slice(b);
    }
}

impl IntAdd {
    /// Performs integer addition, storing results in `c` (i.e. `c = a + b`).
    ///
    /// This function returns the overflow flag as a result of the addition.
    ///
    /// # Warning
    ///
    /// This function assumes `c.len() == a.len() == b.len()` and will generate unexpected results or
    /// `panic`s if that is not the case.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16 && (b.len() > 16 || c.len() > 16)`
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) -> bool {
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            let (result, flag) = a.overflowing_add(b);
            result.write_le_bytes(c);
            // "flag" is used for u128 additions and the "shift-and-cmp" is used for all other
            // primitives.
            return flag || (result >> (c.len() << 3)) != 0;
        }

        c.iter_mut()
            .zip(a.iter().zip(b.iter()))
            .fold(false, |carry, (dest, (&left, &right))| {
                let (a, b) = left.overflowing_add(right);
                let (c, d) = a.overflowing_add(carry as u8);
                *dest = c;
                b || d
            })
    }
}

impl IntSub {
    /// Performs integer subtraction, storing results in `c` (i.e. `c = a - b`).
    ///
    /// This function returns the overflow flag as a result of the subtraction.
    ///
    /// # Warning
    ///
    /// This function assumes `c.len() == a.len() == b.len()` and will generate unexpected results or
    /// `panic`s if that is not the case.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16 && (b.len() > 16 || c.len() > 16)`
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) -> bool {
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            let (result, flag) = a.overflowing_sub(b);
            result.write_le_bytes(c);
            // "flag" is used for u128 subtractions and the "shift-and-cmp" is used for all other
            // primitives.
            return flag || (result >> (c.len() << 3)) != 0;
        }

        c.iter_mut()
            .zip(a.iter())
            .zip(b.iter())
            .fold(false, |borrow, ((dest, &left), &right)| {
                let (a, b) = left.overflowing_sub(right);
                let (c, d) = a.overflowing_sub(borrow as u8);
                *dest = c;
                b || d
            })
    }
}

impl IntCarry {
    /// Checks to see if an integer addition between `a` and `b` would overflow.
    ///
    /// # Warning
    ///
    /// `a` and `b` should have the same length. You are likely to get unexpected results or even
    /// `panic`s if `a` and `b` do not have matching lengths.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16` and `b.len() > 16`.
    pub fn _impl(a: &[u8], b: &[u8]) -> bool {
        if a.len() <= std::mem::size_of::<u128>() {
            let size = a.len();
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            let (result, flag) = a.overflowing_add(b);
            // "flag" is used for u128 additions and the "shift-and-cmp" is used for all other
            // primitives.
            return flag || (result >> (size << 3)) != 0;
        }

        let a_msb = a[a.len() - 1];
        let a = &a[..a.len() - 1];
        let b_msb = b[b.len() - 1];
        let b = &b[..b.len() - 1];

        // If there's a carry in the MSB we can shortcut the rest of the addition.
        let (msb, carry) = a_msb.overflowing_add(b_msb);
        if carry {
            return true;
        }

        // Get the carry for the ripple-carry addition
        let carry = a
            .iter()
            .zip(b.iter())
            .fold(false, |carry, (&left, &right)| {
                let (a, b) = left.overflowing_add(right);
                let (_, d) = a.overflowing_add(carry as u8);
                b || d
            });

        // We already have the MSB sum from before the ripple-carry add, so all we have to do is get
        // the overflow flag of the addition with the carry ouput of the ripple-carry add.
        let (_, carry) = msb.overflowing_add(carry as u8);
        carry
    }
}

impl IntSignedCarry {
    /// Checks to see if a signed integer addition between `a` and `b` would overflow.
    ///
    /// # Warning
    ///
    /// `a` and `b` should have the same length. You are likely to get unexpected results or even
    /// `panic`s if `a` and `b` do not have matching lengths.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16` and `b.len() > 16` or `a.len() == 0`
    pub fn _impl(a: &[u8], b: &[u8]) -> bool {
        match a.len() {
            1 => macros::primitive!(@arith a, b, i8, i8::overflowing_add),
            2 => macros::primitive!(@arith a, b, i16, i16::overflowing_add),
            4 => macros::primitive!(@arith a, b, i32, i32::overflowing_add),
            8 => macros::primitive!(@arith a, b, i64, i64::overflowing_add),
            16 => macros::primitive!(@arith a, b, i128, i128::overflowing_add),
            _ => {
                // This algorithm is the same as in `int_carry` except we treat the MSB as signed int.
                let a_msb = a[a.len() - 1] as i8;
                let a = &a[..a.len() - 1];
                let b_msb = b[b.len() - 1] as i8;
                let b = &b[..b.len() - 1];

                let (msb, carry) = a_msb.overflowing_add(b_msb);
                if carry {
                    return true;
                }

                // The ripple-carry adder still uses `u8`s treating the `a` and `b` as if they were a
                // list like: `[u8_0, u8_1, ..., u8_n-1, i8_n]`.
                let carry = a
                    .iter()
                    .zip(b.iter())
                    .fold(false, |carry, (&left, &right)| {
                        let (a, b) = left.overflowing_add(right);
                        let (_, d) = a.overflowing_add(carry as u8);
                        b || d
                    });

                let (_, carry) = msb.overflowing_add(carry as i8);
                carry
            }
        }
    }
}

impl IntSignedBorrow {
    /// Checks to see if a signed integer subtraction between `a` and `b` would overflow.
    ///
    /// # Warning
    ///
    /// `a` and `b` should have the same length. You are likely to get unexpected results or even
    /// `panic`s if `a` and `b` do not have matching lengths.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16` and `b.len() > 16` or `a.len() == 0`
    pub fn _impl(a: &[u8], b: &[u8]) -> bool {
        match a.len() {
            1 => macros::primitive!(@arith a, b, i8, i8::overflowing_sub),
            2 => macros::primitive!(@arith a, b, i16, i16::overflowing_sub),
            4 => macros::primitive!(@arith a, b, i32, i32::overflowing_sub),
            8 => macros::primitive!(@arith a, b, i64, i64::overflowing_sub),
            16 => macros::primitive!(@arith a, b, i128, i128::overflowing_sub),
            _ => {
                let a_msb = a[a.len() - 1] as i8;
                let a = &a[..a.len() - 1];
                let b_msb = b[b.len() - 1] as i8;
                let b = &b[..b.len() - 1];

                let (msb, borrow) = a_msb.overflowing_sub(b_msb);
                if borrow {
                    return true;
                }

                let borrow = a
                    .iter()
                    .zip(b.iter())
                    .fold(false, |borrow, (&left, &right)| {
                        let (a, b) = left.overflowing_sub(right);
                        let (_, d) = a.overflowing_sub(borrow as u8);
                        b || d
                    });

                let (_, borrow) = msb.overflowing_sub(borrow as i8);
                borrow
            }
        }
    }
}

impl IntNeg {
    /// Performs unary negation of `b` and stores the result in `a` (i.e. `a = -b`).
    ///
    /// # Note
    ///
    /// In SLEIGH's P-code, this operation is refered to as `INT_2COMP` not to be confused with
    /// `INT_NEGATE`. In Rust and a number of other contexts, "negation" is inherently a
    /// twos-complement operation and "not" is the bitwise inverse, so I chose to be consistent
    /// with that terminology over SLEIGH's.
    pub fn _impl(a: &mut [u8], b: &[u8]) {
        if b.len() <= std::mem::size_of::<u128>() {
            let b: i128 = b.to_primitive();
            (-b).write_le_bytes(a);
            return;
        }
        // Twos-complement: a = !b + 1, in order to get a variable sized "1" we use an iterator that
        // yields 1 for its first value and then 0 ad infinitum.
        let one = std::iter::once(1u8).chain(std::iter::repeat(0u8));
        a.iter_mut()
            .zip(b.iter().zip(one))
            .fold(false, |carry, (dest, (&left, right))| {
                let (a, b) = (!left).overflowing_add(right);
                let (c, d) = a.overflowing_add(carry as u8);
                *dest = c;
                b || d
            });
    }
}

impl IntNot {
    /// Performs unary bitwise inversion of `b` and stores the result in `a` (i.e. `a = !b`).
    ///
    /// # Note
    ///
    /// In SLEIGH's P-code, this operation is refered to as `INT_NEGATE`.
    pub fn _impl(a: &mut [u8], b: &[u8]) {
        a.iter_mut().zip(b.iter()).for_each(|(a, &b)| *a = !b);
    }
}

impl IntXor {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        c.iter_mut()
            .zip(a.iter().zip(b.iter()))
            .for_each(|(c, (&a, &b))| {
                *c = a ^ b;
            })
    }
}

impl IntAnd {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        c.iter_mut()
            .zip(a.iter().zip(b.iter()))
            .for_each(|(c, (&a, &b))| {
                *c = a & b;
            })
    }
}

impl IntOr {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        c.iter_mut()
            .zip(a.iter().zip(b.iter()))
            .for_each(|(c, (&a, &b))| {
                *c = a | b;
            })
    }
}

impl IntLeft {
    /// Performs a left shift operation and stores the result in `c` (i.e. `c = a << b`).
    ///
    /// # Panics
    ///
    /// This function panics if the value for `b` is greater than or equal to `usize::MAX`.
    pub fn _impl(c: &mut [u8], a: &[u8], mut b: &[u8]) {
        if b.len() > std::mem::size_of::<usize>() {
            // Try to shrink `b` to fit in a primitive, since we currently do not allow variable sized
            // integers on the right hand side of the shift. The shrinking lets us treat a value like
            // 0x00000000000000000000000000000000_00000000000000000000000000000008 as 0x08. This is
            // particularly important for constants as they may have a size > 16 btyes eventhough their
            // value will always be < u64::MAX
            if let Some(pos) = b.iter().rposition(|&byte| byte != 0x00) {
                b = &b[..pos + 1]
            }
        }

        // This will panic if `b` has a value bigger than usize::MAX.
        let rhs: usize = b.to_primitive();

        // This is both an optimization for the slow path and required to avoid panicking in the fast
        // path: if our shift amount is greater than or equal to the number of bits in input we clear
        // the output.
        if (rhs >> 3) >= a.len() {
            c.fill(0);
            return;
        }

        if a.len() < std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            (a << rhs).write_le_bytes(c);
            return;
        }

        let bytewise = rhs >> 3;
        let bitwise = rhs & 0b111;

        // TODO: Decide if it is the caller or callee's responsibility to clear dest.
        c.fill(0);

        // Optimization: If the shift amount is a multiple of 8 we can `memcpy` the range instead of
        // the more expensive "staggered memcpy" below.
        if bitwise == 0 {
            // We could use wrapping_sub here instead of saturating_sub b/c we already checked that
            // bytewise is less than c.len(), but that makes the code a bit less descriptive even if
            // there may be some perf benefits.
            let amount = std::cmp::min(a.len(), c.len().saturating_sub(bytewise));
            // This will panic if c.len() != a.len(), but it is the caller's responsibility to check
            // this.
            (&mut c[bytewise..bytewise + amount]).copy_from_slice(&a[..amount]);
            return;
        }

        // TODO: Revisit this loop
        for (i, &val) in a.iter().enumerate() {
            // If we are going to copy to an index outside of the range of `c` we just break. Because
            // we are moving forward through the dest, the first time we hit an OOB the remaining
            // indices will also be OOB.
            let Some(index) = i.checked_add(bytewise) else {
                break;
            };
            if index >= c.len() {
                break;
            }

            // "or assign" to avoid stepping on the previous iteration's high bits
            c[index] |= val << bitwise;

            // Even if the low bits of a value are in range of `c` the high bits may shift out of `c`,
            // so we need to check if the next index is safe to copy to, if not we can break a bit
            // early.
            let Some(index) = index.checked_add(1) else {
                break;
            };
            if index >= c.len() {
                break;
            }

            c[index] = val >> (8 - bitwise);
        }
    }
}

impl IntRight {
    pub fn _impl(c: &mut [u8], a: &[u8], mut b: &[u8]) {
        if b.len() > std::mem::size_of::<usize>() {
            // Try to shrink `b` to fit in a primitive, since we currently do not allow variable sized
            // integers on the right hand side of the shift. The shrinking lets us treat a value like
            // 0x00000000000000000000000000000000_00000000000000000000000000000008 as 0x08. This is
            // particularly important for constants as they may have a size > 16 btyes even though their
            // value will always be < u64::MAX
            if let Some(pos) = b.iter().rposition(|&byte| byte != 0x00) {
                b = &b[..pos + 1]
            }
        }

        // This will panic if `b` has a value bigger than usize::MAX.
        let rhs: usize = b.to_primitive();

        // This is both an optimization for the slow path and required to avoid panicking in the fast
        // path: if our shift amount is greater than or equal to the number of bits in input we clear
        // the output.
        if (rhs >> 3) >= a.len() {
            c.fill(0);
            return;
        }

        if a.len() < std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            (a >> rhs).write_le_bytes(c);
            return;
        }

        let bytewise = rhs >> 3;
        let bitwise = rhs & 0b111;

        c.fill(0);

        // Optimization: If the shift amount is a multiple of 8 we can `memcpy` the range instead of
        // the more expensive "staggered memcpy" below.
        if bitwise == 0 {
            let amount = a.len() - bytewise;
            // This will panic if c.len() != a.len(), but it is the caller's responsibility to check
            // this.
            (&mut c[..amount]).copy_from_slice(&a[bytewise..]);
            return;
        }

        // TODO: Revisit this loop
        for (i, &val) in (&a[bytewise..]).iter().enumerate() {
            c[i] = val >> bitwise;

            if let Some(i) = i.checked_sub(1) {
                c[i] |= val << (8 - bitwise);
            }
        }
    }
}

impl IntSignedRight {
    pub fn _impl(c: &mut [u8], a: &[u8], mut b: &[u8]) {
        // Unsigned right shift has a more efficient implementation and if we do this check early we
        // can assume the sign bit is set for the rest of the function.
        if a[a.len() - 1] & 0x80 == 0 {
            IntRight::_impl(c, a, b);
            return;
        }

        if b.len() > std::mem::size_of::<usize>() {
            // Try to shrink `b` to fit in a primitive, since we currently do not allow variable sized
            // integers on the right hand side of the shift. The shrinking lets us treat a value like
            // 0x00000000000000000000000000000000_00000000000000000000000000000008 as 0x08. This is
            // particularly important for constants as they may have a size > 16 btyes eventhough their
            // value will always be < u64::MAX
            if let Some(pos) = b.iter().rposition(|&byte| byte != 0x00) {
                b = &b[..pos + 1]
            }
        }

        // This will panic if `b` has a value bigger than usize::MAX.
        let rhs: usize = b.to_primitive();

        // This is both an optimization for the slow path and required to avoid panicking in the fast
        // path: if our shift amount is greater than or equal to the number of bits in input we set the
        // output to all ones.
        if rhs >= a.len() << 3 {
            c.fill(0xff);
            return;
        }

        match a.len() {
            1 => macros::primitive!(@shr c, a, rhs, i8),
            2 => macros::primitive!(@shr c, a, rhs, i16),
            4 => macros::primitive!(@shr c, a, rhs, i32),
            8 => macros::primitive!(@shr c, a, rhs, i64),
            16 => macros::primitive!(@shr c, a, rhs, i128),
            _ => {}
        }

        let bytewise = rhs >> 3;
        let bitwise = rhs & 0b111;

        c.fill(0xff);

        // Optimization: If the shift amount is a multiple of 8 we can `memcpy` the range instead of
        // the more expensive "staggered memcpy" below.
        if bitwise == 0 {
            let amount = a.len() - bytewise;
            // This will panic if c.len() != a.len(), but it is the caller's responsibility to check
            // this.
            (&mut c[..amount]).copy_from_slice(&a[bytewise..]);
            return;
        }

        let lomask = (1u8 << bitwise) - 1;
        let himask = lomask ^ 0xff;

        for (i, &val) in (&a[bytewise..]).iter().enumerate() {
            c[i] = (c[i] & himask) | (val >> bitwise);

            if let Some(i) = i.checked_sub(1) {
                c[i] = (c[i] & lomask) | (val << (8 - bitwise));
            }
        }
    }
}

impl IntMult {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            (a.wrapping_mul(b)).write_le_bytes(c);
            return;
        }

        // TODO: Karatsuba method
        unimplemented!()
    }
}

impl IntDiv {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            (a.wrapping_div(b)).write_le_bytes(c);
            return;
        }

        unimplemented!()
    }
}

impl IntSignedDiv {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        match a.len() {
            1 => macros::primitive!(@foo c, a, b, i8, i8::wrapping_div_euclid),
            2 => macros::primitive!(@foo c, a, b, i16, i16::wrapping_div_euclid),
            4 => macros::primitive!(@foo c, a, b, i32, i32::wrapping_div_euclid),
            8 => macros::primitive!(@foo c, a, b, i64, i64::wrapping_div_euclid),
            16 => macros::primitive!(@foo c, a, b, i128, i128::wrapping_div_euclid),
            _ => {}
        }
        unimplemented!()
    }
}

impl IntRem {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            (a.wrapping_rem(b)).write_le_bytes(c);
            return;
        }

        unimplemented!()
    }
}

impl IntSignedRem {
    pub fn _impl(c: &mut [u8], a: &[u8], b: &[u8]) {
        match a.len() {
            1 => macros::primitive!(@foo c, a, b, i8, i8::wrapping_rem_euclid),
            2 => macros::primitive!(@foo c, a, b, i16, i16::wrapping_rem_euclid),
            4 => macros::primitive!(@foo c, a, b, i32, i32::wrapping_rem_euclid),
            8 => macros::primitive!(@foo c, a, b, i64, i64::wrapping_rem_euclid),
            16 => macros::primitive!(@foo c, a, b, i128, i128::wrapping_rem_euclid),
            _ => {}
        }

        unimplemented!()
    }
}

impl IntCmp {
    /// Performs unsigned integer comparison of `a` and `b` (i.e. `a <=> b`).
    ///
    /// # Warning
    ///
    /// `a` and `b` should have the same length. You are likely to get unexpected results or even
    /// `panic`s if `a` and `b` do not have matching lengths.
    ///
    /// # Panics
    ///
    /// Panics if `a.len() <= 16` and `b.len() > 16`.
    pub fn _impl(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        // Rather than lowering to the "correct" primitive, we always lower to `u128` to limit branch
        // mispredictions.
        if a.len() <= std::mem::size_of::<u128>() {
            let a: u128 = a.to_primitive();
            let b: u128 = b.to_primitive();
            return a.cmp(&b);
        }
        a.iter().rev().cmp(b.iter().rev())
    }
}

impl IntSignedCmp {
    /// Performs signed integer comparison of `a` and `b` (i.e. `a <=> b`).
    ///
    /// # Panics
    ///
    /// Panics if `a.len() == 0` or `b.len() == 0`
    pub fn _impl(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
        // TODO: Test if branch prediction failures here are worth the "simpler" implementation.
        match a.len() {
            1 => macros::primitive!(@cmp a, b, i8, Ord::cmp),
            2 => macros::primitive!(@cmp a, b, i16, Ord::cmp),
            4 => macros::primitive!(@cmp a, b, i32, Ord::cmp),
            8 => macros::primitive!(@cmp a, b, i64, Ord::cmp),
            16 => macros::primitive!(@cmp a, b, i128, Ord::cmp),
            _ => {
                let sign_a = a[a.len().wrapping_sub(1)] & 0x80 != 0;
                let sign_b = b[b.len().wrapping_sub(1)] & 0x80 != 0;
                if sign_a == sign_b {
                    return a.iter().rev().cmp(b.iter().rev());
                }
                if sign_a {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            }
        }
    }
}

mod macros {
    macro_rules! operations {
        (
            $({
                name = $name:tt,
                opcode = $opc:tt,
                signature = $sig:tt,
                validate = [$($validator:tt),*],
                description = $desc:tt
            })*
        ) => {
            macros::operations!(@opsdecl [$(( $name $sig )),*]);
            macros::operations!(@kinddecl [$(($name $opc)),*]);
            $(
                macros::operations!(@opdecl $name $sig);
                impl $name {
                    macros::operations!(@opconstructors $sig ($($validator)*));
                    macros::operations!(@opinputs $sig);
                    macros::operations!(@opoutput $sig);
                }
            )*
        };

        (@opsdecl [$(( $name:tt $sig:tt )),*]) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub enum Operation {
                $($name ( $name ) ),*
            }

            impl Operation {
                pub fn kind(&self) -> OperationKind {
                    match self {
                        $( Self :: $name (_) => OperationKind :: $name ),*
                    }
                }

                pub fn inputs(&self) -> &[In] {
                    match self {
                        $(Self::$name(ref _op) => macros::operations!(@inputsrhs _op $sig)),*
                    }
                }

                pub fn outputs(&self) -> Option<Out> {
                    match self {
                        $(Self::$name(ref _op) => macros::operations!(@outputrhs _op $sig)),*
                    }
                }

                pub fn unpack(&self) -> UnpackedOp {
                    match self {
                        $(Self::$name(op) => { macros::operations!(@unpackrhs op $name $sig) })*
                    }

                }
            }

            $(
                impl From<$name> for Operation {
                    fn from(op: $name) -> Self {
                        Self :: $name (op)
                    }
                }
            )*
        };

        (@inputsrhs $_:ident (?out)) => {
            &[]
        };

        (@inputsrhs $op:ident $($_:tt)*) => {
            $op.inputs()
        };

        (@outputrhs $_:ident (in $($_rst:tt)*)) => {
            None
        };

        (@outputrhs $op:ident (out $($_rst:tt)*)) => {
            Some($op.output())
        };

        (@outputrhs $op:ident (?out $($_rst:tt)*)) => {
            $op.output()
        };

        (@unpackrhs $op:ident $name:tt (in)) => {
            {
                let $name([in0]) = $op;
                (OperationKind::$name, Some(*in0), None, None, None)
            }
        };

        (@unpackrhs $op:ident $name:tt (in, in)) => {
            {
                let $name([in0, in1]) = $op;
                (OperationKind::$name, Some(*in0), Some(*in1), None, None)
            }
        };

        (@unpackrhs $op:ident $name:tt (in, in, in)) => {
            {
                let $name([in0, in1, in2]) = $op;
                (OperationKind::$name, Some(*in0), Some(*in1), Some(*in2), None)
            }
        };

        (@unpackrhs $op:ident $name:tt (?out)) => {
            {
                let $name(out) = $op;
                (OperationKind::$name, *out, None, None, None)
            }
        };

        (@unpackrhs $op:ident $name:tt (out, in)) => {
            {
                let $name(out, [in0]) = $op;
                (OperationKind::$name, Some(*out), Some(*in0), None, None)
            }
        };

        (@unpackrhs $op:ident $name:tt (out, *in)) => {
            {
                let $name(out, [in0]) = $op;
                (OperationKind::$name, Some(*out), Some(*in0), None, None)
            }
        };

        (@unpackrhs $op:ident $name:tt (out, in, in)) => {
            {
                let $name(out, [in0, in1]) = $op;
                (OperationKind::$name, Some(*out), Some(*in0), Some(*in1), None)
            }
        };

        (@unpackrhs $op:ident $name:tt (out, in, in, in)) => {
            {
                let $name(out, [in0, in1, in2]) = $op;
                (OperationKind::$name, Some(*out), Some(*in0), Some(*in1), Some(*in2))
            }
        };

        (@unpackrhs $op:ident $name:tt (?out, in, *in)) => {
            {
                let $name(out, [in0, in1]) = $op;
                (OperationKind::$name, *out, Some(*in0), Some(*in1), None)
            }
        };

        (@unpackrhs $_op:ident $name:tt $sig:tt) => {
            compile_error!(concat!(
                "invalid signature for `",
                stringify!($name),
                "`: `",
                stringify!($sig),
                "`"
            ));
        };

        (@kinddecl [$(($name:tt $opc:tt)),*]) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub enum OperationKind {
                $($name = $opc),*
            }
        };


        (@opdecl $name:tt (in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( [In; 1] );
        };
        (@opdecl $name:tt (in, in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( [In; 2] );
        };
        (@opdecl $name:tt (in, in, in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( [In; 3] );
        };
        (@opdecl $name:tt (?out)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( Option<Out> );
        };
        (@opdecl $name:tt (out, $(*)? in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( Out, [In; 1] );
        };
        (@opdecl $name:tt (out, in, in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( Out, [In; 2] );
        };
        (@opdecl $name:tt (out, in, in, in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( Out, [In; 3] );
        };
        (@opdecl $name:tt (?out, in, *in)) => {
            #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
            pub struct $name ( Option<Out>, [In; 2] );
        };
        (@opdecl $name:tt $sig:tt) => {
            compile_error!(concat!(
                "invalid signature for `",
                stringify!($name),
                "`: `",
                stringify!($sig),
                "`"
            ));
        };

        (@opconstructors (in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(in0: In) -> Self {
                Self([in0])
            }

            pub fn new(in0: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[], &[in0]))?;)*
                Ok(Self([in0]))
            }
        };
        (@opconstructors (in, in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(in0: In, in1: In) -> Self {
                Self([in0, in1])
            }

            pub fn new(in0: In, in1: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[], &[in0, in1]))?;)*
                Ok(Self([in0, in1]))
            }
        };
        (@opconstructors (in, in, in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(in0: In, in1: In, in2: In) -> Self {
                Self([in0, in1, in2])
            }

            pub fn new(in0: In, in1: In, in2: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[], &[in0, in1, in2]))?;)*
                Ok(Self([in0, in1, in2]))
            }
        };
        (@opconstructors (?out) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(out: Option<Out>) -> Self {
                Self(out)
            }

            // TODO
            pub fn new(out: Option<Out>) -> Result<Self, OperationError> {
                if let Some(out) = out {
                    $($validator::validate(Args(&[out], &[]))?;)*
                } else {
                    $($validator::validate(Args(&[], &[]))?;)*
                }
                Ok(Self(out))
            }
        };
        (@opconstructors (out, $(*)? in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(out: Out, in0: In) -> Self {
                Self(out, [in0])
            }

            pub fn new(out: Out, in0: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[out], &[in0]))?;)*
                Ok(Self(out, [in0]))
            }
        };
        (@opconstructors (out, in, in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(out: Out, in0: In, in1: In) -> Self {
                Self(out, [in0, in1])
            }

            pub fn new(out: Out, in0: In, in1: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[out], &[in0, in1]))?;)*
                Ok(Self(out, [in0, in1]))
            }
        };
        (@opconstructors (out, in, in, in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(out: Out, in0: In, in1: In, in2: In) -> Self {
                Self(out, [in0, in1, in2])
            }

            pub fn new(out: Out, in0: In, in1: In, in2: In) -> Result<Self, OperationError> {
                $($validator::validate(Args(&[out], &[in0, in1, in2]))?;)*
                Ok(Self(out, [in0, in1, in2]))
            }
        };
        (@opconstructors (?out, in, *in) ($($validator:tt)*)) => {
            pub unsafe fn new_unchecked(out: Option<Out>, in0: In, in1: In) -> Self {
                Self(out, [in0, in1])
            }

            // TODO
            pub fn new(out: Option<Out>, in0: In, in1: In) -> Result<Self, OperationError> {
                if let Some(out) = out {
                    $($validator::validate(Args(&[out], &[in0, in1]))?;)*
                } else {
                    $($validator::validate(Args(&[], &[in0, in1]))?;)*
                }
                Ok(Self(out, [in0, in1]))
            }
        };

        // TODO: Consolidate these somehow
        (@opinputs (in)) => {
            pub fn inputs(&self) -> &[In; 1] {
                &self.0
            }
        };
        (@opinputs (in, in)) => {
            pub fn inputs(&self) -> &[In; 2] {
                &self.0
            }
        };
        (@opinputs (in, in, in)) => {
            pub fn inputs(&self) -> &[In; 3] {
                &self.0
            }
        };
        (@opinputs ($(?)? out, $(*)? in)) => {
            pub fn inputs(&self) -> &[In; 1] {
                &self.1
            }
        };
        (@opinputs ($(?)? out, in, $(*)? in)) => {
            pub fn inputs(&self) -> &[In; 2] {
                &self.1
            }
        };
        (@opinputs (out, in, in, in)) => {
            pub fn inputs(&self) -> &[In; 3] {
                &self.1
            }
        };
        (@opinputs $($_:tt)*) => {
        };

        (@opoutput (out $($_:tt)*)) => {
            pub fn output(&self) -> Out {
                self.0
            }
        };
        (@opoutput (?out $($_:tt)*)) => {
            pub fn output(&self) -> Option<Out> {
                self.0
            }
        };
        (@opoutput $($_:tt)*) => {
        };

        (@count) => (0usize);

        (@count $x:tt $($xs:tt)*) => (1usize + macros::operations!(@count $($xs)*));
    }

    macro_rules! validators {
        (
            $(($name:tt $desc:tt $($body:tt)*))*
        ) => {
            macros::validators!(@validators $($name)*);
            $( macros::validators!(@validator $name $desc $($body)*); )*
        };

        (@validators $($name:tt)*) => {
            #[derive(thiserror::Error)]
            #[derive(Debug, Clone)]
            pub(crate) enum Validator {
                $(
                    #[error(transparent)]
                    $name ( #[from] $name )
                ),*
            }

            $(
                impl From<$name> for OperationError {
                    fn from(err: $name) -> Self {
                        Self::Validate(Box::new(Validator::from(err)))
                    }
                }
            )*
        };

        (@validator $name:tt $desc:tt $($body:tt)*) => {
            #[derive(thiserror::Error)]
            #[derive(Debug, Copy, Clone, PartialEq, Eq)]
            #[error($desc)]
            pub(crate) struct $name;

            impl $name {
                #[inline]
                $($body)*
            }
        };
    }

    macro_rules! primitive {
        (@arith $dest:expr,$left:expr,$right:expr,$ty:ty,$($tt:tt)+) => {
            {
                let (result, flag) = $($tt)+ (
                    <$ty>::read_le_bytes($left),
                    <$ty>::read_le_bytes($right)
                );
                result.write_le_bytes($dest);
                flag
            }
        };
        (@arith $left:expr,$right:expr,$ty:ty,$($tt:tt)+) => {
            {
                $($tt)+(<$ty>::read_le_bytes($left), <$ty>::read_le_bytes($right)).1
            }
        };
        (@cmp $left:expr,$right:expr,$ty:ty,$($tt:tt)+) => {
            {
                $($tt)+(&(<$ty>::read_le_bytes($left)), &(<$ty>::read_le_bytes($right)))
            }
        };
        (@shr $dest:expr,$left:expr,$right:expr,$ty:ty) => {
            {
                (<$ty>::read_le_bytes($left) >> $right).write_le_bytes($dest);
                return;
            }
        };
        (@foo $dest:expr,$left:expr,$right:expr,$ty:ty,$($tt:tt)+) => {
            {
                let left = <$ty>::read_le_bytes($left);
                let right = <$ty>::read_le_bytes($right);
                ($($tt)+(left, right)).write_le_bytes($dest);
                return;
            }
        };
    }

    pub(super) use operations;
    pub(super) use primitive;
    pub(super) use validators;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_cmp_for_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        a.write_le_bytes(&mut a_slice[..]);

        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        b.write_le_bytes(&mut b_slice[..]);

        assert_eq!(a.cmp(&b), IntCmp::_impl(&a_slice[..], &b_slice[..]));
    }

    #[test]
    fn test_int_cmp_for_bigint() {
        let a = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
        let b = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x00";
        assert_eq!(IntCmp::_impl(&a[..], &b[..]), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_int_signed_cmp_for_primitive() {
        {
            let a = 0x1337u16 as i16;
            let b = 0xc0deu16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<i16>()];
            a.write_le_bytes(&mut a_slice[..]);

            let mut b_slice = [0u8; std::mem::size_of::<i16>()];
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.cmp(&b), IntSignedCmp::_impl(&a_slice[..], &b_slice[..]),
                "test failed for opposite signs"
            };
        }

        {
            let a = 0xdeadu16 as i16;
            let b = 0xbeefu16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<i16>()];
            a.write_le_bytes(&mut a_slice[..]);

            let mut b_slice = [0u8; std::mem::size_of::<i16>()];
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.cmp(&b), IntSignedCmp::_impl(&a_slice[..], &b_slice[..]),
                "test failed for matching signs"
            }
        }
    }

    #[test]
    fn test_int_signed_cmp_for_bigint() {
        {
            let a = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";
            let b = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x00";
            assert_eq! {
                IntSignedCmp::_impl(&a[..], &b[..]), std::cmp::Ordering::Greater,
                "test failed for matching signs"
            }
        }

        {
            let a = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x80";
            let b = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x00";
            assert_eq! {
                IntSignedCmp::_impl(&a[..], &b[..]), std::cmp::Ordering::Less,
                "test failed for opposite signs"
            }
        }
    }

    #[test]
    fn test_int_zero_extend() {
        let b = 0xfeedu16;

        let mut a_slice = [0u8; std::mem::size_of::<u32>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        b.write_le_bytes(&mut b_slice[..]);
        IntZeroExtend::_impl(&mut a_slice[..], &b_slice[..]);

        assert_eq!(b as u32, (&a_slice[..]).to_primitive());
    }

    #[test]
    fn test_int_signed_extend() {
        {
            let b = 0xfeedu16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<i32>()];
            let mut b_slice = [0u8; std::mem::size_of::<i16>()];
            b.write_le_bytes(&mut b_slice[..]);
            IntSignExtend::_impl(&mut a_slice[..], &b_slice[..]);

            assert_eq! {
                b as i32, (&a_slice[..]).to_primitive(),
                "test failed for negative values"
            }
        }
        {
            let b = 0x1337u16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<i32>()];
            let mut b_slice = [0u8; std::mem::size_of::<i16>()];
            b.write_le_bytes(&mut b_slice[..]);
            IntSignExtend::_impl(&mut a_slice[..], &b_slice[..]);

            assert_eq! {
                b as i32, (&a_slice[..]).to_primitive(),
                "test failed for positive values"
            }
        }
    }

    #[test]
    fn test_int_add_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntAdd::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_add(b), c_slice.to_primitive());
    }

    #[test]
    fn test_int_add_bigint() {
        let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x10";
        let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x00";
        let c = b"\x01\x23\x45\x67\x89\xab\xcd\xef\x11\x34\x56\x78\x9a\xbc\xde\xf0\x11";

        let mut c_slice = [0u8; 17];

        IntAdd::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice);
    }

    #[test]
    fn test_int_sub_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntSub::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_sub(b), c_slice.to_primitive());
    }

    #[test]
    fn test_int_sub_bigint() {
        let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x10";
        let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x00";
        let c = b"\xff\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\xfe\x0e\x10";

        let mut c_slice = [0u8; 17];

        IntSub::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice);
    }

    #[test]
    fn test_int_carry_primitive() {
        {
            let a = 0xdeadu16;
            let b = 0xbeefu16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_add(b).1, IntCarry::_impl(&a_slice[..], &b_slice[..]),
                "test failed for carry"
            }
        }
        {
            let a = 0x1337u16;
            let b = 0xc0deu16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_add(b).1, IntCarry::_impl(&a_slice[..], &b_slice[..]),
                "test failed for no carry"
            }
        }
    }

    #[test]
    fn test_int_carry_bigint() {
        {
            let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x10";
            let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x00";

            assert_eq! {
                IntCarry::_impl(&a[..], &b[..]), false,
                "test failed for no carry"
            }
        }
        {
            let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff";
            let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x00";

            assert_eq! {
                IntCarry::_impl(&a[..], &b[..]), true,
                "test failed for carry"
            }
        }
    }

    #[test]
    fn test_int_signed_carry_primitive() {
        {
            let a = 0xdeadu16 as i16;
            let b = 0xbeefu16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_add(b).1, IntSignedCarry::_impl(&a_slice[..], &b_slice[..]),
                "test failed for no carry"
            }
        }
        {
            let a = 0x8123u16 as i16;
            let b = 0x8000u16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_add(b).1, IntSignedCarry::_impl(&a_slice[..], &b_slice[..]),
                "test failed for carry"
            }
        }
    }

    #[test]
    fn test_int_signed_carry_bigint() {
        {
            let a = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f";
            let b = b"\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

            assert_eq! {
                IntSignedCarry::_impl(&a[..], &b[..]), true,
                "test failed for carry"
            }
        }
        {
            let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff";
            let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x01";

            assert_eq! {
                IntSignedCarry::_impl(&a[..], &b[..]), false,
                "test failed for no carry"
            }
        }
    }

    #[test]
    fn test_int_signed_borrow_primitive() {
        {
            let a = 0xdeadu16 as i16;
            let b = 0xbeefu16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_sub(b).1, IntSignedBorrow::_impl(&a_slice[..], &b_slice[..]),
                "test failed for no borrow"
            }
        }
        {
            let a = 0x07ffeu16 as i16;
            let b = 0x8123u16 as i16;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            assert_eq! {
                a.overflowing_sub(b).1, IntSignedBorrow::_impl(&a_slice[..], &b_slice[..]),
                "test failed for borrow"
            }
        }
    }

    #[test]
    fn test_int_signed_borrow_bigint() {
        {
            let a = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f";
            let b = b"\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88";

            assert_eq! {
                IntSignedBorrow::_impl(&a[..], &b[..]), true,
                "test failed for borrow"
            }
        }
        {
            let a = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff";
            let b = b"\x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\x01";

            assert_eq! {
                IntSignedBorrow::_impl(&a[..], &b[..]), false,
                "test failed for no borrow"
            }
        }
    }

    #[test]
    fn test_int_negate_primitive() {
        let b = 0xa1a1u16 as i16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];

        b.write_le_bytes(&mut b_slice[..]);
        IntNeg::_impl(&mut a_slice[..], &b_slice[..]);

        assert_eq!(-b, a_slice.to_primitive());
    }

    #[test]
    fn test_int_negate_bigint() {
        let b = b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";
        let a = b"\xbf\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe\xbe";

        let mut a_slice = [0u8; 17];

        IntNeg::_impl(&mut a_slice[..], &b[..]);

        assert_eq!(a, &a_slice);
    }

    #[test]
    fn test_int_not() {
        let b = 0xa1a1u16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];

        b.write_le_bytes(&mut b_slice[..]);
        IntNot::_impl(&mut a_slice[..], &b_slice[..]);

        assert_eq!(!b, a_slice.to_primitive());
    }

    #[test]
    fn test_int_xor() {
        let a = 0xffffu16;
        let b = 0xa1a1u16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);
        IntXor::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a ^ b, c_slice.to_primitive());
    }

    #[test]
    fn test_int_and() {
        let a = 0xff00u16;
        let b = 0xa1a1u16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);
        IntAnd::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a & b, c_slice.to_primitive());
    }

    #[test]
    fn test_int_or() {
        let a = 0x00ffu16;
        let b = 0xa1a1u16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);
        IntOr::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a | b, c_slice.to_primitive());
    }

    #[test]
    fn test_int_left_primitive() {
        let a = 0xdeadu16;
        let b = 8usize;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<usize>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntLeft::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a << b, c_slice.to_primitive());
    }

    #[test]
    fn test_int_left_bigint_aligned() {
        let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
        let b = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let c = b"\x00\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f";

        let mut c_slice = [0u8; 17];

        IntLeft::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice)
    }

    #[test]
    fn test_int_left_bigint_unaligned() {
        let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
        let b = b"\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let c = b"\x00\x00\x14\x24\x34\x44\x54\x64\x74\x84\x94\xa4\xb4\xc4\xd4\xe4\xf4";

        let mut c_slice = [0u8; 17];

        IntLeft::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice)
    }

    #[test]
    fn test_int_right_primitive() {
        let a = 0xdeadu16;
        let b = 8usize;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<usize>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntRight::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a >> b, c_slice.to_primitive());
    }

    #[test]
    fn test_int_right_bigint_aligned() {
        let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
        let b = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let c = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x00";

        let mut c_slice = [0u8; 17];

        IntRight::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice)
    }

    #[test]
    fn test_int_right_bigint_unaligned() {
        let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
        let b = b"\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let c = b"\x24\x34\x44\x54\x64\x74\x84\x94\xa4\xb4\xc4\xd4\xe4\xf4\x04\x05\x00";

        let mut c_slice = [0u8; 17];

        IntRight::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice)
    }

    #[test]
    fn test_int_signed_right_primitive() {
        {
            let a = 0xdeadu16 as i16;
            let b = 8usize;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<usize>()];
            let mut c_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            IntSignedRight::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

            assert_eq! {
                a >> b, c_slice.to_primitive(),
                "test failed for negative value"
            }
        }
        {
            let a = 0x1337u16 as i16;
            let b = 8usize;

            let mut a_slice = [0u8; std::mem::size_of::<u16>()];
            let mut b_slice = [0u8; std::mem::size_of::<usize>()];
            let mut c_slice = [0u8; std::mem::size_of::<u16>()];

            a.write_le_bytes(&mut a_slice[..]);
            b.write_le_bytes(&mut b_slice[..]);

            IntSignedRight::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

            assert_eq! {
                a >> b, c_slice.to_primitive(),
                "test failed for positive value"
            }
        }
    }

    #[test]
    fn test_int_signed_right_bigint_aligned() {
        {
            let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
            let b = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            let c = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x00";

            let mut c_slice = [0u8; 17];

            IntSignedRight::_impl(&mut c_slice[..], &a[..], &b[..]);

            assert_eq! {
                c, &c_slice,
                "test failed for positive value"
            }
        }
        {
            let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x80";
            let b = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            let c = b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x80\xff";

            let mut c_slice = [0u8; 17];

            IntSignedRight::_impl(&mut c_slice[..], &a[..], &b[..]);

            assert_eq! {
                c, &c_slice,
                "test failed for negative value"
            }
        }
    }

    #[test]
    fn test_int_signed_right_bigint_unaligned() {
        {
            let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50";
            let b = b"\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            let c = b"\x24\x34\x44\x54\x64\x74\x84\x94\xa4\xb4\xc4\xd4\xe4\xf4\x04\x05\x00";

            let mut c_slice = [0u8; 17];

            IntSignedRight::_impl(&mut c_slice[..], &a[..], &b[..]);

            assert_eq! {
                c, &c_slice,
                "test failed for positive value"
            }
        }
        {
            let a = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x80";
            let b = b"\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            let c = b"\x24\x34\x44\x54\x64\x74\x84\x94\xa4\xb4\xc4\xd4\xe4\xf4\x04\xf8\xff";

            let mut c_slice = [0u8; 17];

            IntSignedRight::_impl(&mut c_slice[..], &a[..], &b[..]);

            assert_eq! {
                c, &c_slice,
                "test failed for negative value"
            }
        }
    }

    #[test]
    fn test_int_mult_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntMult::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_mul(b), c_slice.to_primitive());
    }

    #[test]
    #[should_panic]
    fn test_int_mult_bigint() {
        let a = b"\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1";
        let b = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
        let c = b"\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x42";

        let mut c_slice = [0u8; 17];

        IntMult::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice);
    }

    #[test]
    fn test_int_div_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntDiv::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_div(b), c_slice.to_primitive());
    }

    #[test]
    #[should_panic]
    fn test_int_div_bigint() {
        let a = b"\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1";
        let b = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
        let c = b"\x50\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0\xd0";

        let mut c_slice = [0u8; 17];

        IntDiv::_impl(&mut c_slice[..], &a[..], &b[..]);

        assert_eq!(c, &c_slice);
    }

    #[test]
    fn test_int_rem_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntRem::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_rem(b), c_slice.to_primitive());
    }

    #[test]
    fn test_int_signed_div_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntSignedDiv::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_div_euclid(b), c_slice.to_primitive());
    }

    #[test]
    fn test_int_signed_rem_primitive() {
        let a = 0xdeadu16;
        let b = 0xbeefu16;

        let mut a_slice = [0u8; std::mem::size_of::<u16>()];
        let mut b_slice = [0u8; std::mem::size_of::<u16>()];
        let mut c_slice = [0u8; std::mem::size_of::<u16>()];

        a.write_le_bytes(&mut a_slice[..]);
        b.write_le_bytes(&mut b_slice[..]);

        IntSignedRem::_impl(&mut c_slice[..], &a_slice[..], &b_slice[..]);

        assert_eq!(a.wrapping_rem_euclid(b), c_slice.to_primitive());
    }
}

mod comments {
    // This type represents an IR operation bound with the proper inputs and
    // outputs.
    //
    // All inputs and outputs come in the form of `AddressRanges`. Some operations
    // have undefined or variadic signatures. In the case of undefined signatures,
    // the strongest guarentee is that the operation may or may not have an
    // output.

    // Copies a a sequence of contiguous bytes from one location to another.
    //
    // # Invariants
    //
    // - The input size and output size must be the same.
    //
    // # Semantic Statement
    //
    // `output = input.0`
    //

    // Loads from a dynamic location into the output variable.
    //
    // The first input simply provides information about the abstract memory space from which data
    // should be loaded. Specifically, the [`Space`] for the first input [`AddressRange`] is the space
    // from which the data is loaded while the `size` provides the scaling factor used to convert word
    // offsets to byte offsets.
    //
    // The second input contains the location where the word offset of the pointer can be found. For
    // example, if we were given the following operation:
    //
    // ```text
    // (register, 0x10, 0x04) = LOAD (ram, 0x00, 0x01) (unique, 0x18, 0x08)
    // ```
    //
    // This should be interpreted to mean that the eight bytes located at offset `0x18` in unique space
    // should be multiplied by one (wordsize) and four bytes (dictated by the output variable's size)
    // should be read from `ram` at the resulting offset to be stored in register space at offset
    // `0x10`.
    //
    // The offset field of the first input is not currently used to store any semantic information.
    //
    // # Note
    //
    // This is a subtly different format from SLEIGH's `LOAD` operation. In SLEIGH, the first input
    // parameter is a `constant` value that contains a pointer to the [`ghidralifter::ffi::AddrSpace`]
    // structure that describes the space to load from.
    //
    // Our implementation simply dereferences that pointer and stores all the necessary information in
    // the first parameter itself in order to simplify the implementation of [`Load`] and make it
    // easier for external programs to construct new [`Load`] operations without having to handle raw
    // pointers to foreign structures.
    //
    // # Invariants
    //
    // - The size of the second input should match the address size of the address space provided by
    // the first input (i.e. should be the size of a pointer in that address space). This is not
    // currently checked by the constructor.
    //
    // # Semantic Statement
    //
    //
    // `output = *[input.0]input.1`
    //

    // Stores data located in the third input parameter at a dynamic location.
    //
    // Similar to the [`Load`] operation, the first and second inputs together describe the dynamic
    // location for where the data contained in the third input should be stored. For example, if we
    // were given the following operation:
    //
    // ```text
    // STORE (ram, 0x00, 0x01) (register, 0x10, 0x08) (unique, 0x18, 0x04)
    // ```
    //
    // This should be interpreted to mean that the four bytes (given by the third input's size)
    // located at offset `0x18` in unique space should be stored in `ram` at the byte offset received
    // by multiplying one (wordsize) with the eight byte value stored in register space at offset
    // `0x10`.
    //
    // # Note
    //
    // See the notes in the [`Load`] operation for additional information about the differences in
    // format between this implementation and SLEIGH's.
    //
    // # Invariants
    //
    // - The size of the second input should match the address size of the address space provided by
    // the first input (i.e. should be the size of a pointer in that address space). This is not
    // currently checked by the constructor.
    //
    // # Semantic Statement
    //
    // `*[input.0]input.1 = input2;`
    //

    // Performs an absolute, unconditional jump.
    //
    // Upon applying this instruction the interpreter will stop execution and assume that the
    // following instruction begins at the address space and offset specified by the input. For
    // example, the following operation:
    //
    // ```text
    // BRANCH (ram, 0x1000, 8)
    // ```
    //
    // Will interpret the target of the jump to be address `0x1000` in memory, _not_ whatever the
    // eight byte value stored in `ram` at offset `0x1000` is.
    //
    // If the address space of the input is constant space, the branch is interpreted as a p-code
    // relative jump.

    // The real format for the Insert operation contains 1 output and 4 inputs. That would ordinarily
    // make this the largest variant of operation; however, according to the p-code documentation, this
    // operation is never actually generated, so it would be wasteful to force Operation to be big
    // enough to accommodate a variant that is never actually used. Instead, I am choosing to spill the
    // two constant input arguments onto the interpreter stack.
}
