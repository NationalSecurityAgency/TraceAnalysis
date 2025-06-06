use crate::address::AddressRange;
use crate::operation;
use crate::space::SpaceKind;

use std::ops::{Index, IndexMut};

const HAS_VALUE: u64 = i64::MIN as u64;
const HAS_SOURCE: u64 = i64::MIN as u64 >> 1;

pub struct Scratch {
    val: Vec<u8>,
    src: Vec<u64>,
}

impl Scratch {
    pub fn new() -> Self {
        Self {
            val: Vec::new(),
            src: Vec::new(),
        }
    }

    #[inline]
    fn value_deps<'a, R>(&'a self, range: R, pos: u8) -> impl Iterator<Item = (u64, u8)> + 'a
    where
        R: std::slice::SliceIndex<[u64], Output = [u64]>,
    {
        self.src
            .index(range)
            .iter()
            .copied()
            .filter_map(move |s| (s & HAS_SOURCE != 0).then_some((s & (HAS_SOURCE - 1), pos)))
    }

    #[inline]
    fn resize(&mut self, new_len: usize) {
        self.val.resize(new_len, 0);
        self.src.resize(new_len, 0);
    }

    #[inline]
    fn swap_range<R>(&mut self, range: R)
    where
        R: std::slice::SliceIndex<[u64], Output = [u64]>
            + std::slice::SliceIndex<[u8], Output = [u8]>
            + Clone,
    {
        self.val.index_mut(range.clone()).reverse();
        self.src.index_mut(range).reverse();
    }

    #[inline]
    fn is_complete<R>(&self, range: R) -> bool
    where
        R: std::slice::SliceIndex<[u64], Output = [u64]>,
    {
        self.src.index(range).iter().all(|&s| s & HAS_VALUE != 0)
    }

    #[inline]
    fn clear(&mut self) {
        self.val.clear();
        self.src.clear();
    }
}

impl Extend<(Option<u8>, Option<u64>)> for Scratch {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (Option<u8>, Option<u64>)>,
    {
        let iter = iter.into_iter();
        let additional = iter.size_hint().0;
        self.val.reserve(additional);
        self.src.reserve(additional);
        iter.for_each(|(v, s)| {
            let has_value = if v.is_some() { HAS_VALUE } else { 0 };
            let has_source = if s.is_some() { HAS_SOURCE } else { 0 };
            let val = v.unwrap_or(0);
            let src = s.unwrap_or(0) | has_value | has_source;

            self.val.push(val);
            self.src.push(src);
        });
    }
}

pub trait ProgramState {
    fn resolve<V>(&self, address: &AddressRange, value: &mut V)
    where
        V: Extend<(Option<u8>, Option<u64>)>;

    fn push_argument(&mut self, arg: AddressRange);

    fn get_extended_args(&self, count: u64) -> &[AddressRange];

    fn add_value<V>(&mut self, address: &AddressRange, value: V)
    where
        V: IntoIterator<Item = Option<u8>>;

    fn add_value_deps<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (u64, u8)>;

    fn add_address_deps<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = u64>;

    fn add_control_flow_deps<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = u64>;

    fn set_control_flow(&mut self, cf: ControlFlow);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlFlow {
    Step,
    Break,
    JumpRel(u64),
}

pub trait Emulate {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch);
}

impl Emulate for operation::Operation {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        match self {
            Self::Copy(op) => op.emulate(state, scratch),
            Self::Load(op) => op.emulate(state, scratch),
            Self::Store(op) => op.emulate(state, scratch),
            Self::Branch(op) => op.emulate(state, scratch),
            Self::CondBranch(op) => op.emulate(state, scratch),
            Self::BranchInd(op) => op.emulate(state, scratch),
            Self::Call(op) => op.emulate(state, scratch),
            Self::CallInd(op) => op.emulate(state, scratch),
            Self::CallOther(op) => op.emulate(state, scratch),
            Self::Return(op) => op.emulate(state, scratch),
            Self::IntEqual(op) => op.emulate(state, scratch),
            Self::IntNotEqual(op) => op.emulate(state, scratch),
            Self::IntSignedLess(op) => op.emulate(state, scratch),
            Self::IntSignedLessEqual(op) => op.emulate(state, scratch),
            Self::IntLess(op) => op.emulate(state, scratch),
            Self::IntLessEqual(op) => op.emulate(state, scratch),
            Self::IntZeroExtend(op) => op.emulate(state, scratch),
            Self::IntSignExtend(op) => op.emulate(state, scratch),
            Self::IntAdd(op) => op.emulate(state, scratch),
            Self::IntSub(op) => op.emulate(state, scratch),
            Self::IntCarry(op) => op.emulate(state, scratch),
            Self::IntSignedCarry(op) => op.emulate(state, scratch),
            Self::IntSignedBorrow(op) => op.emulate(state, scratch),
            Self::IntNeg(op) => op.emulate(state, scratch),
            Self::IntNot(op) => op.emulate(state, scratch),
            Self::IntXor(op) => op.emulate(state, scratch),
            Self::IntAnd(op) => op.emulate(state, scratch),
            Self::IntOr(op) => op.emulate(state, scratch),
            Self::IntLeft(op) => op.emulate(state, scratch),
            Self::IntRight(op) => op.emulate(state, scratch),
            Self::IntSignedRight(op) => op.emulate(state, scratch),
            Self::IntMult(op) => op.emulate(state, scratch),
            Self::IntDiv(op) => op.emulate(state, scratch),
            Self::IntSignedDiv(op) => op.emulate(state, scratch),
            Self::IntRem(op) => op.emulate(state, scratch),
            Self::IntSignedRem(op) => op.emulate(state, scratch),
            Self::BoolNot(op) => op.emulate(state, scratch),
            Self::BoolXor(op) => op.emulate(state, scratch),
            Self::BoolAnd(op) => op.emulate(state, scratch),
            Self::BoolOr(op) => op.emulate(state, scratch),
            Self::FloatEqual(op) => op.emulate(state, scratch),
            Self::FloatNotEqual(op) => op.emulate(state, scratch),
            Self::FloatLess(op) => op.emulate(state, scratch),
            Self::FloatLessEqual(op) => op.emulate(state, scratch),
            Self::FloatNaN(op) => op.emulate(state, scratch),
            Self::FloatAdd(op) => op.emulate(state, scratch),
            Self::FloatDiv(op) => op.emulate(state, scratch),
            Self::FloatMult(op) => op.emulate(state, scratch),
            Self::FloatSub(op) => op.emulate(state, scratch),
            Self::FloatNeg(op) => op.emulate(state, scratch),
            Self::FloatAbs(op) => op.emulate(state, scratch),
            Self::FloatSqrt(op) => op.emulate(state, scratch),
            Self::IntToFloat(op) => op.emulate(state, scratch),
            Self::FloatToFloat(op) => op.emulate(state, scratch),
            Self::FloatToInt(op) => op.emulate(state, scratch),
            Self::FloatCeil(op) => op.emulate(state, scratch),
            Self::FloatFloor(op) => op.emulate(state, scratch),
            Self::FloatRound(op) => op.emulate(state, scratch),
            Self::Multiequal(op) => op.emulate(state, scratch),
            Self::Indirect(op) => op.emulate(state, scratch),
            Self::Piece(op) => op.emulate(state, scratch),
            Self::Subpiece(op) => op.emulate(state, scratch),
            Self::Cast(op) => op.emulate(state, scratch),
            Self::AddressOfIndex(op) => op.emulate(state, scratch),
            Self::AddressOfField(op) => op.emulate(state, scratch),
            Self::SegmentOp(op) => op.emulate(state, scratch),
            Self::ConstPoolRef(op) => op.emulate(state, scratch),
            Self::New(op) => op.emulate(state, scratch),
            Self::Insert(op) => op.emulate(state, scratch),
            Self::Extract(op) => op.emulate(state, scratch),
            Self::Popcount(op) => op.emulate(state, scratch),
            Self::Lzcount(op) => op.emulate(state, scratch),
            Self::NewCount(op) => op.emulate(state, scratch),
            Self::IntCmp(op) => op.emulate(state, scratch),
            Self::IntSignedCmp(op) => op.emulate(state, scratch),
            Self::Argument(op) => op.emulate(state, scratch),
            Self::Unknown(op) => op.emulate(state, scratch),
        }
    }
}

impl Emulate for operation::Copy {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [iaddr0] = self.inputs();

        let ival0 = scratch.val.len();
        state.resolve(&iaddr0, scratch);

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        if oaddr.space().big_endian() != iaddr0.space().big_endian() {
            scratch.swap_range(ival0..);
        }

        let oval = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(scratch.src[ival0..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

        state.add_value(&oaddr, oval);

        scratch.clear();
    }
}

impl Emulate for operation::Cast {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [iaddr0] = self.inputs();

        let ival0 = scratch.val.len();
        state.resolve(&iaddr0, scratch);

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        if oaddr.space().big_endian() != iaddr0.space().big_endian() {
            scratch.swap_range(ival0..);
        }

        let oval = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(scratch.src[ival0..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

        state.add_value(&oaddr, oval);

        scratch.clear();

        // panic here b/c this operation should never _actually_ exist
        unimplemented!();
    }
}

impl Emulate for operation::Load {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [iaddr0, iaddr1] = self.inputs();
        let [(_, ival1)] = resolve_inputs(state, scratch, &[*iaddr1]);
        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_address_deps(
                scratch.src[ival1..]
                    .iter()
                    .copied()
                    .filter_map(|s| (s & HAS_SOURCE != 0).then_some(s & (HAS_SOURCE - 1))),
            );
        }

        if scratch.is_complete(ival1..) {
            let mut offset = [0u8; 8];
            (&mut offset[..iaddr1.size() as usize]).copy_from_slice(&scratch.val[ival1..]);
            let offset = u64::from_le_bytes(offset).wrapping_mul(iaddr0.space().word_size() as u64);
            let iaddr2 = iaddr0.space().index(offset..offset + oaddr.size());
            let ival2 = scratch.val.len();
            state.resolve(&iaddr2, scratch);
            state.add_value_deps(scratch.value_deps(ival2.., 0));
            if oaddr.space().big_endian() != iaddr2.space().big_endian() {
                scratch.swap_range(ival2..);
            }
            let oval = scratch.val[ival2..]
                .iter()
                .copied()
                .zip(scratch.src[ival2..].iter().copied())
                .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));
            state.add_value(&oaddr, oval);
        } else {
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        }

        scratch.clear();
    }
}

impl Emulate for operation::Store {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let &[iaddr0, iaddr1, iaddr2] = self.inputs();
        let [(_, ival1), (_, ival2)] = resolve_inputs(state, scratch, &[iaddr1, iaddr2]);
        if iaddr1.space().kind() != SpaceKind::Constant {
            state.add_address_deps(
                scratch.src[ival1..ival2]
                    .iter()
                    .copied()
                    .filter_map(|s| (s & HAS_SOURCE != 0).then_some(s & (HAS_SOURCE - 1))),
            );
        }
        if iaddr2.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival2.., 0));
        }
        if scratch.is_complete(ival1..ival2) {
            let mut offset = [0u8; 8];
            (&mut offset[..iaddr1.size() as usize]).copy_from_slice(&scratch.val[ival1..ival2]);
            let offset = u64::from_le_bytes(offset).wrapping_mul(iaddr0.space().word_size() as u64);
            let oaddr = iaddr0.space().index(offset..offset + iaddr2.size());
            if oaddr.space().big_endian() {
                scratch.swap_range(ival2..);
            }
            let oval = scratch.val[ival2..]
                .iter()
                .copied()
                .zip(scratch.src[ival2..].iter().copied())
                .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));
            state.add_value(&oaddr, oval);
        }
    }
}

macro_rules! impl_flag_binop {
    ($ty:ty) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [(iaddr0, ival0), (iaddr1, ival1)] =
                    resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
                }

                if iaddr1.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival1.., 1));
                }

                let mut oval: Option<u8> = None;
                if scratch.is_complete(ival0..ival1) && scratch.is_complete(ival1..) {
                    let (a, b) = scratch.val[ival0..].split_at(iaddr0.size() as usize);
                    oval = if Self::_impl(a, b) { Some(1) } else { Some(0) };
                }

                state.add_value(&oaddr, std::iter::once(oval));

                scratch.clear();
            }
        }
    };
}

impl_flag_binop!(operation::IntEqual);
impl_flag_binop!(operation::IntNotEqual);
impl_flag_binop!(operation::IntSignedLess);
impl_flag_binop!(operation::IntSignedLessEqual);
impl_flag_binop!(operation::IntLess);
impl_flag_binop!(operation::IntLessEqual);
impl_flag_binop!(operation::IntCarry);
impl_flag_binop!(operation::IntSignedCarry);
impl_flag_binop!(operation::IntSignedBorrow);

impl Emulate for operation::IntZeroExtend {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        scratch.resize(ival0 + oaddr.size() as usize);
        (&mut scratch.src[ival0 + iaddr0.size() as usize..]).fill(HAS_VALUE);

        if oaddr.space().big_endian() {
            scratch.swap_range(ival0..);
        }

        let oval = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(scratch.src[ival0..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

        state.add_value(&oaddr, oval);

        scratch.clear();
    }
}

impl Emulate for operation::IntSignExtend {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        let has_value = scratch.src.last().map_or(false, |&s| s & HAS_VALUE != 0);
        let sign = scratch.val.last().map_or(false, |&v| v & 0x80 != 0);

        scratch.resize(ival0 + oaddr.size() as usize);
        if has_value {
            (&mut scratch.src[ival0 + iaddr0.size() as usize..]).fill(HAS_VALUE);
        }
        if sign {
            (&mut scratch.val[ival0 + iaddr0.size() as usize..]).fill(0xff);
        }

        if oaddr.space().big_endian() {
            scratch.swap_range(ival0..);
        }

        let oval = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(scratch.src[ival0..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

        state.add_value(&oaddr, oval);

        scratch.clear();
    }
}

macro_rules! impl_arith_binop {
    ($ty:ty) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [(iaddr0, ival0), (iaddr1, ival1)] =
                    resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
                }

                if iaddr1.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival1.., 1));
                }

                let oval = scratch.val.len();
                scratch.resize(oval + oaddr.size() as usize);

                if scratch.is_complete(ival0..ival1) && scratch.is_complete(ival1..oval) {
                    let (a, bc) = (&mut scratch.val[ival0..]).split_at_mut(iaddr0.size() as usize);
                    let (b, c) = bc.split_at_mut(iaddr1.size() as usize);
                    Self::_impl(c, a, b);
                    if oaddr.space().big_endian() {
                        c.reverse();
                    }
                    state.add_value(&oaddr, c.iter().copied().map(|v| Some(v)));
                } else {
                    state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
                }

                scratch.clear();
            }
        }
    };
}

impl_arith_binop!(operation::IntAdd);
impl_arith_binop!(operation::IntSub);
impl_arith_binop!(operation::IntMult);
impl_arith_binop!(operation::IntDiv);
impl_arith_binop!(operation::IntSignedDiv);
impl_arith_binop!(operation::IntRem);
impl_arith_binop!(operation::IntSignedRem);
impl_arith_binop!(operation::IntLeft);
impl_arith_binop!(operation::IntRight);
impl_arith_binop!(operation::IntSignedRight);
impl_arith_binop!(operation::AddressOfField);

impl Emulate for operation::IntNeg {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        if scratch.is_complete(ival0..) {
            scratch.resize(ival0 + oaddr.size() as usize);
            let (b, a) = (&mut scratch.val[ival0..]).split_at_mut(iaddr0.size() as usize);
            Self::_impl(a, b);
            if oaddr.space().big_endian() {
                a.reverse();
            }
            state.add_value(&oaddr, a.iter().copied().map(|v| Some(v)));
        } else {
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        }

        scratch.clear();
    }
}

macro_rules! impl_logic_binop {
    ($ty:ty) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [(iaddr0, ival0), (iaddr1, ival1)] =
                    resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
                }

                if iaddr1.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival1.., 1));
                }

                let oval = scratch.val.len();
                scratch.resize(oval + oaddr.size() as usize);

                let (a_src, bc_src) =
                    (&mut scratch.src[ival0..]).split_at_mut(iaddr0.size() as usize);
                let (b_src, c_src) = bc_src.split_at_mut(iaddr1.size() as usize);
                (0..c_src.len()).for_each(|i| c_src[i] = a_src[i] & b_src[i]);

                let (a_val, bc_val) =
                    (&mut scratch.val[ival0..]).split_at_mut(iaddr0.size() as usize);
                let (b_val, c_val) = bc_val.split_at_mut(iaddr1.size() as usize);
                Self::_impl(c_val, b_val, a_val);

                if oaddr.space().big_endian() {
                    c_src.reverse();
                    c_val.reverse();
                }

                let oval = c_val
                    .iter()
                    .copied()
                    .zip(c_src.iter().copied())
                    .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

                state.add_value(&oaddr, oval);

                scratch.clear();
            }
        }
    };
}

impl_logic_binop!(operation::IntXor);
impl_logic_binop!(operation::IntAnd);
impl_logic_binop!(operation::IntOr);

impl Emulate for operation::IntNot {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [iaddr0] = self.inputs();

        let ival0 = scratch.val.len();
        state.resolve(&iaddr0, scratch);

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        (&mut scratch.val[ival0..])
            .iter_mut()
            .for_each(|v| *v = !*v);
        if oaddr.space().big_endian() != iaddr0.space().big_endian() {
            scratch.swap_range(ival0..);
        }

        let oval = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(scratch.src[ival0..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));

        state.add_value(&oaddr, oval);

        scratch.clear();
    }
}

macro_rules! impl_bool_binop {
    ($ty:ty,$($op:tt)*) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [
                    (iaddr0, ival0),
                    (iaddr1, ival1),
                ] = resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
                }

                if iaddr1.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival1.., 1));
                }

                let oval = (scratch.src[ival0] & scratch.src[ival1] & HAS_VALUE != 0)
                    .then_some( $($op)* (scratch.val[ival0], scratch.val[ival1]) & 0x1);

                state.add_value(&oaddr, std::iter::once(oval));

                scratch.clear();
            }
        }
    }
}

impl_bool_binop!(operation::BoolXor, std::ops::BitXor::bitxor);
impl_bool_binop!(operation::BoolAnd, std::ops::BitAnd::bitand);
impl_bool_binop!(operation::BoolOr, std::ops::BitOr::bitor);

impl Emulate for operation::BoolNot {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [iaddr0] = self.inputs();

        let ival0 = scratch.val.len();
        state.resolve(&iaddr0, scratch);

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }

        let oval = (scratch.src[ival0] & HAS_VALUE != 0).then_some(!scratch.val[ival0]);

        state.add_value(&oaddr, std::iter::once(oval));

        scratch.clear();
    }
}

macro_rules! impl_opaque_binop {
    ($ty:ty) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [(iaddr0, ival0), (iaddr1, ival1)] =
                    resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
                }

                if iaddr1.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival1.., 1));
                }

                state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));

                scratch.clear();
            }
        }
    };
}

impl_opaque_binop!(operation::FloatEqual);
impl_opaque_binop!(operation::FloatNotEqual);
impl_opaque_binop!(operation::FloatLess);
impl_opaque_binop!(operation::FloatLessEqual);
impl_opaque_binop!(operation::FloatAdd);
impl_opaque_binop!(operation::FloatDiv);
impl_opaque_binop!(operation::FloatMult);
impl_opaque_binop!(operation::FloatSub);

macro_rules! impl_opaque_unop {
    ($ty:ty) => {
        impl Emulate for $ty {
            fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
                let oaddr = self.output();
                let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());

                if iaddr0.space().kind() != SpaceKind::Constant {
                    state.add_value_deps(scratch.value_deps(ival0.., 0));
                }

                state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));

                scratch.clear();
            }
        }
    };
}

impl_opaque_unop!(operation::FloatNaN);
impl_opaque_unop!(operation::FloatNeg);
impl_opaque_unop!(operation::FloatAbs);
impl_opaque_unop!(operation::FloatSqrt);
impl_opaque_unop!(operation::IntToFloat);
impl_opaque_unop!(operation::FloatToFloat);
impl_opaque_unop!(operation::FloatToInt);
impl_opaque_unop!(operation::FloatCeil);
impl_opaque_unop!(operation::FloatFloor);
impl_opaque_unop!(operation::FloatRound);

impl Emulate for operation::Branch {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let [iaddr0] = self.inputs();
        if iaddr0.space().kind() == SpaceKind::Constant {
            state.set_control_flow(ControlFlow::JumpRel(iaddr0.offset()));
        } else {
            state.set_control_flow(ControlFlow::Break);
        }
    }
}

impl Emulate for operation::CondBranch {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [(iaddr0, ival0), (iaddr1, ival1)] = resolve_inputs(state, scratch, self.inputs());

        if iaddr1.space().kind() != SpaceKind::Constant {
            state.add_control_flow_deps(std::iter::once(scratch.src[ival1] & (HAS_VALUE - 1)));
        }

        let cond = (scratch.src[ival1] & HAS_VALUE != 0).then_some(scratch.val[ival0] != 0);

        match cond {
            Some(true) => {
                if iaddr0.space().kind() == SpaceKind::Constant {
                    state.set_control_flow(ControlFlow::JumpRel(iaddr0.offset()));
                } else {
                    state.set_control_flow(ControlFlow::Break);
                }
            }
            Some(false) => {
                // Default ControlFlow is Step, so nothing to be done here
            }
            None => {
                // We do not know if we have taken the branch or not so we just break.
                // TODO: log this
                state.set_control_flow(ControlFlow::Break);
            }
        }

        scratch.clear();
    }
}

impl Emulate for operation::BranchInd {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [(_iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());
        state.add_control_flow_deps(
            scratch.src[ival0..]
                .iter()
                .copied()
                .filter_map(|s| (s & HAS_SOURCE != 0).then_some(s & (HAS_SOURCE - 1))),
        );
        scratch.clear()
    }
}

impl Emulate for operation::Call {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let [iaddr0] = self.inputs();
        if iaddr0.space().kind() == SpaceKind::Constant {
            state.set_control_flow(ControlFlow::JumpRel(iaddr0.offset()));
        } else {
            state.set_control_flow(ControlFlow::Break);
        }
    }
}

impl Emulate for operation::CallInd {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [(_iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());
        state.add_control_flow_deps(
            scratch.src[ival0..]
                .iter()
                .copied()
                .filter_map(|s| (s & HAS_SOURCE != 0).then_some(s & (HAS_SOURCE - 1))),
        );
        scratch.clear()
    }
}

impl Emulate for operation::Return {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [(_iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());
        state.add_control_flow_deps(
            scratch.src[ival0..]
                .iter()
                .copied()
                .filter_map(|s| (s & HAS_SOURCE != 0).then_some(s & (HAS_SOURCE - 1))),
        );
        scratch.clear()
    }
}

impl Emulate for operation::CallOther {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [_iaddr0, iaddr1] = self.inputs();
        if let Some(oaddr) = self.output() {
            let args = Vec::from(state.get_extended_args(iaddr1.offset()));
            for (i, iaddr) in args.into_iter().enumerate() {
                if iaddr.space().kind() != SpaceKind::Constant {
                    let ival = scratch.val.len();
                    state.resolve(&iaddr, scratch);
                    state.add_value_deps(scratch.value_deps(ival.., i as u8));
                }
            }
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
            scratch.clear()
        }
    }
}

impl Emulate for operation::Multiequal {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let [iaddr0] = self.inputs();
        let oaddr = self.output();
        let args = Vec::from(state.get_extended_args(iaddr0.offset()));
        for (i, iaddr) in args.into_iter().enumerate() {
            if iaddr.space().kind() != SpaceKind::Constant {
                let ival = scratch.val.len();
                state.resolve(&iaddr, scratch);
                state.add_value_deps(scratch.value_deps(ival.., i as u8));
            }
        }
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        scratch.clear()
    }
}

impl Emulate for operation::Indirect {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let &[_iaddr0, iaddr1] = self.inputs();
        let [(_, ival1)] = resolve_inputs(state, scratch, &[iaddr1]);
        if iaddr1.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival1.., 0));
        }
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        scratch.clear();

        // panic here b/c this operation should never _acutally_ exist
        // if we want "indirect" semantics, we will encode them with a different op
        unimplemented!()
    }
}

impl Emulate for operation::Piece {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        // SLEIGH encodes this operation as OUT = PIECE (MSBs, LSBs), but we store all data as
        // little endian internally. Therefore, in order to make this a trival copy to the output,
        // we flip the input parameters before resolving values.
        let &[iaddr0, iaddr1] = self.inputs();
        let [(_, ival1), (_, ival0)] = resolve_inputs(state, scratch, &[iaddr1, iaddr0]);
        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0))
        }
        if iaddr1.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival1..ival0, 1))
        }
        if oaddr.space().big_endian() {
            scratch.swap_range(ival1..);
        }
        let oval = scratch.val[ival1..]
            .iter()
            .copied()
            .zip(scratch.src[ival1..].iter().copied())
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));
        state.add_value(&oaddr, oval);
        scratch.clear();
    }
}

impl Emulate for operation::Subpiece {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let &[iaddr0, iaddr1] = self.inputs();
        let [(_, ival0)] = resolve_inputs(state, scratch, &[iaddr0]);
        let oval = ival0 + iaddr1.offset() as usize;
        if oaddr.space().big_endian() {
            scratch.swap_range(oval..oval + oaddr.size() as usize);
        }
        let oval = scratch.val[oval..oval + oaddr.size() as usize]
            .iter()
            .copied()
            .zip(
                scratch.src[oval..oval + oaddr.size() as usize]
                    .iter()
                    .copied(),
            )
            .map(|(v, s)| (s & HAS_VALUE != 0).then_some(v));
        state.add_value(&oaddr, oval);
        scratch.clear();
    }
}

impl Emulate for operation::AddressOfIndex {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0), (iaddr1, ival1), (iaddr2, ival2)] =
            resolve_inputs(state, scratch, self.inputs());

        let oval = scratch.val.len();
        scratch.resize(oval + (oaddr.size() as usize * 2));

        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0..ival1, 0));
        }

        if iaddr1.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival1.., 1));
        }

        if scratch.is_complete(ival0..ival1) && scratch.is_complete(ival1..ival2) {
            let (a, bcde) = (&mut scratch.val[ival0..]).split_at_mut(iaddr0.size() as usize);
            let (b, cde) = bcde.split_at_mut(iaddr1.size() as usize);
            let (c, de) = cde.split_at_mut(iaddr2.size() as usize);
            let (d, e) = de.split_at_mut(oaddr.size() as usize);

            operation::IntMult::_impl(d, b, c);
            operation::IntAdd::_impl(e, a, d);

            if oaddr.space().big_endian() {
                e.reverse();
            }
            state.add_value(&oaddr, e.iter().copied().map(|v| Some(v)));
        } else {
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        }

        scratch.clear();

        // panic here b/c this operation should never _actually_ exist
        unimplemented!();
    }
}

impl Emulate for operation::SegmentOp {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let Some(oaddr) = self.output() else {
            return;
        };
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
    }
}

impl Emulate for operation::ConstPoolRef {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let oaddr = self.output();
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
    }
}

impl Emulate for operation::New {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let oaddr = self.output();
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
    }
}

impl Emulate for operation::NewCount {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let oaddr = self.output();
        state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
    }
}

impl Emulate for operation::Insert {
    fn emulate<S: ProgramState>(&self, _state: &mut S, _scratch: &mut Scratch) {
        unimplemented!()
    }
}

impl Emulate for operation::Extract {
    fn emulate<S: ProgramState>(&self, _state: &mut S, _scratch: &mut Scratch) {
        unimplemented!()
    }
}

impl Emulate for operation::Popcount {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());
        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }
        if scratch.is_complete(ival0..) {
            let count: u32 = scratch.val[ival0..]
                .iter()
                .copied()
                .map(u8::count_ones)
                .sum();
            let oval = scratch.val.len();
            scratch.resize(oval + oaddr.size() as usize);
            let bytecount = std::cmp::min(oaddr.size() as usize, std::mem::size_of::<u32>());
            (&mut scratch.val[oval..oval + bytecount])
                .copy_from_slice(&count.to_le_bytes()[..bytecount]);
            if oaddr.space().big_endian() {
                scratch.swap_range(oval..);
            }
            state.add_value(&oaddr, scratch.val[oval..].iter().copied().map(|v| Some(v)));
        } else {
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        }
        scratch.clear();
    }
}

impl Emulate for operation::Lzcount {
    fn emulate<S: ProgramState>(&self, state: &mut S, scratch: &mut Scratch) {
        let oaddr = self.output();
        let [(iaddr0, ival0)] = resolve_inputs(state, scratch, self.inputs());
        if iaddr0.space().kind() != SpaceKind::Constant {
            state.add_value_deps(scratch.value_deps(ival0.., 0));
        }
        let count = scratch.val[ival0..]
            .iter()
            .copied()
            .zip(
                scratch.src[ival0..]
                    .iter()
                    .copied()
                    .map(|s| s & HAS_VALUE != 0),
            )
            .enumerate()
            .find_map(|(i, (v, b))| match (b, v.leading_zeros()) {
                (false, _) => Some(None),
                (true, 8) => None,
                (true, n) => Some(Some((i * 8) + n as usize)),
            });
        if let Some(Some(count)) = count {
            let oval = scratch.val.len();
            scratch.resize(oval + oaddr.size() as usize);
            let bytecount = std::cmp::min(oaddr.size() as usize, std::mem::size_of::<usize>());
            (&mut scratch.val[oval..oval + bytecount])
                .copy_from_slice(&count.to_le_bytes()[..bytecount]);
            if oaddr.space().big_endian() {
                scratch.swap_range(oval..);
            }
            state.add_value(&oaddr, scratch.val[oval..].iter().copied().map(|v| Some(v)));
        } else {
            state.add_value(&oaddr, std::iter::repeat(None).take(oaddr.size() as usize));
        }
    }
}

impl Emulate for operation::IntCmp {
    fn emulate<S: ProgramState>(&self, _state: &mut S, _scratch: &mut Scratch) {
        unimplemented!()
    }
}

impl Emulate for operation::IntSignedCmp {
    fn emulate<S: ProgramState>(&self, _state: &mut S, _scratch: &mut Scratch) {
        unimplemented!()
    }
}

impl Emulate for operation::Argument {
    fn emulate<S: ProgramState>(&self, state: &mut S, _scratch: &mut Scratch) {
        let &[_iaddr0, iaddr1] = self.inputs();
        state.push_argument(iaddr1);
    }
}

impl Emulate for operation::Unknown {
    fn emulate<S: ProgramState>(&self, _state: &mut S, _scratch: &mut Scratch) {
        unimplemented!()
    }
}

fn resolve_inputs<S: ProgramState, const N: usize>(
    state: &S,
    scratch: &mut Scratch,
    inputs: &[AddressRange; N],
) -> [(AddressRange, usize); N] {
    std::array::from_fn(|i| {
        let iaddr = inputs[i];
        let ival = scratch.val.len();
        state.resolve(&iaddr, scratch);
        if iaddr.space().big_endian() {
            scratch.swap_range(ival..);
        }
        (iaddr, ival)
    })
}
