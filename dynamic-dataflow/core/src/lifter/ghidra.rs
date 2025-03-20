use ghidra_lifter as ghidra;

use crate::address::AddressRange;
use crate::architecture;
use crate::lifter::{Lift, LiftError};
use crate::operation::{self, Operation};
use crate::space::{Space, SpaceAttributes, SpaceKind, SpaceManager};

pub struct GhidraLifter {
    lifter: ghidra::Lifter,
    space_info: Vec<(String, Space)>,
    constant_space: i32,
    unique_space: i32,
    code_space: i32,
    data_space: i32,
    register_space: i32,

    seqnum_changes: Vec<usize>,
    target_fixups: Vec<(usize, usize)>,
}

impl GhidraLifter {
    pub fn new(arch: impl GhidraArchitecture) -> Result<Self, LiftError> {
        let lifter = ghidra::Lifter::new(arch.language_id())?;

        let constant_space = lifter.getConstantSpaceId();
        let unique_space = lifter.getUniqueSpaceId();
        let code_space = lifter.getDefaultCodeSpaceId();
        let data_space = lifter.getDefaultDataSpaceId();
        let mut register_space: Option<i32> = None;

        let mut space_info = Vec::new();

        for i in 0..lifter.numSpaces() {
            let Some(space) = (unsafe { lifter.getSpace(i).as_ref() }) else {
                tracing::warn!(space_id = i, "failed to get space from lifter");
                continue;
            };

            assert!(i == space.getIndex());
            assert!(i < 0x1000);

            let name = space.getName().to_string_lossy().to_string();
            let info = Space::from(space);
            if register_space.is_none() && info.kind() == SpaceKind::Register {
                register_space = Some(i);
            }
            space_info.push((name, info));
        }

        assert!(space_info[constant_space as usize].1.kind() == SpaceKind::Constant);
        assert!(space_info[unique_space as usize].1.kind() == SpaceKind::Unique);
        assert!(space_info[code_space as usize].1.kind() == SpaceKind::Memory);
        assert!(space_info[data_space as usize].1.kind() == SpaceKind::Memory);

        Ok(Self {
            lifter,
            space_info,
            constant_space,
            unique_space,
            code_space,
            data_space,
            register_space: register_space.expect("missing register space"),

            seqnum_changes: Vec::new(),
            target_fixups: Vec::new(),
        })
    }

    pub fn instruction_length(&mut self, pc: u64, insbytes: &[u8]) -> Result<usize, LiftError> {
        self.lifter.clear();
        Ok(self.lifter.instruction_length(pc, insbytes)? as usize)
    }

    pub fn register_by_name(&self, register: &str) -> Result<AddressRange, LiftError> {
        Ok(self.lift_varnode(self.lifter.register_by_name(register)?))
    }
}

impl Lift for GhidraLifter {
    fn lift_instruction(
        &mut self,
        pc: u64,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
    ) -> Result<i32, LiftError> {
        self.lifter.clear();
        let inslength = self.lifter.lift(pc, insbytes)?;
        assembly.push_str(self.lifter.getAssembly().to_string_lossy().as_ref());
        let varnodes = self.lifter.getVars().as_slice();

        self.seqnum_changes.clear();
        self.target_fixups.clear();

        // Fixups are at least a little expensive so make sure they are needed first with the
        // following two conditions:
        // - At least one expansion/contraction of a pcode operation has occured
        // - There is at least one pcode relative branch
        let mut seqnums_modified = false;

        for (orig_seqnum, op) in self.lifter.getOperations().iter().enumerate() {
            let next_seqnum = operations.len();
            seqnums_modified = seqnums_modified || next_seqnum != orig_seqnum;
            self.seqnum_changes.push(next_seqnum);

            let vars = &varnodes[op.vars..op.vars + op.size];

            self.translate_operation_staging(op, vars, operations)
                .map_err(|e| LiftError::failed_to_lift(pc, insbytes, assembly.as_str(), Some(e)))?;

            if let Some(new_ops) = operations.get(next_seqnum..) {
                for (i, new_op) in new_ops.iter().enumerate() {
                    match new_op {
                        Operation::Branch(ref op) => {
                            let &[target] = op.inputs();
                            if target.space().kind() == SpaceKind::Constant {
                                self.target_fixups.push((next_seqnum + i, orig_seqnum));
                            }
                        }
                        Operation::CondBranch(ref op) => {
                            let &[target, _] = op.inputs();
                            if target.space().kind() == SpaceKind::Constant {
                                self.target_fixups.push((next_seqnum + i, orig_seqnum));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if seqnums_modified {
            let end = operations.len();
            for &(new_seqnum, orig_seqnum) in self.target_fixups.iter() {
                let op = operations
                    .get_mut(new_seqnum)
                    .expect("target fixups contains an invalid seqnum");

                match op {
                    Operation::Branch(ref mut op) => {
                        let &[orig_target] = op.inputs();
                        let new_target = self.fixup_pcode_relative_target(
                            orig_target,
                            orig_seqnum,
                            new_seqnum,
                            end,
                        );
                        op.set_target(new_target);
                    }
                    Operation::CondBranch(ref mut op) => {
                        let &[orig_target, _] = op.inputs();
                        let new_target = self.fixup_pcode_relative_target(
                            orig_target,
                            orig_seqnum,
                            new_seqnum,
                            end,
                        );
                        op.set_target(new_target);
                    }
                    _ => unreachable!(),
                }
            }
        }

        Ok(inslength)
    }
}

impl SpaceManager for GhidraLifter {
    fn register_space(&self) -> Space {
        let (_, space) = self.space_info[self.register_space as usize];
        space
    }

    fn default_data_space(&self) -> Space {
        let (_, space) = self.space_info[self.data_space as usize];
        space
    }

    fn default_code_space(&self) -> Space {
        let (_, space) = self.space_info[self.code_space as usize];
        space
    }

    fn unique_space(&self) -> Space {
        let (_, space) = self.space_info[self.unique_space as usize];
        space
    }

    fn constant_space(&self) -> Space {
        let (_, space) = self.space_info[self.constant_space as usize];
        space
    }

    fn space_by_name(&self, _name: &str) -> Option<Space> {
        todo!()
    }

    fn space_by_id(&self, _id: u16) -> Option<Space> {
        todo!()
    }
}

impl GhidraLifter {
    fn translate_operation_staging(
        &self,
        op: &ghidra::PcodeOperation,
        vars: &[ghidra::PcodeVar],
        ops: &mut Vec<Operation>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        macros::lift! {
            context { self, op, vars, ops },
            standard {
                CPUI_COPY                => Copy                 (2),
                CPUI_LOAD                => Load                 (3),
                CPUI_STORE               => Store                (3),
                CPUI_BRANCH              => Branch               (1),
                CPUI_CBRANCH             => CondBranch           (2),
                CPUI_BRANCHIND           => BranchInd            (1),
                CPUI_CALL                => Call                 (1),
                CPUI_CALLIND             => CallInd              (1),
                CPUI_RETURN              => Return               (1),
                CPUI_INT_EQUAL           => IntEqual             (3),
                CPUI_INT_NOTEQUAL        => IntNotEqual          (3),
                CPUI_INT_SLESS           => IntSignedLess        (3),
                CPUI_INT_SLESSEQUAL      => IntSignedLessEqual   (3),
                CPUI_INT_LESS            => IntLess              (3),
                CPUI_INT_LESSEQUAL       => IntLessEqual         (3),
                CPUI_INT_ZEXT            => IntZeroExtend        (2),
                CPUI_INT_SEXT            => IntSignExtend        (2),
                CPUI_INT_ADD             => IntAdd               (3),
                CPUI_INT_SUB             => IntSub               (3),
                CPUI_INT_CARRY           => IntCarry             (3),
                CPUI_INT_SCARRY          => IntSignedCarry       (3),
                CPUI_INT_SBORROW         => IntSignedBorrow      (3),
                CPUI_INT_2COMP           => IntNeg               (2),
                CPUI_INT_NEGATE          => IntNot               (2),
                CPUI_INT_XOR             => IntXor               (3),
                CPUI_INT_AND             => IntAnd               (3),
                CPUI_INT_OR              => IntOr                (3),
                CPUI_INT_LEFT            => IntLeft              (3),
                CPUI_INT_RIGHT           => IntRight             (3),
                CPUI_INT_SRIGHT          => IntSignedRight       (3),
                CPUI_INT_MULT            => IntMult              (3),
                CPUI_INT_DIV             => IntDiv               (3),
                CPUI_INT_SDIV            => IntSignedDiv         (3),
                CPUI_INT_REM             => IntRem               (3),
                CPUI_INT_SREM            => IntSignedRem         (3),
                CPUI_BOOL_NEGATE         => BoolNot              (2),
                CPUI_BOOL_XOR            => BoolXor              (3),
                CPUI_BOOL_AND            => BoolAnd              (3),
                CPUI_BOOL_OR             => BoolOr               (3),
                CPUI_FLOAT_EQUAL         => FloatEqual           (3),
                CPUI_FLOAT_NOTEQUAL      => FloatNotEqual        (3),
                CPUI_FLOAT_LESS          => FloatLess            (3),
                CPUI_FLOAT_LESSEQUAL     => FloatLessEqual       (3),
                CPUI_FLOAT_NAN           => FloatNaN             (2),
                CPUI_FLOAT_ADD           => FloatAdd             (3),
                CPUI_FLOAT_DIV           => FloatDiv             (3),
                CPUI_FLOAT_MULT          => FloatMult            (3),
                CPUI_FLOAT_SUB           => FloatSub             (3),
                CPUI_FLOAT_NEG           => FloatNeg             (2),
                CPUI_FLOAT_ABS           => FloatAbs             (2),
                CPUI_FLOAT_SQRT          => FloatSqrt            (2),
                CPUI_FLOAT_INT2FLOAT     => IntToFloat           (2),
                CPUI_FLOAT_FLOAT2FLOAT   => FloatToFloat         (2),
                CPUI_FLOAT_TRUNC         => FloatToInt           (2),
                CPUI_FLOAT_CEIL          => FloatCeil            (2),
                CPUI_FLOAT_FLOOR         => FloatFloor           (2),
                CPUI_FLOAT_ROUND         => FloatRound           (2),
                CPUI_INDIRECT            => Indirect             (3),
                CPUI_PIECE               => Piece                (3),
                CPUI_SUBPIECE            => Subpiece             (3),
                CPUI_PTRADD              => AddressOfIndex       (4),
                CPUI_PTRSUB              => AddressOfField       (3),
                CPUI_POPCOUNT            => Popcount             (2),
                CPUI_LZCOUNT             => Lzcount              (2),
            },
            custom {
                ghidra::OpCode::CPUI_SEGMENTOP => {}
                ghidra::OpCode::CPUI_INSERT => {}
                ghidra::OpCode::CPUI_EXTRACT => {}
                ghidra::OpCode::CPUI_CAST => {}

                /*
                ghidra::OpCode::CPUI_LOAD => {
                    let [ out, in0, in1 ] = self.lift_arguments(vars);

                    // From Ghidra, we are given the following:
                    // input0 -> Constant ID of space to load from (i.e. const varnode w/ a pointer
                    // to an AddrSpace)
                    // input1 -> Varnode containing pointer offset to data (i.e. varnode whose
                    // value is the offset we load from the above AddrSpace)
                    // output -> Destination varnode (also specifies size)
                    //
                    // Additionally, the offset from input1 is NOT the byte offset into AddrSpace;
                    // it is the word offset.
                    //
                    // So, in order to reduce what is needed to interpret load, we modify input0 to
                    // be a space info parameter by replacing the space id with the id of the
                    // resolved `AddrSpace`.

                    // This check probably isn't needed, but I'm keeping it around for now b/c it
                    // feels like a nice sanity check before dereferencing some `u64`.

                    /*
                    debug_assert!(in0.space().kind() == SpaceKind::Constant);

                    let addrspace = in0.offset() as *const ghidra::AddrSpace;
                    let id  = unsafe {
                        addrspace
                            .as_ref()
                            .expect("space param to LOAD was null")
                            .getIndex() as usize
                    };
                    let (_, space) = self.space_info[id];
                    let in0 = space.index(0..1);
                    */
                    let operation = operation::Load::new(out, in0, in1)?;
                    ops.push(Operation::from(operation));
                }

                ghidra::OpCode::CPUI_STORE => {
                    let [ in0, in1, in2 ] = self.lift_arguments(vars);

                    // See comments in LOAD for what is going on here

                    //debug_assert!(in0.space().kind() == SpaceKind::Constant);

                    //let addrspace = in0.offset() as *const ghidra::AddrSpace;
                    //let id  = unsafe {
                    //    addrspace
                    //        .as_ref()
                    //        .expect("space param to LOAD was null")
                    //        .getIndex() as usize
                    //};
                    //let (_, space) = self.space_info[id];
                    //let in0 = space.index(0..1);
                    let operation = operation::Store::new(in0, in1, in2)?;
                    ops.push(Operation::from(operation));
                }
                */

                ghidra::OpCode::CPUI_CPOOLREF => {
                    let [ out, in0, in1 ] = self.lift_arguments(vars);
                    let rem = &vars[3..];

                    let const_space = self.constant_space();
                    for (i, varnode) in rem.iter().enumerate() {
                        let in1 = self.lift_varnode(*varnode);
                        let in0 = const_space.index(i as u64..8 + i as u64);
                        let operation = unsafe { operation::Argument::new_unchecked(in0, in1) };
                        ops.push(Operation::from(operation));
                    }
                    let in2 = const_space.index(rem.len() as u64..8 + rem.len() as u64);
                    let operation = operation::ConstPoolRef::new(out, in0, in1, in2)?;
                    ops.push(Operation::from(operation));
                }

                ghidra::OpCode::CPUI_NEW => {
                    if op.size < 3 {
                        macros::lift!(@expandstandard self vars ops New 2)
                    } else {
                        macros::lift!(@expandstandard self vars ops NewCount 3)
                    }
                }

                ghidra::OpCode::CPUI_MULTIEQUAL => {
                    let [ out ] = self.lift_arguments(vars);
                    let rem = &vars[1..];
                    let const_space = self.constant_space();
                    for (i, varnode) in rem.iter().enumerate() {
                        let in1 = self.lift_varnode(*varnode);
                        let in0 = const_space.index(i as u64..8 + i as u64);
                        let operation = unsafe { operation::Argument::new_unchecked(in0, in1) };
                        ops.push(Operation::from(operation));
                    }
                    let in0 = const_space.index(rem.len() as u64..8 + rem.len() as u64);
                    let operation = operation::Multiequal::new(out, in0)?;
                    ops.push(Operation::from(operation));
                }

                ghidra::OpCode::CPUI_CALLOTHER => {

                    // CallOther can have a variable amount of argument (including an optional
                    // output), but must have at least one constant input. In order to allow
                    // operations to be `Copy`, we handle variable length arguments by emitting a
                    // non-standard pcode operation that will push all but the first input onto an
                    // interpreter stack and provide a length argument to CallOther to indicate how
                    // many arguments to grab off the stack at runtime.

                    // TODO: Check this logic
                    let (out, in0, rem) = if op.has_outvar {
                        (
                            Some(self.lift_varnode(vars[0])),
                            self.lift_varnode(vars[1]),
                            &vars[2..]
                        )
                    } else {
                        (
                            None,
                            self.lift_varnode(vars[0]),
                            &vars[1..],
                        )
                    };
                    let const_space = self.constant_space();
                    for (i, varnode) in rem.iter().enumerate() {
                        let in1 = self.lift_varnode(*varnode);
                        let in0 = const_space.index(i as u64..8 + i as u64);
                        let operation = unsafe { operation::Argument::new_unchecked(in0, in1) };
                        ops.push(Operation::from(operation));
                    }
                    let in1 = const_space.index(rem.len() as u64..8 + rem.len() as u64);
                    let operation = operation::CallOther::new(out, in0, in1)?;
                    ops.push(Operation::from(operation));
                }
            }
        }
        Ok(())
    }

    fn lift_arguments<const N: usize>(&self, vars: &[ghidra::PcodeVar]) -> [AddressRange; N] {
        std::array::from_fn(|i| self.lift_varnode(vars[i]))
    }

    fn lift_varnode(&self, var: ghidra::PcodeVar) -> AddressRange {
        // Intentionally panic if `space_id` is OOB. Fix ghidra bindings if panic occurs.
        let (_, space) = self.space_info[var.space_id as usize];
        let start = var.offset as u64;
        let end = start + var.size as u64;
        space.index(start..end)
    }

    fn fixup_pcode_relative_target(
        &self,
        target: AddressRange,
        orig_seqnum: usize,
        new_seqnum: usize,
        end: usize,
    ) -> AddressRange {
        let orig_offset = match target.size() {
            1 => target.offset() as i8 as i64 as u64,
            2 => target.offset() as i16 as i64 as u64,
            4 => target.offset() as i32 as i64 as u64,
            8 => target.offset(),
            _ => panic!("invalid size for pcode relative branch target"),
        };
        let orig_target = orig_offset.wrapping_add(orig_seqnum as u64) as usize;
        let new_target = self.seqnum_changes.get(orig_target).unwrap_or(&end);
        let new_offset = new_target.wrapping_sub(new_seqnum) as u64;
        let size = std::mem::size_of::<usize>() as u64;
        self.constant_space().index(new_offset..new_offset + size)
    }
}

impl From<&ghidra::AddrSpace> for Space {
    fn from(space: &ghidra::AddrSpace) -> Self {
        let name = space.getName().to_str().unwrap_or("");
        let index = space.getIndex() as u16;
        let word_size = space.getWordSize() as u8;
        let addr_size = space.getAddrSize() as u8;
        let mut attrs: u16 = if name == "register" {
            0b000
        } else if name == "unique" {
            0b011
        } else if name == "const" {
            0b001
        } else if space.getType() == ghidra::SpaceType::IPTR_PROCESSOR && space.hasPhysical() {
            0b010
        } else if space.getType() == ghidra::SpaceType::IPTR_CONSTANT {
            0b001
        } else {
            0b101
        };
        if space.isBigEndian() {
            attrs |= 0b1000;
        }
        Self::new(index, SpaceAttributes(attrs), addr_size, word_size)
    }
}

pub trait GhidraArchitecture {
    fn language_id(&self) -> &str;
}

impl<'a, T> GhidraArchitecture for &'a T
where
    T: GhidraArchitecture,
{
    fn language_id(&self) -> &str {
        <T as GhidraArchitecture>::language_id(self)
    }
}

impl GhidraArchitecture for architecture::X86 {
    fn language_id(&self) -> &str {
        "x86:LE:32:default:default"
    }
}

impl GhidraArchitecture for architecture::X86_64 {
    fn language_id(&self) -> &str {
        "x86:LE:64:default:default"
    }
}

impl GhidraArchitecture for architecture::X86_64Compat32 {
    fn language_id(&self) -> &str {
        "x86:LE:64:compat32:default"
    }
}

impl GhidraArchitecture for architecture::PPCBE32 {
    fn language_id(&self) -> &str {
        "PowerPC:BE:32:default:default"
    }
}

impl GhidraArchitecture for architecture::ARM32 {
    fn language_id(&self) -> &str {
        "ARM:LE:32:v8:default"
    }
}

impl GhidraArchitecture for architecture::AARCH64 {
    fn language_id(&self) -> &str {
        "AARCH64:LE:64:v8A:default"
    }
}

impl GhidraArchitecture for architecture::M68K {
    fn language_id(&self) -> &str {
        "68000:BE:32:MC68020:default"
    }
}

impl GhidraArchitecture for architecture::Architecture {
    fn language_id(&self) -> &str {
        match self {
            Self::X86(a) => a.language_id(),
            Self::X86_64(a) => a.language_id(),
            Self::X86_64Compat32(a) => a.language_id(),
            Self::PPCBE32(a) => a.language_id(),
            Self::AARCH64(a) => a.language_id(),
            Self::ARM32(a) => a.language_id(),
            Self::M68K(a) => a.language_id(),
        }
    }
}

impl GhidraArchitecture for &'_ str {
    fn language_id(&self) -> &str {
        self
    }
}

impl From<ghidra::LifterError> for LiftError {
    fn from(err: ghidra::LifterError) -> LiftError {
        match err {
            ghidra::LifterError::FailedToInitialize(_) => LiftError::FailedToBuild(Box::new(err)),
            ghidra::LifterError::FailedToCreate {
                archid: _,
                source: _,
            } => LiftError::FailedToBuild(Box::new(err)),
            ghidra::LifterError::FailedToLift { pc, bytes, source } => LiftError::FailedToLift {
                pc,
                bytes,
                asm: String::from("<unknown>"),
                source: Some(Box::new(source)),
            },
            ghidra::LifterError::InvalidRegisterName { name, source } => {
                LiftError::InvalidRegisterName {
                    name,
                    source: Some(Box::new(source)),
                }
            }
        }
    }
}

mod macros {
    macro_rules! lift {
        (
            context { $lifter:ident, $pcode_op:ident, $pcode_vars:ident, $translated_ops:ident },
            standard { $( $opcode:tt => $operation:tt ($numargs:tt) ),* $(,)? },
            custom { $($custom:tt)* }
        ) => {
            match $pcode_op.opc {
                $(macros::lift! { @expandopcode $opcode } => macros::lift! {
                    @expandstandard $lifter $pcode_vars $translated_ops $operation $numargs
                },)*

                $( $custom )*

                ::ghidra_lifter::OpCode { repr: _n } => {
                    // Do nothing
                }
            }
        };

        (@expandopcode $opcode:tt) => {
            ::ghidra_lifter::OpCode::$opcode
        };

        (@expandstandard $lifter:ident $pcode_vars:ident $translated_ops:ident $operation:tt 1) => {
            {
                let [ arg0 ] = $lifter.lift_arguments($pcode_vars);
                let operation = $crate::operation::$operation::new(arg0)?;
                $translated_ops.push(Operation::from(operation));
            }
        };
        (@expandstandard $lifter:ident $pcode_vars:ident $translated_ops:ident $operation:tt 2) => {
            {
                let [ arg0, arg1 ] = $lifter.lift_arguments($pcode_vars);
                let operation = $crate::operation::$operation::new(arg0, arg1)?;
                $translated_ops.push(Operation::from(operation));
            }
        };
        (@expandstandard $lifter:ident $pcode_vars:ident $translated_ops:ident $operation:tt 3) => {
            {
                let [ arg0, arg1, arg2 ] = $lifter.lift_arguments($pcode_vars);
                let operation = $crate::operation::$operation::new(arg0, arg1, arg2)?;
                $translated_ops.push(Operation::from(operation));
            }
        };
        (@expandstandard $lifter:ident $pcode_vars:ident $translated_ops:ident $operation:tt 4) => {
            {
                let [ arg0, arg1, arg2, arg3 ] = $lifter.lift_arguments($pcode_vars);
                let operation = $crate::operation::$operation::new(arg0, arg1, arg2, arg3)?;
                $translated_ops.push(Operation::from(operation));
            }
        };
    }

    pub(super) use lift;
}
