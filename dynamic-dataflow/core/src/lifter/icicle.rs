use crate::types::*;
use std::collections::HashMap;

pub struct Lifter {
    sleigh: sleigh_runtime::SleighData,
    lifter: sleigh_runtime::Lifter,
    decoder: sleigh_runtime::Decoder,
    decoded: sleigh_runtime::Instruction,
    labels: Vec<(u16, usize)>,
    fixups: Vec<(u16, usize)>,
    args: Vec<AddressRange>,
    reverse_register_map: HashMap<u64, u32>,
}

impl Lifter {
    pub fn register_by_name(&mut self, name: &str) -> Result<AddressRange> {
        self.sleigh
            .get_reg(name)
            .map(|r| {
                AddressRange::new(
                    Bank::Registers,
                    Offset::from(r.offset as u64),
                    r.var.size as _,
                )
            })
            .ok_or_else(|| Error::new(file!(), line!(), "failed to lookup register"))
    }

    pub fn on_instruction(
        &mut self,
        pc: Offset,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
    ) -> Result<()> {
        let Lifter {
            ref sleigh,
            ref mut lifter,
            ref mut decoder,
            ref mut decoded,
            ref mut labels,
            ref mut fixups,
            ref mut args,
            ref reverse_register_map,
        } = self;

        assembly.clear();
        labels.clear();
        fixups.clear();
        args.clear();

        decoder.set_inst(pc.as_u64(), insbytes);
        decoder
            .decode_into(sleigh, decoded)
            .ok_or_else(|| Error::new(file!(), line!(), "failed to decode instruction"))?;
        sleigh
            .disasm_into(decoded, assembly)
            .ok_or_else(|| Error::new(file!(), line!(), "failed to disassemble instruction"))?;

        let block = lifter
            .lift(sleigh, decoded)
            .map_err(|_| Error::new(file!(), line!(), "failed to lift instruction"))?;

        for ins in block.instructions.iter() {
            match ins.op {
                pcode::Op::Arg(n) => {
                    eprintln!("[PC:{:#x?}]: Pushing argument {n:?} to stack", pc.as_u64());
                    if args.len() <= n as usize {
                        let dummy = AddressRange::new(Bank::Null, Offset::from(0), 0);
                        args.resize(n as usize + 1, dummy);
                    }
                    args[n as usize] =
                        value_to_address_range(ins.inputs.first(), reverse_register_map);
                    continue;
                }
                pcode::Op::PcodeLabel(n) => {
                    let next = operations.len();
                    labels.push((n, next));
                }
                pcode::Op::PcodeBranch(n) => {
                    let next = operations.len();
                    fixups.push((n, next));
                }
                _ => {}
            }
            if let Some(op) = instruction_to_operation(*ins, reverse_register_map) {
                operations.push(op);
            }
            match ins.op {
                pcode::Op::PcodeOp(_) => {
                    if args.len() > 0 {
                        eprintln!("[PC:{:#x?}]: Consuming argument stack", pc.as_u64());
                    }
                    let last = operations.len() - 1;
                    if let Some(Operation::CallOther(_, ref mut inputs)) = operations.get_mut(last)
                    {
                        inputs.extend(args.drain(..));
                    }
                }
                _ => {}
            }
        }

        for &(label, index) in fixups.iter() {
            let offset = labels
                .iter()
                .find_map(|&(n, target)| {
                    if n == label {
                        return Some(target.wrapping_sub(index));
                    }
                    None
                })
                .ok_or_else(|| {
                    Error::new(file!(), line!(), "pcode relative branch missing target")
                })?;

            match operations.get_mut(index) {
                Some(Operation::Branch(ref mut target)) => {
                    *target = AddressRange::constant(offset as _, 4);
                }
                Some(Operation::CBranch(_, ref mut target)) => {
                    *target = AddressRange::constant(offset as _, 4);
                }
                _ => {
                    return Err(Error::new(
                        file!(),
                        line!(),
                        "unexpected operation from pcode branch",
                    ));
                }
            }
        }

        /*
        operations.extend(block.instructions.iter().filter_map(|ins| {
            instruction_to_operation(*ins, reverse_register_map)
        }));
        */

        Ok(())
    }

    pub fn big_endian(&self) -> bool {
        self.sleigh.big_endian
    }
}

impl std::convert::TryFrom<DataflowConfig> for Lifter {
    type Error = Error;

    fn try_from(config: DataflowConfig) -> Result<Self> {
        let lifter = sleigh_runtime::Lifter::new();
        let mut decoder = sleigh_runtime::Decoder::new();
        let decoded = sleigh_runtime::Instruction::default();
        let labels = Vec::new();
        let fixups = Vec::new();
        let args = Vec::new();

        let sleigh = match config.arch {
            Arch::i386 => {
                let path = std::env::var_os("GHIDRA_SRC")
                    .map_or_else(|| ".".into(), std::path::PathBuf::from)
                    .join("Ghidra/Processors")
                    .join("x86/data/languages/x86-64.slaspec");

                let sleigh = sleigh_compile::from_path(&path)
                    .map_err(|_| Error::new(file!(), line!(), "failed to parse slaspec"))?;

                let field = sleigh
                    .get_context_field("addrsize")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set addrsize"))?;
                field.field.set(&mut decoder.global_context, 1);
                let field = sleigh
                    .get_context_field("opsize")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set opsize"))?;
                field.field.set(&mut decoder.global_context, 1);

                sleigh
            }
            Arch::x86_64 => {
                let path = std::env::var_os("GHIDRA_SRC")
                    .map_or_else(|| ".".into(), std::path::PathBuf::from)
                    .join("Ghidra/Processors")
                    .join("x86/data/languages/x86-64.slaspec");

                let sleigh = sleigh_compile::from_path(&path)
                    .map_err(|_| Error::new(file!(), line!(), "failed to parse slaspec"))?;

                let field = sleigh
                    .get_context_field("addrsize")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set addrsize"))?;
                field.field.set(&mut decoder.global_context, 2);
                let field = sleigh
                    .get_context_field("bit64")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set bit64"))?;
                field.field.set(&mut decoder.global_context, 1);
                let field = sleigh
                    .get_context_field("opsize")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set opsize"))?;
                field.field.set(&mut decoder.global_context, 1);
                let field = sleigh
                    .get_context_field("rexprefix")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set rexprefix"))?;
                field.field.set(&mut decoder.global_context, 0);
                let field = sleigh
                    .get_context_field("longMode")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set longMode"))?;
                field.field.set(&mut decoder.global_context, 1);

                sleigh
            }
            Arch::ppc32 => {
                let path = std::env::var_os("GHIDRA_SRC")
                    .map_or_else(|| ".".into(), std::path::PathBuf::from)
                    .join("Ghidra/Processors")
                    .join("PowerPC/data/languages/ppc_32_be.slaspec");

                let sleigh = sleigh_compile::from_path(&path)
                    .map_err(|_| Error::new(file!(), line!(), "failed to parse slaspec"))?;

                let field = sleigh
                    .get_context_field("linkreg")
                    .ok_or_else(|| Error::new(file!(), line!(), "failed to set linkreg"))?;
                field.field.set(&mut decoder.global_context, 0);

                sleigh
            }
        };

        let reverse_register_map: HashMap<u64, u32> = sleigh
            .register_mapping
            .iter()
            .map(|(&key, &(id, offset))| (((id as u64) << 32) | offset as u64, key))
            .collect();

        Ok(Self {
            sleigh,
            lifter,
            decoder,
            decoded,
            labels,
            fixups,
            args,
            reverse_register_map,
        })
    }
}

fn instruction_to_operation(
    ins: pcode::Instruction,
    lookup: &HashMap<u64, u32>,
) -> Option<Operation> {
    match ins.op {
        pcode::Op::Copy => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::Copy(out, in0))
        }
        pcode::Op::Select(_) => {
            todo!()
        }
        pcode::Op::Subpiece(_) => {
            todo!()
        }
        pcode::Op::ZeroExtend => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::IntZExt(out, in0))
        }
        pcode::Op::SignExtend => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::IntSExt(out, in0))
        }
        pcode::Op::IntToFloat => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatInt2Float(out, in0))
        }
        pcode::Op::UintToFloat => {
            todo!()
        }
        pcode::Op::FloatToFloat => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatFloat2Float(out, in0))
        }
        pcode::Op::FloatToInt => {
            todo!()
        }
        pcode::Op::IntAdd => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntAdd(out, in0, in1))
        }
        pcode::Op::IntSub => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSub(out, in0, in1))
        }
        pcode::Op::IntXor => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntXor(out, in0, in1))
        }
        pcode::Op::IntOr => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntOr(out, in0, in1))
        }
        pcode::Op::IntAnd => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntAnd(out, in0, in1))
        }
        pcode::Op::IntMul => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntMult(out, in0, in1))
        }
        pcode::Op::IntDiv => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntDiv(out, in0, in1))
        }
        pcode::Op::IntSignedDiv => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSDiv(out, in0, in1))
        }
        pcode::Op::IntRem => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntRem(out, in0, in1))
        }
        pcode::Op::IntSignedRem => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSRem(out, in0, in1))
        }
        pcode::Op::IntLeft => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntLeft(out, in0, in1))
        }
        pcode::Op::IntRotateLeft => {
            todo!()
        }
        pcode::Op::IntRight => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntRight(out, in0, in1))
        }
        pcode::Op::IntSignedRight => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSRight(out, in0, in1))
        }
        pcode::Op::IntRotateRight => {
            todo!()
        }
        pcode::Op::IntEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntEqual(out, in0, in1))
        }
        pcode::Op::IntNotEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntNotEqual(out, in0, in1))
        }
        pcode::Op::IntLess => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntLess(out, in0, in1))
        }
        pcode::Op::IntSignedLess => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSLess(out, in0, in1))
        }
        pcode::Op::IntLessEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntLessEqual(out, in0, in1))
        }
        pcode::Op::IntSignedLessEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSLessEqual(out, in0, in1))
        }
        pcode::Op::IntCarry => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntCarry(out, in0, in1))
        }
        pcode::Op::IntSignedCarry => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSCarry(out, in0, in1))
        }
        pcode::Op::IntSignedBorrow => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::IntSBorrow(out, in0, in1))
        }

        // icicle makes an opinionated choice here. Ghidra refers to `~a` as INT_NEGATE
        // (bitwise negation) and `-a` as INT_2COMP (twos complement negation). icicle calls
        // `~a` IntNot and `-a` IntNegate which means that INT_NEGATE and IntNegate are NOT
        // the same thing.
        pcode::Op::IntNot => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::IntNegate(out, in0))
        }
        pcode::Op::IntNegate => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::Int2Comp(out, in0))
        }

        pcode::Op::IntCountOnes => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::Popcount(out, in0))
        }
        pcode::Op::IntCountLeadingZeroes => {
            todo!()
        }
        pcode::Op::BoolAnd => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::BoolAnd(out, in0, in1))
        }
        pcode::Op::BoolOr => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::BoolOr(out, in0, in1))
        }
        pcode::Op::BoolXor => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::BoolXor(out, in0, in1))
        }
        pcode::Op::BoolNot => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::BoolNegate(out, in0))
        }
        pcode::Op::FloatAdd => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatAdd(out, in0, in1))
        }
        pcode::Op::FloatSub => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatSub(out, in0, in1))
        }
        pcode::Op::FloatMul => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatMult(out, in0, in1))
        }
        pcode::Op::FloatDiv => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatDiv(out, in0, in1))
        }
        pcode::Op::FloatNegate => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatNeg(out, in0))
        }
        pcode::Op::FloatAbs => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatAbs(out, in0))
        }
        pcode::Op::FloatSqrt => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatSqrt(out, in0))
        }
        pcode::Op::FloatCeil => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatCeil(out, in0))
        }
        pcode::Op::FloatFloor => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatFloor(out, in0))
        }
        pcode::Op::FloatRound => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatRound(out, in0))
        }
        pcode::Op::FloatIsNan => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::FloatNaN(out, in0))
        }
        pcode::Op::FloatEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatEqual(out, in0, in1))
        }
        pcode::Op::FloatNotEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatNotEqual(out, in0, in1))
        }
        pcode::Op::FloatLess => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatLess(out, in0, in1))
        }
        pcode::Op::FloatLessEqual => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let in1 = value_to_address_range(ins.inputs.second(), lookup);
            Some(Operation::FloatLessEqual(out, in0, in1))
        }
        pcode::Op::Load(n) => {
            let out = varnode_to_address_range(ins.output, lookup);
            let in0 = AddressRange::constant(n as _, out.size);
            let in1 = value_to_address_range(ins.inputs.first(), lookup);
            Some(Operation::Load(out, in0, in1))
        }
        pcode::Op::Store(n) => {
            let in2 = value_to_address_range(ins.inputs.second(), lookup);
            let in1 = value_to_address_range(ins.inputs.first(), lookup);
            let in0 = AddressRange::constant(n as _, in2.size);
            Some(Operation::Store(in0, in1, in2))
        }
        pcode::Op::Branch(pcode::BranchHint::Jump) => {
            let in0 = value_to_address_range(ins.inputs.first(), lookup);
            let mut in1 = value_to_address_range(ins.inputs.second(), lookup);

            if ins.inputs.second().is_const() {
                in1.bank = Bank::Memory;
            }

            if !ins.inputs.first().is_const() {
                return Some(Operation::CBranch(in0, in1));
            }

            match ins.inputs.second() {
                pcode::Value::Var(_) => Some(Operation::BranchInd(in1)),
                pcode::Value::Const(_, _) => Some(Operation::Branch(in1)),
            }
        }
        pcode::Op::Branch(pcode::BranchHint::Call) => {
            assert!(ins.inputs.first().const_eq(1));
            let mut in0 = value_to_address_range(ins.inputs.second(), lookup);
            match ins.inputs.second() {
                pcode::Value::Var(_) => Some(Operation::CallInd(in0)),
                pcode::Value::Const(_, _) => {
                    in0.bank = Bank::Memory;
                    Some(Operation::Call(in0))
                }
            }
        }
        pcode::Op::Branch(pcode::BranchHint::Return) => {
            assert!(ins.inputs.first().const_eq(1));
            let mut in0 = value_to_address_range(ins.inputs.second(), lookup);
            // Return appears to have implicit indirect semantics when a register is passed in. So,
            // we actually have to perform this check.
            if ins.inputs.second().is_const() {
                in0.bank = Bank::Memory;
            }
            Some(Operation::Return(in0))
        }
        pcode::Op::PcodeBranch(_) => {
            assert!(ins.inputs.second().const_eq(0));
            // Branch target is not necessarily known at the time operation is generated.
            // Instead we insert dummy target here to be fixed up at a later pass.
            let dummy = AddressRange::new(Bank::Null, Offset::from(0), 0);
            let ins0 = value_to_address_range(ins.inputs.first(), lookup);
            if ins.inputs.first().const_eq(1) {
                Some(Operation::Branch(dummy))
            } else {
                Some(Operation::CBranch(ins0, dummy))
            }
        }
        pcode::Op::PcodeLabel(_) => {
            // This operation gets fixed-up after t
            None
        }
        pcode::Op::Arg(_) => {
            // This operation gets
            unreachable!()
        }
        pcode::Op::PcodeOp(n) => {
            //eprintln!("INS: {:?}", ins);
            //eprintln!("OUT: {:?}", ins.output);
            //eprintln!("INP: {:?}", ins.inputs);
            //eprintln!("N: {:?}", n);
            let output = match ins.output {
                pcode::VarNode::NONE => None,
                var => Some(varnode_to_address_range(var, lookup)),
            };
            Some(Operation::CallOther(
                output,
                vec![AddressRange::constant(n as _, 4)],
            ))
        }
        pcode::Op::Hook(_) => None,
        pcode::Op::HookIf(_) => None,
        pcode::Op::TracerLoad(_) => None,
        pcode::Op::TracerStore(_) => None,
        pcode::Op::Exception => None,
        pcode::Op::InstructionMarker => None,
        pcode::Op::Invalid => Some(Operation::Unknown(None)),
    }
}

fn varnode_to_address_range(var: pcode::VarNode, lookup: &HashMap<u64, u32>) -> AddressRange {
    let key = (var.id as u64) << 32 | var.offset as u64;

    let (bank, offset) = if var.is_temp() {
        (Bank::Other, Offset::from(var.id as i32))
    } else if let Some(&o) = lookup.get(&key) {
        (Bank::Registers, Offset::from(o as u64))
    } else {
        (Bank::Null, Offset::from(key))
    };

    AddressRange::new(bank, offset, var.size as _)
}

fn value_to_address_range(val: pcode::Value, lookup: &HashMap<u64, u32>) -> AddressRange {
    match val {
        pcode::Value::Var(var) => varnode_to_address_range(var, lookup),
        pcode::Value::Const(n, size) => AddressRange::constant(n, size as _),
    }
}

/*
use std::cell::RefCell;
use std::convert::TryInto;
use std::ffi::CString;
use std::path::Path;
use std::rc::Rc;

use sleighrs::{AddrSpace, StdString};

pub struct Lifter {
    space_to_bank: HashMap<i32, Bank>,
    trans: sleighrs::Sleigh<'static, SharedLoader>,
    instr: SharedBuffer,
    loader: *mut SharedLoader,
}

impl std::convert::TryFrom<DataflowConfig> for Lifter {
    type Error = Error;

    fn try_from(config: DataflowConfig) -> Result<Self> {
        let instr: SharedBuffer = Rc::new(RefCell::new(Vec::new()));

        let loader: &'static mut SharedLoader =
            Box::leak(Box::new(SharedLoader::new(Rc::clone(&instr))));
        let raw = loader as *mut SharedLoader;

        let mut trans =
            sleighrs::Sleigh::try_new(loader).map_err(|e| Error::new(file!(), line!(), e))?;

        match config.arch {
            Arch::i386 => {
                let addrsize = CString::new("addrsize")
                    .map_err(|_| Error::new(file!(), line!(), "allocation failure"))?;
                let opsize = CString::new("opsize")
                    .map_err(|_| Error::new(file!(), line!(), "allocation failure"))?;

                let slafile: sleighrs::SlaFile = Path::new("./specfiles/x86.sla") // FIXME: this hardcoded path is annoying
                    .try_into()
                    .map_err(|e| Error::new(file!(), line!(), e))?;

                trans.initialize(slafile);
                trans.set_context_default(&addrsize, 1);
                trans.set_context_default(&opsize, 1);
            }
            Arch::x86_64 => {
                let addrsize = CString::new("addrsize")
                    .map_err(|_| Error::new(file!(), line!(), "allocation failure"))?;
                let opsize = CString::new("opsize")
                    .map_err(|_| Error::new(file!(), line!(), "allocation failure"))?;

                let slafile: sleighrs::SlaFile = Path::new("./specfiles/x86-64.sla") // FIXME: this hardcoded path is annoying
                    .try_into()
                    .map_err(|e| Error::new(file!(), line!(), e))?;

                trans.initialize(slafile);
                trans.set_context_default(&addrsize, 2);
                trans.set_context_default(&opsize, 1);
            }
            Arch::ppc32 => {
                let slafile: sleighrs::SlaFile = Path::new("./specfiles/ppc32_be.sla") // FIXME: this hardcoded path is annoying
                    .try_into()
                    .map_err(|e| Error::new(file!(), line!(), e))?;

                trans.initialize(slafile);
            }
        }

        let mut space_to_bank: HashMap<i32, Bank> = HashMap::new();

        for i in 0..trans.num_spaces() {
            let space = match unsafe { trans.space(i) } {
                Some(s) => s,
                None => continue,
            };

            let index = space.index();
            let name = match space.name() {
                Some(s) => s,
                None => continue,
            };
            let (name, len) = (name.c_str() as *const u8, name.len());
            let name = match len < 1 || name.is_null() {
                true => continue,
                false => unsafe { std::slice::from_raw_parts(name, len) },
            };

            match name {
                b"const" => space_to_bank.insert(index, Bank::Constants),
                b"register" => space_to_bank.insert(index, Bank::Registers),
                b"ram" => space_to_bank.insert(index, Bank::Memory),
                _ => space_to_bank.insert(index, Bank::Other),
            };
        }

        Ok(Self {
            space_to_bank,
            trans,
            instr,
            loader: raw,
        })
    }
}

impl Lifter {
    pub fn register_by_name(&mut self, name: &str) -> Result<AddressRange> {
        let name =
            CString::new(name).map_err(|_| Error::new(file!(), line!(), "allocation failure"))?;
        let address = self.trans.register(name).ok_or(Error::new(
            file!(),
            line!(),
            "could not find register",
        ))?;

        Ok(AddressRange::new(
            Bank::Registers,
            Offset::from(address.offset()),
            address.size() as usize,
        ))
    }

    pub fn on_instruction(
        &mut self,
        pc: Offset,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
    ) -> Result<()> {
        //println!("About to disassemble: {:x?}", insbytes);

        /*
        if insbytes.len() == 1 {
            match insbytes[0] {
                0x06 | 0x07 | 0x1e | 0x1f => {
                    return Err(Error::new(file!(), line!(), "do not disassemble"));
                }
                _ => {}
            }
        } else if insbytes.len() == 2 && insbytes[0] == 0x0f {
            match insbytes[1] {
                0xa0 | 0xa1 | 0xa8 | 0xa9 => {
                    return Err(Error::new(file!(), line!(), "do not disassemble"));
                }
                _ => {}
            }
        } else if insbytes == &[0x0f, 0x01, 0xf8] {
            return Err(Error::new(file!(), line!(), "do not disassemble"));
        } else if insbytes.len() > 3 && insbytes.starts_with(&[0x66, 0x0f]) {
            return Err(Error::new(file!(), line!(), "do not disassemble"));
        } else if insbytes.len() > 3 && insbytes.starts_with(&[0x66, 0x44, 0x0f]) {
            return Err(Error::new(file!(), line!(), "do not disassemble"));
        }

        //if insbytes == &[0x66, 0x0f, 0x74, 0xc1] {
        //    return Err(Error::new(file!(), line!(), "do not disassemble"));
        //}
        */

        let mut buffer = self.instr.borrow_mut();
        for i in insbytes.iter() {
            buffer.push(*i);
        }
        std::mem::drop(buffer);

        let mut consumer = Consumer {
            assembly,
            operations,
            lifter: self,
        };
        self.trans
            .print_assembly(&mut consumer, pc.as_usize())
            .map_err(|e| Error::new(file!(), line!(), e))?;
        self.trans
            .one_instruction(&mut consumer, pc.as_usize())
            .map_err(|e| Error::new(file!(), line!(), e))?;
        std::mem::drop(consumer);

        self.instr.borrow_mut().clear();
        Ok(())
    }

    fn lift_varnode(&self, varnode: &sleighrs::VarnodeData) -> AddressRange {
        let index = varnode.space().unwrap().index();
        let bank = match self.space_to_bank.get(&index) {
            Some(b) => *b,
            None => Bank::Other,
        };
        AddressRange::new(
            bank,
            Offset::from(varnode.offset()),
            varnode.size() as usize,
        )
    }
}

impl Drop for Lifter {
    fn drop(&mut self) {
        let _ = unsafe { Box::from_raw(self.loader) };
    }
}

type SharedBuffer = Rc<RefCell<Vec<u8>>>;

struct SharedLoader {
    buffer: SharedBuffer,
}

impl SharedLoader {
    fn new(buffer: SharedBuffer) -> Self {
        Self { buffer }
    }
}

impl sleighrs::Loader for SharedLoader {
    fn load_fill(&mut self, ptr: &mut [u8], _addr: &dyn sleighrs::Address) {
        let buffer = self.buffer.borrow();
        for (i, byte) in ptr.iter_mut().enumerate() {
            *byte = match buffer.get(i) {
                Some(value) => *value,
                None => 0,
            }
        }
    }
}

struct Consumer<'a> {
    assembly: &'a mut String,
    operations: &'a mut Vec<Operation>,
    lifter: &'a Lifter,
}

impl sleighrs::PcodeConsumer for Consumer<'_> {
    fn on_pcode(
        &mut self,
        _addr: &dyn sleighrs::Address,
        opc: &sleighrs::OpCode,
        outvar: Option<&sleighrs::VarnodeData>,
        vars: &[Option<&sleighrs::VarnodeData>],
    ) {
        let Consumer {
            operations, lifter, ..
        } = self;

        let opc = OpCode::from(opc.value());
        let outvar = outvar.map(|v| lifter.lift_varnode(v));
        let vars = vars
            .iter()
            .filter(|x| x.is_some())
            .map(|x| lifter.lift_varnode(x.unwrap()));

        let op = Operation::new(opc, vars, outvar).expect("invalid operation");
        operations.push(op);
    }
}

impl sleighrs::AssemblyConsumer for Consumer<'_> {
    fn on_assembly(
        &mut self,
        _addr: &dyn sleighrs::Address,
        mnem: &dyn sleighrs::StdString,
        body: &dyn sleighrs::StdString,
    ) {
        let Consumer { assembly, .. } = self;
        assembly.push_str(format!("{} {}", mnem, body).as_str());
    }
}
*/
