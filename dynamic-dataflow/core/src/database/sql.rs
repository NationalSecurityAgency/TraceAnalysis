use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instruction<'d> {
    pub id: i64,
    pub pc: i64,
    pub bytes: Cow<'d, [u8]>,
    pub disasm_id: i64,
    pub oplist_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Disassembly<'d> {
    pub id: i64,
    pub text: Cow<'d, str>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Operation {
    pub id: i64,
    pub oplist: i64,
    pub seqnum: i64,
    pub opcode: u8,

    pub arg0_space: Option<u16>,
    pub arg0_offset: Option<i64>,
    pub arg0_size: Option<i64>,

    pub arg1_space: Option<u16>,
    pub arg1_offset: Option<i64>,
    pub arg1_size: Option<i64>,

    pub arg2_space: Option<u16>,
    pub arg2_offset: Option<i64>,
    pub arg2_size: Option<i64>,

    pub arg3_space: Option<u16>,
    pub arg3_offset: Option<i64>,
    pub arg3_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstructionRun {
    pub id: i64,
    pub tick: i64,
    pub ins_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationRun {
    pub id: i64,
    pub op_id: i64,
    pub ins_run_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delta<'d> {
    pub id: i64,
    pub op_run_id: i64,
    pub space: u16,
    pub offset: i64,
    pub size: i64,
    pub value: Option<Cow<'d, [u8]>>,
    pub bitmask: Option<Cow<'d, [u8]>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValueDep {
    pub from: i64,
    pub to: i64,
    pub pos: u8,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressDep {
    pub from: i64,
    pub to: i64,
}
