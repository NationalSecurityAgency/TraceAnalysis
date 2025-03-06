use crate::{validate_magic, RawRecord};
use std::borrow::Cow;

pub use architecture::Arch;

/// Enumeration of possible record types.
///
/// This type corresponds to the six most significant bits of the first byte of the record.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    Magic = 0b1111_0000,          /* 0xf0 */
    Arch = 0b0000_0000,           /* 0x00 */
    FileMeta = 0b0000_0100,       /* 0x04 */
    Map = 0b0001_0000,            /* 0x10 */
    Unmap = 0b0001_1100,          /* 0x1c */
    Instruction = 0b0010_0000,    /* 0x20 */
    Pc = 0b0010_0100,             /* 0x24 */
    Meta = 0b0011_0000,           /* 0x30 */
    Interrupt = 0b0011_1000,      /* 0x38 */
    RegRead = 0b0100_0000,        /* 0x40 */
    RegWrite = 0b0100_0100,       /* 0x44 */
    RegWriteNative = 0b0101_0100, /* 0x54 */
    MemRead = 0b1000_0000,        /* 0x80 */
    MemWrite = 0b1000_0100,       /* 0x84 */
}

impl TryFrom<u8> for RecordKind {
    type Error = UnknownRecordKind;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & 0b1111_1100 {
            0b0000_0000 => Ok(Self::Arch),
            0b0000_0100 => Ok(Self::FileMeta),
            0b0001_0000 => Ok(Self::Map),
            0b0001_1100 => Ok(Self::Unmap),
            0b0010_0000 => Ok(Self::Instruction),
            0b0010_0100 => Ok(Self::Pc),
            0b0011_0000 => Ok(Self::Meta),
            0b0011_1000 => Ok(Self::Interrupt),
            0b0100_0000 => Ok(Self::RegRead),
            0b0100_0100 => Ok(Self::RegWrite),
            0b0101_0100 => Ok(Self::RegWriteNative),
            0b1000_0000 => Ok(Self::MemRead),
            0b1000_0100 => Ok(Self::MemWrite),
            0b1111_0000 => Ok(Self::Magic),
            _ => Err(UnknownRecordKind(value)),
        }
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A parsed record corresponding to some event or metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Record<'d> {
    Magic,
    Arch(Arch),
    FileMeta(FileMeta<'d>),
    Map(Map<'d>),
    Unmap(Unmap),
    Instruction(Instruction<'d>),
    Pc(Pc),
    Meta(Meta<'d>),
    Interrupt(Interrupt),
    RegRead(RegRead<'d>),
    RegWrite(RegWrite<'d>),
    RegWriteNative(RegWriteNative<'d>),
    MemRead(MemRead<'d>),
    MemWrite(MemWrite<'d>),
}

impl<'d> Record<'d> {
    /// Returns the corresponding [`RecordKind`] for this record.
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Magic => RecordKind::Magic,
            Self::Arch(_) => RecordKind::Arch,
            Self::FileMeta(_) => RecordKind::FileMeta,
            Self::Map(_) => RecordKind::Map,
            Self::Unmap(_) => RecordKind::Unmap,
            Self::Instruction(_) => RecordKind::Instruction,
            Self::Pc(_) => RecordKind::Pc,
            Self::Meta(_) => RecordKind::Meta,
            Self::Interrupt(_) => RecordKind::Interrupt,
            Self::RegRead(_) => RecordKind::RegRead,
            Self::RegWrite(_) => RecordKind::RegWrite,
            Self::RegWriteNative(_) => RecordKind::RegWriteNative,
            Self::MemRead(_) => RecordKind::MemRead,
            Self::MemWrite(_) => RecordKind::MemWrite,
        }
    }

    /// Parses a [`RawRecord`] to produce a record.
    ///
    /// This method takes a helper function used to parse variable format fields (fields whose size
    /// and endian-ness depends on the architecture for the trace). Not all records contain
    /// variable format fields (e.g. [`RecordKind::Magic`] and [`RecordKind::Arch`]), so for those
    /// records it is acceptable to pass in the [`parse_unknown`] helper function. The helper
    /// function provided should be able to produce a `u64` out of the first set of bytes returning
    /// both the `u64` and the remaining unused bytes or fail with a [`ParseError`] if it is not
    /// possible. For convenience, the following helper functions are provided:
    ///
    /// - [`parse_le32`]
    /// - [`parse_be32`]
    /// - [`parse_le64`]
    /// - [`parse_be64`]
    /// - [`parse_unknown`]
    ///
    /// While a [`RawRecord`] is used to ensure that the record is framed properly, parsing can
    /// still fail if the contents of the record do not match the expectations for the record
    /// type. At the moment, providing extraneous data in a record does not cause parsing to fail,
    /// but this is an implementation detail that may cahnge in the future.
    pub fn parse<F>(raw: RawRecord<'d>, varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        match raw.kind()? {
            RecordKind::Magic => {
                if !validate_magic(raw) {
                    return Err(Error::record("magic", Error::InvalidMagic))?;
                }
                Ok(Self::Magic)
            }
            RecordKind::Arch => {
                let value = raw.value().ok_or(Error::record("arch", Error::NoData))?;
                let record = Arch::parse(value).map_err(|e| Error::wrap("arch", e))?;
                Ok(Self::Arch(record))
            }
            RecordKind::FileMeta => {
                let value = raw
                    .value()
                    .ok_or(Error::record("filemeta", Error::NoData))?;
                let record = FileMeta::parse(value).map_err(|e| Error::wrap("filemeta", e))?;
                Ok(Self::FileMeta(record))
            }
            RecordKind::Map => {
                let value = raw.value().ok_or(Error::record("img", Error::NoData))?;
                let record = Map::parse(value, varfmt).map_err(|e| Error::wrap("img", e))?;
                Ok(Self::Map(record))
            }
            RecordKind::Unmap => {
                let value = raw.value().ok_or(Error::record("unmap", Error::NoData))?;
                let record = Unmap::parse(value, varfmt).map_err(|e| Error::wrap("unmap", e))?;
                Ok(Self::Unmap(record))
            }
            RecordKind::Instruction => {
                let value = raw.value().ok_or(Error::record("ins", Error::NoData))?;
                let record =
                    Instruction::parse(value, varfmt).map_err(|e| Error::wrap("ins", e))?;
                Ok(Self::Instruction(record))
            }
            RecordKind::Pc => {
                let value = raw.value().ok_or(Error::record("pc", Error::NoData))?;
                let record = Pc::parse(value, varfmt).map_err(|e| Error::wrap("pc", e))?;
                Ok(Self::Pc(record))
            }
            RecordKind::Meta => {
                let value = raw.value().ok_or(Error::record("meta", Error::NoData))?;
                let record = Meta::parse(value).map_err(|e| Error::wrap("meta", e))?;
                Ok(Self::Meta(record))
            }
            RecordKind::Interrupt => {
                let value = raw.value().ok_or(Error::record("intr", Error::NoData))?;
                let record = Interrupt::parse(value).map_err(|e| Error::wrap("intr", e))?;
                Ok(Self::Interrupt(record))
            }
            RecordKind::RegRead => {
                let value = raw.value().ok_or(Error::record("regread", Error::NoData))?;
                let record = RegRead::parse(value).map_err(|e| Error::wrap("regread", e))?;
                Ok(Self::RegRead(record))
            }
            RecordKind::RegWrite => {
                let value = raw
                    .value()
                    .ok_or(Error::record("regwrite", Error::NoData))?;
                let record = RegWrite::parse(value).map_err(|e| Error::wrap("regwrite", e))?;
                Ok(Self::RegWrite(record))
            }
            RecordKind::RegWriteNative => {
                let value = raw
                    .value()
                    .ok_or(Error::record("regwritenative", Error::NoData))?;
                let record =
                    RegWriteNative::parse(value).map_err(|e| Error::wrap("regwritenative", e))?;
                Ok(Self::RegWriteNative(record))
            }
            RecordKind::MemRead => {
                let value = raw.value().ok_or(Error::record("memread", Error::NoData))?;
                let record =
                    MemRead::parse(value, varfmt).map_err(|e| Error::wrap("memread", e))?;
                Ok(Self::MemRead(record))
            }
            RecordKind::MemWrite => {
                let value = raw
                    .value()
                    .ok_or(Error::record("memwrite", Error::NoData))?;
                let record =
                    MemWrite::parse(value, varfmt).map_err(|e| Error::wrap("memwrite", e))?;
                Ok(Self::MemWrite(record))
            }
        }
    }

    /// Write a serialized record into the provided buffer.
    ///
    /// This method takes a helper function for writing variable format fields from a record. If
    /// the helper function is not needed for a given record, it will not be called. The helper
    /// function should be written to serialize a value stored in a `u64` into the buffer provided
    /// and return a slice of the buffer containing the data that was written. For example, if this
    /// record is for a 32-bit architecture, the helper function can truncate the provided value,
    /// store data in only four bytes of the provided buffer, and return a slice of those four
    /// bytes. For convenience the following helper functions are already provided:
    ///
    /// - [`emit_le32`]
    /// - [`emit_be32`]
    /// - [`emit_le64`]
    /// - [`emit_be64`]
    pub fn emit<F>(&self, buffer: &mut Vec<u8>, varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        match self {
            Self::Magic => buffer.extend_from_slice(b"\xf1\x06\x65\x78\x00\x3c\x7f\x07"),
            Self::Arch(record) => record.emit(buffer),
            Self::FileMeta(record) => record.emit(buffer),
            Self::Map(record) => record.emit(buffer, varfmt),
            Self::Unmap(record) => record.emit(buffer, varfmt),
            Self::Instruction(record) => record.emit(buffer, varfmt),
            Self::Pc(record) => record.emit(buffer, varfmt),
            Self::Meta(record) => record.emit(buffer),
            Self::Interrupt(record) => record.emit(buffer),
            Self::RegRead(record) => record.emit(buffer),
            Self::RegWrite(record) => record.emit(buffer),
            Self::RegWriteNative(record) => record.emit(buffer),
            Self::MemRead(record) => record.emit(buffer, varfmt),
            Self::MemWrite(record) => record.emit(buffer, varfmt),
        }
    }

    pub fn into_owned(self) -> Record<'static> {
        match self {
            Self::Magic => Record::Magic,
            Self::Arch(record) => Record::Arch(record),
            Self::Unmap(record) => Record::Unmap(record),
            Self::Pc(record) => Record::Pc(record),
            Self::Interrupt(record) => Record::Interrupt(record),
            _ => todo!(),
        }
    }
}

impl From<Arch> for Record<'_> {
    fn from(record: Arch) -> Self {
        Self::Arch(record)
    }
}

impl<'d> From<FileMeta<'d>> for Record<'d> {
    fn from(record: FileMeta<'d>) -> Self {
        Self::FileMeta(record)
    }
}

impl<'d> From<Map<'d>> for Record<'d> {
    fn from(record: Map<'d>) -> Self {
        Self::Map(record)
    }
}

impl From<Unmap> for Record<'_> {
    fn from(record: Unmap) -> Self {
        Self::Unmap(record)
    }
}

impl<'d> From<Instruction<'d>> for Record<'d> {
    fn from(record: Instruction<'d>) -> Self {
        Self::Instruction(record)
    }
}

impl From<Pc> for Record<'_> {
    fn from(record: Pc) -> Self {
        Self::Pc(record)
    }
}

impl<'d> From<Meta<'d>> for Record<'d> {
    fn from(record: Meta<'d>) -> Self {
        Self::Meta(record)
    }
}

impl From<Interrupt> for Record<'_> {
    fn from(record: Interrupt) -> Self {
        Self::Interrupt(record)
    }
}

impl<'d> From<RegRead<'d>> for Record<'d> {
    fn from(record: RegRead<'d>) -> Self {
        Self::RegRead(record)
    }
}

impl<'d> From<RegWrite<'d>> for Record<'d> {
    fn from(record: RegWrite<'d>) -> Self {
        Self::RegWrite(record)
    }
}

impl<'d> From<RegWriteNative<'d>> for Record<'d> {
    fn from(record: RegWriteNative<'d>) -> Self {
        Self::RegWriteNative(record)
    }
}

impl<'d> From<MemRead<'d>> for Record<'d> {
    fn from(record: MemRead<'d>) -> Self {
        Self::MemRead(record)
    }
}

impl<'d> From<MemWrite<'d>> for Record<'d> {
    fn from(record: MemWrite<'d>) -> Self {
        Self::MemWrite(record)
    }
}

impl<'d> From<RegisterNameMap<'d>> for Record<'d> {
    fn from(record: RegisterNameMap<'d>) -> Self {
        Self::FileMeta(FileMeta::RegisterNameMap(record))
    }
}

impl<'d> From<UnknownFileMeta<'d>> for Record<'d> {
    fn from(record: UnknownFileMeta<'d>) -> Self {
        Self::FileMeta(FileMeta::Unknown(record))
    }
}

impl From<InstructionCount> for Record<'_> {
    fn from(record: InstructionCount) -> Self {
        Self::Meta(Meta::InstructionCount(record))
    }
}

impl From<ThreadId> for Record<'_> {
    fn from(record: ThreadId) -> Self {
        Self::Meta(Meta::ThreadId(record))
    }
}

impl From<ProcessId> for Record<'_> {
    fn from(record: ProcessId) -> Self {
        Self::Meta(Meta::ProcessId(record))
    }
}

impl<'d> From<UnknownMeta<'d>> for Record<'d> {
    fn from(record: UnknownMeta<'d>) -> Self {
        Self::Meta(Meta::Unknown(record))
    }
}

/// Record containing metadata that applies to all records within the trace.
///
/// # Format
///
/// `| 0b0000_01LL | vlen | tag: u8 | contents: [u8] | rlen |`
///
/// ## Tags
///
/// - 0 = [`RegisterNameMap`]
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileMeta<'d> {
    RegisterNameMap(RegisterNameMap<'d>),
    Unknown(UnknownFileMeta<'d>),
}

impl<'d> FileMeta<'d> {
    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes)?;
        }
        let (tag, contents) = bytes.split_at(1);
        match tag[0] {
            0 => {
                let record = RegisterNameMap::parse(contents)
                    .map_err(|e| Error::wrap("registernamemap", e))?;
                Ok(Self::RegisterNameMap(record))
            }
            n => Ok(Self::Unknown(UnknownFileMeta {
                tag: n,
                contents: Cow::from(contents),
            })),
        }
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::RegisterNameMap(record) => record.emit(buffer),
            Self::Unknown(record) => record.emit(buffer),
        }
    }
}

/// Trace-wide metadata that provides a mapping from register names to register numbers.
///
/// # Format
///
/// contents:
///
/// `| num_records: u8 | records: [name_map_record; num_records] |`
///
/// name_map_record:
///
/// `| regnum: u8 | namesz: u8 | name: [u8; namesz] |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterNameMap<'d> {
    num_records: u8,
    records: Cow<'d, [u8]>,
}

impl RegisterNameMap<'static> {
    pub fn new<'a, I>(iter: I) -> Self
    where
        I: Iterator<Item = (u16, &'a [u8])>,
    {
        let mut records = Vec::new();
        let mut num_records = 0u8;
        for (regnum, regname) in iter {
            num_records += 1;
            records.extend(regnum.to_le_bytes());
            records.push(regname.len() as u8);
            records.extend_from_slice(regname);
        }
        Self {
            num_records,
            records: Cow::from(records),
        }
    }
}

impl<'d> RegisterNameMap<'d> {
    pub fn iter<'this: 'd>(&'this self) -> impl Iterator<Item = (u16, &'d [u8])> + 'this {
        struct Iter<'a> {
            cursor: usize,
            records: &'a [u8],
        }

        impl<'a> Iterator for Iter<'a> {
            type Item = (u16, &'a [u8]);

            fn next(&mut self) -> Option<Self::Item> {
                let x = *self.records.get(self.cursor)?;
                self.cursor += 1;
                let y = *self.records.get(self.cursor)?;
                self.cursor += 1;
                let regnum = ((y as u16) << 8) | x as u16;

                let namesz = *self.records.get(self.cursor)?;
                self.cursor += 1;
                let start = self.cursor;
                self.cursor += namesz as usize;
                let name = self.records.get(start..self.cursor)?;
                Some((regnum, name))
            }
        }

        Iter {
            cursor: 0,
            records: &self.records,
        }
    }

    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes)?;
        }
        let (&[numrecords], mut records) = bytes.split_at(1) else {
            unreachable!() // We've checked the length already
        };
        for _ in 0..numrecords {
            if records.len() < 3 {
                return Err(Error::NotEnoughBytes)?;
            }
            let (&[_regnum_part1, _regnum_part2, namesz], remaining) = records.split_at(3) else {
                unreachable!() // We've checked the length already
            };
            if remaining.len() < namesz as usize {
                return Err(Error::NotEnoughBytes)?;
            }
            records = &remaining[namesz as usize..];
        }
        Ok(Self {
            num_records: numrecords,
            records: Cow::from(&bytes[1..]),
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let (vlen, rlen) = calculate_vlen_rlen(2 + self.records.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::FileMeta as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(&[0x00, self.num_records]);
        buffer.extend_from_slice(&self.records);
        buffer.extend_from_slice(rlen);
    }

    pub fn into_owned(self) -> RegisterNameMap<'static> {
        let Self {
            num_records,
            records,
        } = self;
        RegisterNameMap {
            num_records,
            records: Cow::from(records.into_owned()),
        }
    }
}

/// Unknown record type containing metadata that applies to all record within the trace.
///
/// This type provides access to the tag as well as the contents of the record so that users may
/// perform additional parsing for custom records.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownFileMeta<'d> {
    tag: u8,
    contents: Cow<'d, [u8]>,
}

impl<'d> UnknownFileMeta<'d> {
    /// Returns the tag for the [`FileMeta`] record.
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Returnt the contents of the [`FileMeta`] record.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let (vlen, rlen) = calculate_vlen_rlen(1 + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::FileMeta as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.push(self.tag);
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record containing the metadata that applies to the following record(s).
///
/// # Format
///
/// `| 0b0011_00LL | vlen | tag: u8 | contents: [u8] | rlen |`
///
/// ## Tags
///
/// - 0 = [`InstructionCount`]
/// - 1 = [`ThreadId`]
/// - 2 = [`ProcessId`]
/// - 3 = [`CallBegin`]
/// - 4 = [`CallModeledOpsEnd`]
/// - 5 = [`CallEnd`]
/// - 6 = [`OperandUncertain`]
/// - 7 = [`AddressDependencyEdge`]
/// - 8 = [`RegisterDependencyEdge`]
/// - 9 = [`MemoryAllocated`]
/// - 10 = [`MemoryFreed`]
/// - 11 = [`MemoryReallocated`]
/// - 12 = [`ModelEffectsBegin`]
/// - 13 = [`ModelEffectsEnd`]
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Meta<'d> {
    InstructionCount(InstructionCount),
    ThreadId(ThreadId),
    ProcessId(ProcessId),
    CallBegin(CallBegin),
    CallModeledOpsEnd(CallModeledOpsEnd),
    CallEnd(CallEnd),
    ModelEffectsBegin(ModelEffectsBegin),
    ModelEffectsEnd(ModelEffectsEnd),
    OperandUncertain(OperandUncertain),
    AddressDependencyEdge(AddressDependencyEdge),
    RegisterDependencyEdge(RegisterDependencyEdge),
    MemoryAllocated(MemoryAllocated),
    MemoryFreed(MemoryFreed),
    MemoryReallocated(MemoryReallocated),
    Unknown(UnknownMeta<'d>),
}

impl<'d> Meta<'d> {
    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes)?;
        }
        let (tag, contents) = bytes.split_at(1);
        match tag[0] {
            0 => {
                let record =
                    InstructionCount::parse(contents).map_err(|e| Error::wrap("metainscnt", e))?;
                Ok(Self::InstructionCount(record))
            }
            1 => {
                let record =
                    ThreadId::parse(contents).map_err(|e| Error::wrap("metathreadid", e))?;
                Ok(Self::ThreadId(record))
            }
            2 => {
                let record =
                    ProcessId::parse(contents).map_err(|e| Error::wrap("metaprocessid", e))?;
                Ok(Self::ProcessId(record))
            }
            3 => {
                let record =
                    CallBegin::parse(contents).map_err(|e| Error::wrap("metacallbegin", e))?;
                Ok(Self::CallBegin(record))
            }
            4 => {
                let record = CallModeledOpsEnd::parse(contents)
                    .map_err(|e| Error::wrap("metacallmodeledopsend", e))?;
                Ok(Self::CallModeledOpsEnd(record))
            }
            5 => {
                let record = CallEnd::parse(contents).map_err(|e| Error::wrap("metacallend", e))?;
                Ok(Self::CallEnd(record))
            }
            6 => {
                let record = OperandUncertain::parse(contents)
                    .map_err(|e| Error::wrap("metaoperanduncertain", e))?;
                Ok(Self::OperandUncertain(record))
            }
            7 => {
                let record = AddressDependencyEdge::parse(contents)
                    .map_err(|e| Error::wrap("metaaddressdependencyedge", e))?;
                Ok(Self::AddressDependencyEdge(record))
            }
            8 => {
                let record = RegisterDependencyEdge::parse(contents)
                    .map_err(|e| Error::wrap("metaregisterdependencyedge", e))?;
                Ok(Self::RegisterDependencyEdge(record))
            }
            9 => {
                let record = MemoryAllocated::parse(contents)
                    .map_err(|e| Error::wrap("metamemoryallocated", e))?;
                Ok(Self::MemoryAllocated(record))
            }
            10 => {
                let record =
                    MemoryFreed::parse(contents).map_err(|e| Error::wrap("metamemoryfreed", e))?;
                Ok(Self::MemoryFreed(record))
            }
            11 => {
                let record = MemoryReallocated::parse(contents)
                    .map_err(|e| Error::wrap("metamemoryreallocated", e))?;
                Ok(Self::MemoryReallocated(record))
            }
            12 => {
                let record = ModelEffectsBegin::parse(contents)
                    .map_err(|e| Error::wrap("metamodeleffectsbegin", e))?;
                Ok(Self::ModelEffectsBegin(record))
            }
            13 => {
                let record = ModelEffectsEnd::parse(contents)
                    .map_err(|e| Error::wrap("metamodeleffectsend", e))?;
                Ok(Self::ModelEffectsEnd(record))
            }
            n => Ok(Self::Unknown(UnknownMeta {
                tag: n,
                contents: Cow::from(contents),
            })),
        }
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::InstructionCount(record) => record.emit(buffer),
            Self::ThreadId(record) => record.emit(buffer),
            Self::ProcessId(record) => record.emit(buffer),
            Self::CallBegin(record) => record.emit(buffer),
            Self::ModelEffectsBegin(record) => record.emit(buffer),
            Self::ModelEffectsEnd(record) => record.emit(buffer),
            Self::CallModeledOpsEnd(record) => record.emit(buffer),
            Self::CallEnd(record) => record.emit(buffer),
            Self::OperandUncertain(record) => record.emit(buffer),
            Self::AddressDependencyEdge(record) => record.emit(buffer),
            Self::RegisterDependencyEdge(record) => record.emit(buffer),
            Self::MemoryAllocated(record) => record.emit(buffer),
            Self::MemoryFreed(record) => record.emit(buffer),
            Self::MemoryReallocated(record) => record.emit(buffer),
            Self::Unknown(record) => record.emit(buffer),
        }
    }
}

/// Recording indicating that the following records occur starting at a given instruction count.
///
/// # Format
///
/// `| tick: le64 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstructionCount {
    tick: u64,
}

impl InstructionCount {
    /// Constructs a record that indicates that the current instruction count is `tick`.
    pub fn new(tick: u64) -> Self {
        Self { tick }
    }

    /// Returns the instruction count.
    pub fn tick(&self) -> u64 {
        self.tick
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (tick, _) = parse_le64(bytes)?;
        Ok(Self { tick })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            0x31u8, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        ];
        bytes[3..11].copy_from_slice(&self.tick.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Recording indicating that the following records occured on the given thread id.
///
/// # Format
///
/// `| threadid: le32 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadId {
    threadid: u32,
}

impl ThreadId {
    /// Constructs a record that indicates that the current thread id `threadid`.
    pub fn new(threadid: u32) -> Self {
        Self { threadid }
    }

    /// Returns the threadid.
    pub fn threadid(&self) -> u32 {
        self.threadid
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (threadid, _) = parse_le32(bytes)?;
        Ok(Self {
            threadid: threadid as u32,
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [0x31u8, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07];
        bytes[3..7].copy_from_slice(&self.threadid.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Recording indicating that the following records occured on the given process id.
///
/// # Format
///
/// `| processid: le64 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessId {
    processid: u64,
}

impl ProcessId {
    /// Constructs a record that indicates that the current thread id `threadid`.
    pub fn new(processid: u64) -> Self {
        Self { processid }
    }

    /// Returns the threadid.
    pub fn processid(&self) -> u64 {
        self.processid
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (processid, _) = parse_le64(bytes)?;
        Ok(Self { processid })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            0x31u8, 0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        ];
        bytes[3..11].copy_from_slice(&self.processid.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that following records prior to the next
/// ModelEffectsEnd meta record are effects modelled by the named
/// model
///
/// # Format
///
/// `| model_name: String |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelEffectsBegin {
    model_name: String,
}

impl ModelEffectsBegin {
    /// Constructs a record that indicates a call to a function
    pub fn new(model_name: String) -> Self {
        Self { model_name }
    }

    /// Returns the callee function's name.
    pub fn name(&self) -> &str {
        &self.model_name
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let len: usize = bytes[..MAX_MODEL_NAME_LEN]
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(MAX_MODEL_NAME_LEN);

        let name = String::from_utf8(bytes[..len].to_vec())
            .map_err(|_| Error::record("Could not read model name", Error::BadData))?;
        Ok(Self { model_name: name })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x22 bytes follow; 0x20 byte model name, 2 metadata
            0x22, // vlen
            0x0c, // ModelEffectsBegin tag
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // 0x20 bytes (MAX_MODEL_NAME_LEN) for model name
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x23, // rlen
        ];
        let name = self.model_name.clone().into_bytes();
        let copy_len = name.len().min(MAX_MODEL_NAME_LEN);
        bytes[3..(3 + copy_len)].copy_from_slice(&name[..copy_len]);
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that following records prior to the next
/// ModelEffectsEnd meta record are effects modelled by the named
/// model
///
/// # Format
///
/// `| model_name: String |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelEffectsEnd;

impl ModelEffectsEnd {
    /// Constructs a record that indicates a call to a function
    pub fn new() -> Self {
        Self {}
    }

    fn parse(_bytes: &[u8]) -> Result<Self, ParseError> {
        Ok(Self)
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, 0x2,  // vlen
            0x0d, // ModelEffectsEnd tag
            0x3,  // rlen
        ];
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that following records prior to the next CallEnd meta
/// record are modeled inputs and outputs of a function call.
///
/// # Format
///
/// `| function_name: String, address: u64 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBegin {
    function_name: String,
    address: u64,
}

const MAX_FN_NAME_LEN: usize = 0x20;
const MAX_MODEL_NAME_LEN: usize = 0x20;

impl CallBegin {
    /// Constructs a record that indicates a call to a function
    pub fn new(function_name: String, address: u64) -> Self {
        Self {
            function_name,
            address,
        }
    }

    /// Returns the callee function's name.
    pub fn name(&self) -> &str {
        &self.function_name
    }

    /// Returns the callee function's address.
    pub fn address(&self) -> u64 {
        self.address
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let len: usize = bytes[..MAX_FN_NAME_LEN]
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(MAX_FN_NAME_LEN);

        let name = String::from_utf8(bytes[..len].to_vec())
            .map_err(|_| Error::record("Could not read function name", Error::BadData))?;
        let (address, _) = parse_le64(&bytes[MAX_FN_NAME_LEN..])?;
        Ok(Self {
            function_name: name,
            address,
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8,
            // 0x2a bytes follow; 0x20 byte function name, 8 byte address, 2 metadata
            0x2a, // CallBegin record
            0x03, // Will receive function name
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // Will receive function address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rlen
            0x2b,
        ];
        let name = self.function_name.clone().into_bytes();
        let copy_len = name.len().min(MAX_FN_NAME_LEN);
        (&mut bytes[3..3 + copy_len]).copy_from_slice(&name[..copy_len]);
        (&mut bytes[3 + MAX_FN_NAME_LEN..3 + MAX_FN_NAME_LEN + 8])
            .copy_from_slice(&self.address.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that following records are still associated with a modeled call but are
/// not themselves modeled.
///
/// # Format
///
/// `||`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallModeledOpsEnd {}

impl CallModeledOpsEnd {
    /// Constructs a record that indicates the end to modeled operations associated with a call to
    /// a modeled functions
    pub fn new() -> Self {
        Self {}
    }

    fn parse(_: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {})
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x02 bytes follow.
            0x02,   // CallModeledOpsEnd record
            0x04,   // rlen
            0x03,
        ];
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that the operations associated with a particular call have all been
/// recorded.
///
/// # Format
///
/// `| call_instruction_addr: u64 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEnd {
    call_instruction_addr: u64,
}

impl CallEnd {
    /// Constructs a record that indicates the end of operations associated with a call to a
    /// function
    pub fn new(call_instruction_addr: u64) -> Self {
        Self {
            call_instruction_addr,
        }
    }

    pub fn call_instruction_addr(&self) -> u64 {
        return self.call_instruction_addr;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (call_instruction_addr, _) = parse_le64(bytes)?;
        Ok(Self {
            call_instruction_addr,
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x0a bytes follow.
            0x0a,   // CallEnd record
            0x05,   // Will receive associated call instruction's address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rlen
            0x0b,
        ];
        bytes[3..11].copy_from_slice(&self.call_instruction_addr.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating that the following record's operand is unknown data.
///
/// # Format
///
/// `||`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperandUncertain {}

impl OperandUncertain {
    /// Constructs a record indicating that the following record's operand is unknown data.
    pub fn new() -> Self {
        Self {}
    }

    fn parse(_: &[u8]) -> Result<Self, ParseError> {
        Ok(Self {})
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x02 bytes follow.
            0x02,   // OperandUncertain record
            0x06,   // rlen
            0x03,
        ];
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating an address dependency edge for the memory access to follow.
///
/// # Format
///
/// `| address: u64 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressDependencyEdge {
    address: u64,
}

impl AddressDependencyEdge {
    /// Constructs a record that indicates an address dependency edge for the memory access to
    /// follow.
    pub fn new(address: u64) -> Self {
        Self { address }
    }

    pub fn address(&self) -> u64 {
        return self.address;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (address, _) = parse_le64(bytes)?;
        Ok(Self { address })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x0a bytes follow.
            0x0a,   // AddressDependencyEdge record
            0x07,
            // Will receive the address of the pointer to serve as the address dependency edge for
            // the memory access to follow
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rlen
            0x0b,
        ];
        bytes[3..11].copy_from_slice(&self.address.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating an address dependency edge for the memory access to follow when the
/// dependency is a register.
///
/// # Format
///
/// `| register: u32 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterDependencyEdge {
    register: u32,
}

impl RegisterDependencyEdge {
    /// Constructs a record that indicates an address dependency edge for the memory access to
    /// follow when the dependency is a register.
    pub fn new(register: u32) -> Self {
        Self { register }
    }

    pub fn register(&self) -> u32 {
        return self.register;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (register, _) = parse_le32(bytes)?;
        Ok(Self {
            register: register as u32,
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x06 bytes follow.
            0x06,   // RegisterDependencyEdge record
            0x08,
            // Will receive the SLEIGH offset of the register containing the pointer serving as
            // the address dependency edge for the memory access to follow
            0x00, 0x00, 0x00, 0x00, // rlen
            0x07,
        ];
        bytes[3..7].copy_from_slice(&self.register.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating memory was allocated.
///
/// # Format
///
/// `| address: u64, size: u32 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryAllocated {
    address: u64,
    size: u32,
}

impl MemoryAllocated {
    /// Constructs a record that indicates memory at the specified address was freed.
    pub fn new(address: u64, size: u32) -> Self {
        Self { address, size }
    }

    pub fn address(&self) -> u64 {
        return self.address;
    }
    pub fn size(&self) -> u32 {
        return self.size;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (address, _) = parse_le64(&bytes[..8])?;
        let (size, _) = parse_le32(&bytes[8..])?;
        Ok(Self::new(address, size as u32))
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x0e bytes follow.
            0x0e,   // MemoryAllocated record
            0x09,   // Will receive the address of the allocated memory
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Will receive the number of bytes allocated
            0x00, 0x00, 0x00, 0x00, // rlen
            0x0f,
        ];
        bytes[3..11].copy_from_slice(&self.address.to_le_bytes());
        bytes[11..15].copy_from_slice(&self.size.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating memory was freed.
///
/// # Format
///
/// `| address: u64, size: u32 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryFreed {
    address: u64,
    size: u32,
}

impl MemoryFreed {
    /// Constructs a record that indicates memory was allocated at the specified address.
    pub fn new(address: u64, size: u32) -> Self {
        Self {
            address: address,
            size: size,
        }
    }

    pub fn address(&self) -> u64 {
        return self.address;
    }
    pub fn size(&self) -> u32 {
        return self.size;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (address, _) = parse_le64(&bytes[..8])?;
        let (size, _) = parse_le32(&bytes[8..])?;
        Ok(Self::new(address, size as u32))
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x0e bytes follow.
            0x0e,   // MemoryFreed record
            0x0a,   // Will receive the address of the freed memory
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Will receive the number of bytes freed
            0x00, 0x00, 0x00, 0x00, // rlen
            0x0f,
        ];
        bytes[3..11].copy_from_slice(&self.address.to_le_bytes());
        bytes[11..15].copy_from_slice(&self.size.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Record indicating memory was reallocated.
///
/// # Format
///
/// `| new_address: u64, old_address: u64, size: u32 |`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryReallocated {
    new_address: u64,
    old_address: u64,
    size: u32,
}

impl MemoryReallocated {
    /// Constructs a record that indicates memory was reallocated.
    pub fn new(new_address: u64, old_address: u64, size: u32) -> Self {
        Self {
            new_address: new_address,
            old_address: old_address,
            size: size,
        }
    }

    pub fn new_address(&self) -> u64 {
        return self.new_address;
    }
    pub fn old_address(&self) -> u64 {
        return self.old_address;
    }
    pub fn size(&self) -> u32 {
        return self.size;
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (new_address, _) = parse_le64(&bytes[..8])?;
        let (old_address, _) = parse_le64(&bytes[8..16])?;
        let (size, _) = parse_le32(&bytes[16..])?;
        Ok(Self::new(new_address, old_address, size as u32))
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            // (0b001100, 0b01): (Meta, length is 1 byte long)
            0x31u8, // 0x16 bytes follow.
            0x16,   // MemoryReallocated record
            0x0b,   // Will receive the new address of the reallocated memory
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Will receive the old address of the reallocated memory
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Will receive the number of bytes reallocated
            0x00, 0x00, 0x00, 0x00, // rlen
            0x17,
        ];
        bytes[3..11].copy_from_slice(&self.new_address.to_le_bytes());
        bytes[11..19].copy_from_slice(&self.old_address.to_le_bytes());
        bytes[19..23].copy_from_slice(&self.size.to_le_bytes());
        buffer.extend_from_slice(&bytes)
    }
}

/// Unknown record type containing metadata that applies to the following record(s) within the
/// trace.
///
/// This type provides access to the tag as well as the contents of the record so that users may
/// perform additional parsing for custom records.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownMeta<'d> {
    tag: u8,
    contents: Cow<'d, [u8]>,
}

impl<'d> UnknownMeta<'d> {
    /// Returns the tag for the [`Meta`] record.
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// Returnt the contents of the [`Meta`] record.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let (vlen, rlen) = calculate_vlen_rlen(1 + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::Meta as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.push(self.tag);
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that an instruction has been executed.
///
/// # Format
///
/// `| 0b0010_00LL | vlen | pc: varfmt | insbytes: [u8] | rlen`
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Instruction<'d> {
    pc: u64,
    insbytes: Cow<'d, [u8]>,
}

impl<'d> Instruction<'d> {
    /// Constructs a new record indicating that an instruction at `pc` with bytes, `insbytes`, was
    /// executed.
    pub fn new(pc: u64, insbytes: &'d [u8]) -> Self {
        Self {
            pc,
            insbytes: Cow::from(insbytes),
        }
    }

    /// Returns the address of the recorded instruction.
    pub fn pc(&self) -> u64 {
        self.pc
    }

    /// Returns the bytes of the recorded instruction.
    pub fn insbytes(&self) -> &[u8] {
        &self.insbytes
    }

    fn parse<F>(bytes: &'d [u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (pc, insbytes) = varfmt(bytes)?;
        Ok(Self {
            pc,
            insbytes: Cow::from(insbytes),
        })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        let mut pc = [0u8; 8];
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let pc = varfmt(self.pc, &mut pc);
        let (vlen, rlen) =
            calculate_vlen_rlen(pc.len() + self.insbytes.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::Instruction as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(pc);
        buffer.extend_from_slice(&self.insbytes);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data has been written to memory.
///
/// # Format
///
/// `| 0b1000_01LL | vlen | address: varfmt | contents: [u8] | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemWrite<'d> {
    address: u64,
    contents: Cow<'d, [u8]>,
}

impl<'d> MemWrite<'d> {
    /// Constructs a new record indicating that `contents` have been written to `address`.
    pub fn new(address: u64, contents: &'d [u8]) -> Self {
        Self {
            address,
            contents: Cow::from(contents),
        }
    }

    /// Returns the address at which data was written.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the bytes that were written.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse<F>(bytes: &'d [u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (address, contents) = varfmt(bytes)?;
        Ok(Self {
            address,
            contents: Cow::from(contents),
        })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        let mut addr = [0u8; 8];
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let addr = varfmt(self.address, &mut addr);
        let (vlen, rlen) =
            calculate_vlen_rlen(addr.len() + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::MemWrite as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(addr);
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data has been read from memory.
///
/// # Format
///
/// `| 0b1000_00LL | vlen | address: varfmt | contents: [u8] | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemRead<'d> {
    address: u64,
    contents: Cow<'d, [u8]>,
}

impl<'d> MemRead<'d> {
    /// Constructs a new record indicating that `contents` have been written to `address`.
    pub fn new(address: u64, contents: &'d [u8]) -> Self {
        Self {
            address,
            contents: Cow::from(contents),
        }
    }

    /// Returns the address from which data was read.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the bytes that were read.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse<F>(bytes: &'d [u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (address, contents) = varfmt(bytes)?;
        Ok(Self {
            address,
            contents: Cow::from(contents),
        })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        let mut addr = [0u8; 8];
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let addr = varfmt(self.address, &mut addr);
        let (vlen, rlen) =
            calculate_vlen_rlen(addr.len() + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::MemRead as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(addr);
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data has been written to a register.
///
/// Note that the difference between this record and [`RegWrite`] is that this record uses
/// register numbers corresponding with the [`RegisterNameMap`] rather than SLEIGH.
///
/// # Format
///
/// `| 0b0101_01LL | vlen | regnum: u8 | contents: [u8] | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegWriteNative<'d> {
    regnum: u16,
    contents: Cow<'d, [u8]>,
}

impl<'d> RegWriteNative<'d> {
    /// Constructs a new record indicating that the register, `regnum`, was written to with the
    /// bytes, `contents`.
    pub fn new(regnum: u16, contents: &'d [u8]) -> Self {
        Self {
            regnum,
            contents: Cow::from(contents),
        }
    }

    /// Returns the index of register that was written.
    pub fn regnum(&self) -> u16 {
        self.regnum
    }

    /// Returns the data that was written.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughBytes)?;
        }

        let (regnum, contents) = bytes.split_at(2);
        Ok(Self {
            regnum: ((regnum[1] as u16) << 8) | (regnum[0] as u16),
            contents: Cow::from(contents),
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let data_size = std::mem::size_of::<u16>() + self.contents.len();
        let (vlen, rlen) = calculate_vlen_rlen(data_size, &mut vlen, &mut rlen);
        buffer.push(RecordKind::RegWriteNative as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(&u16::to_le_bytes(self.regnum));
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data has been written to a register.
///
/// Note that the difference between this record and [`RegWriteNative`] is that this record
/// uses register numbers corresponding with the SLEIGH specification for the trace's architecture
/// rather than the [`RegisterNameMap`].
///
/// # Format
///
/// `| 0b0100_01LL | vlen | regnum: le32 | contents: [u8] | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegWrite<'d> {
    regnum: u32,
    contents: Cow<'d, [u8]>,
}

impl<'d> RegWrite<'d> {
    /// Constructs a new record indicating that the register, `regnum`, was written to with the
    /// bytes, `contents`.
    pub fn new(regnum: u32, contents: &'d [u8]) -> Self {
        Self {
            regnum,
            contents: Cow::from(contents),
        }
    }

    /// Returns the offset of register that was written.
    pub fn regnum(&self) -> u32 {
        self.regnum
    }

    /// Returns the data that was written.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        let (regnum, contents) = parse_le32(bytes)?;
        Ok(Self {
            regnum: regnum as u32,
            contents: Cow::from(contents),
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let (vlen, rlen) = calculate_vlen_rlen(4 + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::RegWrite as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(&self.regnum.to_le_bytes());
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data has been read from a register.
///
/// # Format
///
/// `| 0b0100_00LL | vlen | regnum: le32 | contents: [u8] | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegRead<'d> {
    regnum: u32,
    contents: Cow<'d, [u8]>,
}

impl<'d> RegRead<'d> {
    /// Constructs a new record indicating that the register, `regnum`, was read from with the
    /// bytes, `contents`.
    pub fn new(regnum: u32, contents: &'d [u8]) -> Self {
        Self {
            regnum,
            contents: Cow::from(contents),
        }
    }

    /// Returns the offset of register that was read.
    pub fn regnum(&self) -> u32 {
        self.regnum
    }

    /// Returns the data that was read.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse(bytes: &'d [u8]) -> Result<Self, ParseError> {
        let (regnum, contents) = parse_le32(bytes)?;
        Ok(Self {
            regnum: regnum as u32,
            contents: Cow::from(contents),
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let (vlen, rlen) = calculate_vlen_rlen(4 + self.contents.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::RegRead as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(&self.regnum.to_le_bytes());
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that an interrupt has occured during execution.
///
/// # Format
///
/// `| 0b0011_10LL | vlen | num: le32 | tick: le64 | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interrupt {
    num: u32,
    tick: u64,
}

impl Interrupt {
    /// Constructs a record indicating that an interrupt occurred.
    pub fn new(num: u32, tick: u64) -> Self {
        Self { num, tick }
    }

    /// Returns the interrupt number.
    pub fn num(&self) -> u32 {
        self.num
    }

    /// Returns the instruction count immediately following the interrupt.
    pub fn tick(&self) -> u64 {
        self.tick
    }

    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (num, bytes) = parse_le32(bytes)?;
        let (tick, _) = parse_le64(bytes)?;
        Ok(Self {
            num: num as u32,
            tick,
        })
    }

    fn emit(&self, buffer: &mut Vec<u8>) {
        let mut bytes = [
            0x39u8, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0e,
        ];
        bytes[2..6].copy_from_slice(&self.num.to_le_bytes());
        bytes[6..14].copy_from_slice(&self.tick.to_le_bytes());
        buffer.extend_from_slice(&bytes);
    }
}

/// Record indicating that instruction decoding has started at a given address.
///
/// # Format
///
/// `| 0b0010_01LL | vlen | pc: varfmt | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pc {
    pc: u64,
}

impl Pc {
    /// Constructs a record that indicates that decoding has started at `pc`.
    pub fn new(pc: u64) -> Self {
        Self { pc }
    }

    /// Returns the address of the instruction being decoded.
    pub fn pc(&self) -> u64 {
        self.pc
    }

    fn parse<F>(bytes: &[u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (pc, _) = varfmt(bytes)?;
        Ok(Self { pc })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        let mut pc = [0u8; 8];
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let pc = varfmt(self.pc, &mut pc[..]);
        let (vlen, rlen) = calculate_vlen_rlen(pc.len(), &mut vlen, &mut rlen);
        buffer.push(RecordKind::Pc as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(pc);
        buffer.extend_from_slice(rlen);
    }
}

/// Record indicating that data (likely from a file) has been mapped into memory.
///
/// # Format
///
/// `| 0b0001_0011 | vlen: le32 | base: varfmt | contents: [u8] | rlen: [u8; 5] |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Map<'d> {
    base: u64,
    contents: Cow<'d, [u8]>,
}

impl<'d> Map<'d> {
    /// Constructs a record indicating that `contents` has been mapped to `base`.
    pub fn new(base: u64, contents: &'d [u8]) -> Self {
        Self {
            base,
            contents: Cow::from(contents),
        }
    }

    /// Returns the base address of the mapping.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the data that was mapped into memory.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    fn parse<F>(bytes: &'d [u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (base, contents) = varfmt(bytes)?;
        Ok(Self {
            base,
            contents: Cow::from(contents),
        })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        // TODO: Split into multiple records if size is too large for single record

        let mut base = [0u8; 8];
        let base = varfmt(self.base, &mut base[..]);

        let vlen = base.len() + self.contents.len() + 5;
        let rlen = 1 + 4 + base.len() + self.contents.len();

        buffer.push(RecordKind::Map as u8 | 0b11);
        buffer.extend_from_slice(&u32::to_le_bytes(vlen as _));
        buffer.extend_from_slice(base);
        buffer.extend_from_slice(&self.contents);
        buffer.extend_from_slice(&u32::to_le_bytes(rlen as _));
        buffer.push(0);
    }
}

/// Record indicating that an address range is no longer mapped into memory.
///
/// # Format
///
/// `| 0b0001_11LL | vlen | base: varfmt | len: varfmt | rlen |`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Unmap {
    base: u64,
    length: u64,
}

impl Unmap {
    /// Constructs a record indicating that the region from `base` to `base+length` has been
    /// unmapped from memory.
    pub fn new(base: u64, length: u64) -> Self {
        Self { base, length }
    }

    /// Returns the base address of the region that was unmapped.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the length of the region that was unmapped.
    pub fn length(&self) -> u64 {
        self.length
    }

    fn parse<F>(bytes: &[u8], mut varfmt: F) -> Result<Self, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        let (base, bytes) = varfmt(bytes)?;
        let (length, _) = varfmt(bytes)?;
        Ok(Self { base, length })
    }

    fn emit<F>(&self, buffer: &mut Vec<u8>, mut varfmt: F)
    where
        F: FnMut(u64, &mut [u8]) -> &[u8],
    {
        let mut base = [0u8; 8];
        let mut length = [0u8; 8];
        let mut vlen = [0u8; 4];
        let mut rlen = [0u8; 5];
        let base = varfmt(self.base, &mut base[..]);
        let length = varfmt(self.length, &mut length[..]);
        let (vlen, rlen) = calculate_vlen_rlen(base.len() << 1, &mut vlen, &mut rlen);
        buffer.push(RecordKind::Unmap as u8 | to_lenlen(vlen.len()));
        buffer.extend_from_slice(vlen);
        buffer.extend_from_slice(base);
        buffer.extend_from_slice(length);
        buffer.extend_from_slice(rlen);
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ParseError(#[from] Error);

impl From<UnknownRecordKind> for ParseError {
    fn from(err: UnknownRecordKind) -> Self {
        Self(Error::from(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse {0:} record")]
    ParseRecord(String, #[source] Box<Error>),

    #[error("record contains invalid magic bytes")]
    InvalidMagic,

    #[error(transparent)]
    UnknownRecordKind(#[from] UnknownRecordKind),

    #[error("unknown architecture: {0:x}")]
    UnknownArch(u32),

    #[error("record data does not contain enough bytes")]
    NotEnoughBytes,

    #[error("no data present for record with required fields")]
    NoData,

    #[error("Data present for record did not match the required format")]
    BadData,

    #[error("architecture has not been specified")]
    MissingArch,

    #[error("variable format field could not be parsed")]
    VarfmtField(#[source] Box<Error>),

    #[error("'{0:?}' is not supported by dataflow.")]
    NoDataflowArch(Arch),
}

impl Error {
    fn record(s: &str, e: Error) -> Self {
        Self::ParseRecord(String::from(s), Box::new(e))
    }

    fn wrap(s: &str, e: ParseError) -> Self {
        Self::ParseRecord(String::from(s), Box::new(e.0))
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown record kind: {0:x}")]
pub struct UnknownRecordKind(u8);

macro_rules! generate_parse_func {
    ($name:ident,$ty:ty,$impl:expr) => {
        pub fn $name(bytes: &[u8]) -> Result<(u64, &[u8]), ParseError> {
            let mut buffer = [0u8; ::std::mem::size_of::<$ty>()];
            if bytes.len() < ::std::mem::size_of::<$ty>() {
                Err(Error::NotEnoughBytes)?;
            }
            let (left, right) = bytes.split_at(::std::mem::size_of::<$ty>());
            buffer.as_mut_slice().copy_from_slice(left);
            Ok(($impl(buffer) as _, right))
        }
    };
}

generate_parse_func!(parse_be32, u32, u32::from_be_bytes);
generate_parse_func!(parse_le32, u32, u32::from_le_bytes);
generate_parse_func!(parse_be64, u64, u64::from_be_bytes);
generate_parse_func!(parse_le64, u64, u64::from_le_bytes);

pub fn parse_unknown(_: &[u8]) -> Result<(u64, &[u8]), ParseError> {
    Err(Error::MissingArch.into())
}

macro_rules! generate_emit_func {
    ($name:ident,$ty:ty,$impl:expr) => {
        pub fn $name(addr: u64, buffer: &mut [u8]) -> &[u8] {
            (&mut buffer[..::std::mem::size_of::<$ty>()]).copy_from_slice(&$impl(addr as _));
            &buffer[..::std::mem::size_of::<$ty>()]
        }
    };
}

generate_emit_func!(emit_be32, u32, u32::to_be_bytes);
generate_emit_func!(emit_le32, u32, u32::to_le_bytes);
generate_emit_func!(emit_be64, u64, u64::to_be_bytes);
generate_emit_func!(emit_le64, u64, u64::to_le_bytes);

fn calculate_vlen_rlen<'v, 'r>(
    clen: usize,
    vlen: &'v mut [u8; 4],
    rlen: &'r mut [u8; 5],
) -> (&'v [u8], &'r [u8]) {
    let vlenlen: usize;
    let rlenlen: usize;

    match clen {
        n if n < 254 => {
            vlenlen = 1;
            rlenlen = 1;
            vlen[0] = clen as u8 + 1;
            rlen[0] = 1 + 1 + clen as u8;
        }
        n if (254..(0xffff - 4)).contains(&n) => {
            vlenlen = 2;
            rlenlen = 5;
            vlen[..2].copy_from_slice(&u16::to_le_bytes(clen as u16 + 5));
            rlen[..4].copy_from_slice(&u32::to_le_bytes(1 + 2 + clen as u32));
        }
        n if ((0xffff - 4)..(0xffff_ffff - 4)).contains(&n) => {
            vlenlen = 4;
            rlenlen = 5;
            vlen[..2].copy_from_slice(&u32::to_le_bytes(clen as u32 + 5));
            rlen[..4].copy_from_slice(&u32::to_le_bytes(1 + 4 + clen as u32));
        }
        _ => {
            panic!("contents are too large for record")
        }
    }
    (&vlen[..vlenlen], &rlen[..rlenlen])
}

fn to_lenlen(v: usize) -> u8 {
    ((v - (v >> 2)) & 0b0000_0011) as u8
}

pub mod architecture {
    use super::{Error, ParseError, RawRecord, Record};

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
    pub enum Arch {
        X86,
        X86_64,
        X86_64Compat32,
        PowerPc,
        PowerPc64,
        Arm,
        Arm64,
        M68k,
        Mips,
        Mips64,
        Mipsel,
        Mipsel64,
        Sparc,
        Sparc64,
        RiscV,
        RiscV64,
        Unknown(u32),
    }

    impl Arch {
        /// The bytes represening a trace architecture will always be little endian!
        pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
            let (value, _) = super::parse_le32(bytes)?;
            Ok(match value {
                0x20 => Self::X86,
                0x40 => Self::X86_64,
                0x21 => Self::X86_64Compat32,
                0x10 => Self::PowerPc,
                0x11 => Self::PowerPc64,
                0x120 => Self::Arm,
                0x121 => Self::Arm64,
                0x01 => Self::M68k,
                0x60 => Self::Mips,
                0x61 => Self::Mips64,
                0x62 => Self::Mipsel,
                0x63 => Self::Mipsel64,
                0x80 => Self::Sparc,
                0x81 => Self::Sparc64,
                0x70 => Self::RiscV,
                0x71 => Self::RiscV64,
                n => Self::Unknown(n as u32),
            })
        }

        pub(crate) fn emit(&self, buffer: &mut Vec<u8>) {
            let mut bytes = [0x01u8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x06];
            let val = match self {
                Self::X86 => 0x20u32,
                Self::X86_64 => 0x40u32,
                Self::X86_64Compat32 => 0x21u32,
                Self::PowerPc => 0x10u32,
                Self::PowerPc64 => 0x11u32,
                Self::Arm => 0x120u32,
                Self::Arm64 => 0x121u32,
                Self::M68k => 0x01u32,
                Self::Mips => 0x60u32,
                Self::Mips64 => 0x61u32,
                Self::Mipsel => 0x62u32,
                Self::Mipsel64 => 0x63u32,
                Self::Sparc => 0x80u32,
                Self::Sparc64 => 0x81u32,
                Self::RiscV => 0x70u32,
                Self::RiscV64 => 0x71u32,
                Self::Unknown(n) => *n,
            };
            bytes[2..6].copy_from_slice(&val.to_le_bytes());
            buffer.extend_from_slice(&bytes);
        }

        /// Parses a `RawRecord` using a `varfmt` function that takes into account the endianness of the
        /// architecture.
        pub fn parse_record<'a>(&self, raw: RawRecord<'a>) -> Result<Record<'a>, Error> {
            let varfmt = match self {
                Self::X86 => super::parse_le32,
                Self::X86_64 => super::parse_le64,
                Self::X86_64Compat32 => super::parse_le64,
                Self::PowerPc => super::parse_be32,
                Self::PowerPc64 => super::parse_be64,
                Self::Arm => super::parse_be32,
                Self::Arm64 => super::parse_be64,
                Self::M68k => super::parse_be32,
                Self::Mips => super::parse_be32,
                Self::Mips64 => super::parse_be64,
                Self::Mipsel => super::parse_le32,
                Self::Mipsel64 => super::parse_le64,
                Self::Sparc => super::parse_be32,
                Self::Sparc64 => super::parse_be64,
                Self::RiscV => super::parse_le32,
                Self::RiscV64 => super::parse_le64,
                Self::Unknown(n) => return Err(Error::UnknownArch(*n)),
            };

            Record::parse(raw, varfmt)
                .map_err(move |e| Error::ParseRecord(e.to_string(), Box::new(Error::NoData)))
        }
    }

    // NOTE: Below I import the Architecture enum from dataflow along with all of the
    // unit structs corresponding to each architecture supportd by dataflow.
    use dataflow::architecture::*;

    impl std::convert::TryInto<Architecture> for Arch {
        type Error = Error;

        fn try_into(self) -> Result<Architecture, Self::Error> {
            let df_arch = match self {
                Arch::X86 => Architecture::X86(X86),
                Arch::X86_64 => Architecture::X86_64(X86_64),
                Arch::X86_64Compat32 => Architecture::X86_64Compat32(X86_64Compat32),
                Arch::PowerPc => Architecture::PPCBE32(PPCBE32),
                // Arch::PowerPc64 => todo!(),
                Arch::Arm => Architecture::ARM32(ARM32),
                Arch::Arm64 => Architecture::AARCH64(AARCH64),
                Arch::M68k => Architecture::M68K(M68K),
                // Arch::Mips => todo!(),
                // Arch::Mips64 => todo!(),
                // Arch::Mipsel => todo!(),
                // Arch::Mipsel64 => todo!(),
                // Arch::Sparc => todo!(),
                // Arch::Sparc64 => todo!(),
                // Arch::RiscV => todo!(),
                // Arch::RiscV64 => todo!(),
                Arch::Unknown(num) => {
                    return Err(Error::UnknownArch(num));
                }
                _ => {
                    return Err(Error::NoDataflowArch(self));
                }
            };

            Ok(df_arch)
        }
    }

    impl From<Architecture> for Arch {
        fn from(value: Architecture) -> Self {
            match value {
                Architecture::X86(_) => Arch::X86,
                Architecture::X86_64(_) => Arch::X86_64,
                Architecture::X86_64Compat32(_) => Arch::X86_64Compat32,
                Architecture::PPCBE32(_) => Arch::PowerPc,
                Architecture::AARCH64(_) => Arch::Arm64,
                Architecture::ARM32(_) => Arch::Arm,
                Architecture::M68K(_) => Arch::M68k,
                // TODO: docs
                _ => unreachable!(),
            }
        }
    }
}
