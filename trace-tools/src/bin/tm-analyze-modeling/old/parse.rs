use std::io::Read;

macro_rules! check_result {
    ($expr:expr) => {
        if let Err(e) = $expr {
            return Some(Err(e));
        }
    };
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Ins(InsEvent),
    RegWrite(RegWriteEvent),
    MemRead(MemReadEvent),
    MemWrite(MemWriteEvent),
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct InsEvent {
    pc: u64,
    insbytes: [u8; 16],
    inslen: usize,
}

impl InsEvent {
    pub fn new(pc: u64, bytes: &[u8]) -> Self {
        assert!(bytes.len() < 16);
        let mut insbytes = [0u8; 16];
        insbytes[..bytes.len()].copy_from_slice(bytes);
        Self {
            pc,
            insbytes,
            inslen: bytes.len(),
        }
    }

    pub fn pc(&self) -> u64 {
        self.pc
    }

    pub fn insbytes(&self) -> &[u8] {
        &self.insbytes[..self.inslen]
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegWriteEvent {
    reg: Register,
}

impl RegWriteEvent {
    pub fn new(reg: Register) -> Self {
        Self { reg }
    }

    pub fn register(&self) -> &Register {
        &self.reg
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemReadEvent {
    addr: u64,
    buffer: MemoryBuffer,
}

impl MemReadEvent {
    fn short(addr: u64, bytes: &[u8]) -> Self {
        Self {
            addr,
            buffer: MemoryBuffer::from(bytes),
        }
    }

    fn long(addr: u64, bytes: Vec<u8>) -> Self {
        Self {
            addr,
            buffer: MemoryBuffer::from(bytes),
        }
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn bytes(&self) -> &[u8] {
        self.buffer.bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemWriteEvent {
    addr: u64,
    buffer: MemoryBuffer,
}

impl MemWriteEvent {
    fn short(addr: u64, bytes: &[u8]) -> Self {
        Self {
            addr,
            buffer: MemoryBuffer::from(bytes),
        }
    }

    fn long(addr: u64, bytes: Vec<u8>) -> Self {
        Self {
            addr,
            buffer: MemoryBuffer::from(bytes),
        }
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn bytes(&self) -> &[u8] {
        self.buffer.bytes()
    }
}

#[derive(Clone)]
pub struct Parser<T> {
    data: T,
}

impl<T> Parser<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

impl<T> std::iter::IntoIterator for Parser<T>
where
    T: Read,
{
    type Item = Result<Event, ParseError>;
    type IntoIter = ParseReadIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let Self { data } = self;
        Self::IntoIter {
            reader: data,
            done: false,
        }
    }
}

pub struct ParseReadIter<T> {
    reader: T,
    done: bool,
}

impl<T: Read> ParseReadIter<T> {
    fn next_chunk(&mut self, bytes: &mut [u8]) -> Result<(), ParseError> {
        if let Err(e) = self.reader.read_exact(bytes) {
            self.done = true;
            return match e.kind() {
                std::io::ErrorKind::UnexpectedEof => Err(ParseError::Incomplete),
                _ => Err(ParseError::from(e)),
            };
        }
        Ok(())
    }
}

impl<T> Iterator for ParseReadIter<T>
where
    T: Read,
{
    type Item = Result<Event, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let mut ty = [0u8];

        match self.next_chunk(&mut ty) {
            Ok(_) => {}
            Err(ParseError::Incomplete) => {
                return None;
            }
            Err(e) => {
                return Some(Err(e));
            }
        }

        let et = match EventType::try_from(ty[0]) {
            Ok(et) => et,
            Err(e) => {
                return Some(Err(e));
            }
        };

        Some(match et {
            EventType::Ins(inslen) => {
                let mut pc = [0u8; 8];
                let mut insbytes = [0u8; 16];

                check_result!(self.next_chunk(&mut pc));
                check_result!(self.next_chunk(&mut insbytes[..inslen]));

                Ok(Event::Ins(InsEvent::new(
                    u64::from_le_bytes(pc),
                    &insbytes[..inslen],
                )))
            }

            EventType::RegWrite(mut reg) => {
                check_result!(self.next_chunk(reg.bytes_mut()));
                Ok(Event::RegWrite(RegWriteEvent::new(reg)))
            }

            EventType::MemReadShort(len) => {
                let mut addr = [0u8; 8];
                let mut bytes = [0u8; 16];

                check_result!(self.next_chunk(&mut addr));
                check_result!(self.next_chunk(&mut bytes[..len]));

                Ok(Event::MemRead(MemReadEvent::short(
                    u64::from_le_bytes(addr),
                    &bytes[..len],
                )))
            }

            EventType::MemWriteShort(len) => {
                let mut addr = [0u8; 8];
                let mut bytes = [0u8; 16];

                check_result!(self.next_chunk(&mut addr));
                check_result!(self.next_chunk(&mut bytes[..len]));

                Ok(Event::MemWrite(MemWriteEvent::short(
                    u64::from_le_bytes(addr),
                    &bytes[..len],
                )))
            }

            EventType::MemReadLong(high) => {
                let mut lower = [0u8];
                let mut addr = [0u8; 8];

                check_result!(self.next_chunk(&mut lower));
                check_result!(self.next_chunk(&mut addr));

                let size = (high << 8) | (lower[0] as usize);
                let mut buffer = Vec::new();
                buffer.resize(if size == 0 { 4096 } else { size }, 0);

                check_result!(self.next_chunk(buffer.as_mut_slice()));

                Ok(Event::MemRead(MemReadEvent::long(
                    u64::from_le_bytes(addr),
                    buffer,
                )))
            }

            EventType::MemWriteLong(high) => {
                let mut lower = [0u8];
                let mut addr = [0u8; 8];

                check_result!(self.next_chunk(&mut lower));
                check_result!(self.next_chunk(&mut addr));

                let size = (high << 8) | (lower[0] as usize);
                let mut buffer = Vec::new();
                buffer.resize(if size == 0 { 4096 } else { size }, 0);

                check_result!(self.next_chunk(buffer.as_mut_slice()));

                Ok(Event::MemWrite(MemWriteEvent::long(
                    u64::from_le_bytes(addr),
                    buffer,
                )))
            }

            EventType::Extended(data) => {
                let mut code = [0u8];
                check_result!(self.next_chunk(&mut code));
                Err(ParseError::unsupported(code[0], data))
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Register {
    RDI([u8; 8]),
    RSI([u8; 8]),
    RBP([u8; 8]),
    RSP([u8; 8]),
    RBX([u8; 8]),
    RDX([u8; 8]),
    RCX([u8; 8]),
    RAX([u8; 8]),
    R8([u8; 8]),
    R9([u8; 8]),
    R10([u8; 8]),
    R11([u8; 8]),
    R12([u8; 8]),
    R13([u8; 8]),
    R14([u8; 8]),
    R15([u8; 8]),
}

impl Register {
    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::RDI(ref mut bytes) => bytes,
            Self::RSI(ref mut bytes) => bytes,
            Self::RBP(ref mut bytes) => bytes,
            Self::RSP(ref mut bytes) => bytes,
            Self::RBX(ref mut bytes) => bytes,
            Self::RDX(ref mut bytes) => bytes,
            Self::RCX(ref mut bytes) => bytes,
            Self::RAX(ref mut bytes) => bytes,
            Self::R8(ref mut bytes) => bytes,
            Self::R9(ref mut bytes) => bytes,
            Self::R10(ref mut bytes) => bytes,
            Self::R11(ref mut bytes) => bytes,
            Self::R12(ref mut bytes) => bytes,
            Self::R13(ref mut bytes) => bytes,
            Self::R14(ref mut bytes) => bytes,
            Self::R15(ref mut bytes) => bytes,
        }
    }

    pub fn sleigh(&self) -> u64 {
        match self {
            Self::RDI(_) => 0x38,
            Self::RSI(_) => 0x30,
            Self::RBP(_) => 0x28,
            Self::RSP(_) => 0x20,
            Self::RBX(_) => 0x18,
            Self::RDX(_) => 0x10,
            Self::RCX(_) => 0x08,
            Self::RAX(_) => 0x00,
            Self::R8(_) => 0x80,
            Self::R9(_) => 0x88,
            Self::R10(_) => 0x90,
            Self::R11(_) => 0x98,
            Self::R12(_) => 0xa0,
            Self::R13(_) => 0xa8,
            Self::R14(_) => 0xb0,
            Self::R15(_) => 0xb8,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::RDI(ref bytes) => bytes,
            Self::RSI(ref bytes) => bytes,
            Self::RBP(ref bytes) => bytes,
            Self::RSP(ref bytes) => bytes,
            Self::RBX(ref bytes) => bytes,
            Self::RDX(ref bytes) => bytes,
            Self::RCX(ref bytes) => bytes,
            Self::RAX(ref bytes) => bytes,
            Self::R8(ref bytes) => bytes,
            Self::R9(ref bytes) => bytes,
            Self::R10(ref bytes) => bytes,
            Self::R11(ref bytes) => bytes,
            Self::R12(ref bytes) => bytes,
            Self::R13(ref bytes) => bytes,
            Self::R14(ref bytes) => bytes,
            Self::R15(ref bytes) => bytes,
        }
    }
}

impl TryFrom<u8> for Register {
    type Error = ParseError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::RDI([0u8; 8])),
            1 => Ok(Self::RSI([0u8; 8])),
            2 => Ok(Self::RBP([0u8; 8])),
            3 => Ok(Self::RSP([0u8; 8])),
            4 => Ok(Self::RBX([0u8; 8])),
            5 => Ok(Self::RDX([0u8; 8])),
            6 => Ok(Self::RCX([0u8; 8])),
            7 => Ok(Self::RAX([0u8; 8])),
            8 => Ok(Self::R8([0u8; 8])),
            9 => Ok(Self::R9([0u8; 8])),
            10 => Ok(Self::R10([0u8; 8])),
            11 => Ok(Self::R11([0u8; 8])),
            12 => Ok(Self::R12([0u8; 8])),
            13 => Ok(Self::R13([0u8; 8])),
            14 => Ok(Self::R14([0u8; 8])),
            15 => Ok(Self::R15([0u8; 8])),
            _ => Err(ParseError::BadRegister(val)),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("failed to parse due to I/O error")]
    Io(#[from] std::io::Error),

    #[error("failed to parse a complete event")]
    Incomplete,

    #[error("unable to parse extended event")]
    Unsupported(#[source] UnsupportedError),

    #[error("bad register value: {0}")]
    BadRegister(u8),
}

impl ParseError {
    fn unsupported(code: u8, data: u8) -> Self {
        Self::Unsupported(UnsupportedError { code, data })
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq)]
#[error("code: {code:x?}, data {data:x?}")]
pub struct UnsupportedError {
    code: u8,
    data: u8,
}

enum EventType {
    Ins(usize),
    RegWrite(Register),
    MemReadShort(usize),
    MemWriteShort(usize),
    MemReadLong(usize),
    MemWriteLong(usize),
    Extended(u8),
}

impl TryFrom<u8> for EventType {
    type Error = ParseError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val & 0b1100_0000 {
            0b0000_0000 => Ok(Self::Ins((val & 0b0001_1111) as usize)),
            0b0100_0000 => {
                let sz = (val & 0b0000_1111) as usize;
                match val & 0b0011_0000 {
                    0b0000_0000 => Ok(Self::MemReadShort(sz)),
                    0b0001_0000 => Ok(Self::MemReadLong(sz)),
                    0b0010_0000 => Ok(Self::MemWriteShort(sz)),
                    0b0011_0000 => Ok(Self::MemWriteLong(sz)),
                    _ => unreachable!(),
                }
            }
            0b1000_0000 => Ok(Self::RegWrite(Register::try_from(val & 0b0011_1111)?)),
            0b1100_0000 => Ok(Self::Extended(val & 0b0011_1111)),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum MemoryBuffer {
    Inline { size: usize, bytes: [u8; 8] },
    Alloc(Box<[u8]>),
}

impl MemoryBuffer {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline { size, ref bytes } => &bytes[..*size],
            Self::Alloc(ref buffer) => buffer,
        }
    }
}

impl From<Vec<u8>> for MemoryBuffer {
    fn from(v: Vec<u8>) -> Self {
        Self::Alloc(v.into_boxed_slice())
    }
}

impl<'a> From<&'a [u8]> for MemoryBuffer {
    fn from(v: &'a [u8]) -> MemoryBuffer {
        if v.len() > 8 {
            return Self::from(Vec::from(v));
        }

        let mut bytes = [0u8; 8];
        (&mut bytes[..v.len()]).copy_from_slice(v);
        Self::Inline {
            size: v.len(),
            bytes,
        }
    }
}
