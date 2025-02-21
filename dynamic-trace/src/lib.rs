use std::path::Path;
use std::{fs, io};

pub mod index;

pub mod record;

// Expose record::Arch as a top level import
pub use record::Arch;

use record::{ParseError, Record, RecordKind, UnknownRecordKind};

pub fn validate_magic(record: RawRecord) -> bool {
    record.0 == b"\xf1\x06\x65\x78\x00\x3c\x7f\x07"
}

#[inline]
pub fn kind(ty: u8) -> Option<RecordKind> {
    RecordKind::try_from(ty).ok()
}

#[inline]
pub fn lenlen(ty: u8) -> usize {
    4 >> (3 - (ty & 0b0000_0011))
}

#[inline]
pub fn vlen(lenlen: usize, record: &[u8]) -> Option<usize> {
    let mut buffer = [0u8; 4];
    let bytes = record.get(1..1 + lenlen)?;
    buffer[..lenlen].copy_from_slice(bytes);
    Some(u32::from_le_bytes(buffer) as usize)
}

#[inline]
pub fn value(lenlen: usize, vlen: usize, record: &[u8]) -> Option<&[u8]> {
    let bytes = record.get(1 + lenlen..1 + lenlen + vlen)?;
    match bytes.last() {
        Some(0) => bytes.get(..bytes.len() - 5),
        Some(_) => bytes.get(..bytes.len() - 1),
        None => None,
    }
}

fn one_record(buffer: &[u8]) -> Result<RawRecord, usize> {
    let lenlen = lenlen(*buffer.first().ok_or(1usize)?);
    if lenlen == 0 {
        return Ok(RawRecord(&buffer[..1]));
    }
    let vlen = vlen(lenlen, buffer).ok_or(1 + lenlen)?;
    let tlen = 1 + lenlen + vlen;
    buffer.get(..tlen).ok_or(tlen).map(RawRecord)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TraceBuffer<'b>(&'b [u8]);

impl<'b> TraceBuffer<'b> {
    pub fn new(bytes: &'b [u8]) -> Self {
        Self(bytes)
    }

    pub fn iter(&self) -> impl Iterator<Item = RawRecord<'b>> + 'b {
        TraceBufferIter {
            buffer: self.0,
            pos: 0,
        }
    }
}

impl TraceBuffer<'static> {
    pub unsafe fn map<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = fs::File::open(path)?;
        let mmap = std::mem::ManuallyDrop::new(memmap::Mmap::map(&file)?);
        Ok(Self(std::slice::from_raw_parts(mmap.as_ptr(), mmap.len())))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TraceBufferIter<'b> {
    buffer: &'b [u8],
    pos: usize,
}

impl<'b> Iterator for TraceBufferIter<'b> {
    type Item = RawRecord<'b>;

    fn next(&mut self) -> Option<Self::Item> {
        let buffer = self.buffer.get(self.pos..)?;
        let record = one_record(buffer).ok()?;
        self.pos += record.len();
        Some(record)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawRecord<'a>(&'a [u8]);

impl<'a> RawRecord<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        RawRecord(bytes)
    }

    pub fn kind(&self) -> Result<RecordKind, UnknownRecordKind> {
        RecordKind::try_from(unsafe { *self.0.get_unchecked(0) })
    }

    pub fn value(&self) -> Option<&'a [u8]> {
        let lenlen = lenlen(unsafe { *self.0.get_unchecked(0) });
        let vlen = vlen(lenlen, self.0)?;
        value(lenlen, vlen, self.0)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn parse<F>(&self, varlen: F) -> Result<Record<'a>, ParseError>
    where
        F: FnMut(&[u8]) -> Result<(u64, &[u8]), ParseError>,
    {
        Record::parse(*self, varlen)
    }

    pub fn bytes(&self) -> &[u8] {
        self.0
    }
}

pub static MAGIC_BYTES: &[u8] = b"\x65\x78\x00\x3c\x7f";

pub mod reader {
    use super::{lenlen, vlen, RawRecord};
    use std::io::{BufReader, Read};
    use std::ops::ControlFlow;

    pub use macros::{__cont as cont, __try_break as try_break, __try_cont as try_cont};

    /// TODO: Docs
    #[derive(Debug)]
    pub struct TraceReader<R> {
        reader: BufReader<R>,
        buffer: Vec<u8>,
    }

    impl<R: Read> TraceReader<R> {
        /// Creates a new TraceReader with an internal temp buffer that can hold 4096 bytes.
        pub fn new(reader: R) -> Self {
            Self {
                reader: BufReader::new(reader),
                buffer: Vec::with_capacity(4096), // Should be a size most records will fit in.
            }
        }

        pub fn next<'a>(&'a mut self) -> Option<RawRecord<'a>> {
            self.buffer.resize(1, 0);
            self.reader.read_exact(self.buffer.as_mut_slice()).ok()?;
            let lenlen = lenlen(self.buffer[0]);
            if lenlen == 0 {
                return Some(RawRecord(&self.buffer[..1]));
            }
            self.buffer.resize(1 + lenlen, 0);
            self.reader
                .read_exact(&mut self.buffer[1..1 + lenlen])
                .ok()?;
            let vlen = vlen(lenlen, self.buffer.as_slice())?;
            let tlen = 1 + lenlen + vlen;
            self.buffer.resize(tlen, 0);
            self.reader
                .read_exact(&mut self.buffer[1 + lenlen..tlen])
                .ok()?;
            Some(RawRecord(self.buffer.as_slice()))
        }

        pub fn for_each<F, T>(&mut self, mut func: F) -> Option<T>
        where
            F: FnMut(RawRecord) -> ControlFlow<T>,
        {
            while let Some(item) = self.next() {
                if let ControlFlow::Break(value) = func(item) {
                    return Some(value);
                }
            }
            None
        }
    }

    mod macros {
        #[macro_export]
        macro_rules! __try_break {
            ($expr:expr $(,)?) => {
                match $expr {
                    ::core::result::Result::Ok(val) => val,
                    ::core::result::Result::Err(err) => {
                        return ::core::ops::ControlFlow::Break(::core::convert::From::from(err));
                    }
                }
            };
        }

        #[macro_export]
        macro_rules! __try_cont {
            ($expr:expr $(,)?) => {
                match $expr {
                    ::core::result::Result::Ok(val) => val,
                    ::core::result::Result::Err(_) => {
                        return ::core::ops::ControlFlow::Continue(());
                    }
                }
            };
        }

        #[macro_export]
        macro_rules! __cont {
            () => {{
                return ::core::ops::ControlFlow::Continue(());
            }};
        }

        pub use __cont;
        pub use __try_break;
        pub use __try_cont;
    }
}

use dataflow::lifter::LiftError;

use dataflow::error::DataflowError;

// TODO: We may want to move runtime things to their own module
#[derive(thiserror::Error, Debug)]
pub enum RuntimeError {
    #[error("trace is missing magic record")]
    MissingMagic,

    #[error("trace is missing arch record")]
    MissingArch,

    #[error("trace contains a duplicate magic record")]
    DuplicateMagic,

    #[error("trace contains a duplicate arch record")]
    DuplicateArch,

    #[error("unknown architecture")]
    UnknownArch,

    #[error("unknown native register: {0:?} is not in tranlation map")]
    TranslateError((u16, String)),

    #[error("record error")]
    Record(#[from] record::Error),

    #[error("IO Error:")]
    Io(#[from] io::Error),

    #[error("unable to lift assembly intruction")]
    Lift(#[from] LiftError),

    #[error("dataflow analysis failed")]
    Dataflow(#[from] DataflowError),
}
