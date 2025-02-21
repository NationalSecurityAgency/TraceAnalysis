pub use cxx;
pub use ffi::{spacetype as SpaceType, AddrSpace, OpCode, PcodeOperation, PcodeVar};

use std::ops::Deref;
use std::sync::OnceLock;

pub struct Lifter(cxx::UniquePtr<ffi::GhidraLifter>);

impl Lifter {
    pub fn new(archid: &str) -> Result<Self, LifterError> {
        let handle = Handle::get()?;
        cxx::let_cxx_string!(archid_ffi = archid);
        Ok(Self(ffi::new_ghidra_lifter(&handle, &archid_ffi).map_err(
            |e| LifterError::FailedToCreate {
                archid: String::from(archid),
                source: e,
            },
        )?))
    }

    pub fn lift(&mut self, pc: u64, bytes: &[u8]) -> Result<i32, LifterError> {
        let size = bytes.len();
        let ptr = bytes.as_ptr();
        unsafe {
            self.0
                .pin_mut()
                .lift(pc, ptr, size)
                .map_err(|e| LifterError::FailedToLift {
                    pc,
                    bytes: Vec::from(bytes),
                    source: e,
                })
        }
    }

    pub fn instruction_length(&mut self, pc: u64, bytes: &[u8]) -> Result<i32, LifterError> {
        let size = bytes.len();
        let ptr = bytes.as_ptr();
        unsafe {
            self.0
                .pin_mut()
                .instructionLength(pc, ptr, size)
                .map_err(|e| LifterError::FailedToLift {
                    pc,
                    bytes: Vec::from(bytes),
                    source: e,
                })
        }
    }

    pub fn register_by_name(&self, register: &str) -> Result<PcodeVar, LifterError> {
        cxx::let_cxx_string!(regname = register);
        self.0
            .getRegisterByName(&regname)
            .map_err(|e| LifterError::InvalidRegisterName {
                name: String::from(register),
                source: e,
            })
    }

    pub fn clear(&mut self) {
        self.0.pin_mut().clear();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifterError {
    #[error("failed to intialize the decompiler: `{0:}`")]
    FailedToInitialize(String),

    #[error("failed to create a ghidra lifter for `{archid:}`")]
    FailedToCreate {
        archid: String,
        #[source]
        source: cxx::Exception,
    },

    #[error("failed to lift instruction at {pc:#x?}: {bytes:x?}")]
    FailedToLift {
        pc: u64,
        bytes: Vec<u8>,
        #[source]
        source: cxx::Exception,
    },

    #[error("invalid register name: {name:?}")]
    InvalidRegisterName {
        name: String,
        #[source]
        source: cxx::Exception,
    },
}

impl Deref for Lifter {
    type Target = <cxx::UniquePtr<ffi::GhidraLifter> as Deref>::Target;

    fn deref(&self) -> &Self::Target {
        Deref::deref(&self.0)
    }
}

#[derive(Copy, Clone)]
pub struct Handle(());

impl Handle {
    pub fn get() -> Result<Self, LifterError> {
        static HANDLE: OnceLock<Result<Handle, String>> = OnceLock::new();
        HANDLE
            .get_or_init(|| {
                let ghidra_dir = std::env::var("GHIDRA_INSTALL_DIR").unwrap_or_else(|e| {
                    match e {
                        std::env::VarError::NotPresent => {
                            tracing::warn!(
                                "GHIDRA_INSTALL_DIR is not set to a valid Ghidra installation"
                            );
                        }
                        std::env::VarError::NotUnicode(_) => {
                            tracing::warn!("GHIDRA_INSTALL_DIR contains unsupported characters");
                        }
                    }
                    String::new()
                });

                cxx::let_cxx_string!(sleighhome = ghidra_dir);

                let extrapaths = cxx::CxxVector::new();

                unsafe {
                    ffi::startDecompilerLibrary(&sleighhome, &extrapaths)
                        .map_err(|e| String::from(e.what()))?
                }

                Ok(Self(()))
            })
            .clone()
            .map_err(LifterError::FailedToInitialize)
    }
}

#[cxx::bridge(namespace = "lifter")]
pub mod ffi {

    #[derive(Debug, Copy, Clone)]
    pub struct PcodeOperation {
        pub opc: OpCode,
        pub has_outvar: bool,
        pub vars: usize,
        pub size: usize,
    }

    #[derive(Debug, Copy, Clone)]
    pub struct PcodeVar {
        pub space_id: i32,
        pub offset: u64,
        pub size: i32,
    }

    #[namespace = "ghidra"]
    #[repr(i32)]
    #[derive(Debug, Copy, Clone)]
    pub enum OpCode {
        CPUI_COPY = 1,
        CPUI_LOAD = 2,
        CPUI_STORE = 3,

        CPUI_BRANCH = 4,
        CPUI_CBRANCH = 5,
        CPUI_BRANCHIND = 6,

        CPUI_CALL = 7,
        CPUI_CALLIND = 8,
        CPUI_CALLOTHER = 9,
        CPUI_RETURN = 10,

        CPUI_INT_EQUAL = 11,
        CPUI_INT_NOTEQUAL = 12,
        CPUI_INT_SLESS = 13,
        CPUI_INT_SLESSEQUAL = 14,
        CPUI_INT_LESS = 15,

        CPUI_INT_LESSEQUAL = 16,
        CPUI_INT_ZEXT = 17,
        CPUI_INT_SEXT = 18,
        CPUI_INT_ADD = 19,
        CPUI_INT_SUB = 20,
        CPUI_INT_CARRY = 21,
        CPUI_INT_SCARRY = 22,
        CPUI_INT_SBORROW = 23,
        CPUI_INT_2COMP = 24,
        CPUI_INT_NEGATE = 25,
        CPUI_INT_XOR = 26,
        CPUI_INT_AND = 27,
        CPUI_INT_OR = 28,
        CPUI_INT_LEFT = 29,
        CPUI_INT_RIGHT = 30,
        CPUI_INT_SRIGHT = 31,
        CPUI_INT_MULT = 32,
        CPUI_INT_DIV = 33,
        CPUI_INT_SDIV = 34,
        CPUI_INT_REM = 35,
        CPUI_INT_SREM = 36,

        CPUI_BOOL_NEGATE = 37,
        CPUI_BOOL_XOR = 38,
        CPUI_BOOL_AND = 39,
        CPUI_BOOL_OR = 40,

        CPUI_FLOAT_EQUAL = 41,
        CPUI_FLOAT_NOTEQUAL = 42,
        CPUI_FLOAT_LESS = 43,
        CPUI_FLOAT_LESSEQUAL = 44,
        // Slot 45 is currently unused
        CPUI_FLOAT_NAN = 46,

        CPUI_FLOAT_ADD = 47,
        CPUI_FLOAT_DIV = 48,
        CPUI_FLOAT_MULT = 49,
        CPUI_FLOAT_SUB = 50,
        CPUI_FLOAT_NEG = 51,
        CPUI_FLOAT_ABS = 52,
        CPUI_FLOAT_SQRT = 53,

        CPUI_FLOAT_INT2FLOAT = 54,
        CPUI_FLOAT_FLOAT2FLOAT = 55,
        CPUI_FLOAT_TRUNC = 56,
        CPUI_FLOAT_CEIL = 57,
        CPUI_FLOAT_FLOOR = 58,
        CPUI_FLOAT_ROUND = 59,

        CPUI_MULTIEQUAL = 60,
        CPUI_INDIRECT = 61,
        CPUI_PIECE = 62,
        CPUI_SUBPIECE = 63,

        CPUI_CAST = 64,
        CPUI_PTRADD = 65,
        CPUI_PTRSUB = 66,
        CPUI_SEGMENTOP = 67,
        CPUI_CPOOLREF = 68,
        CPUI_NEW = 69,
        CPUI_INSERT = 70,
        CPUI_EXTRACT = 71,
        CPUI_POPCOUNT = 72,
        CPUI_LZCOUNT = 73,

        CPUI_MAX = 74,
    }

    #[namespace = "ghidra"]
    #[repr(i32)]
    #[derive(Debug, Copy, Clone)]
    pub enum spacetype {
        IPTR_CONSTANT = 0,
        IPTR_PROCESSOR = 1,
        IPTR_SPACEBASE = 2,
        IPTR_INTERNAL = 3,
        IPTR_FSPEC = 4,
        IPTR_IOP = 5,
        IPTR_JOIN = 6,
    }

    extern "Rust" {
        type Handle;
    }

    unsafe extern "C++" {
        include!("ghidra-lifter/include/lifter.h");

        pub unsafe fn startDecompilerLibrary(
            sleighhome: &CxxString,
            extrapaths: &CxxVector<CxxString>,
        ) -> Result<()>;

        pub type GhidraLifter;
        pub fn new_ghidra_lifter(
            handle: &Handle,
            archid: &CxxString,
        ) -> Result<UniquePtr<GhidraLifter>>;
        pub unsafe fn lift(
            self: Pin<&mut GhidraLifter>,
            pc: u64,
            bytes: *const u8,
            size: usize,
        ) -> Result<i32>;
        pub unsafe fn instructionLength(
            self: Pin<&mut GhidraLifter>,
            pc: u64,
            bytes: *const u8,
            size: usize,
        ) -> Result<i32>;
        pub fn clear(self: Pin<&mut GhidraLifter>);
        pub fn getAssembly(self: &GhidraLifter) -> &CxxString;
        pub fn getOperations(self: &GhidraLifter) -> &CxxVector<PcodeOperation>;
        pub fn getVars(self: &GhidraLifter) -> &CxxVector<PcodeVar>;
        pub fn getConstantSpaceId(self: &GhidraLifter) -> i32;
        pub fn getUniqueSpaceId(self: &GhidraLifter) -> i32;
        pub fn getDefaultCodeSpaceId(self: &GhidraLifter) -> i32;
        pub fn getDefaultDataSpaceId(self: &GhidraLifter) -> i32;
        pub fn numSpaces(self: &GhidraLifter) -> i32;
        pub unsafe fn getSpace(self: &GhidraLifter, i: i32) -> *mut AddrSpace;
        pub fn getRegisterByName(self: &GhidraLifter, regname: &CxxString) -> Result<PcodeVar>;

        type PcodeOperation;
        type PcodeVar;

        #[namespace = "ghidra"]
        type OpCode;

        #[namespace = "ghidra"]
        type spacetype;

        #[namespace = "ghidra"]
        pub type AddrSpace;
        pub fn getName(self: &AddrSpace) -> &CxxString;
        pub fn getType(self: &AddrSpace) -> spacetype;
        pub fn getIndex(self: &AddrSpace) -> i32;
        pub fn getWordSize(self: &AddrSpace) -> u32;
        pub fn getAddrSize(self: &AddrSpace) -> u32;
        pub fn getHighest(self: &AddrSpace) -> u64;
        pub fn hasPhysical(self: &AddrSpace) -> bool;
        pub fn isBigEndian(self: &AddrSpace) -> bool;
        pub fn isReverseJustified(self: &AddrSpace) -> bool;
        pub fn isFormalStackSpace(self: &AddrSpace) -> bool;
        pub fn isOverlay(self: &AddrSpace) -> bool;
        pub fn isOverlayBase(self: &AddrSpace) -> bool;
        pub fn isOtherSpace(self: &AddrSpace) -> bool;
        pub fn isTruncated(self: &AddrSpace) -> bool;

        /*
        #[namespace = "ghidra"]
        pub type LanguageDescription;
        pub fn getProcessor(self: &LanguageDescription) -> &CxxString;
        pub fn isBigEndian(self: &LanguageDescription) -> bool;
        pub fn getSize(self: &LanguageDescription) -> i32;
        pub fn getVariant(self: &LanguageDescription) -> &CxxString;
        pub fn getVersion(self: &LanguageDescription) -> &CxxString;
        pub fn getSlaFile(self: &LanguageDescription) -> &CxxString;
        pub fn getProcessorSpec(self: &LanguageDescription) -> &CxxString;
        pub fn getId(self: &LanguageDescription) -> &CxxString;
        pub fn getDescription(self: &LanguageDescription) -> &CxxString;


        #[namespace = "ghidra"]
        pub type FileManage;
        pub fn specpaths() -> &'static FileManage;
        pub fn findFile(self: &FileManage, res: Pin<&mut CxxString>, name: &CxxString);
        */
    }
}
