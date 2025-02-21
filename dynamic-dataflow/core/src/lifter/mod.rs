//#[cfg(feature = "icicle")]
//mod icicle;

//#[cfg(not(feature = "icicle"))]
mod ghidra;

//#[cfg(feature = "icicle")]
//pub use icicle::*;

//#[cfg(not(feature = "icicle"))]
pub use ghidra::*;

pub(crate) mod cache;

use crate::database::{Database, DisasmIndex, InstructionIndex, OpListIndex};
use crate::operation::Operation;

pub trait Lift {
    fn lift_instruction(
        &mut self,
        pc: u64,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
    ) -> Result<i32, LiftError>;

    fn lift_instruction_with_cache(
        &mut self,
        pc: u64,
        insbytes: &[u8],
        assembly: &mut String,
        operations: &mut Vec<Operation>,
        db: &mut Database,
    ) -> Result<(InstructionIndex, DisasmIndex, OpListIndex), LiftError> {
        if let Some(&ins_idx) = db.cache_lookup((pc, insbytes)) {
            let &(_, _, disasm_idx, oplist_idx) = db.cache_lookup(ins_idx).unwrap();
            assembly.push_str(db.cache_lookup(disasm_idx).unwrap());
            operations.extend_from_slice(db.cache_lookup(oplist_idx).unwrap());
            return Ok((ins_idx, disasm_idx, oplist_idx));
        }

        // WARNING: We do NOT use the returned instruction length in the key for the cache entry.
        // If the caller does NOT know the length of the instruction, they should use alternative
        // APIs to get that information before inserting into the cache.

        let _inslength = self.lift_instruction(pc, insbytes, assembly, operations)? as usize;
        let ins = (pc, insbytes, assembly.as_str(), operations.as_slice());
        let (ins_idx, disasm_idx, oplist_idx) = db.cache_insert(&ins);
        Ok((ins_idx, disasm_idx, oplist_idx))
    }
}

type SourceError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(thiserror::Error, Debug)]
pub enum LiftError {
    #[error("failed to build the requested lifter")]
    FailedToBuild(#[source] SourceError),

    #[error("failed to decode instruction at {pc:#x?}: {bytes:x?}")]
    FailedToDecode {
        pc: u64,
        bytes: Vec<u8>,
        #[source]
        source: Option<SourceError>,
    },

    #[error("failed to disassemble instruction at {pc:#x?}: {bytes:x?}")]
    FailedToDisassemble {
        pc: u64,
        bytes: Vec<u8>,
        #[source]
        source: Option<SourceError>,
    },

    #[error("failed to lift instruction at {pc:#x?}: {asm:} ({bytes:x?})")]
    FailedToLift {
        pc: u64,
        bytes: Vec<u8>,
        asm: String,
        #[source]
        source: Option<SourceError>,
    },

    #[error("invalid register name: {name:?}")]
    InvalidRegisterName {
        name: String,
        #[source]
        source: Option<SourceError>,
    },
}

impl LiftError {
    pub fn failed_to_decode(pc: u64, bytes: &[u8], source: Option<SourceError>) -> Self {
        Self::FailedToDecode {
            pc,
            bytes: Vec::from(bytes),
            source,
        }
    }

    pub fn failed_to_lift(pc: u64, bytes: &[u8], asm: &str, source: Option<SourceError>) -> Self {
        Self::FailedToLift {
            pc,
            bytes: Vec::from(bytes),
            asm: String::from(asm),
            source,
        }
    }
}
