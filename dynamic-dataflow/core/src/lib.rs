//! Crate for implementing core dataflow tracking components
//!
//! This crate is broken up into three modules for functional components and a
//! fourth module for common types. The `analysis` modules is the primary
//! interface to this crate. Through the `Analysis` type an API is exposed that
//! allows the user to input recorded events from a trace or other source and
//! perform dataflow tracking on these events.
//!
//! To perform this tracking, `Analysis` relies on two other components that
//! are exposed as modules: `datastore` and `lifter`. The `lifter` module
//! provides an API for lifting machine code instructions to an IR used for
//! semantic understanding. Right now this is strongly tied to Ghidra's p-code
//! and uses the SLEIGH decompiler library to do the heavy lifting; however,
//! there is nothing that requires this to continue to be the case in the
//! future. The `datastore` component provides an in-memory, graph-like
//! structure for storing relationships and tracking abstract memory state.
//!
//! The `types` module exports all of the common types used between the
//! modules and provides function behavior on those types.

pub mod address;
pub mod analysis;
pub mod architecture;
pub mod database;
pub mod datastore;
pub mod delta;
pub mod error;
pub mod export;
pub mod lifter;
pub mod operation;
pub mod oplog;
#[cfg(feature = "plugins")]
pub mod plugins;
pub mod slot;
pub mod space;
pub mod value;

pub type Tick = u64;
pub type Index = usize;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Access(pub Tick, pub u8);

impl Access {
    pub fn tick(&self) -> Tick {
        self.0
    }

    pub fn value(&self) -> u8 {
        self.1
    }
}

pub(crate) mod seqcache;

pub mod prelude {
    pub use super::address::{Address, AddressRange};

    pub use super::analysis::Analysis;

    pub use super::architecture::{
        Architecture, X86_64Compat32, AARCH64, ARM32, PPCBE32, X86, X86_64,
    };

    pub use super::lifter::{GhidraLifter, Lift, LiftError};

    pub use super::operation::{Operation, OperationKind};

    pub use super::space::{Space, SpaceAttributes, SpaceIndex, SpaceKind, SpaceManager};
}

#[derive(Copy, Clone)]
pub(crate) struct Hex<T>(pub(crate) T);

impl std::fmt::Display for Hex<Option<u64>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(v) => write!(f, "Some({})", Hex(v)),
            None => write!(f, "None"),
        }
    }
}

impl std::fmt::Display for Hex<u64> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

impl std::fmt::Display for Hex<u8> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl std::fmt::Debug for Hex<u8> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl std::fmt::Display for Hex<&[u8]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().copied().map(Hex))
            .finish()
    }
}
