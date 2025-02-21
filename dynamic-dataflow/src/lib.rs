pub use dataflow_core::{analysis, architecture, database, datastore, error};

pub use dataflow_core::{Index, Tick};

pub mod lifter {
    pub use dataflow_core::lifter::*;
    pub use dataflow_core::operation::*;
}

pub mod address {
    pub use dataflow_core::address::*;
    pub use dataflow_core::space::*;
}

pub mod delta {
    pub use dataflow_core::delta::*;
    pub use dataflow_core::oplog::*;
    pub use dataflow_core::slot::*;
    pub use dataflow_core::value::*;
}

pub mod operation {
    pub use dataflow_core::operation::*;
}

pub mod prelude {
    pub use dataflow_core::prelude::*;
}

//pub mod trace {
//    pub mod util {
//        pub use dataflow_trace::{
//            kind, lenlen, record::emit_be32, record::emit_be64, record::emit_le32,
//            record::emit_le64, record::parse_be32, record::parse_be64, record::parse_le32,
//            record::parse_le64, record::parse_unknown, value, vlen,
//        };
//    }
//
//    pub use dataflow_trace::TraceBuffer;
//
//    pub mod record {
//        pub use dataflow_trace::{
//            record::FileMeta, record::Instruction, record::InstructionCount, record::Interrupt,
//            record::Map, record::MemRead, record::MemWrite, record::Meta, record::Pc,
//            record::Record, record::RecordKind, record::RegRead, record::RegWrite,
//            record::RegWriteNative, record::RegisterNameMap, record::UnknownFileMeta,
//            record::UnknownMeta, record::Unmap, Arch, RawRecord,
//        };
//    }
//
//    pub use record::{Record, RecordKind};
//
//    pub mod error {
//        pub use dataflow_trace::record::ParseError;
//    }
//}

pub mod export {
    pub use dataflow_core::export::{ConstEdge, DataflowExport, Edge, Message};

    #[cfg(feature = "exportcsv")]
    pub use dataflow_csv as csv;

    #[cfg(feature = "exportjsonl")]
    pub use dataflow_jsonl as jsonl;

    #[cfg(feature = "exportarango")]
    pub use dataflow_arango as arango;
}

#[cfg(feature = "plugins")]
pub mod plugins {
    pub use dataflow_cbranch as cbranch;
    pub use dataflow_core::plugins::DataflowPlugin;
    pub use dataflow_fntrack as fntrack;
    pub use dataflow_fpmodels as fpmodels;
    pub use dataflow_pointsto as pointsto;
    pub use dataflow_syscalls as syscalls;
}

//#[cfg(feature = "staging")]
//pub mod staging {
//    pub use dataflow_staging::*;
//}
