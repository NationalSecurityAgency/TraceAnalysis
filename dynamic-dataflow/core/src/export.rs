use crate::delta::Delta;
use crate::operation::OperationKind;
use crate::value::SizedValue;
use crate::{Index, Tick};

pub trait DataflowExport {
    fn write(&mut self, msg: Message) -> Result<(), ExportError>;
    fn flush(&mut self) -> Result<(), ExportError>;
}

#[derive(Copy, Clone)]
pub enum Message<'a> {
    Tick(Tick, u64, &'a str),
    Deltas(Index, &'a [(Tick, OperationKind, Delta)]),
    AddrDeps(&'a [Edge]),
    ValueDeps(&'a [(Edge, u8)]),
    ConstAddrDeps(&'a [ConstEdge]),
    ConstValueDeps(&'a [(ConstEdge, u8)]),
    ControlflowDeps(&'a [Edge]),
}

#[derive(Copy, Clone)]
pub enum Edge {
    Certain(Index, Index),
    Maybe(Index, Index),
}

#[derive(Copy, Clone)]
pub struct ConstEdge(pub Index, pub SizedValue);

#[derive(thiserror::Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl ExportError {
    pub fn other<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Other(Box::new(err))
    }
}
