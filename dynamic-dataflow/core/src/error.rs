use crate::export::ExportError;
use crate::lifter::LiftError;

#[derive(thiserror::Error, Debug)]
pub enum DataflowError {
    #[error(transparent)]
    Lifter(#[from] LiftError),

    #[error(transparent)]
    Export(#[from] ExportError),
}
