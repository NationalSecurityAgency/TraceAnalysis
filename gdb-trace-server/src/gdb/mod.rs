/// TODO: Documentation
pub mod server;

pub mod stub;
use stub::TraceState;
pub use stub::{DynamicTarget, MyTargetEvent};

pub mod arch;

pub type TraceX64Target = TraceState<arch::TraceRegsX64>;

mod mappings;
