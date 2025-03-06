use gdbstub::arch::Arch;
use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt}; // note the use of `ConnectionExt`
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::stub::{run_blocking, DisconnectReason, GdbStub};
use gdbstub::target::Target;
use tracing::{error, info};

use crate::gdb::{MyTargetEvent, TraceState};

use super::DynamicTarget;

pub struct GdbTraceServer<T> {
    _target: std::marker::PhantomData<T>,
}

impl<T: DynamicTarget> run_blocking::BlockingEventLoop for GdbTraceServer<T> {
    type Target = TraceState<T>;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;

    type StopReason = SingleThreadStopReason<<T::Arch as Arch>::Usize>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<SingleThreadStopReason<<T::Arch as Arch>::Usize>>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        if conn.peek().map(|b| b.is_some()).unwrap_or(true) {
            let byte = conn
                .read()
                .map_err(run_blocking::WaitForStopReasonError::Connection)?;
            return Ok(run_blocking::Event::IncomingData(byte));
        }

        let event = match target.run() {
            MyTargetEvent::StopReason(reason) => run_blocking::Event::TargetStopped(reason),
        };

        Ok(event)
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<
        Option<SingleThreadStopReason<<T::Arch as Arch>::Usize>>,
        <Self::Target as Target>::Error,
    > {
        target.interrupt();

        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

pub fn gdb_event_loop_thread<T: DynamicTarget>(
    debugger: GdbStub<TraceState<T>, Box<dyn ConnectionExt<Error = std::io::Error>>>,
    mut target: TraceState<T>,
) {
    match debugger.run_blocking::<GdbTraceServer<T>>(&mut target) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                info!("Client disconnected")
            }
            DisconnectReason::TargetExited(code) => {
                info!("Target exited with code {}", code)
            }
            DisconnectReason::TargetTerminated(sig) => {
                info!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => info!("GDB sent a kill command"),
        },
        Err(e) => {
            if e.is_target_error() {
                error!(
                    "target encountered a fatal error: {:?}",
                    e.into_target_error().unwrap()
                )
            } else if e.is_connection_error() {
                let (e, kind) = e.into_connection_error().unwrap();
                error!("connection error: {:?} - {}", kind, e,)
            } else {
                error!("gdbstub encountered a fatal error: {:?}", e)
            }
        }
    }
}
