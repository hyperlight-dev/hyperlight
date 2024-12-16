use gdbstub::common::Signal;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking;
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};

use super::target::HyperlightKvmSandboxTarget;

pub struct GdbBlockingEventLoop;

impl run_blocking::BlockingEventLoop for GdbBlockingEventLoop {
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u64>;
    type Target = HyperlightKvmSandboxTarget;

    fn wait_for_stop_reason(
        _target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as gdbstub::target::Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        loop {
            // Event from vcpu should be expected here

            if conn.peek().map(|b| b.is_some()).unwrap_or(false) {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;

                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(
        _target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as gdbstub::target::Target>::Error> {
        Ok(Some(SingleThreadStopReason::SignalWithThread {
            tid: (),
            signal: Signal::SIGINT,
        }))
    }
}

pub fn event_loop_thread(
    debugger: GdbStub<HyperlightKvmSandboxTarget, Box<dyn ConnectionExt<Error = std::io::Error>>>,
    mut target: HyperlightKvmSandboxTarget,
) {
    match debugger.run_blocking::<GdbBlockingEventLoop>(&mut target) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => log::info!("Gdb client disconnected"),
            DisconnectReason::TargetExited(code) => {
                log::info!("Gdb target exited with code {}", code)
            }
            DisconnectReason::TargetTerminated(sig) => {
                log::info!("Gdb target terminated with signale {}", sig)
            }
            DisconnectReason::Kill => log::info!("Gdb sent a kill command"),
        },
        Err(e) => {
            if e.is_target_error() {
                log::error!("Target encountered a fatal error: {e:?}");
            } else if e.is_connection_error() {
                log::error!("connection error: {:?}", e);
            } else {
                log::error!("gdbstub got a fatal error {:?}", e);
            }
        }
    }
}
