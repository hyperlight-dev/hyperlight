use gdbstub::common::Signal;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking::{self, WaitForStopReasonError};
use gdbstub::stub::{BaseStopReason, DisconnectReason, GdbStub, SingleThreadStopReason};

use super::x86_64_target::HyperlightSandboxTarget;
use super::{DebugResponse, VcpuStopReason};

pub struct GdbBlockingEventLoop;

impl run_blocking::BlockingEventLoop for GdbBlockingEventLoop {
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<u64>;
    type Target = HyperlightSandboxTarget;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as gdbstub::target::Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        loop {
            match target.try_recv() {
                Ok(DebugResponse::VcpuStopped(stop_reason)) => {
                    log::debug!("VcpuStopped with reason {:?}", stop_reason);

                    // Resume execution if unknown reason for stop
                    let stop_response = match stop_reason {
                        VcpuStopReason::DoneStep => BaseStopReason::DoneStep,
                        VcpuStopReason::SwBp => BaseStopReason::SwBreak(()),
                        VcpuStopReason::HwBp => BaseStopReason::HwBreak(()),
                        VcpuStopReason::Unknown => {
                            target
                                .resume_vcpu()
                                .map_err(WaitForStopReasonError::Target)?;

                            continue;
                        }
                    };

                    return Ok(run_blocking::Event::TargetStopped(stop_response));
                }
                Ok(msg) => {
                    log::error!("Unexpected message received {:?}", msg);
                }
                Err(crossbeam_channel::TryRecvError::Empty) => (),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    return Ok(run_blocking::Event::TargetStopped(BaseStopReason::Exited(
                        0,
                    )));
                }
            }

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
    debugger: GdbStub<HyperlightSandboxTarget, Box<dyn ConnectionExt<Error = std::io::Error>>>,
    target: &mut HyperlightSandboxTarget,
) {
    match debugger.run_blocking::<GdbBlockingEventLoop>(target) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => { 
                log::info!("Gdb client disconnected");
                if let Err(e) = target.disable_debug() {
                    log::error!("Cannot disable debugging: {:?}", e);
                }
            }
            DisconnectReason::TargetExited(_) => {
                log::info!("Guest finalized execution and disconnected");
            }
            DisconnectReason::TargetTerminated(sig) => {
                log::info!("Gdb target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => log::info!("Gdb sent a kill command"),
        },
        Err(e) => {
            log::error!("fatal error encountered: {e:?}");
        }
    }
}
