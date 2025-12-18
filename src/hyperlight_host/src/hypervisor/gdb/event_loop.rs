/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use gdbstub::common::Signal;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::{
    BaseStopReason, DisconnectReason, GdbStub, SingleThreadStopReason, run_blocking,
};

use super::x86_64_target::HyperlightSandboxTarget;
use super::{DebugResponse, GdbTargetError, VcpuStopReason};

// Signals are defined differently on Windows and Linux, so we use conditional compilation
#[cfg(target_os = "linux")]
mod signals {
    pub use libc::{SIGINT, SIGSEGV};
}
#[cfg(windows)]
mod signals {
    pub const SIGINT: i8 = 2;
    pub const SIGSEGV: i8 = 11;
}

struct GdbBlockingEventLoop;

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
                    tracing::debug!("VcpuStopped with reason {:?}", stop_reason);

                    // Resume execution if unknown reason for stop
                    let stop_response = match stop_reason {
                        VcpuStopReason::DoneStep => BaseStopReason::DoneStep,
                        VcpuStopReason::EntryPointBp => BaseStopReason::HwBreak(()),
                        VcpuStopReason::SwBp => BaseStopReason::SwBreak(()),
                        VcpuStopReason::HwBp => BaseStopReason::HwBreak(()),
                        // This is a consequence of the GDB client sending an interrupt signal
                        // to the target thread
                        VcpuStopReason::Interrupt => BaseStopReason::SignalWithThread {
                            tid: (),
                            signal: Signal(signals::SIGINT as u8),
                        },
                        VcpuStopReason::Crash => BaseStopReason::SignalWithThread {
                            tid: (),
                            signal: Signal(signals::SIGSEGV as u8),
                        },
                        VcpuStopReason::Unknown => {
                            tracing::warn!("Unknown stop reason received");

                            // Marking as a SwBreak so the gdb inspect where/why it stopped
                            BaseStopReason::SwBreak(())
                        }
                    };

                    return Ok(run_blocking::Event::TargetStopped(stop_response));
                }
                Ok(msg) => {
                    tracing::error!("Unexpected message received {:?}", msg);
                }
                Err(crossbeam_channel::TryRecvError::Empty) => (),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    return Ok(run_blocking::Event::TargetStopped(BaseStopReason::Exited(
                        0,
                    )));
                }
            }

            // Check if there is any data to read from the connection
            // If there is, return the data as an incoming data event
            // Otherwise, continue waiting for a stop reason from the target
            if conn.peek().map(|b| b.is_some()).unwrap_or(false) {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;

                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    /// Handle an interrupt from the GDB client.
    /// This function is called when the GDB client sends an interrupt signal.
    /// Passing `None` defers sending a stop reason to later (e.g. when the target stops).
    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as gdbstub::target::Target>::Error> {
        tracing::info!("Received interrupt from GDB client - sending signal to target thread");

        // Send a signal to the target thread to interrupt it
        let res = target.interrupt_vcpu();

        if !res {
            tracing::error!("Failed to send signal to target thread");
            return Err(GdbTargetError::SendSignalError);
        }

        Ok(None)
    }
}

pub(crate) fn event_loop_thread(
    debugger: GdbStub<HyperlightSandboxTarget, Box<dyn ConnectionExt<Error = std::io::Error>>>,
    target: &mut HyperlightSandboxTarget,
) {
    match debugger.run_blocking::<GdbBlockingEventLoop>(target) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                tracing::info!("Gdb client disconnected");
                if let Err(e) = target.disable_debug() {
                    tracing::error!("Cannot disable debugging: {:?}", e);
                }
            }
            DisconnectReason::TargetExited(_) => {
                tracing::info!("Guest finalized execution and disconnected");
            }
            DisconnectReason::TargetTerminated(sig) => {
                tracing::info!("Gdb target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => tracing::info!("Gdb sent a kill command"),
        },
        Err(e) => {
            tracing::error!("fatal error encountered: {e:?}");
        }
    }
}
