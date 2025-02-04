mod event_loop;
pub mod x86_64_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::GdbStub;
use gdbstub::target::TargetError;
use thiserror::Error;
use x86_64_target::HyperlightSandboxTarget;

#[derive(Debug, Error)]
pub enum GdbTargetError {
    #[error("Error encountered while binding to address and port")]
    CannotBind,
    #[error("Error encountered while listening for connections")]
    ListenerError,
    #[error("Error encountered when waiting to receive message")]
    CannotReceiveMsg,
    #[error("Error encountered when sending message")]
    CannotSendMsg,
    #[error("Encountered an unexpected message over communication channel")]
    UnexpectedMessage,
    #[error("Unexpected error encountered")]
    UnexpectedError,
}

impl From<io::Error> for GdbTargetError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            ErrorKind::AddrInUse => Self::CannotBind,
            ErrorKind::AddrNotAvailable => Self::CannotBind,
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused => Self::ListenerError,
            _ => Self::UnexpectedError,
        }
    }
}

impl From<GdbTargetError> for TargetError<GdbTargetError> {
    fn from(value: GdbTargetError) -> TargetError<GdbTargetError> {
        TargetError::Io(std::io::Error::other(value))
    }
}

#[derive(Debug)]
/// Defines the possible reasons for which a vCPU ce be stopped when debugging
pub enum VcpuStopReason {
    DoneStep,
    HwBp,
    SwBp,
    Unknown,
}

#[allow(dead_code)]
#[derive(Debug)]
/// Enumerates the possible actions that a debugger can ask from a Hypervisor
pub enum DebugMsg {
    Continue,
}

#[allow(dead_code)]
#[derive(Debug)]
/// Enumerates the possible responses that a hypervisor can provide to a debugger 
pub enum DebugResponse {
    Continue,
    VcpuStopped(VcpuStopReason),
}

/// Debug communication channel that is used for sending a request type and
/// receive a different response type
pub struct DebugCommChannel<T, U> {
    /// Transmit channel
    tx: Sender<T>,
    /// Receive channel
    rx: Receiver<U>,
}

impl<T, U> DebugCommChannel<T, U> {
    pub fn unbounded() -> (DebugCommChannel<T, U>, DebugCommChannel<U, T>) {
        let (hyp_tx, gdb_rx): (Sender<U>, Receiver<U>) = crossbeam_channel::unbounded();
        let (gdb_tx, hyp_rx): (Sender<T>, Receiver<T>) = crossbeam_channel::unbounded();

        let gdb_conn = DebugCommChannel {
            tx: gdb_tx,
            rx: gdb_rx,
        };

        let hyp_conn = DebugCommChannel {
            tx: hyp_tx,
            rx: hyp_rx,
        };

        (gdb_conn, hyp_conn)
    }

    /// Sends message over the transmit channel and expects a response
    pub fn send(&self, msg: T) -> Result<(), GdbTargetError> {
        self.tx.send(msg).map_err(|_| GdbTargetError::CannotSendMsg)
    }

    /// Waits for a message over the receive channel
    pub fn recv(&self) -> Result<U, GdbTargetError> {
        self.rx.recv().map_err(|_| GdbTargetError::CannotReceiveMsg)
    }

    /// Checks whether there's a message waiting on the receive channel
    pub fn try_recv(&self) -> Result<U, TryRecvError> {
        self.rx.try_recv()
    }
}

/// Creates a thread that handles gdb protocol
pub fn create_gdb_thread(
    port: u16,
) -> Result<DebugCommChannel<DebugResponse, DebugMsg>, GdbTargetError> {
    let (gdb_conn, hyp_conn) = DebugCommChannel::unbounded();
    let socket = format!("localhost:{}", port);

    log::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket)?;

    log::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(move || -> Result<(), GdbTargetError> {
            log::info!("Waiting for GDB connection ... ");
            let (conn, _) = listener.accept()?;

            let conn: Box<dyn ConnectionExt<Error = io::Error>> = Box::new(conn);
            let debugger = GdbStub::new(conn);

            let mut target = HyperlightSandboxTarget::new(hyp_conn);

            // Waits for vCPU to stop at entrypoint breakpoint
            let res = target.recv()?;
            if let DebugResponse::VcpuStopped(_) = res {
                event_loop_thread(debugger, &mut target);
            }

            Ok(())
        });

    Ok(gdb_conn)
}
