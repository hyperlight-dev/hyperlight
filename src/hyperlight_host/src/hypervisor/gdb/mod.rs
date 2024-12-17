mod event_loop;
pub mod target;

use std::net::TcpListener;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::GdbStub;
use target::HyperlightKvmSandboxTarget;

#[allow(dead_code)]
#[derive(Debug)]
pub enum GdbTargetError {
    BindError,
    ListenerError,
    ReceiveMsgError,
    SendMsgError,
    SpawnThreadError,
}

#[allow(dead_code)]
/// Event sent to the VCPU execution loop
#[derive(Debug)]
pub enum DebugMessage {
    /// VCPU stopped in debug
    VcpuStoppedEv,
    /// Resume VCPU execution
    VcpuResumeEv,
    /// Response ok
    RspOk,
    /// Response error
    RspErr,
}

#[allow(dead_code)]
/// Type that takes care of communication between Hypervisor and Gdb
pub struct GdbConnection {
    /// Transmit channel
    tx: Sender<DebugMessage>,
    /// Receive channel
    rx: Receiver<DebugMessage>,
}

#[allow(dead_code)]
impl GdbConnection {
    pub fn new_pair() -> (Self, Self) {
        let (hyp_tx, gdb_rx) = crossbeam_channel::unbounded();
        let (gdb_tx, hyp_rx) = crossbeam_channel::unbounded();

        let gdb_conn = GdbConnection {
            tx: gdb_tx,
            rx: gdb_rx,
        };

        let hyp_conn = GdbConnection {
            tx: hyp_tx,
            rx: hyp_rx,
        };

        (gdb_conn, hyp_conn)
    }

    /// Sends message over the transmit channel
    pub fn send(&self, msg: DebugMessage) -> Result<(), GdbTargetError> {
        self.tx.send(msg).map_err(|_| GdbTargetError::SendMsgError)
    }

    /// Waits for a message over the receive channel
    pub fn recv(&self) -> Result<DebugMessage, GdbTargetError> {
        self.rx.recv().map_err(|_| GdbTargetError::ReceiveMsgError)
    }

    /// Checks whether there's a message waiting on the receive channel
    pub fn try_recv(&self) -> Result<DebugMessage, TryRecvError> {
        self.rx.try_recv()
    }
}

/// Creates a thread that handles gdb protocol
pub fn create_gdb_thread(
    target: HyperlightKvmSandboxTarget,
) -> Result<(), GdbTargetError> {
    // TODO: Address multiple sandboxes scenario
    let socket = format!("localhost:{}", 8081);

    log::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket).map_err(|_| GdbTargetError::BindError)?;

    log::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(move || -> Result<(), GdbTargetError> {
            log::info!("Waiting for GDB connection ... ");
            let (conn, _) = listener
                .accept()
                .map_err(|_| GdbTargetError::ListenerError)?;

            let conn: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(conn);
            let debugger = GdbStub::new(conn);


            event_loop_thread(debugger, target);

            Ok(())
        })
        .map_err(|_| GdbTargetError::SpawnThreadError)?;

    Ok(())
}
