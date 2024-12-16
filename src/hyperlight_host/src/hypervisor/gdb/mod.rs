mod event_loop;
pub mod target;

use std::net::TcpListener;
use std::thread;
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
