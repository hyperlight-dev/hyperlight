pub mod target;

use std::net::TcpListener;
use std::thread;

#[allow(dead_code)]
#[derive(Debug)]
pub enum GdbTargetError {
    BindError,
    ListenerError,
    SpawnThreadError,
}

/// Creates a thread that handles gdb protocol
#[allow(dead_code)]
pub fn create_gdb_thread(
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
            let (_conn, _) = listener
                .accept()
                .map_err(|_| GdbTargetError::ListenerError)?;
            todo!()
        })
        .map_err(|_| GdbTargetError::SpawnThreadError)?;

    Ok(())
}
