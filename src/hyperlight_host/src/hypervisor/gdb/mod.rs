use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::thread;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum GdbTargetError {
    #[error("Error encountered while binding to address and port")]
    CannotBind,
    #[error("Error encountered while listening for connections")]
    ListenerError,
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
/// Creates a thread that handles gdb protocol
pub fn create_gdb_thread(
    port: u16,
) -> Result<(), GdbTargetError> {
    let socket = format!("localhost:{}", port);

    log::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket)?;

    log::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(move || -> Result<(), GdbTargetError> {
            log::info!("Waiting for GDB connection ... ");
            let (_, _) = listener.accept()?;
            Ok(())
        });

    Ok(())
}
