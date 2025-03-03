/*
Copyright 2024 The Hyperlight Authors.

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

mod event_loop;
#[cfg(kvm)]
mod kvm_debug;
mod x86_64_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::GdbStub;
use gdbstub::target::TargetError;
#[cfg(kvm)]
pub(crate) use kvm_debug::KvmDebug;
use thiserror::Error;
use x86_64_target::HyperlightSandboxTarget;

use crate::new_error;

/// Software Breakpoint size in memory
pub(crate) const SW_BP_SIZE: usize = 1;
/// Software Breakpoint opcode - INT3
/// Check page 7-28 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual
const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];
/// Maximum number of supported hardware breakpoints
pub(crate) const MAX_NO_OF_HW_BP: usize = 4;

#[derive(Debug, Error)]
pub(crate) enum GdbTargetError {
    #[error("Error encountered while binding to address and port")]
    CannotBind,
    #[error("Error encountered while listening for connections")]
    ListenerError,
    #[error("Error encountered when waiting to receive message")]
    CannotReceiveMsg,
    #[error("Error encountered when sending message")]
    CannotSendMsg,
    #[error("Error encountered when sending a signal to the hypervisor thread")]
    SendSignalError,
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

/// Struct that contains the x86_64 core registers
#[derive(Debug, Default)]
pub(crate) struct X86_64Regs {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
}

/// Defines the possible reasons for which a vCPU can be stopped when debugging
#[derive(Debug)]
pub enum VcpuStopReason {
    DoneStep,
    HwBp,
    SwBp,
    Interrupt,
    Unknown,
}

/// Enumerates the possible actions that a debugger can ask from a Hypervisor
#[derive(Debug)]
pub(crate) enum DebugMsg {
    AddHwBreakpoint(u64),
    AddSwBreakpoint(u64),
    Continue,
    DisableDebug,
    GetCodeSectionOffset,
    ReadAddr(u64, usize),
    ReadRegisters,
    RemoveHwBreakpoint(u64),
    RemoveSwBreakpoint(u64),
    Step,
    WriteAddr(u64, Vec<u8>),
    WriteRegisters(X86_64Regs),
}

/// Enumerates the possible responses that a hypervisor can provide to a debugger
#[derive(Debug)]
pub(crate) enum DebugResponse {
    AddHwBreakpoint(bool),
    AddSwBreakpoint(bool),
    Continue,
    DisableDebug,
    ErrorOccurred,
    GetCodeSectionOffset(u64),
    ReadAddr(Vec<u8>),
    ReadRegisters(X86_64Regs),
    RemoveHwBreakpoint(bool),
    RemoveSwBreakpoint(bool),
    Step,
    VcpuStopped(VcpuStopReason),
    WriteAddr,
    WriteRegisters,
}

/// This trait is used to define common debugging functionality for Hypervisors
pub(crate) trait GuestDebug {
    /// Type that wraps the vCPU functionality
    type Vcpu;

    /// Returns true whether the provided address is a hardware breakpoint
    fn is_hw_breakpoint(&self, addr: &u64) -> bool;
    /// Stores the address of the hw breakpoint
    fn save_hw_breakpoint(&mut self, addr: &u64) -> bool;
    /// Deletes the address of the hw breakpoint from storage
    fn delete_hw_breakpoint(&mut self, addr: &u64);

    /// Read registers
    fn read_regs(&self, vcpu_fd: &Self::Vcpu, regs: &mut X86_64Regs) -> crate::Result<()>;
    /// Enables or disables stepping and sets the vCPU debug configuration
    fn set_single_step(&mut self, vcpu_fd: &Self::Vcpu, enable: bool) -> crate::Result<()>;
    /// Translates the guest address to physical address
    fn translate_gva(&self, vcpu_fd: &Self::Vcpu, gva: u64) -> crate::Result<u64>;
    /// Write registers
    fn write_regs(&self, vcpu_fd: &Self::Vcpu, regs: &X86_64Regs) -> crate::Result<()>;

    /// Adds hardware breakpoint
    fn add_hw_breakpoint(&mut self, vcpu_fd: &Self::Vcpu, addr: u64) -> crate::Result<()> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        if self.is_hw_breakpoint(&addr) {
            return Ok(());
        }

        self.save_hw_breakpoint(&addr)
            .then(|| self.set_single_step(vcpu_fd, false))
            .ok_or_else(|| new_error!("Failed to save hw breakpoint"))?
    }
    /// Removes hardware breakpoint
    fn remove_hw_breakpoint(&mut self, vcpu_fd: &Self::Vcpu, addr: u64) -> crate::Result<()> {
        let addr = self.translate_gva(vcpu_fd, addr)?;

        self.is_hw_breakpoint(&addr)
            .then(|| {
                self.delete_hw_breakpoint(&addr);
                self.set_single_step(vcpu_fd, false)
            })
            .ok_or_else(|| new_error!("The address: {:?} is not a hw breakpoint", addr))?
    }
}

/// Debug communication channel that is used for sending a request type and
/// receive a different response type
pub(crate) struct DebugCommChannel<T, U> {
    /// Transmit channel
    tx: Sender<T>,
    /// Receive channel
    rx: Receiver<U>,
}

impl<T, U> DebugCommChannel<T, U> {
    pub(crate) fn unbounded() -> (DebugCommChannel<T, U>, DebugCommChannel<U, T>) {
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
    pub(crate) fn send(&self, msg: T) -> Result<(), GdbTargetError> {
        self.tx.send(msg).map_err(|_| GdbTargetError::CannotSendMsg)
    }

    /// Waits for a message over the receive channel
    pub(crate) fn recv(&self) -> Result<U, GdbTargetError> {
        self.rx.recv().map_err(|_| GdbTargetError::CannotReceiveMsg)
    }

    /// Checks whether there's a message waiting on the receive channel
    pub(crate) fn try_recv(&self) -> Result<U, TryRecvError> {
        self.rx.try_recv()
    }
}

/// Creates a thread that handles gdb protocol
pub(crate) fn create_gdb_thread(
    port: u16,
    thread_id: u64,
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

            let mut target = HyperlightSandboxTarget::new(hyp_conn, thread_id);

            // Waits for vCPU to stop at entrypoint breakpoint
            let res = target.recv()?;
            if let DebugResponse::VcpuStopped(_) = res {
                event_loop_thread(debugger, &mut target);
            }

            Ok(())
        });

    Ok(gdb_conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdb_debug_comm_channel() {
        let (gdb_conn, hyp_conn) = DebugCommChannel::<DebugMsg, DebugResponse>::unbounded();

        let msg = DebugMsg::ReadRegisters;
        let res = gdb_conn.send(msg);
        assert!(res.is_ok());

        let res = hyp_conn.recv();
        assert!(res.is_ok());

        let res = gdb_conn.try_recv();
        assert!(res.is_err());

        let res = hyp_conn.send(DebugResponse::ReadRegisters(X86_64Regs::default()));
        assert!(res.is_ok());

        let res = gdb_conn.recv();
        assert!(res.is_ok());
    }
}
