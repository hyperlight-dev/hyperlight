// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

pub(crate) mod arch;
mod event_loop;
mod x86_64_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use event_loop::event_loop_thread;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::GdbStub;
use gdbstub::target::TargetError;
use thiserror::Error;
use x86_64_target::HyperlightSandboxTarget;

use super::InterruptHandle;
use super::regs::CommonRegisters;
use crate::HyperlightError;
use crate::hypervisor::regs::CommonFpu;
use crate::hypervisor::virtual_machine::{HypervisorError, RegisterError, VirtualMachine};
use crate::mem::layout::BaseGpaRegion;
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::HostSharedMemory;

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

/// A borrowed view of the sandbox memory visible to GDB.
pub(crate) struct DebugMemoryView<'a> {
    mem_mgr: &'a SandboxMemoryManager<HostSharedMemory>,
    guest_mmap_regions: Vec<MemoryRegion>,
}

/// Errors that can occur during debug memory access operations
#[derive(Debug, thiserror::Error)]
pub enum DebugMemoryAccessError {
    #[error("Failed to copy memory: {0}")]
    CopyFailed(Box<HyperlightError>),
    #[error("Failed to translate guest address {0:#x}")]
    TranslateGuestAddress(u64),
    #[error("Failed to write to read-only region")]
    WriteToReadOnly,
}

impl<'a> DebugMemoryView<'a> {
    pub(crate) fn new(
        mem_mgr: &'a SandboxMemoryManager<HostSharedMemory>,
        guest_mmap_regions: Vec<MemoryRegion>,
    ) -> Self {
        Self {
            mem_mgr,
            guest_mmap_regions,
        }
    }

    pub(crate) fn code_section_offset(&self) -> u64 {
        self.mem_mgr.layout.get_guest_code_address() as u64
    }

    /// Reads memory from the guest's address space with a maximum length of a PAGE_SIZE
    ///
    /// # Arguments
    /// * `data` - Buffer to store the read data
    /// * `gpa` - Guest physical address to read from.
    ///   This address is shall be translated before calling this function
    /// # Returns
    /// * `Result<(), DebugMemoryAccessError>` - Ok if successful, Err otherwise
    pub(crate) fn read(
        &self,
        data: &mut [u8],
        gpa: u64,
    ) -> std::result::Result<(), DebugMemoryAccessError> {
        self.mem_mgr
            .layout
            .resolve_gpa(gpa, &self.guest_mmap_regions)
            .ok_or(DebugMemoryAccessError::TranslateGuestAddress(gpa))?
            .with_memories(&self.mem_mgr.shared_mem, &self.mem_mgr.scratch_mem)
            .copy_to_slice(data)
            .map_err(|e| DebugMemoryAccessError::CopyFailed(Box::new(e)))
    }

    /// Writes memory from the guest's address space with a maximum length of a PAGE_SIZE
    ///
    /// # Arguments
    /// * `data` - Buffer containing the data to write
    /// * `gpa` - Guest physical address to write to.
    ///   This address is shall be translated before calling this function
    /// # Returns
    /// * `Result<(), DebugMemoryAccessError>` - Ok if successful, Err otherwise
    pub(crate) fn write(
        &self,
        data: &[u8],
        gpa: u64,
    ) -> std::result::Result<(), DebugMemoryAccessError> {
        let resolved = self
            .mem_mgr
            .layout
            .resolve_gpa(gpa, &self.guest_mmap_regions)
            .ok_or(DebugMemoryAccessError::TranslateGuestAddress(gpa))?;

        // We can only safely write (without causing UB in the host
        // process) if the address is in the scratch region
        match resolved.base {
            #[cfg(unshared_snapshot_mem)]
            BaseGpaRegion::Snapshot(()) => self
                .mem_mgr
                .shared_mem
                .copy_from_slice(data, resolved.offset)
                .map_err(|e| DebugMemoryAccessError::CopyFailed(Box::new(e.into()))),
            BaseGpaRegion::Scratch(()) => self
                .mem_mgr
                .scratch_mem
                .copy_from_slice(data, resolved.offset)
                .map_err(|e| DebugMemoryAccessError::CopyFailed(Box::new(e.into()))),
            _ => Err(DebugMemoryAccessError::WriteToReadOnly),
        }
    }
}

/// Defines the possible reasons for which a vCPU can be stopped when debugging
#[derive(Debug)]
pub enum VcpuStopReason {
    Crash,
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
    WriteRegisters(Box<(CommonRegisters, CommonFpu)>),
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
    NotAllowed,
    InterruptHandle(Arc<dyn InterruptHandle>),
    ReadAddr(Vec<u8>),
    ReadRegisters(Box<(CommonRegisters, CommonFpu)>),
    RemoveHwBreakpoint(bool),
    RemoveSwBreakpoint(bool),
    Step,
    VcpuStopped(VcpuStopReason),
    WriteAddr,
    WriteRegisters,
}

/// Errors that can occur during debug operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum DebugError {
    #[error("Hardware breakpoint not found at address {0:#x}")]
    HwBreakpointNotFound(u64),
    #[error("Failed to enable/disable intercept: {enable}, {inner}")]
    Intercept {
        enable: bool,
        inner: HypervisorError,
    },
    #[error("Register operation failed: {0}")]
    Register(#[from] RegisterError),
    #[error("Maximum hardware breakpoints ({0}) exceeded")]
    TooManyHwBreakpoints(usize),
    #[error("Translation of guest virtual address failed: {0}")]
    TranslateGva(u64),
}

/// Trait for VMs that support debugging capabilities.
/// This extends the base VirtualMachine trait with GDB-specific functionality.
pub(crate) trait DebuggableVm: VirtualMachine {
    /// Translates a guest virtual address to a guest physical address
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError>;

    /// Enable/disable debugging
    fn set_debug(&mut self, enable: bool) -> std::result::Result<(), DebugError>;

    /// Enable/disable single stepping
    fn set_single_step(&mut self, enable: bool) -> std::result::Result<(), DebugError>;

    /// Add a hardware breakpoint at the given address.
    /// Must be idempotent.
    fn add_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError>;

    /// Remove a hardware breakpoint at the given address
    fn remove_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError>;
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
) -> Result<DebugCommChannel<DebugResponse, DebugMsg>, GdbTargetError> {
    let (gdb_conn, hyp_conn) = DebugCommChannel::unbounded();
    let socket = format!("localhost:{}", port);

    tracing::info!("Listening on {:?}", socket);
    let listener = TcpListener::bind(socket)?;

    tracing::info!("Starting GDB thread");
    let _handle = thread::Builder::new()
        .name("GDB handler".to_string())
        .spawn(move || -> Result<(), GdbTargetError> {
            tracing::info!("Waiting for GDB connection ... ");
            let (conn, _) = listener.accept()?;

            let conn: Box<dyn ConnectionExt<Error = io::Error>> = Box::new(conn);
            let debugger = GdbStub::new(conn);

            let mut target = HyperlightSandboxTarget::new(hyp_conn);

            // Waits for vCPU to stop at entrypoint breakpoint
            let msg = target.recv()?;
            if let DebugResponse::InterruptHandle(handle) = msg {
                tracing::info!("Received interrupt handle: {:?}", handle);
                target.set_interrupt_handle(handle);
            } else {
                return Err(GdbTargetError::UnexpectedMessage);
            }

            // Waits for vCPU to stop at entrypoint breakpoint
            let msg = target.recv()?;
            if let DebugResponse::VcpuStopped(_) = msg {
                event_loop_thread(debugger, &mut target);
            } else {
                return Err(GdbTargetError::UnexpectedMessage);
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

        let res = hyp_conn.send(DebugResponse::ReadRegisters(Box::new((
            Default::default(),
            Default::default(),
        ))));
        assert!(res.is_ok());

        let res = gdb_conn.recv();
        assert!(res.is_ok());
    }

    #[cfg(target_os = "linux")]
    mod mem_access_tests {
        use std::os::fd::AsRawFd;
        use std::os::linux::fs::MetadataExt;

        use hyperlight_testing::dummy_guest_as_pathbuf;

        use super::*;
        use crate::log_then_return;
        use crate::mem::layout::SandboxMemoryLayout;
        use crate::mem::memory_region::{MemoryRegionFlags, MemoryRegionType};
        use crate::sandbox::UninitializedSandbox;
        use crate::sandbox::uninitialized::GuestBinary;

        #[cfg(target_os = "linux")]
        const BASE_VIRT: usize = 0x10000000 + SandboxMemoryLayout::BASE_ADDRESS;

        struct TestMemory {
            mem_mgr: SandboxMemoryManager<HostSharedMemory>,
            mmap_region: MemoryRegion,
        }

        impl TestMemory {
            fn new() -> crate::Result<Self> {
                let filename = dummy_guest_as_pathbuf();
                let file = std::fs::File::options()
                    .read(true)
                    .write(true)
                    .open(&filename)?;
                let file_size = file.metadata()?.st_size();
                let page_size = page_size::get();
                let size = (file_size as usize).div_ceil(page_size) * page_size;

                let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(filename), None)?;
                let (mem_mgr, _) = sandbox.mgr.build()?;

                // SAFETY: `file` is open for this call, and `size` is the page-aligned
                // file size. `MAP_FAILED` is checked below.
                let mapped_mem = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                        libc::MAP_PRIVATE,
                        file.as_raw_fd(),
                        0,
                    )
                };
                if mapped_mem == libc::MAP_FAILED {
                    log_then_return!("mmap error: {:?}", std::io::Error::last_os_error());
                }

                Ok(Self {
                    mem_mgr,
                    mmap_region: MemoryRegion {
                        host_region: mapped_mem as usize..mapped_mem.wrapping_add(size) as usize,
                        guest_region: BASE_VIRT..BASE_VIRT + size,
                        flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                        region_type: MemoryRegionType::Heap,
                    },
                })
            }

            fn access(&self) -> DebugMemoryView<'_> {
                DebugMemoryView::new(&self.mem_mgr, vec![self.mmap_region.clone()])
            }

            fn mmap_slice(&mut self) -> &mut [u8] {
                // SAFETY: `mmap_region` describes the live mapping owned by `self`.
                // The mutable borrow prevents overlapping slices from this method.
                unsafe {
                    std::slice::from_raw_parts_mut(
                        self.mmap_region.host_region.start as *mut u8,
                        self.mmap_region.host_region.len(),
                    )
                }
            }
        }

        impl Drop for TestMemory {
            fn drop(&mut self) {
                // SAFETY: this is the mapping returned by `mmap` in `new`, with
                // the same base and length, and `Drop` unmaps it exactly once.
                unsafe {
                    libc::munmap(
                        self.mmap_region.host_region.start as *mut libc::c_void,
                        self.mmap_region.host_region.len(),
                    );
                }
            }
        }

        #[test]
        fn test_mem_access_read_single_byte() -> crate::Result<()> {
            let mut memory = TestMemory::new()?;
            let offset = 2000;

            // Modify the memory directly to have a known value to read
            {
                let slice = memory.mmap_slice();
                slice[offset] = 0xAA;
            }

            let mut read_data = [0u8; 1];
            memory
                .access()
                .read(&mut read_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            assert_eq!(read_data[0], 0xAA);

            Ok(())
        }

        #[test]
        fn test_mem_access_read_multiple_bytes() -> crate::Result<()> {
            let mut memory = TestMemory::new()?;
            let offset = 20;

            // Modify the memory directly to have a known value to read
            {
                let slice = memory.mmap_slice();
                for i in 0..16 {
                    slice[offset + i] = i as u8;
                }
            }

            let mut read_data = [0u8; 16];
            memory
                .access()
                .read(&mut read_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            assert_eq!(
                read_data,
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            );
            Ok(())
        }

        #[test]
        fn test_mem_access_write_single_byte() -> crate::Result<()> {
            let memory = TestMemory::new()?;
            let scratch_gpa = memory.mem_mgr.layout.get_first_free_scratch_gpa();

            let write_data = [0xCCu8; 1];
            memory.access().write(&write_data, scratch_gpa).unwrap();

            let mut actual = [0u8; 1];
            memory.access().read(&mut actual, scratch_gpa).unwrap();
            assert_eq!(actual, write_data);

            Ok(())
        }

        #[test]
        fn test_mem_access_write_multiple_bytes() -> crate::Result<()> {
            let memory = TestMemory::new()?;
            let scratch_gpa = memory.mem_mgr.layout.get_first_free_scratch_gpa();

            let write_data = [0xAAu8; 16];
            memory.access().write(&write_data, scratch_gpa).unwrap();

            let mut actual = [0u8; 16];
            memory.access().read(&mut actual, scratch_gpa).unwrap();
            assert_eq!(actual, write_data);

            Ok(())
        }

        #[test]
        fn test_mem_access_write_rejects_mmap_region() -> crate::Result<()> {
            let memory = TestMemory::new()?;

            let error = memory
                .access()
                .write(&[0xAA], BASE_VIRT as u64)
                .unwrap_err();

            assert!(matches!(error, DebugMemoryAccessError::WriteToReadOnly));
            Ok(())
        }
    }
}
