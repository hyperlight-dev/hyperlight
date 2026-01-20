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

pub(crate) mod arch;
mod event_loop;
mod x86_64_target;

use std::io::{self, ErrorKind};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::{slice, thread};

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
use crate::mem::layout::SandboxMemoryLayout;
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

/// This abstracts the memory access functions that debugging needs from a sandbox
pub(crate) struct DebugMemoryAccess {
    /// Memory manager that provides access to the guest memory
    pub(crate) dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    /// Guest mapped memory regions
    pub(crate) guest_mmap_regions: Vec<MemoryRegion>,
}

/// Errors that can occur during debug memory access operations
#[derive(Debug, thiserror::Error)]
pub enum DebugMemoryAccessError {
    #[error("Failed to copy memory: {0}")]
    CopyFailed(Box<HyperlightError>),
    #[error("Failed to acquire lock at {0}:{1} - {2}")]
    LockFailed(&'static str, u32, String),
    #[error("Failed to translate guest address {0:#x}")]
    TranslateGuestAddress(u64),
}

impl DebugMemoryAccess {
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
        let read_len = data.len();

        let mem_offset = (gpa as usize)
            .checked_sub(SandboxMemoryLayout::BASE_ADDRESS)
            .ok_or_else(|| {
                log::warn!(
                    "gpa={:#X} causes subtract with underflow: \"gpa - BASE_ADDRESS={:#X}-{:#X}\"",
                    gpa,
                    gpa,
                    SandboxMemoryLayout::BASE_ADDRESS
                );
                DebugMemoryAccessError::TranslateGuestAddress(gpa)
            })?;

        // First check the mapped memory regions to see if the address is within any of them
        let mut region_found = false;
        for reg in self.guest_mmap_regions.iter() {
            if reg.guest_region.contains(&mem_offset) {
                log::debug!("Found mapped region containing {:X}: {:#?}", gpa, reg);

                // Region found - calculate the offset within the region
                let region_offset = mem_offset.checked_sub(reg.guest_region.start).ok_or_else(|| {
                    log::warn!(
                        "Cannot calculate offset in memory region: mem_offset={:#X}, base={:#X}",
                        mem_offset,
                        reg.guest_region.start,
                    );
                    DebugMemoryAccessError::TranslateGuestAddress(mem_offset as u64)
                })?;

                let bytes: &[u8] = unsafe {
                    slice::from_raw_parts(reg.host_region.start as *const u8, reg.host_region.len())
                };
                data[..read_len].copy_from_slice(&bytes[region_offset..region_offset + read_len]);

                region_found = true;
                break;
            }
        }

        if !region_found {
            log::debug!(
                "No mapped region found containing {:X}. Trying shared memory ...",
                gpa
            );

            self.dbg_mem_access_fn
                .try_lock()
                .map_err(|e| DebugMemoryAccessError::LockFailed(file!(), line!(), e.to_string()))?
                .get_shared_mem_mut()
                .copy_to_slice(&mut data[..read_len], mem_offset)
                .map_err(|e| DebugMemoryAccessError::CopyFailed(Box::new(e)))?;
        }

        Ok(())
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
        let write_len = data.len();

        let mem_offset = (gpa as usize)
            .checked_sub(SandboxMemoryLayout::BASE_ADDRESS)
            .ok_or_else(|| {
                log::warn!(
                    "gpa={:#X} causes subtract with underflow: \"gpa - BASE_ADDRESS={:#X}-{:#X}\"",
                    gpa,
                    gpa,
                    SandboxMemoryLayout::BASE_ADDRESS
                );
                DebugMemoryAccessError::TranslateGuestAddress(gpa)
            })?;

        // First check the mapped memory regions to see if the address is within any of them
        let mut region_found = false;
        for reg in self.guest_mmap_regions.iter() {
            if reg.guest_region.contains(&mem_offset) {
                log::debug!("Found mapped region containing {:X}: {:#?}", gpa, reg);

                // Region found - calculate the offset within the region
                let region_offset = mem_offset.checked_sub(reg.guest_region.start).ok_or_else(|| {
                    log::warn!(
                        "Cannot calculate offset in memory region: mem_offset={:#X}, base={:#X}",
                        mem_offset,
                        reg.guest_region.start,
                    );
                    DebugMemoryAccessError::TranslateGuestAddress(mem_offset as u64)
                })?;

                let bytes: &mut [u8] = unsafe {
                    slice::from_raw_parts_mut(
                        reg.host_region.start as *mut u8,
                        reg.host_region.len(),
                    )
                };
                bytes[region_offset..region_offset + write_len].copy_from_slice(&data[..write_len]);

                region_found = true;
                break;
            }
        }

        if !region_found {
            log::debug!(
                "No mapped region found containing {:X}. Trying shared memory at offset {:X} ...",
                gpa,
                mem_offset
            );

            self.dbg_mem_access_fn
                .try_lock()
                .map_err(|e| DebugMemoryAccessError::LockFailed(file!(), line!(), e.to_string()))?
                .get_shared_mem_mut()
                .copy_from_slice(&data[..write_len], mem_offset)
                .map_err(|e| DebugMemoryAccessError::CopyFailed(Box::new(e)))?;
        }

        Ok(())
    }
}

/// Defines the possible reasons for which a vCPU can be stopped when debugging
#[derive(Debug)]
pub enum VcpuStopReason {
    Crash,
    DoneStep,
    /// Hardware breakpoint inserted by the hypervisor so the guest can be stopped
    /// at the entry point. This is used to avoid the guest from executing
    /// the entry point code before the debugger is connected
    EntryPointBp,
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
            let msg = target.recv()?;
            if let DebugResponse::InterruptHandle(handle) = msg {
                log::info!("Received interrupt handle: {:?}", handle);
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
        use std::sync::{Arc, Mutex};

        use hyperlight_testing::dummy_guest_as_string;

        use super::*;
        use crate::mem::memory_region::{MemoryRegionFlags, MemoryRegionType};
        use crate::sandbox::UninitializedSandbox;
        use crate::sandbox::uninitialized::GuestBinary;
        use crate::{log_then_return, new_error};

        #[cfg(target_os = "linux")]
        const BASE_VIRT: usize = 0x10000000 + SandboxMemoryLayout::BASE_ADDRESS;

        /// Dummy memory region to test memory access
        /// This maps a file into memory and uses it as guest memory
        fn get_mem_access() -> crate::Result<DebugMemoryAccess> {
            let filename = dummy_guest_as_string().map_err(|e| new_error!("{}", e))?;

            let file = std::fs::File::options()
                .read(true)
                .write(true)
                .open(&filename)?;
            let file_size = file.metadata()?.st_size();
            let page_size = page_size::get();
            let size = (file_size as usize).div_ceil(page_size) * page_size;
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

            // Create a sandbox memory manager with the mapped memory region
            let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(filename.clone()), None)
                .inspect_err(|_| unsafe {
                    libc::munmap(mapped_mem, size);
                })?;
            let (mem_mgr, _) = sandbox.mgr.build();

            // Create the memory access struct
            let mem_access = DebugMemoryAccess {
                dbg_mem_access_fn: Arc::new(Mutex::new(mem_mgr)),
                guest_mmap_regions: vec![MemoryRegion {
                    host_region: mapped_mem as usize..mapped_mem.wrapping_add(size) as usize,
                    guest_region: BASE_VIRT..BASE_VIRT + size,
                    flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                    region_type: MemoryRegionType::Heap,
                }],
            };

            Ok(mem_access)
        }

        /// Gets a slice to the mapped memory region to be able to modify it
        ///
        /// NOTE: By returning a mutable slice from a mutable reference, we ensure
        /// that the memory is not deallocated while the slice is in use.
        unsafe fn get_mmap_slice(mem_access: &mut DebugMemoryAccess) -> &mut [u8] {
            unsafe {
                std::slice::from_raw_parts_mut(
                    mem_access.guest_mmap_regions[0].host_region.start as *mut u8,
                    mem_access.guest_mmap_regions[0].host_region.end
                        - mem_access.guest_mmap_regions[0].host_region.start,
                )
            }
        }

        /// Drops the mapped memory region
        fn drop_mem_access(mem_access: DebugMemoryAccess) {
            let mapped_mem =
                mem_access.guest_mmap_regions[0].host_region.start as *mut libc::c_void;
            let size = mem_access.guest_mmap_regions[0].host_region.end
                - mem_access.guest_mmap_regions[0].host_region.start;

            unsafe {
                libc::munmap(mapped_mem, size);
            }
        }

        #[test]
        fn test_mem_access_read_single_byte() -> crate::Result<()> {
            let mut mem_access = get_mem_access()?;
            let offset = 2000;

            // Modify the memory directly to have a known value to read
            {
                let slice = unsafe { get_mmap_slice(&mut mem_access) };
                slice[offset] = 0xAA;
            }

            let mut read_data = [0u8; 1];
            mem_access
                .read(&mut read_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            assert_eq!(read_data[0], 0xAA);

            drop_mem_access(mem_access);

            Ok(())
        }

        #[test]
        fn test_mem_access_read_multiple_bytes() -> crate::Result<()> {
            let mut mem_access = get_mem_access()?;
            let offset = 20;

            // Modify the memory directly to have a known value to read
            {
                let slice = unsafe { get_mmap_slice(&mut mem_access) };
                for i in 0..16 {
                    slice[offset + i] = i as u8;
                }
            }

            let mut read_data = [0u8; 16];
            mem_access
                .read(&mut read_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            assert_eq!(
                read_data,
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            );
            drop_mem_access(mem_access);
            Ok(())
        }

        #[test]
        fn test_mem_access_write_single_byte() -> crate::Result<()> {
            let mut mem_access = get_mem_access()?;
            let offset = 3000;
            {
                let slice = unsafe { get_mmap_slice(&mut mem_access) };
                slice[offset] = 0xBB;
            }

            let write_data = [0xCCu8; 1];
            mem_access
                .write(&write_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            let slice = unsafe { get_mmap_slice(&mut mem_access) };
            assert_eq!(slice[offset], write_data[0]);
            drop_mem_access(mem_access);

            Ok(())
        }

        #[test]
        fn test_mem_access_write_multiple_bytes() -> crate::Result<()> {
            let mut mem_access = get_mem_access()?;
            let offset = 56;
            {
                let slice = unsafe { get_mmap_slice(&mut mem_access) };
                for i in 0..16 {
                    slice[offset + i] = i as u8;
                }
            }

            let write_data = [0xAAu8; 16];
            mem_access
                .write(&write_data, (BASE_VIRT + offset) as u64)
                .unwrap();

            let slice = unsafe { get_mmap_slice(&mut mem_access) };
            assert_eq!(slice[offset..offset + 16], write_data);
            drop_mem_access(mem_access);

            Ok(())
        }
    }
}
