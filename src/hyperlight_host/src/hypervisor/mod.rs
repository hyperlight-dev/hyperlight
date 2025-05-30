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

use log::LevelFilter;
use tracing::{instrument, Span};

use crate::error::HyperlightError::ExecutionCanceledByHost;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::{log_then_return, new_error, HyperlightError, Result};

/// Util for handling x87 fpu state
#[cfg(any(kvm, mshv, target_os = "windows"))]
pub mod fpu;
/// Handlers for Hypervisor custom logic
pub mod handlers;
/// HyperV-on-linux functionality
#[cfg(mshv)]
pub mod hyperv_linux;
#[cfg(target_os = "windows")]
/// Hyperv-on-windows functionality
pub(crate) mod hyperv_windows;
pub(crate) mod hypervisor_handler;

/// GDB debugging support
#[cfg(gdb)]
mod gdb;

#[cfg(kvm)]
/// Functionality to manipulate KVM-based virtual machines
pub mod kvm;
#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process;
#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process_manager;
/// WindowsHypervisorPlatform utilities
#[cfg(target_os = "windows")]
pub(crate) mod windows_hypervisor_platform;
/// Safe wrappers around windows types like `PSTR`
#[cfg(target_os = "windows")]
pub(crate) mod wrappers;

#[cfg(crashdump)]
pub(crate) mod crashdump;

use std::fmt::Debug;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[cfg(gdb)]
use gdb::VcpuStopReason;

#[cfg(gdb)]
use self::handlers::{DbgMemAccessHandlerCaller, DbgMemAccessHandlerWrapper};
use self::handlers::{
    MemAccessHandlerCaller, MemAccessHandlerWrapper, OutBHandlerCaller, OutBHandlerWrapper,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::ptr::RawPtr;

pub(crate) const CR4_PAE: u64 = 1 << 5;
pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub(crate) const CR0_PE: u64 = 1;
pub(crate) const CR0_MP: u64 = 1 << 1;
pub(crate) const CR0_ET: u64 = 1 << 4;
pub(crate) const CR0_NE: u64 = 1 << 5;
pub(crate) const CR0_WP: u64 = 1 << 16;
pub(crate) const CR0_AM: u64 = 1 << 18;
pub(crate) const CR0_PG: u64 = 1 << 31;
pub(crate) const EFER_LME: u64 = 1 << 8;
pub(crate) const EFER_LMA: u64 = 1 << 10;
pub(crate) const EFER_SCE: u64 = 1;
pub(crate) const EFER_NX: u64 = 1 << 11;

/// These are the generic exit reasons that we can handle from a Hypervisor the Hypervisors run method is responsible for mapping from
/// the hypervisor specific exit reasons to these generic ones
pub enum HyperlightExit {
    #[cfg(gdb)]
    /// The vCPU has exited due to a debug event
    Debug(VcpuStopReason),
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>, u64, u64),
    /// The vCPU has attempted to read or write from an unmapped address
    Mmio(u64),
    /// The vCPU tried to access memory but was missing the required permissions
    AccessViolation(u64, MemoryRegionFlags, MemoryRegionFlags),
    /// The vCPU execution has been cancelled
    Cancelled(),
    /// The vCPU has exited for a reason that is not handled by Hyperlight
    Unknown(String),
    /// The operation should be retried, for example this can happen on Linux where a call to run the CPU can return EAGAIN
    Retry(),
}

/// A common set of hypervisor functionality
///
/// Note: a lot of these structures take in an `Option<HypervisorHandler>`.
/// This is because, if we are coming from the C API, we don't have a HypervisorHandler and have
/// to account for the fact the Hypervisor was set up beforehand.
pub(crate) trait Hypervisor: Debug + Sync + Send {
    /// Initialise the internally stored vCPU with the given PEB address and
    /// random number seed, then run it until a HLT instruction.
    #[allow(clippy::too_many_arguments)]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        outb_handle_fn: OutBHandlerWrapper,
        mem_access_fn: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        guest_max_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()>;

    /// Dispatch a call from the host to the guest using the given pointer
    /// to the dispatch function _in the guest's address space_.
    ///
    /// Do this by setting the instruction pointer to `dispatch_func_addr`
    /// and then running the execution loop until a halt instruction.
    ///
    /// Returns `Ok` if the call succeeded, and an `Err` if it failed
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        outb_handle_fn: OutBHandlerWrapper,
        mem_access_fn: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()>;

    /// Handle an IO exit from the internally stored vCPU.
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        rip: u64,
        instruction_length: u64,
        outb_handle_fn: OutBHandlerWrapper,
    ) -> Result<()>;

    /// Run the vCPU
    fn run(&mut self) -> Result<HyperlightExit>;

    /// Returns a Some(HyperlightExit::AccessViolation(..)) if the given gpa doesn't have
    /// access its corresponding region. Returns None otherwise, or if the region is not found.
    fn get_memory_access_violation(
        &self,
        gpa: usize,
        mem_regions: &[MemoryRegion],
        access_info: MemoryRegionFlags,
    ) -> Option<HyperlightExit> {
        // find the region containing the given gpa
        let region = mem_regions
            .iter()
            .find(|region| region.guest_region.contains(&gpa));

        if let Some(region) = region {
            if !region.flags.contains(access_info)
                || region.flags.contains(MemoryRegionFlags::STACK_GUARD)
            {
                return Some(HyperlightExit::AccessViolation(
                    gpa as u64,
                    access_info,
                    region.flags,
                ));
            }
        }
        None
    }

    /// Get the logging level to pass to the guest entrypoint
    fn get_max_log_level(&self) -> u32 {
        // Check to see if the RUST_LOG environment variable is set
        // and if so, parse it to get the log_level for hyperlight_guest
        // if that is not set get the log level for the hyperlight_host

        // This is done as the guest will produce logs based on the log level returned here
        // producing those logs is expensive and we don't want to do it if the host is not
        // going to process them

        let val = std::env::var("RUST_LOG").unwrap_or_default();

        let level = if val.contains("hyperlight_guest") {
            val.split(',')
                .find(|s| s.contains("hyperlight_guest"))
                .unwrap_or("")
                .split('=')
                .nth(1)
                .unwrap_or("")
        } else if val.contains("hyperlight_host") {
            val.split(',')
                .find(|s| s.contains("hyperlight_host"))
                .unwrap_or("")
                .split('=')
                .nth(1)
                .unwrap_or("")
        } else {
            // look for a value string that does not contain "="
            val.split(',').find(|s| !s.contains("=")).unwrap_or("")
        };

        log::info!("Determined guest log level: {}", level);
        // Convert the log level string to a LevelFilter
        // If no value is found, default to Error
        LevelFilter::from_str(level).unwrap_or(LevelFilter::Error) as u32
    }

    /// get a mutable trait object from self
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor;

    /// Get the partition handle for WHP
    #[cfg(target_os = "windows")]
    fn get_partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion];

    #[cfg(gdb)]
    /// handles the cases when the vCPU stops due to a Debug event
    fn handle_debug(
        &mut self,
        _dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        _stop_reason: VcpuStopReason,
    ) -> Result<()> {
        unimplemented!()
    }
}

/// A virtual CPU that can be run until an exit occurs
pub struct VirtualCPU {}

impl VirtualCPU {
    /// Run the given hypervisor until a halt instruction is reached
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn run(
        hv: &mut dyn Hypervisor,
        hv_handler: Option<HypervisorHandler>,
        outb_handle_fn: Arc<Mutex<dyn OutBHandlerCaller>>,
        mem_access_fn: Arc<Mutex<dyn MemAccessHandlerCaller>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
    ) -> Result<()> {
        loop {
            match hv.run() {
                #[cfg(gdb)]
                Ok(HyperlightExit::Debug(stop_reason)) => {
                    if let Err(e) = hv.handle_debug(dbg_mem_access_fn.clone(), stop_reason) {
                        log_then_return!(e);
                    }
                }

                Ok(HyperlightExit::Halt()) => {
                    break;
                }
                Ok(HyperlightExit::IoOut(port, data, rip, instruction_length)) => {
                    hv.handle_io(port, data, rip, instruction_length, outb_handle_fn.clone())?
                }
                Ok(HyperlightExit::Mmio(addr)) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    mem_access_fn
                        .clone()
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                        .call()?;

                    log_then_return!("MMIO access address {:#x}", addr);
                }
                Ok(HyperlightExit::AccessViolation(addr, tried, region_permission)) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    if region_permission.intersects(MemoryRegionFlags::STACK_GUARD) {
                        return Err(HyperlightError::StackOverflow());
                    }
                    log_then_return!(HyperlightError::MemoryAccessViolation(
                        addr,
                        tried,
                        region_permission
                    ));
                }
                Ok(HyperlightExit::Cancelled()) => {
                    // Shutdown is returned when the host has cancelled execution
                    // After termination, the main thread will re-initialize the VM
                    if let Some(hvh) = hv_handler {
                        // If hvh is None, then we are running from the C API, which doesn't use
                        // the HypervisorHandler
                        hvh.set_running(false);
                        #[cfg(target_os = "linux")]
                        hvh.set_run_cancelled(true);
                    }
                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    log_then_return!(ExecutionCanceledByHost());
                }
                Ok(HyperlightExit::Unknown(reason)) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    log_then_return!("Unexpected VM Exit {:?}", reason);
                }
                Ok(HyperlightExit::Retry()) => continue,
                Err(e) => {
                    #[cfg(crashdump)]
                    crashdump::crashdump_to_tempfile(hv)?;

                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, any(target_os = "windows", kvm)))]
pub(crate) mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hyperlight_testing::dummy_guest_as_string;

    #[cfg(gdb)]
    use super::handlers::DbgMemAccessHandlerWrapper;
    use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
    use crate::hypervisor::hypervisor_handler::{
        HvHandlerConfig, HypervisorHandler, HypervisorHandlerAction,
    };
    use crate::mem::ptr::RawPtr;
    use crate::sandbox::uninitialized::GuestBinary;
    use crate::sandbox::{SandboxConfiguration, UninitializedSandbox};
    use crate::{new_error, Result};

    pub(crate) fn test_initialise(
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        let filename = dummy_guest_as_string().map_err(|e| new_error!("{}", e))?;
        if !Path::new(&filename).exists() {
            return Err(new_error!(
                "test_initialise: file {} does not exist",
                filename
            ));
        }

        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(filename.clone()), None)?;
        let (hshm, gshm) = sandbox.mgr.build();
        drop(hshm);

        let hv_handler_config = HvHandlerConfig {
            outb_handler: outb_hdl,
            mem_access_handler: mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_handler: dbg_mem_access_fn,
            seed: 1234567890,
            page_size: 4096,
            peb_addr: RawPtr::from(0x230000),
            dispatch_function_addr: Arc::new(Mutex::new(None)),
            max_init_time: Duration::from_millis(
                SandboxConfiguration::DEFAULT_MAX_INITIALIZATION_TIME as u64,
            ),
            max_exec_time: Duration::from_millis(
                SandboxConfiguration::DEFAULT_MAX_EXECUTION_TIME as u64,
            ),
            max_wait_for_cancellation: Duration::from_millis(
                SandboxConfiguration::DEFAULT_MAX_WAIT_FOR_CANCELLATION as u64,
            ),
            max_guest_log_level: None,
        };

        let mut hv_handler = HypervisorHandler::new(hv_handler_config);

        // call initialise on the hypervisor implementation with specific values
        // for PEB (process environment block) address, seed and page size.
        //
        // these values are not actually used, they're just checked inside
        // the dummy guest, and if they don't match these values, the dummy
        // guest issues a write to an invalid memory address, which in turn
        // fails this test.
        //
        // in this test, we're not actually testing whether a guest can issue
        // memory operations, call functions, etc... - we're just testing
        // whether we can configure the shared memory region, load a binary
        // into it, and run the CPU to completion (e.g., a HLT interrupt)

        hv_handler.start_hypervisor_handler(
            gshm,
            #[cfg(gdb)]
            None,
        )?;

        hv_handler.execute_hypervisor_handler_action(HypervisorHandlerAction::Initialise)
    }
}
