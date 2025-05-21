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

use log::LevelFilter;
use tracing::{Span, instrument};

use crate::error::HyperlightError::ExecutionCanceledByHost;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::metrics::METRIC_GUEST_CANCELLATION;
use crate::{HyperlightError, Result, log_then_return, new_error};

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

/// GDB debugging support
#[cfg(gdb)]
pub(crate) mod gdb;

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
#[cfg(any(kvm, mshv))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(any(kvm, mshv))]
use std::time::Duration;

#[cfg(gdb)]
use gdb::VcpuStopReason;

#[cfg(gdb)]
use self::handlers::{DbgMemAccessHandlerCaller, DbgMemAccessHandlerWrapper};
use self::handlers::{
    MemAccessHandlerCaller, MemAccessHandlerWrapper, OutBHandlerCaller, OutBHandlerWrapper,
};
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

    /// Get InterruptHandle to underlying VM
    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle>;

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

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>>;

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
                    crashdump::generate_crashdump(hv)?;

                    mem_access_fn
                        .clone()
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                        .call()?;

                    log_then_return!("MMIO access address {:#x}", addr);
                }
                Ok(HyperlightExit::AccessViolation(addr, tried, region_permission)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

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
                    metrics::counter!(METRIC_GUEST_CANCELLATION).increment(1);
                    log_then_return!(ExecutionCanceledByHost());
                }
                Ok(HyperlightExit::Unknown(reason)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    log_then_return!("Unexpected VM Exit {:?}", reason);
                }
                Ok(HyperlightExit::Retry()) => continue,
                Err(e) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// A trait for handling interrupts to a sandbox's vcpu
pub trait InterruptHandle: Send + Sync {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the vcpu is running, then it will interrupt the vcpu and return `true`.
    /// - If this is called while the vcpu is not running, (for example during a host call), the
    ///     vcpu will not immediately be interrupted, but will prevent the vcpu from running **the next time**
    ///     it's scheduled, and returns `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    fn kill(&self) -> bool;

    /// Returns true iff the corresponding sandbox has been dropped
    fn dropped(&self) -> bool;
}

#[cfg(any(kvm, mshv))]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandle {
    /// Invariant: vcpu is running => most significant bit (63) of `running` is set. (Neither converse nor inverse is true)
    ///
    /// Additionally, bit 0-62 tracks how many times the VCPU has been run. Incremented each time `run()` is called.
    ///
    /// This prevents an ABA problem where:
    /// 1. The VCPU is running (generation N),
    /// 2. It gets cancelled,
    /// 3. Then quickly restarted (generation N+1),
    ///     before the original thread has observed that it was cancelled.
    ///
    /// Without this generation counter, the interrupt logic might assume the VCPU is still
    /// in the *original* run (generation N), see that it's `running`, and re-send the signal.
    /// But the new VCPU run (generation N+1) would treat this as a stale signal and ignore it,
    /// potentially causing an infinite loop where no effective interrupt is delivered.
    ///
    /// Invariant: If the VCPU is running, `run_generation[bit 0-62]` matches the current run's generation.
    running: AtomicU64,
    /// Invariant: vcpu is running => `tid` is the thread on which it is running.
    /// Note: multiple vms may have the same `tid`, but at most one vm will have `running` set to true.
    tid: AtomicU64,
    /// True when an "interruptor" has requested the VM to be cancelled. Set immediately when
    /// `kill()` is called, and cleared when the vcpu is no longer running.
    /// This is used to
    /// 1. make sure stale signals do not interrupt the
    ///     the wrong vcpu (a vcpu may only be interrupted iff `cancel_requested` is true),
    /// 2. ensure that if a vm is killed while a host call is running,
    ///     the vm will not re-enter the guest after the host call returns.
    cancel_requested: AtomicBool,
    /// Whether the corresponding vm is dropped
    dropped: AtomicBool,
    /// Retry delay between signals sent to the vcpu thread
    retry_delay: Duration,
    /// The offset of the SIGRTMIN signal used to interrupt the vcpu thread
    sig_rt_min_offset: u8,
}

#[cfg(any(kvm, mshv))]
impl LinuxInterruptHandle {
    const RUNNING_BIT: u64 = 1 << 63;
    const MAX_GENERATION: u64 = Self::RUNNING_BIT - 1;

    // set running to true and increment the generation. Generation will wrap around at `MAX_GENERATION`.
    fn set_running_and_increment_generation(&self) -> std::result::Result<u64, u64> {
        self.running
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |raw| {
                let generation = raw & !Self::RUNNING_BIT;
                if generation == Self::MAX_GENERATION {
                    // restart generation from 0
                    return Some(Self::RUNNING_BIT);
                }
                Some((generation + 1) | Self::RUNNING_BIT)
            })
    }

    // clear the running bit and return the generation
    fn clear_running_bit(&self) -> u64 {
        self.running
            .fetch_and(!Self::RUNNING_BIT, Ordering::Relaxed)
    }

    fn get_running_and_generation(&self) -> (bool, u64) {
        let raw = self.running.load(Ordering::Relaxed);
        let running = raw & Self::RUNNING_BIT != 0;
        let generation = raw & !Self::RUNNING_BIT;
        (running, generation)
    }
}

#[cfg(any(kvm, mshv))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        self.cancel_requested.store(true, Ordering::Relaxed);

        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;
        let mut target_generation: Option<u64> = None;

        loop {
            let (running, generation) = self.get_running_and_generation();

            if !running {
                break;
            }

            match target_generation {
                None => target_generation = Some(generation),
                // prevent ABA problem
                Some(expected) if expected != generation => break,
                _ => {}
            }

            log::info!("Sending signal to kill vcpu thread...");
            sent_signal = true;
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Relaxed) as _, signal_number);
            }
            std::thread::sleep(self.retry_delay);
        }

        sent_signal
    }
    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(all(test, any(target_os = "windows", kvm)))]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_testing::dummy_guest_as_string;

    use super::handlers::{MemAccessHandler, OutBHandler};
    #[cfg(gdb)]
    use crate::hypervisor::DbgMemAccessHandlerCaller;
    use crate::mem::ptr::RawPtr;
    use crate::sandbox::uninitialized::GuestBinary;
    #[cfg(any(crashdump, gdb))]
    use crate::sandbox::uninitialized::SandboxRuntimeConfig;
    use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;
    use crate::sandbox::{SandboxConfiguration, UninitializedSandbox};
    use crate::{Result, is_hypervisor_present, new_error};

    #[cfg(gdb)]
    struct DbgMemAccessHandler {}

    #[cfg(gdb)]
    impl DbgMemAccessHandlerCaller for DbgMemAccessHandler {
        fn read(&mut self, _offset: usize, _data: &mut [u8]) -> Result<()> {
            Ok(())
        }

        fn write(&mut self, _offset: usize, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn get_code_offset(&mut self) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_initialise() -> Result<()> {
        if !is_hypervisor_present() {
            return Ok(());
        }

        let outb_handler: Arc<Mutex<OutBHandler>> = {
            let func: Box<dyn FnMut(u16, u32) -> Result<()> + Send> =
                Box::new(|_, _| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(OutBHandler::from(func)))
        };
        let mem_access_handler = {
            let func: Box<dyn FnMut() -> Result<()> + Send> = Box::new(|| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(MemAccessHandler::from(func)))
        };
        #[cfg(gdb)]
        let dbg_mem_access_handler = Arc::new(Mutex::new(DbgMemAccessHandler {}));

        let filename = dummy_guest_as_string().map_err(|e| new_error!("{}", e))?;

        let config: SandboxConfiguration = Default::default();
        #[cfg(any(crashdump, gdb))]
        let rt_cfg: SandboxRuntimeConfig = Default::default();
        let sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(filename.clone()), Some(config))?;
        let (_hshm, mut gshm) = sandbox.mgr.build();
        let mut vm = set_up_hypervisor_partition(
            &mut gshm,
            &config,
            #[cfg(any(crashdump, gdb))]
            &rt_cfg,
        )?;
        vm.initialise(
            RawPtr::from(0x230000),
            1234567890,
            4096,
            outb_handler,
            mem_access_handler,
            None,
            #[cfg(gdb)]
            dbg_mem_access_handler,
        )
    }
}
