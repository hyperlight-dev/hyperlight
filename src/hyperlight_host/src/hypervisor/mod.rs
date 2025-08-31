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

use crate::HyperlightError::StackOverflow;
use crate::error::HyperlightError::ExecutionCanceledByHost;
use crate::hypervisor::regs::{
    CommonFpu, CommonRegisters, CommonSegmentRegister, CommonSpecialRegisters,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::metrics::METRIC_GUEST_CANCELLATION;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
use crate::{HyperlightError, Result, log_then_return};

/// HyperV-on-linux functionality
#[cfg(mshv)]
pub mod hyperv_linux;
#[cfg(target_os = "windows")]
/// Hyperv-on-windows functionality
pub(crate) mod hyperv_windows;

/// GDB debugging support
#[cfg(gdb)]
pub(crate) mod gdb;

/// Abstracts over different hypervisor register representations
pub(crate) mod regs;

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

use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::host_funcs::FunctionRegistry;

cfg_if::cfg_if! {
    if #[cfg(feature = "init-paging")] {
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
    }
}

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
pub(crate) trait Hypervisor: Debug + Send {
    /// Initialise the internally stored vCPU with the given PEB address and
    /// random number seed, then run it until a HLT instruction.
    #[allow(clippy::too_many_arguments)]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        guest_max_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()>;

    /// Map a region of host memory into the sandbox.
    ///
    /// Depending on the host platform, there are likely alignment
    /// requirements of at least one page for base and len.
    unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()>;

    /// Unmap a memory region from the sandbox
    unsafe fn unmap_region(&mut self, rgn: &MemoryRegion) -> Result<()>;

    /// Get the currently mapped dynamic memory regions (not including sandbox regions)
    ///
    /// Note: Box needed for trait to be object-safe :(
    fn get_mapped_regions(&self) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_>;

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
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()>;

    /// Handle an IO exit from the internally stored vCPU.
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        rip: u64,
        instruction_length: u64,
    ) -> Result<()>;

    /// Run the vCPU
    fn run(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut crate::sandbox::trace::TraceContext,
    ) -> Result<HyperlightExit>;

    /// Get InterruptHandle to underlying VM
    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle>;

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters>;
    /// Set regs
    #[allow(dead_code)]
    fn set_regs(&mut self, regs: &CommonRegisters) -> Result<()>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu>;
    /// Set fpu regs
    #[allow(dead_code)]
    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<()>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set special regs
    #[allow(dead_code)]
    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// Setup initial special registers for the hypervisor
    /// This is a default implementation that works for all hypervisors
    fn setup_initial_sregs(&mut self, _pml4_addr: u64) -> Result<()> {
        #[cfg(feature = "init-paging")]
        let sregs = CommonSpecialRegisters {
            cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
            cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
            cr3: _pml4_addr,
            efer: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
            cs: CommonSegmentRegister {
                type_: 11,
                present: 1,
                s: 1,
                l: 1,
                ..Default::default()
            },
            tr: CommonSegmentRegister {
                limit: 65535,
                type_: 11,
                present: 1,
                s: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        #[cfg(not(feature = "init-paging"))]
        let sregs = CommonSpecialRegisters {
            cs: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 1,
                ..Default::default()
            },
            ds: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 3,
                present: 1,
                s: 1,
                ..Default::default()
            },
            tr: CommonSegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        self.set_sregs(&sregs)?;
        Ok(())
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

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>>;

    #[cfg(gdb)]
    /// handles the cases when the vCPU stops due to a Debug event
    fn handle_debug(
        &mut self,
        _dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        _stop_reason: VcpuStopReason,
    ) -> Result<()> {
        unimplemented!()
    }

    /// Check stack guard to see if the stack is still valid
    fn check_stack_guard(&self) -> Result<bool>;

    #[cfg(feature = "trace_guest")]
    fn handle_trace(&mut self, tc: &mut crate::sandbox::trace::TraceContext) -> Result<()>;

    /// Get a mutable reference of the trace info for the guest
    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo;
}

/// Returns a Some(HyperlightExit::AccessViolation(..)) if the given gpa doesn't have
/// access its corresponding region. Returns None otherwise, or if the region is not found.
pub(crate) fn get_memory_access_violation<'a>(
    gpa: usize,
    mut mem_regions: impl Iterator<Item = &'a MemoryRegion>,
    access_info: MemoryRegionFlags,
) -> Option<HyperlightExit> {
    // find the region containing the given gpa
    let region = mem_regions.find(|region| region.guest_region.contains(&gpa));

    if let Some(region) = region
        && (!region.flags.contains(access_info)
            || region.flags.contains(MemoryRegionFlags::STACK_GUARD))
    {
        return Some(HyperlightExit::AccessViolation(
            gpa as u64,
            access_info,
            region.flags,
        ));
    }
    None
}

/// A virtual CPU that can be run until an exit occurs
pub struct VirtualCPU {}

impl VirtualCPU {
    /// Run the given hypervisor until a halt instruction is reached
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn run(
        hv: &mut dyn Hypervisor,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Keeps the trace context and open spans
        #[cfg(feature = "trace_guest")]
        let mut tc = crate::sandbox::trace::TraceContext::new();

        loop {
            #[cfg(feature = "trace_guest")]
            let result = {
                let result = hv.run(&mut tc);
                // End current host trace by closing the current span that captures traces
                // happening when a guest exits and re-enters.
                tc.end_host_trace();

                // Handle the guest trace data if any
                if let Err(e) = hv.handle_trace(&mut tc) {
                    // If no trace data is available, we just log a message and continue
                    // Is this the right thing to do?
                    log::debug!("Error handling guest trace: {:?}", e);
                }

                result
            };
            #[cfg(not(feature = "trace_guest"))]
            let result = hv.run();

            match result {
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
                    hv.handle_io(port, data, rip, instruction_length)?
                }
                Ok(HyperlightExit::Mmio(addr)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    if !hv.check_stack_guard()? {
                        log_then_return!(StackOverflow());
                    }

                    log_then_return!("MMIO access address {:#x}", addr);
                }
                Ok(HyperlightExit::AccessViolation(addr, tried, region_permission)) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;

                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

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
                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

                    log_then_return!("Unexpected VM Exit {:?}", reason);
                }
                Ok(HyperlightExit::Retry()) => continue,
                Err(e) => {
                    #[cfg(crashdump)]
                    crashdump::generate_crashdump(hv)?;
                    // If GDB is enabled, we handle the debug memory access
                    // Disregard return value as we want to return the error
                    #[cfg(gdb)]
                    let _ = hv.handle_debug(dbg_mem_access_fn.clone(), VcpuStopReason::Crash);

                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// A trait for handling interrupts to a sandbox's vcpu
pub trait InterruptHandle: Debug + Send + Sync {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the vcpu is running, then it will interrupt the vcpu and return `true`.
    /// - If this is called while the vcpu is not running, (for example during a host call), the
    ///   vcpu will not immediately be interrupted, but will prevent the vcpu from running **the next time**
    ///   it's scheduled, and returns `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    fn kill(&self) -> bool;

    /// Used by a debugger to interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the vcpu is running, then it will interrupt the vcpu and return `true`.
    /// - If this is called while the vcpu is not running, (for example during a host call), the
    ///   vcpu will not immediately be interrupted, but will prevent the vcpu from running **the next time**
    ///   it's scheduled, and returns `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool;

    /// Returns true if the corresponding sandbox has been dropped
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
    ///    before the original thread has observed that it was cancelled.
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
    ///    the wrong vcpu (a vcpu may only be interrupted iff `cancel_requested` is true),
    /// 2. ensure that if a vm is killed while a host call is running,
    ///    the vm will not re-enter the guest after the host call returns.
    cancel_requested: AtomicBool,
    /// True when the debugger has requested the VM to be interrupted. Set immediately when
    /// `kill_from_debugger()` is called, and cleared when the vcpu is no longer running.
    /// This is used to make sure stale signals do not interrupt the the wrong vcpu
    /// (a vcpu may only be interrupted by a debugger if `debug_interrupt` is true),
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,
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

    fn send_signal(&self) -> bool {
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
}

#[cfg(any(kvm, mshv))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        self.cancel_requested.store(true, Ordering::Relaxed);

        self.send_signal()
    }
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        self.debug_interrupt.store(true, Ordering::Relaxed);
        self.send_signal()
    }
    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(all(test, any(target_os = "windows", kvm)))]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use hyperlight_testing::dummy_guest_as_string;

    use crate::sandbox::uninitialized::GuestBinary;
    #[cfg(any(crashdump, gdb))]
    use crate::sandbox::uninitialized::SandboxRuntimeConfig;
    use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;
    use crate::sandbox::{SandboxConfiguration, UninitializedSandbox};
    use crate::{Result, is_hypervisor_present, new_error};

    #[test]
    fn test_initialise() -> Result<()> {
        if !is_hypervisor_present() {
            return Ok(());
        }

        use crate::mem::ptr::RawPtr;
        use crate::sandbox::host_funcs::FunctionRegistry;

        let filename = dummy_guest_as_string().map_err(|e| new_error!("{}", e))?;

        let config: SandboxConfiguration = Default::default();
        #[cfg(any(crashdump, gdb))]
        let rt_cfg: SandboxRuntimeConfig = Default::default();
        let sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(filename.clone()), Some(config))?;
        let (mem_mgr, mut gshm) = sandbox.mgr.build();
        let mut vm = set_up_hypervisor_partition(
            &mut gshm,
            &config,
            #[cfg(any(crashdump, gdb))]
            &rt_cfg,
            sandbox.load_info,
        )?;

        // Set up required parameters for initialise
        let peb_addr = RawPtr::from(0x1000u64); // Dummy PEB address
        let seed = 12345u64; // Random seed
        let page_size = 4096u32; // Standard page size
        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));
        let guest_max_log_level = Some(log::LevelFilter::Error);

        #[cfg(gdb)]
        let dbg_mem_access_fn = Arc::new(Mutex::new(mem_mgr.clone()));

        // Test the initialise method
        vm.initialise(
            peb_addr,
            seed,
            page_size,
            mem_mgr,
            host_funcs,
            guest_max_log_level,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }
}
