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

use crate::Result;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::mem::memory_region::MemoryRegion;

/// GDB debugging support
#[cfg(gdb)]
pub(crate) mod gdb;

/// Abstracts over different hypervisor register representations
pub(crate) mod regs;

pub(crate) mod virtual_machine;

#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process;
#[cfg(target_os = "windows")]
/// Hyperlight Surrogate Process
pub(crate) mod surrogate_process_manager;
/// Safe wrappers around windows types like `PSTR`
#[cfg(target_os = "windows")]
pub(crate) mod wrappers;

#[cfg(crashdump)]
pub(crate) mod crashdump;

pub(crate) mod hyperlight_vm;

use std::fmt::Debug;
use std::str::FromStr;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(any(kvm, mshv3))]
use std::time::Duration;

pub(crate) enum HyperlightExit {
    /// The vCPU has exited due to a debug event (usually breakpoint)
    #[cfg(gdb)]
    Debug { dr6: u64, exception: u32 },
    /// The vCPU has halted
    Halt(),
    /// The vCPU has issued a write to the given port with the given value
    IoOut(u16, Vec<u8>),
    /// The vCPU tried to read from the given (unmapped) addr
    MmioRead(u64),
    /// The vCPU tried to write to the given (unmapped) addr
    MmioWrite(u64),
    /// The vCPU execution has been cancelled
    Cancelled(),
    /// The vCPU has exited for a reason that is not handled by Hyperlight
    Unknown(String),
    /// The operation should be retried, for example this can happen on Linux where a call to run the CPU can return EAGAIN
    #[cfg_attr(
        target_os = "windows",
        expect(
            dead_code,
            reason = "Retry() is never constructed on Windows, but it is still matched on (which dead_code lint ignores)"
        )
    )]
    Retry(),
}

/// Trait for single-vCPU VMs. Provides a common interface for basic VM operations.
/// Abstracts over differences between KVM, MSHV and WHP implementations.
pub(crate) trait Hypervisor: Debug + Send {
    /// Map memory region into this VM
    ///
    /// # Safety
    /// The caller must ensure that the memory region is valid and points to valid memory,
    /// and lives long enough for the VM to use it.
    /// The caller must ensure that the given u32 is not already mapped, otherwise previously mapped
    /// memory regions may be overwritten.
    /// The memory region must not overlap with an existing region, and depending on platform, must be aligned to page boundaries.
    unsafe fn map_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Unmap memory region from this VM that has previously been mapped using `map_memory`.
    fn unmap_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<()>;

    /// Runs the vCPU until it exits.
    /// Note: this function should not emit any traces or spans as it is called after guest span is setup
    fn run_vcpu(&mut self) -> Result<HyperlightExit>;

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters>;
    /// Set regs
    fn set_regs(&self, regs: &CommonRegisters) -> Result<()>;
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu>;
    /// Set fpu regs
    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()>;
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters>;
    /// Set special regs
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()>;

    /// xsave
    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>>;

    /// Get partition handle
    #[cfg(target_os = "windows")]
    fn partition_handle(&self) -> windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

    /// Mark that initial memory setup is complete. After this, map_memory will fail.
    /// This is only needed on Windows where dynamic memory mapping is not yet supported.
    #[cfg(target_os = "windows")]
    fn complete_initial_memory_setup(&mut self);
}

/// Get the logging level to pass to the guest entrypoint
fn get_max_log_level() -> u32 {
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

/// A trait for platform-specific interrupt handle implementation details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread
    #[cfg(any(kvm, mshv3))]
    fn set_tid(&self);

    /// Set the running state
    fn set_running(&self);

    /// Clear the running state
    fn clear_running(&self);

    /// Mark the handle as dropped
    fn set_dropped(&self);

    /// Check if cancellation was requested
    fn is_cancelled(&self) -> bool;

    /// Clear the cancellation request flag
    fn clear_cancel(&self);

    /// Check if debug interrupt was requested (always returns false when gdb feature is disabled)
    fn is_debug_interrupted(&self) -> bool;

    // Clear the debug interrupt request flag
    #[cfg(gdb)]
    fn clear_debug_interrupt(&self);
}

/// A trait for handling interrupts to a sandbox's vcpu
pub trait InterruptHandle: Send + Sync + Debug {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the the sandbox currently executing a guest function call, it will interrupt the sandbox and return `true`.
    /// - If this is called while the sandbox is not running (for example before or after calling a guest function), it will do nothing and return `false`.
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

#[cfg(any(kvm, mshv3))]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 2: DEBUG_INTERRUPT_BIT - set when debugger interrupt is requested
    /// - Bit 1: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 0: CANCEL_BIT - set when cancellation has been requested
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `VirtualCPU::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `VirtualCPU::run()` call.
    state: AtomicU8,

    /// Thread ID where the vcpu is running.
    ///
    /// Note: Multiple VMs may have the same `tid` (same thread runs multiple sandboxes sequentially),
    /// but at most one VM will have RUNNING_BIT set at any given time.
    tid: AtomicU64,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Delay between retry attempts when sending signals to interrupt the vcpu.
    retry_delay: Duration,

    /// Offset from SIGRTMIN for the signal used to interrupt the vcpu thread.
    sig_rt_min_offset: u8,
}

#[cfg(any(kvm, mshv3))]
impl LinuxInterruptHandle {
    const RUNNING_BIT: u8 = 1 << 1;
    const CANCEL_BIT: u8 = 1 << 0;
    #[cfg(gdb)]
    const DEBUG_INTERRUPT_BIT: u8 = 1 << 2;

    /// Get the running, cancel and debug flags atomically.
    ///
    /// # Memory Ordering
    /// Uses `Acquire` ordering to synchronize with the `Release` in `set_running()` and `kill()`.
    /// This ensures that when we observe running=true, we also see the correct `tid` value.
    fn get_running_cancel_debug(&self) -> (bool, bool, bool) {
        let state = self.state.load(Ordering::Acquire);
        let running = state & Self::RUNNING_BIT != 0;
        let cancel = state & Self::CANCEL_BIT != 0;
        #[cfg(gdb)]
        let debug = state & Self::DEBUG_INTERRUPT_BIT != 0;
        #[cfg(not(gdb))]
        let debug = false;
        (running, cancel, debug)
    }

    fn send_signal(&self) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;

        loop {
            let (running, cancel, debug) = self.get_running_cancel_debug();

            // Check if we should continue sending signals
            // Exit if not running OR if neither cancel nor debug_interrupt is set
            let should_continue = running && (cancel || debug);

            if !should_continue {
                break;
            }

            log::info!("Sending signal to kill vcpu thread...");
            sent_signal = true;
            // Acquire ordering to synchronize with the Release store in set_tid()
            // This ensures we see the correct tid value for the currently running vcpu
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Acquire) as _, signal_number);
            }
            std::thread::sleep(self.retry_delay);
        }

        sent_signal
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandleImpl for LinuxInterruptHandle {
    fn set_tid(&self) {
        // Release ordering to synchronize with the Acquire load of `running` in send_signal()
        // This ensures that when send_signal() observes RUNNING_BIT=true (via Acquire),
        // it also sees the correct tid value stored here
        self.tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Release);
    }

    fn set_running(&self) {
        // Release ordering to ensure that the tid store (which uses Release)
        // is visible to any thread that observes running=true via Acquire ordering.
        // This prevents the interrupt thread from reading a stale tid value.
        self.state.fetch_or(Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the cancel flag set by the interrupt thread
        self.state.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Release ordering to ensure that any operations from the previous run()
        // are visible to other threads. While this is typically called by the vcpu thread
        // at the start of run(), the VM itself can move between threads across guest calls.
        self.state.fetch_and(!Self::CANCEL_BIT, Ordering::Release);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.state.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.state.load(Ordering::Acquire) & Self::DEBUG_INTERRUPT_BIT != 0
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        self.state
            .fetch_and(!Self::DEBUG_INTERRUPT_BIT, Ordering::Release);
    }

    fn set_dropped(&self) {
        // Release ordering to ensure all VM cleanup operations are visible
        // to any thread that checks dropped() via Acquire
        self.dropped.store(true, Ordering::Release);
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.state.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Send signals to interrupt the vcpu if it's currently running
        self.send_signal()
    }

    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        self.state
            .fetch_or(Self::DEBUG_INTERRUPT_BIT, Ordering::Release);
        self.send_signal()
    }
    fn dropped(&self) -> bool {
        // Acquire ordering to synchronize with the Release in set_dropped()
        // This ensures we see all VM cleanup operations that happened before drop
        self.dropped.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(super) struct WindowsInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 2: DEBUG_INTERRUPT_BIT - set when debugger interrupt is requested
    /// - Bit 1: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 0: CANCEL_BIT - set when cancellation has been requested
    ///
    /// `WHvCancelRunVirtualProcessor()` will return Ok even if the vcpu is not running,
    /// which is why we need the RUNNING_BIT.
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `VirtualCPU::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `VirtualCPU::run()` call.
    state: AtomicU8,

    /// RwLock protecting the partition handle and dropped state.
    ///
    /// This lock prevents a race condition between `kill()` calling `WHvCancelRunVirtualProcessor`
    /// and `WhpVm::drop()` calling `WHvDeletePartition`. These two Windows Hypervisor Platform APIs
    /// must not execute concurrently - if `WHvDeletePartition` frees the partition while
    /// `WHvCancelRunVirtualProcessor` is still accessing it, the result is a use-after-free
    /// causing STATUS_ACCESS_VIOLATION or STATUS_HEAP_CORRUPTION.
    ///
    /// The synchronization works as follows:
    /// - `kill()` takes a read lock before calling `WHvCancelRunVirtualProcessor`
    /// - `set_dropped()` takes a write lock, which blocks until all in-flight `kill()` calls complete,
    ///   then sets `dropped = true`. This is called from `HyperlightVm::drop()` before `WhpVm::drop()`
    ///   runs, ensuring no `kill()` is accessing the partition when `WHvDeletePartition` is called.
    partition_state: std::sync::RwLock<PartitionState>,
}

/// State protected by the RwLock in `WindowsInterruptHandle`.
///
/// Contains a copy of the partition handle from `WhpVm` (not an owning reference).
/// The RwLock and `dropped` flag ensure this handle is never used after `WhpVm`
/// deletes the partition.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(super) struct PartitionState {
    /// Copy of partition handle from `WhpVm`. Only valid while `dropped` is false.
    pub(super) handle: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    /// Set true before partition deletion; prevents further use of `handle`.
    pub(super) dropped: bool,
}

#[cfg(target_os = "windows")]
impl WindowsInterruptHandle {
    const RUNNING_BIT: u8 = 1 << 1;
    const CANCEL_BIT: u8 = 1 << 0;
    #[cfg(gdb)]
    const DEBUG_INTERRUPT_BIT: u8 = 1 << 2;
}

#[cfg(target_os = "windows")]
impl InterruptHandleImpl for WindowsInterruptHandle {
    fn set_running(&self) {
        // Release ordering to ensure prior memory operations are visible when another thread observes running=true
        self.state.fetch_or(Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the CANCEL_BIT set by the interrupt thread
        self.state.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Release ordering to ensure that any operations from the previous run()
        // are visible to other threads. While this is typically called by the vcpu thread
        // at the start of run(), the VM itself can move between threads across guest calls.
        self.state.fetch_and(!Self::CANCEL_BIT, Ordering::Release);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.state.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.state.load(Ordering::Acquire) & Self::DEBUG_INTERRUPT_BIT != 0
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        self.state
            .fetch_and(!Self::DEBUG_INTERRUPT_BIT, Ordering::Release);
    }

    fn set_dropped(&self) {
        // Take write lock to:
        // 1. Wait for any in-flight kill() calls (holding read locks) to complete
        // 2. Block new kill() calls from starting while we hold the write lock
        // 3. Set dropped=true so no future kill() calls will use the handle
        // After this returns, no WHvCancelRunVirtualProcessor calls are in progress
        // or will ever be made, so WHvDeletePartition can safely be called.
        match self.partition_state.write() {
            Ok(mut guard) => {
                guard.dropped = true;
            }
            Err(e) => {
                log::error!("Failed to acquire partition_state write lock: {}", e);
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl InterruptHandle for WindowsInterruptHandle {
    fn kill(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.state.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Acquire ordering to synchronize with the Release in set_running()
        // This ensures we see the running state set by the vcpu thread
        let state = self.state.load(Ordering::Acquire);
        if state & Self::RUNNING_BIT == 0 {
            return false;
        }

        // Take read lock to prevent race with WHvDeletePartition in set_dropped().
        // Multiple kill() calls can proceed concurrently (read locks don't block each other),
        // but set_dropped() will wait for all kill() calls to complete before proceeding.
        let guard = match self.partition_state.read() {
            Ok(guard) => guard,
            Err(e) => {
                log::error!("Failed to acquire partition_state read lock: {}", e);
                return false;
            }
        };

        if guard.dropped {
            return false;
        }

        unsafe { WHvCancelRunVirtualProcessor(guard.handle, 0, 0).is_ok() }
    }
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        self.state
            .fetch_or(Self::DEBUG_INTERRUPT_BIT, Ordering::Release);

        // Acquire ordering to synchronize with the Release in set_running()
        let state = self.state.load(Ordering::Acquire);
        if state & Self::RUNNING_BIT == 0 {
            return false;
        }

        // Take read lock to prevent race with WHvDeletePartition in set_dropped()
        let guard = match self.partition_state.read() {
            Ok(guard) => guard,
            Err(e) => {
                log::error!("Failed to acquire partition_state read lock: {}", e);
                return false;
            }
        };

        if guard.dropped {
            return false;
        }

        unsafe { WHvCancelRunVirtualProcessor(guard.handle, 0, 0).is_ok() }
    }

    fn dropped(&self) -> bool {
        // Take read lock to check dropped state consistently
        match self.partition_state.read() {
            Ok(guard) => guard.dropped,
            Err(e) => {
                log::error!("Failed to acquire partition_state read lock: {}", e);
                true // Assume dropped if we can't acquire lock
            }
        }
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
        let (mut mem_mgr, mut gshm) = sandbox.mgr.build();
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
            &mut mem_mgr,
            &host_funcs,
            guest_max_log_level,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }
}
