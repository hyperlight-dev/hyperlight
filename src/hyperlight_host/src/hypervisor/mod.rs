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

use std::fmt::Debug;
use std::str::FromStr;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(kvm, mshv3))]
use std::time::Duration;

use log::LevelFilter;

/// GDB debugging support
#[cfg(gdb)]
pub(crate) mod gdb;
pub(crate) mod vm;

/// Abstracts over different hypervisor register representations
pub(crate) mod regs;

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

#[cfg(mshv3)]
pub(crate) mod hyperv_linux;
#[cfg(target_os = "windows")]
pub(crate) mod hyperv_windows;
#[cfg(kvm)]
pub(crate) mod kvm;

pub(crate) mod hyperlight_vm;

/// A trait for platform-specific interrupt handle implementation details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread (no-op on Windows)
    fn set_tid(&self);

    /// Set the running state and increment generation if needed
    /// Returns Ok(generation) on success, Err(generation) if generation wrapped
    fn set_running(&self);

    /// Clear the running state
    /// On Windows, this also clears cancel_requested and debug_interrupt
    /// On Linux, this only clears the running bit
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
    /// - Bit 63: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 62: CANCEL_BIT - set when cancellation has been requested
    /// - Bits 61-0: generation counter - tracks vcpu run iterations to prevent ABA problem
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `HyperlightVm::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `HyperlightVm::run()` call.
    running: AtomicU64,

    /// Thread ID where the vcpu is running.
    ///
    /// Note: Multiple VMs may have the same `tid` (same thread runs multiple sandboxes sequentially),
    /// but at most one VM will have RUNNING_BIT set at any given time.
    tid: AtomicU64,

    /// Debugger interrupt flag (gdb feature only).
    /// Set when `kill_from_debugger()` is called, cleared when vcpu stops running.
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Delay between retry attempts when sending signals to interrupt the vcpu.
    retry_delay: Duration,

    /// Offset from SIGRTMIN for the signal used to interrupt the vcpu thread.
    sig_rt_min_offset: u8,
}

#[cfg(any(kvm, mshv3))]
impl LinuxInterruptHandle {
    const RUNNING_BIT: u64 = 1 << 63;
    const CANCEL_BIT: u64 = 1 << 62;
    const MAX_GENERATION: u64 = (1 << 62) - 1;

    /// Sets the RUNNING_BIT and increments the generation counter.
    ///
    /// # Preserves
    /// - CANCEL_BIT: The current value of CANCEL_BIT is preserved
    ///
    /// # Invariants Maintained
    /// - Generation increments by 1 (wraps to 0 at MAX_GENERATION)
    /// - RUNNING_BIT is set
    /// - CANCEL_BIT remains unchanged
    ///
    /// # Memory Ordering
    /// Uses `Release` ordering to ensure that the `tid` store (which uses `Relaxed`)
    /// is visible to any thread that observes RUNNING_BIT=true via `Acquire` ordering.
    /// This prevents the interrupt thread from reading a stale `tid` value.
    #[expect(clippy::expect_used)]
    fn set_running_and_increment_generation(&self) -> u64 {
        self.running
            .fetch_update(Ordering::Release, Ordering::Relaxed, |raw| {
                let cancel_bit = raw & Self::CANCEL_BIT; // Preserve CANCEL_BIT
                let generation = raw & Self::MAX_GENERATION;
                let new_generation = if generation == Self::MAX_GENERATION {
                    // restart generation from 0
                    0
                } else {
                    generation + 1
                };
                // Set RUNNING_BIT, preserve CANCEL_BIT, increment generation
                Some(Self::RUNNING_BIT | cancel_bit | new_generation)
            })
            .expect("Should never fail since we always return Some")
    }

    /// Get the running and cancel bits, return the previous value.
    ///
    /// # Memory Ordering
    /// Uses `Acquire` ordering to synchronize with the `Release` in `set_running_and_increment_generation()`.
    /// This ensures that when we observe RUNNING_BIT=true, we also see the correct `tid` value.
    fn get_running_cancel_and_generation(&self) -> (bool, bool, u64) {
        let raw = self.running.load(Ordering::Acquire);
        let running = raw & Self::RUNNING_BIT != 0;
        let cancel = raw & Self::CANCEL_BIT != 0;
        let generation = raw & Self::MAX_GENERATION;
        (running, cancel, generation)
    }

    fn send_signal(&self) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        let mut sent_signal = false;
        let mut target_generation: Option<u64> = None;

        loop {
            let (running, cancel, generation) = self.get_running_cancel_and_generation();

            // Check if we should continue sending signals
            // Exit if not running OR if neither cancel nor debug_interrupt is set
            #[cfg(gdb)]
            let should_continue =
                running && (cancel || self.debug_interrupt.load(Ordering::Relaxed));
            #[cfg(not(gdb))]
            let should_continue = running && cancel;

            if !should_continue {
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
        self.set_running_and_increment_generation();
    }

    fn is_cancelled(&self) -> bool {
        // Acquire ordering to synchronize with the Release in kill()
        // This ensures we see the CANCEL_BIT set by the interrupt thread
        self.running.load(Ordering::Acquire) & Self::CANCEL_BIT != 0
    }

    fn clear_cancel(&self) {
        // Relaxed is sufficient here - we're the only thread that clears this bit
        // at the start of run(), and there's no data race on the clear operation itself
        self.running.fetch_and(!Self::CANCEL_BIT, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing RUNNING_BIT
        self.running
            .fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.debug_interrupt.load(Ordering::Relaxed)
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn set_dropped(&self) {
        self.dropped.store(true, Ordering::Relaxed);
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandle for LinuxInterruptHandle {
    fn kill(&self) -> bool {
        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.running.fetch_or(Self::CANCEL_BIT, Ordering::Release);

        // Send signals to interrupt the vcpu if it's currently running
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

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(super) struct WindowsInterruptHandle {
    /// Atomic value packing vcpu execution state.
    ///
    /// Bit layout:
    /// - Bit 1: RUNNING_BIT - set when vcpu is actively running
    /// - Bit 0: CANCEL_BIT - set when cancellation has been requested
    ///
    /// `WHvCancelRunVirtualProcessor()` will return Ok even if the vcpu is not running,
    /// which is why we need the RUNNING_BIT.
    ///
    /// CANCEL_BIT persists across vcpu exits/re-entries within a single `HyperlightVm::run()` call
    /// (e.g., during host function calls), but is cleared at the start of each new `HyperlightVm::run()` call.
    state: AtomicU64,

    // This is used to signal the GDB thread to stop the vCPU
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,
    partition_handle: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    dropped: AtomicBool,
}

#[cfg(target_os = "windows")]
impl WindowsInterruptHandle {
    const RUNNING_BIT: u64 = 1 << 1;
    const CANCEL_BIT: u64 = 1 << 0;
}

#[cfg(target_os = "windows")]
impl InterruptHandleImpl for WindowsInterruptHandle {
    fn set_tid(&self) {
        // No-op on Windows - we don't need to track thread ID
    }

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
        // Relaxed is sufficient here - we're the only thread that clears this bit
        // at the start of run(), and there's no data race on the clear operation itself
        self.state.fetch_and(!Self::CANCEL_BIT, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.state.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
        #[cfg(gdb)]
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.debug_interrupt.load(Ordering::Relaxed)
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        #[cfg(gdb)]
        self.debug_interrupt.store(false, Ordering::Relaxed);
    }

    fn set_dropped(&self) {
        self.dropped.store(true, Ordering::Relaxed);
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
        (state & Self::RUNNING_BIT != 0)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        self.debug_interrupt.store(true, Ordering::Relaxed);
        // Acquire ordering to synchronize with the Release in set_running()
        let state = self.state.load(Ordering::Acquire);
        (state & Self::RUNNING_BIT != 0)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }

    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
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
