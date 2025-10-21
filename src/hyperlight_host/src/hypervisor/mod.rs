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
#[cfg(any(kvm, mshv))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(kvm, mshv))]
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

#[cfg(mshv)]
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
    #[expect(clippy::expect_used)]
    fn set_running_and_increment_generation(&self) -> u64 {
        self.running
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |raw| {
                let generation = raw & !Self::RUNNING_BIT;
                if generation == Self::MAX_GENERATION {
                    // restart generation from 0
                    return Some(Self::RUNNING_BIT);
                }
                Some((generation + 1) | Self::RUNNING_BIT)
            })
            .expect("Should never fail since we always return Some")
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
impl InterruptHandleImpl for LinuxInterruptHandle {
    fn set_tid(&self) {
        self.tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Relaxed);
    }

    fn set_running(&self) {
        self.set_running_and_increment_generation();
    }

    fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(Ordering::Relaxed)
    }

    fn clear_cancel(&self) {
        self.cancel_requested.store(false, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        self.clear_running_bit();
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

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub(super) struct WindowsInterruptHandle {
    // `WHvCancelRunVirtualProcessor()` will return Ok even if the vcpu is not running, which is the reason we need this flag.
    running: AtomicBool,
    cancel_requested: AtomicBool,
    // This is used to signal the GDB thread to stop the vCPU
    #[cfg(gdb)]
    debug_interrupt: AtomicBool,
    partition_handle: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    dropped: AtomicBool,
}

#[cfg(target_os = "windows")]
impl InterruptHandleImpl for WindowsInterruptHandle {
    fn set_tid(&self) {
        // No-op on Windows - we don't need to track thread ID
    }

    fn set_running(&self) {
        self.running.store(true, Ordering::Relaxed);
    }

    fn is_cancelled(&self) -> bool {
        self.cancel_requested.load(Ordering::Relaxed)
    }

    fn clear_cancel(&self) {
        self.cancel_requested.store(false, Ordering::Relaxed);
    }

    fn clear_running(&self) {
        // On Windows, clear running, cancel_requested, and debug_interrupt together
        self.running.store(false, Ordering::Relaxed);
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

        self.cancel_requested.store(true, Ordering::Relaxed);
        self.running.load(Ordering::Relaxed)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;

        self.debug_interrupt.store(true, Ordering::Relaxed);
        self.running.load(Ordering::Relaxed)
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
