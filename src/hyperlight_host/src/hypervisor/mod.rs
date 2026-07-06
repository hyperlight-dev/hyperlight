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
pub mod wrappers;

#[cfg(crashdump)]
pub(crate) mod crashdump;

pub(crate) mod hyperlight_vm;

use std::fmt::Debug;
#[cfg(any(kvm, mshv3))]
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(any(kvm, mshv3, hvf))]
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct InterruptHandleStateMachine(AtomicU8);
impl InterruptHandleStateMachine {
    const RUNNING_BIT: u8 = 1 << 1;
    const CANCEL_BIT: u8 = 1 << 0;
    #[cfg(gdb)]
    const DEBUG_INTERRUPT_BIT: u8 = 1 << 2;

    fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    /// Set the running state
    pub(crate) fn set_running(&self) {
        // Release ordering to ensure that the tid store (which uses Release)
        // is visible to any thread that observes running=true via Acquire ordering.
        // This prevents the interrupt thread from reading a stale tid value.
        self.0.fetch_or(Self::RUNNING_BIT, Ordering::Release);
    }

    /// Clear the running state
    pub(crate) fn clear_running(&self) {
        // Release ordering to ensure all vcpu operations are visible before clearing running
        self.0.fetch_and(!Self::RUNNING_BIT, Ordering::Release);
    }

    /// Check if cancellation was requested
    pub(crate) fn is_cancelled(&self) -> bool {
        self.get_running_cancel_debug().1
    }

    /// Set the cancellation request flag
    fn set_cancel(&self) {
        // Release ordering ensures that any writes before kill() are visible to the vcpu thread
        // when it checks is_cancelled() with Acquire ordering
        self.0.fetch_or(Self::CANCEL_BIT, Ordering::Release);
    }

    /// Clear the cancellation request flag
    fn clear_cancel(&self) {
        // Release ordering to ensure that any operations from the previous run()
        // are visible to other threads. While this is typically called by the vcpu thread
        // at the start of run(), the VM itself can move between threads across guest calls.
        self.0.fetch_and(!Self::CANCEL_BIT, Ordering::Release);
    }

    /// Check if debug interrupt was requested (always returns false when gdb feature is disabled)
    pub(crate) fn is_debug_interrupted(&self) -> bool {
        #[cfg(gdb)]
        {
            self.get_running_cancel_debug().2
        }
        #[cfg(not(gdb))]
        {
            false
        }
    }

    /// Clear the debug interrupt request flag
    #[cfg(gdb)]
    fn set_debug_interrupt(&self) {
        self.0
            .fetch_or(Self::DEBUG_INTERRUPT_BIT, Ordering::Release);
    }

    /// Clear the debug interrupt request flag
    #[cfg(gdb)]
    fn clear_debug_interrupt(&self) {
        self.0
            .fetch_and(!Self::DEBUG_INTERRUPT_BIT, Ordering::Release);
    }

    /// Get the running, cancel and debug flags atomically.
    fn get_running_cancel_debug(&self) -> (bool, bool, bool) {
        let state = self.0.load(Ordering::Acquire);
        let running = state & Self::RUNNING_BIT != 0;
        let cancel = state & Self::CANCEL_BIT != 0;
        #[cfg(gdb)]
        let debug = state & Self::DEBUG_INTERRUPT_BIT != 0;
        #[cfg(not(gdb))]
        let debug = false;
        (running, cancel, debug)
    }
}

/// A trait for platform-specific interrupt handle implementation details
pub(crate) trait InterruptHandleImpl: InterruptHandle {
    /// Set the thread ID for the vcpu thread
    #[cfg(any(kvm, mshv3))]
    fn set_tid(&self);

    /// Set the currently-executing vcpu id
    #[cfg(hvf)]
    fn set_vcpu(&self, vcpu: hv_vcpu_t);

    /// Mark the handle as dropped
    fn set_dropped(&self);
}

pub(crate) trait InterruptHandleInternal {
    /// Local access the shared state, which does not perform any
    /// operations other than updating the state machine
    fn state(&self) -> &InterruptHandleStateMachine;
    /// Trigger the actual kill-like operation without
    /// modifying the state
    fn common_kill(&self) -> bool;
}

/// A trait for handling interrupts to a sandbox's vcpu
#[allow(private_bounds)]
pub trait InterruptHandle: Send + Sync + Debug + InterruptHandleInternal {
    /// Interrupt the corresponding sandbox from running.
    ///
    /// - If this is called while the the sandbox currently executing a guest function call, it will interrupt the sandbox and return `true`.
    /// - If this is called while the sandbox is not running (for example before or after calling a guest function), it will do nothing and return `false`.
    ///
    /// # Note
    /// This function will block for the duration of the time it takes for the vcpu thread to be interrupted.
    fn kill(&self) -> bool {
        self.state().set_cancel();
        self.common_kill()
    }

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
    fn kill_from_debugger(&self) -> bool {
        self.state().set_debug_interrupt();
        self.common_kill()
    }

    /// Returns true if the corresponding sandbox has been dropped
    fn dropped(&self) -> bool;
}

#[cfg(any(kvm, mshv3, hvf))]
#[derive(Debug)]
pub(super) struct RetryingInterruptHandle<T: InterruptHandleImpl> {
    retry_delay: Duration,
    inner: T,
}

#[cfg(any(kvm, mshv3, hvf))]
impl<T: InterruptHandleImpl> InterruptHandleImpl for RetryingInterruptHandle<T> {
    #[cfg(any(kvm, mshv3))]
    fn set_tid(&self) {
        self.inner.set_tid();
    }

    #[cfg(hvf)]
    fn set_vcpu(&self, vcpu: hv_vcpu_t) {
        self.inner.set_vcpu(vcpu);
    }

    fn set_dropped(&self) {
        self.inner.set_dropped();
    }
}
#[cfg(any(kvm, mshv3, hvf))]
impl<T: InterruptHandleImpl> InterruptHandle for RetryingInterruptHandle<T> {
    fn dropped(&self) -> bool {
        self.inner.dropped()
    }
}
#[cfg(any(kvm, mshv3, hvf))]
impl<T: InterruptHandleImpl> InterruptHandleInternal for RetryingInterruptHandle<T> {
    fn state(&self) -> &InterruptHandleStateMachine {
        self.inner.state()
    }
    fn common_kill(&self) -> bool {
        let mut succeeded = false;
        loop {
            let (running, cancel, debug) = self.state().get_running_cancel_debug();
            // Check if we should continue sending signals
            // Exit if not running OR if neither cancel nor debug_interrupt is set
            let should_continue = running && (cancel || debug);
            if !should_continue {
                break;
            }
            tracing::info!("Trying to kill vcpu thread...");
            succeeded |= self.inner.common_kill();
            std::thread::sleep(self.retry_delay);
        }
        succeeded
    }
}

#[cfg(any(kvm, mshv3))]
#[derive(Debug)]
pub(super) struct LinuxInterruptHandleState {
    state: InterruptHandleStateMachine,

    /// Thread ID where the vcpu is running.
    ///
    /// Note: Multiple VMs may have the same `tid` (same thread runs multiple sandboxes sequentially),
    /// but at most one VM will have RUNNING_BIT set at any given time.
    tid: AtomicU64,

    /// Whether the corresponding VM has been dropped.
    dropped: AtomicBool,

    /// Offset from SIGRTMIN for the signal used to interrupt the vcpu thread.
    sig_rt_min_offset: u8,
}
#[cfg(any(kvm, mshv3))]
pub(super) type LinuxInterruptHandle = RetryingInterruptHandle<LinuxInterruptHandleState>;

#[cfg(any(kvm, mshv3))]
impl LinuxInterruptHandle {
    fn new(config: &crate::sandbox::SandboxConfiguration) -> Self {
        RetryingInterruptHandle {
            retry_delay: config.get_interrupt_retry_delay(),
            inner: LinuxInterruptHandleState {
                state: InterruptHandleStateMachine::new(),
                #[cfg(all(
                    target_arch = "x86_64",
                    target_vendor = "unknown",
                    target_os = "linux",
                    target_env = "musl"
                ))]
                tid: AtomicU64::new(unsafe { libc::pthread_self() as u64 }),
                #[cfg(not(all(
                    target_arch = "x86_64",
                    target_vendor = "unknown",
                    target_os = "linux",
                    target_env = "musl"
                )))]
                tid: AtomicU64::new(unsafe { libc::pthread_self() as u64 }),
                sig_rt_min_offset: config.get_interrupt_vcpu_sigrtmin_offset(),
                dropped: AtomicBool::new(false),
            },
        }
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandleImpl for LinuxInterruptHandleState {
    fn set_tid(&self) {
        // Release ordering to synchronize with the Acquire load of `running` in send_signal()
        // This ensures that when send_signal() observes RUNNING_BIT=true (via Acquire),
        // it also sees the correct tid value stored here
        self.tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Release);
    }

    fn set_dropped(&self) {
        // Release ordering to ensure all VM cleanup operations are visible
        // to any thread that checks dropped() via Acquire
        self.dropped.store(true, Ordering::Release);
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandle for LinuxInterruptHandleState {
    fn dropped(&self) -> bool {
        // Acquire ordering to synchronize with the Release in set_dropped()
        // This ensures we see all VM cleanup operations that happened before drop
        self.dropped.load(Ordering::Acquire)
    }
}

#[cfg(any(kvm, mshv3))]
impl InterruptHandleInternal for LinuxInterruptHandleState {
    fn state(&self) -> &InterruptHandleStateMachine {
        &self.state
    }
    fn common_kill(&self) -> bool {
        let signal_number = libc::SIGRTMIN() + self.sig_rt_min_offset as libc::c_int;
        unsafe {
            libc::pthread_kill(self.tid.load(Ordering::Acquire) as _, signal_number);
        }
        true
    }
}

#[cfg(any(target_os = "windows", hvf))]
#[derive(Debug)]
/// An interrupt handle that captures the pattern that requests to
/// cancel need to be mutually exclusive with partition destruction
#[allow(private_bounds)]
pub(super) struct SynchronousInterruptHandle<T: SynchronousInterruptState> {
    state: InterruptHandleStateMachine,
    /// RwLock protecting the partition handle and dropped state.
    ///
    /// Fox example, on Windows, this lock prevents a race condition
    /// between `kill()` calling `WHvCancelRunVirtualProcessor` and
    /// `WhpVm::drop()` calling `WHvDeletePartition`. These two
    /// Windows Hypervisor Platform APIs must not execute
    /// concurrently---if `WHvDeletePartition` frees the partition
    /// while `WHvCancelRunVirtualProcessor` is still accessing it,
    /// the result is a use-after-free causing STATUS_ACCESS_VIOLATION
    /// or STATUS_HEAP_CORRUPTION.
    ///
    /// The synchronization works as follows:
    /// - `kill()` takes a read lock before calling `WHvCancelRunVirtualProcessor`
    /// - `set_dropped()` takes a write lock, which blocks until all in-flight `kill()` calls complete,
    ///   then sets `dropped = true`. This is called from `HyperlightVm::drop()` before `WhpVm::drop()`
    ///   runs, ensuring no `kill()` is accessing the partition when `WHvDeletePartition` is called.
    dropped_state: std::sync::RwLock<(bool, T)>,
}
#[cfg(any(target_os = "windows", hvf))]
trait SynchronousInterruptState: Debug + Send + Sync {
    ///  The inside-the-lock part of the common part of both kill()
    ///  and kill_from_debugger()
    fn actually_cancel(&self) -> bool;

    #[cfg(hvf)]
    fn set_vcpu(&mut self, vcpu: hv_vcpu_t);
}

#[cfg(any(target_os = "windows", hvf))]
impl<T: SynchronousInterruptState> InterruptHandleImpl for SynchronousInterruptHandle<T> {
    #[cfg(hvf)]
    fn set_vcpu(&self, vcpu: hv_vcpu_t) {
        let Ok(mut guard) = self.dropped_state.write() else {
            return;
        };
        guard.1.set_vcpu(vcpu);
    }

    fn set_dropped(&self) {
        // Take write lock to:
        // 1. Wait for any in-flight kill() calls (holding read locks) to complete
        // 2. Block new kill() calls from starting while we hold the write lock
        // 3. Set dropped=true so no future kill() calls will use the handle
        // After this returns, no WHvCancelRunVirtualProcessor calls are in progress
        // or will ever be made, so WHvDeletePartition can safely be called.
        match self.dropped_state.write() {
            Ok(mut guard) => {
                guard.0 = true;
            }
            Err(e) => {
                tracing::error!("Failed to acquire partition_state write lock: {}", e);
            }
        }
    }
}

#[cfg(any(target_os = "windows", hvf))]
impl<T: SynchronousInterruptState> InterruptHandle for SynchronousInterruptHandle<T> {
    fn dropped(&self) -> bool {
        // Take read lock to check dropped state consistently
        match self.dropped_state.read() {
            Ok(guard) => guard.0,
            Err(e) => {
                tracing::error!("Failed to acquire partition_state read lock: {}", e);
                true // Assume dropped if we can't acquire lock
            }
        }
    }
}
#[cfg(any(target_os = "windows", hvf))]
impl<T: SynchronousInterruptState> InterruptHandleInternal for SynchronousInterruptHandle<T> {
    fn state(&self) -> &InterruptHandleStateMachine {
        &self.state
    }
    fn common_kill(&self) -> bool {
        if !self.state.get_running_cancel_debug().0 {
            return false;
        }

        // Take read lock to prevent race with WHvDeletePartition in set_dropped().
        // Multiple kill() calls can proceed concurrently (read locks don't block each other),
        // but set_dropped() will wait for all kill() calls to complete before proceeding.
        let guard = match self.dropped_state.read() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!("Failed to acquire partition_state read lock: {}", e);
                return false;
            }
        };

        if guard.0 {
            return false;
        }

        guard.1.actually_cancel()
    }
}

#[cfg(target_os = "windows")]
use windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;
#[cfg(target_os = "windows")]
pub(super) type WindowsInterruptHandle = SynchronousInterruptHandle<WHV_PARTITION_HANDLE>;
#[cfg(target_os = "windows")]
impl WindowsInterruptHandle {
    fn new(hdl: WHV_PARTITION_HANDLE) -> Self {
        SynchronousInterruptHandle {
            state: InterruptHandleStateMachine::new(),
            dropped_state: std::sync::RwLock::new((false, hdl)),
        }
    }
}
#[cfg(target_os = "windows")]
impl SynchronousInterruptState for WHV_PARTITION_HANDLE {
    fn actually_cancel(&self) -> bool {
        use windows::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor;
        unsafe { WHvCancelRunVirtualProcessor(*self, 0, 0).is_ok() }
    }
}

#[cfg(hvf)]
use crate::hypervisor::virtual_machine::hvf::bindings::hv_vcpu_t;
#[cfg(hvf)]
pub(super) type HvfInterruptHandle =
    RetryingInterruptHandle<SynchronousInterruptHandle<Option<hv_vcpu_t>>>;
#[cfg(hvf)]
impl SynchronousInterruptState for Option<hv_vcpu_t> {
    fn actually_cancel(&self) -> bool {
        use crate::hypervisor::virtual_machine::hvf::bindings::{HV_SUCCESS, hv_vcpus_exit};
        let Some(vcpu) = self else {
            return false;
        };
        unsafe {
            // bindgen automatically uses *mut, but actually this will
            // not be written to.
            hv_vcpus_exit(&raw const *vcpu as *mut hv_vcpu_t, 1).0.0.0 == HV_SUCCESS
        }
    }

    fn set_vcpu(&mut self, vcpu: hv_vcpu_t) {
        *self = Some(vcpu);
    }
}
#[cfg(hvf)]
impl HvfInterruptHandle {
    pub(super) fn new(retry_delay: Duration) -> Self {
        RetryingInterruptHandle {
            retry_delay,
            inner: SynchronousInterruptHandle {
                state: InterruptHandleStateMachine::new(),
                dropped_state: std::sync::RwLock::new((false, None)),
            },
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

    #[cfg_attr(feature = "hw-interrupts", ignore)]
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
        let (mut mem_mgr, gshm) = sandbox.mgr.build().unwrap();
        let exn_stack_top_gva = hyperlight_common::layout::SCRATCH_TOP_GVA as u64
            - hyperlight_common::layout::SCRATCH_TOP_EXN_STACK_OFFSET
            + 1;
        let mut vm = set_up_hypervisor_partition(
            gshm,
            &config,
            exn_stack_top_gva,
            page_size::get(),
            #[cfg(any(crashdump, gdb))]
            rt_cfg,
            sandbox.load_info,
        )?;

        // Set up required parameters for initialise
        let peb_addr = RawPtr::from(0x1000u64); // Dummy PEB address
        let seed = 12345u64; // Random seed
        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::default()));
        let guest_max_log_level = Some(tracing_core::LevelFilter::ERROR);

        #[cfg(gdb)]
        let dbg_mem_access_fn = Arc::new(Mutex::new(mem_mgr.clone()));

        // Test the initialise method
        vm.initialise(
            peb_addr,
            seed,
            &mut mem_mgr,
            &host_funcs,
            guest_max_log_level,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
        .unwrap();

        Ok(())
    }
}
