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

use std::path::Path;
use std::sync::{Arc, Mutex};

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use tracing::{Span, instrument};

use super::Callable;
use super::file_mapping::prepare_file_cow;
use super::host_funcs::FunctionRegistry;
use super::snapshot::Snapshot;
use crate::func::{ParameterTuple, SupportedReturnType};
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::{HyperlightVm, HyperlightVmError};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{HostSharedMemory, SharedMemory as _};
use crate::metrics::{
    METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE, maybe_time_and_emit_guest_call,
};
use crate::{HyperlightError, Result, log_then_return};

/// A fully initialized sandbox that can execute guest functions multiple times.
///
/// Guest functions can be called repeatedly while maintaining state between calls.
/// The sandbox supports creating snapshots and restoring to previous states.
///
/// ## Sandbox Poisoning
///
/// The sandbox becomes **poisoned** when the guest is not run to completion, leaving it in
/// an inconsistent state that could compromise memory safety, data integrity, or security.
///
/// ### When Does Poisoning Occur?
///
/// Poisoning happens when guest execution is interrupted before normal completion:
///
/// - **Guest panics or aborts** - When a guest function panics, crashes, or calls `abort()`,
///   the normal cleanup and unwinding process is interrupted
/// - **Invalid memory access** - Attempts to read/write/execute memory outside allowed regions
/// - **Stack overflow** - Guest exhausts its stack space during execution
/// - **Heap exhaustion** - Guest runs out of heap memory
/// - **Host-initiated cancellation** - Calling [`InterruptHandle::kill()`] to forcefully
///   terminate an in-progress guest function
///
/// ### Why This Is Unsafe
///
/// When guest execution doesn't complete normally, critical cleanup operations are skipped:
///
/// - **Memory leaks** - Heap allocations remain unreachable as the call stack is unwound
/// - **Corrupted allocator state** - Memory allocator metadata (free lists, heap headers)
///   left inconsistent
/// - **Locked resources** - Mutexes or other synchronization primitives remain locked
/// - **Partial state updates** - Data structures left half-modified (corrupted linked lists,
///   inconsistent hash tables, etc.)
///
/// ### Recovery
///
/// Use [`restore()`](Self::restore) with a snapshot taken before poisoning occurred.
/// This is the **only safe way** to recover - it completely replaces all memory state,
/// eliminating any inconsistencies. See [`restore()`](Self::restore) for details.
pub struct MultiUseSandbox {
    /// Whether this sandbox is poisoned
    poisoned: bool,
    pub(crate) host_funcs: Arc<Mutex<FunctionRegistry>>,
    pub(crate) mem_mgr: SandboxMemoryManager<HostSharedMemory>,
    vm: HyperlightVm,
    #[cfg(gdb)]
    dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    /// If the current state of the sandbox has been captured in a snapshot,
    /// that snapshot is stored here.
    pub(crate) snapshot: Option<Arc<Snapshot>>,
    /// Optional callback to discover page table roots from guest memory.
    /// Given (snapshot_mem, scratch_mem, cr3), returns a list of root GPAs.
    /// If not set, only CR3 is used as the single root.
    pt_root_finder: Option<PtRootFinder>,
}

/// Callback for discovering page table roots from guest memory.
///
/// Called during [`MultiUseSandbox::snapshot`] with:
/// - `snapshot_mem` - the sandbox's snapshot (shared) memory as a byte slice
/// - `scratch_mem` - the sandbox's scratch memory as a byte slice
/// - `root_pt_gpa` - the root page table GPA of the currently-executing
///   address space
///
/// Returns a list of root page table GPAs to walk. If the list is
/// empty, only `root_pt_gpa` is used.
pub type PtRootFinder = Box<dyn Fn(&[u8], &[u8], u64) -> Vec<u64> + Send>;

impl MultiUseSandbox {
    /// Move an `UninitializedSandbox` into a new `MultiUseSandbox` instance.
    ///
    /// This function is not equivalent to doing an `evolve` from uninitialized
    /// to initialized, and is purposely not exposed publicly outside the crate
    /// (as a `From` implementation would be)
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn from_uninit(
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        mgr: SandboxMemoryManager<HostSharedMemory>,
        vm: HyperlightVm,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> MultiUseSandbox {
        Self {
            poisoned: false,
            host_funcs,
            mem_mgr: mgr,
            vm,
            #[cfg(gdb)]
            dbg_mem_access_fn,
            snapshot: None,
            pt_root_finder: None,
        }
    }

    /// Set a callback that discovers page table roots from guest memory.
    /// The callback receives (snapshot_mem, scratch_mem, cr3) and returns
    /// the list of root GPAs to walk during snapshot creation.
    pub fn set_pt_root_finder(&mut self, finder: PtRootFinder) {
        self.pt_root_finder = Some(finder);
    }

    /// Create a `MultiUseSandbox` directly from a [`Snapshot`],
    /// bypassing [`UninitializedSandbox`](crate::UninitializedSandbox)
    /// and [`evolve()`](crate::UninitializedSandbox::evolve).
    ///
    /// This is useful for fast sandbox creation when a snapshot of
    /// an already-initialized guest is available, either saved to disk
    /// or captured in memory from another sandbox.
    ///
    /// The provided [`HostFunctions`] must include every host function
    /// that was registered on the sandbox at the time the snapshot was
    /// taken (matched by name and signature). Additional host functions
    /// not present in the snapshot are allowed. A mismatch returns
    /// [`SnapshotHostFunctionMismatch`](crate::HyperlightError::SnapshotHostFunctionMismatch)
    /// carrying the missing names and signature differences.
    ///
    /// An optional [`SandboxConfiguration`](crate::sandbox::SandboxConfiguration)
    /// can be supplied to override runtime settings such as timeouts and
    /// interrupt behavior. Memory layout fields
    /// (`input_data_size`, `output_data_size`, `heap_size`, `scratch_size`)
    /// are always taken from the snapshot. Any values supplied in
    /// `config` for those fields are ignored. On x86_64 the `config` MSR
    /// allow list must be a superset of the one the snapshot was taken with,
    /// or the load fails with an MSR mismatch.
    ///
    /// # Examples
    ///
    /// From a snapshot taken on another sandbox:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::{HostFunctions, MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create and initialize a sandbox the normal way
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None,
    /// )?.evolve()?;
    ///
    /// // Capture a snapshot of the initialized state
    /// let snapshot = sandbox.snapshot()?;
    ///
    /// // Create a new sandbox directly from the snapshot
    /// let mut sandbox2 = MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None)?;
    /// let result: i32 = sandbox2.call("GetValue", ())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// From a snapshot loaded from disk:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::{HostFunctions, MultiUseSandbox};
    /// # use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tag = OciTag::new("latest")?;
    /// let snapshot = Arc::new(Snapshot::load("./guest_snapshot", tag)?);
    /// let mut sandbox = MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None)?;
    /// let result: String = sandbox.call("Echo", "hello".to_string())?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn from_snapshot(
        snapshot: Arc<Snapshot>,
        host_funcs: crate::HostFunctions,
        config: Option<crate::sandbox::SandboxConfiguration>,
    ) -> Result<Self> {
        use rand::RngExt;

        use crate::mem::ptr::RawPtr;
        use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;

        // Validate that the provided host functions are a superset of
        // those required by the snapshot.
        snapshot.validate_host_functions(host_funcs.inner())?;

        let host_funcs = Arc::new(Mutex::new(host_funcs.into_inner()));

        let stack_top_gva = snapshot.stack_top_gva();
        // Start from the caller's config (if any) so runtime fields
        // such as timeouts and interrupt knobs are honored, then
        // overwrite the layout fields from the snapshot. The on-disk
        // layout is fixed, so any layout values supplied by the
        // caller are silently ignored. Warn if the caller passed a
        // config whose layout fields disagree with the snapshot, so
        // the override is at least visible.
        let caller_supplied_config = config.is_some();
        let mut config = config.unwrap_or_default();
        if caller_supplied_config {
            warn_on_layout_override(&config, snapshot.layout());
        }
        config.set_input_data_size(snapshot.layout().input_data_size());
        config.set_output_data_size(snapshot.layout().output_data_size());
        config.set_heap_size(snapshot.layout().heap_size() as u64);
        config.set_scratch_size(snapshot.layout().get_scratch_size());
        let load_info = snapshot.load_info();

        let mgr = crate::mem::mgr::SandboxMemoryManager::from_snapshot(&snapshot)?;
        let (mut hshm, gshm) = mgr.build()?;

        let page_size = u32::try_from(page_size::get())? as usize;

        #[cfg(target_os = "linux")]
        crate::signal_handlers::setup_signal_handlers(&config)?;

        // Runtime config for the restored sandbox. `guest_core_dump`
        // (crashdump) and `guest_debug_info` (gdb) come from the caller's
        // config. `binary_path` stays `None`. `set_up_hypervisor_partition`
        // fills `entry_point` from the manager's entry point so crashdumps
        // carry the correct `AT_ENTRY`.
        #[cfg(any(crashdump, gdb))]
        let rt_cfg = crate::sandbox::uninitialized::SandboxRuntimeConfig {
            #[cfg(crashdump)]
            binary_path: None,
            #[cfg(gdb)]
            debug_info: config.get_guest_debug_info(),
            #[cfg(crashdump)]
            guest_core_dump: config.get_guest_core_dump(),
            #[cfg(crashdump)]
            entry_point: None,
        };

        let mut vm = set_up_hypervisor_partition(
            gshm,
            &config,
            stack_top_gva,
            page_size,
            #[cfg(any(crashdump, gdb))]
            rt_cfg,
            load_info,
        )?;

        let seed = {
            let mut rng = rand::rng();
            rng.random::<u64>()
        };
        let peb_addr = RawPtr::from(u64::try_from(hshm.layout.peb_address())?);

        #[cfg(gdb)]
        let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

        // noop for NextAction::Call
        vm.initialise(
            peb_addr,
            seed,
            &mut hshm,
            &host_funcs,
            None,
            #[cfg(gdb)]
            dbg_mem_access_hdl,
        )
        .map_err(crate::hypervisor::hyperlight_vm::HyperlightVmError::Initialize)?;

        // If the snapshot was taken from an already-initialized guest
        // (NextAction::Call), apply the captured special registers so
        // the guest resumes in the correct CPU state.
        if matches!(snapshot.next_action(), super::snapshot::NextAction::Call(_)) {
            let sregs = snapshot.sregs().ok_or_else(|| {
                crate::new_error!("snapshot with NextAction::Call must have captured sregs")
            })?;
            vm.apply_sregs(hshm.layout.get_pt_base_gpa(), sregs)
                .map_err(|e| {
                    crate::HyperlightError::HyperlightVmError(
                        crate::hypervisor::hyperlight_vm::HyperlightVmError::Restore(e.into()),
                    )
                })?;

            // Restore captured MSR state.
            #[cfg(target_arch = "x86_64")]
            vm.restore_msrs(snapshot.msrs(), snapshot.allowed_msrs())
                .map_err(|e| {
                    crate::HyperlightError::HyperlightVmError(
                        crate::hypervisor::hyperlight_vm::HyperlightVmError::Restore(e),
                    )
                })?;
        }

        #[cfg(gdb)]
        let dbg_mem_wrapper = Arc::new(Mutex::new(hshm.clone()));

        let sbox = MultiUseSandbox::from_uninit(
            host_funcs,
            hshm,
            vm,
            #[cfg(gdb)]
            dbg_mem_wrapper,
        );
        Ok(sbox)
    }

    /// Creates a snapshot of the sandbox's current memory state.
    ///
    /// The returned snapshot can be applied to any
    /// [`MultiUseSandbox`] whose memory layout is structurally
    /// compatible with this sandbox's layout and whose registered
    /// host functions are a superset of those registered here at the
    /// time of capture. See [`MultiUseSandbox::restore`] and
    /// [`MultiUseSandbox::from_snapshot`] for the exact compatibility
    /// rules and the error variants returned on mismatch.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Snapshots can only be taken from non-poisoned sandboxes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Modify sandbox state
    /// sandbox.call_guest_function_by_name::<i32>("SetValue", 42)?;
    ///
    /// // Capture a snapshot of the current memory state
    /// let snapshot = sandbox.snapshot()?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn snapshot(&mut self) -> Result<Arc<Snapshot>> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }

        if let Some(snapshot) = &self.snapshot {
            return Ok(snapshot.clone());
        }
        let mapped_regions_iter = self.vm.get_mapped_regions();
        let mapped_regions_vec: Vec<MemoryRegion> = mapped_regions_iter.cloned().collect();
        // Get CR3 from the vCPU
        let cr3 = self
            .vm
            .get_root_pt()
            .map_err(|e| HyperlightError::HyperlightVmError(e.into()))?;
        // Use the callback if set, otherwise just CR3
        let root_pt_gpas = if let Some(finder) = &self.pt_root_finder {
            let roots = self.mem_mgr.shared_mem.with_contents(|snap| {
                self.mem_mgr
                    .scratch_mem
                    .with_contents(|scratch| finder(snap, scratch, cr3))
            })??;
            if roots.is_empty() { vec![cr3] } else { roots }
        } else {
            vec![cr3]
        };

        let stack_top_gpa = self.vm.get_stack_top();
        let sregs = self
            .vm
            .get_snapshot_sregs()
            .map_err(|e| HyperlightError::HyperlightVmError(e.into()))?;
        #[cfg(target_arch = "x86_64")]
        let msrs = self
            .vm
            .get_msr_reset_state()
            .map_err(|e| HyperlightError::HyperlightVmError(e.into()))?;
        #[cfg(target_arch = "x86_64")]
        let allowed_msrs = self.vm.get_msr_allow_list();
        let next_action = self.vm.get_next_action();
        let host_functions = (&*self.host_funcs.try_lock().map_err(|e| {
            crate::new_error!("Error locking host_funcs at {}:{}: {}", file!(), line!(), e)
        })?)
            .into();

        let memory_snapshot = self.mem_mgr.snapshot(
            mapped_regions_vec,
            &root_pt_gpas,
            stack_top_gpa,
            sregs,
            #[cfg(target_arch = "x86_64")]
            Some(msrs),
            #[cfg(target_arch = "x86_64")]
            Some(allowed_msrs),
            next_action,
            host_functions,
        )?;
        let snapshot = Arc::new(memory_snapshot);
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Restores the sandbox's memory to a previously captured snapshot state.
    ///
    /// The snapshot's memory layout must be structurally compatible
    /// with this sandbox's layout, otherwise this returns
    /// [`SnapshotLayoutMismatch`](crate::HyperlightError::SnapshotLayoutMismatch).
    ///
    /// The sandbox's registered host functions must be a superset of
    /// those required by the snapshot (matched by name and
    /// signature). Extras on the sandbox are allowed. The registry
    /// itself is left unchanged. A mismatch returns
    /// [`SnapshotHostFunctionMismatch`](crate::HyperlightError::SnapshotHostFunctionMismatch)
    /// carrying the missing names and signature differences.
    ///
    /// On x86_64 this sandbox's MSR allow list must be a superset of the one
    /// the snapshot was taken with, or the restore poisons with an MSR
    /// mismatch.
    ///
    /// ## Poison State Recovery
    ///
    /// This method automatically clears any poison state when successful. This is safe because:
    /// - Snapshots can only be taken from non-poisoned sandboxes
    /// - Restoration completely replaces all memory state, eliminating any inconsistencies
    ///   caused by incomplete guest execution
    ///
    /// ### What Gets Fixed During Restore
    ///
    /// When a poisoned sandbox is restored, the memory state is completely reset:
    /// - **Leaked heap memory** - All allocations from interrupted execution are discarded
    /// - **Corrupted allocator metadata** - Free lists and heap headers restored to consistent state
    /// - **Locked mutexes** - All lock state is reset
    /// - **Partial updates** - Data structures restored to their pre-execution state
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Take initial snapshot from this sandbox
    /// let snapshot = sandbox.snapshot()?;
    ///
    /// // Modify sandbox state
    /// sandbox.call_guest_function_by_name::<i32>("SetValue", 100)?;
    /// let value: i32 = sandbox.call_guest_function_by_name("GetValue", ())?;
    /// assert_eq!(value, 100);
    ///
    /// // Restore to previous state (same sandbox)
    /// sandbox.restore(snapshot)?;
    /// let restored_value: i32 = sandbox.call_guest_function_by_name("GetValue", ())?;
    /// assert_eq!(restored_value, 0); // Back to initial state
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Recovering from Poison
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary, HyperlightError};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Take snapshot before potentially poisoning operation
    /// let snapshot = sandbox.snapshot()?;
    ///
    /// // This might poison the sandbox (guest not run to completion)
    /// let result = sandbox.call::<()>("guest_panic", ());
    /// if result.is_err() {
    ///     if sandbox.poisoned() {
    ///         // Restore from snapshot to clear poison
    ///         sandbox.restore(snapshot.clone())?;
    ///         assert!(!sandbox.poisoned());
    ///         
    ///         // Sandbox is now usable again
    ///         sandbox.call::<String>("Echo", "hello".to_string())?;
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn restore(&mut self, snapshot: Arc<Snapshot>) -> Result<()> {
        // Currently, we do not try to optimise restore to the
        // most-current snapshot. This is because the most-current
        // snapshot, while it must have identical virtual memory
        // layout to the current sandbox, does not necessarily have
        // the exact same /physical/ memory contents. It is not
        // entirely inconceivable that this could lead to breakage of
        // cross-request isolation in some way, although it would
        // require some /very/ odd code.  For example, suppose that a
        // service uses Hyperlight to sandbox native code from
        // clients, and promises cross-request isolation. A tenant
        // provides a binary that can process two forms of request,
        // either writing a secret into physical memory, or reading
        // from arbitrary physical memory, assuming that the two kinds
        // of requests can never (dangerously) meet in the same
        // sandbox.
        //
        // It is presently unclear whether this is a sensible threat
        // model, especially since Hyperlight is often used with
        // managed-code runtimes which do not allow even arbitrary
        // access to virtual memory, much less physical memory.
        // However, out of an abundance of caution, the optimisation
        // is presently disabled.

        {
            let host_funcs = self
                .host_funcs
                .try_lock()
                .map_err(|e| crate::new_error!("Error locking host_funcs: {}", e))?;
            snapshot.validate_compatibility(&self.mem_mgr.layout, &host_funcs)?;
        }

        let (gsnapshot, gscratch) = self.mem_mgr.restore_snapshot(&snapshot)?;
        if let Some(gsnapshot) = gsnapshot {
            self.vm
                .update_snapshot_mapping(gsnapshot)
                .map_err(|e| HyperlightError::HyperlightVmError(e.into()))?;
        }
        if let Some(gscratch) = gscratch {
            self.vm
                .update_scratch_mapping(gscratch)
                .map_err(|e| HyperlightError::HyperlightVmError(e.into()))?;
        }

        let sregs = snapshot.sregs().ok_or_else(|| {
            HyperlightError::Error("snapshot from running sandbox should have sregs".to_string())
        })?;
        // TODO (ludfjig): Go through the rest of possible errors in this `MultiUseSandbox::restore` function
        // and determine if they should also poison the sandbox.
        self.vm
            .reset_vcpu(snapshot.root_pt_gpa(), sregs)
            .map_err(|e| {
                self.poisoned = true;
                HyperlightVmError::Restore(e)
            })?;

        // Restore captured MSR state.
        #[cfg(target_arch = "x86_64")]
        self.vm
            .restore_msrs(snapshot.msrs(), snapshot.allowed_msrs())
            .map_err(|e| {
                self.poisoned = true;
                HyperlightVmError::Restore(e)
            })?;

        self.vm.set_stack_top(snapshot.stack_top_gva());
        self.vm.set_next_action(snapshot.next_action());
        // Carry the guest ELF entry point across restore so a later
        // crashdump fills `AT_ENTRY` from the restored image.
        #[cfg(crashdump)]
        self.vm
            .set_crashdump_entry_point(snapshot.original_entrypoint());

        let current_regions: Vec<MemoryRegion> = self.vm.get_mapped_regions().cloned().collect();
        for region in &current_regions {
            self.vm
                .unmap_region(region)
                .map_err(HyperlightVmError::UnmapRegion)?;
        }

        // The restored snapshot is now our most current snapshot
        self.snapshot = Some(snapshot.clone());

        // Clear poison state when successfully restoring from snapshot.
        //
        // # Safety:
        // This is safe because:
        // 1. Snapshots can only be taken from non-poisoned sandboxes (verified at snapshot creation)
        // 2. Restoration completely replaces all memory state, eliminating:
        //    - All leaked heap allocations (memory is restored to snapshot state)
        //    - All corrupted data structures (overwritten with consistent snapshot data)
        //    - All inconsistent global state (reset to snapshot values)
        self.poisoned = false;

        Ok(())
    }

    /// Calls a guest function by name with the specified arguments.
    ///
    /// Changes made to the sandbox during execution are *not* persisted.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Use [`restore()`](Self::restore) to recover from a poisoned state.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Call function with no arguments
    /// let result: i32 = sandbox.call_guest_function_by_name("GetCounter", ())?;
    ///
    /// // Call function with single argument
    /// let doubled: i32 = sandbox.call_guest_function_by_name("Double", 21)?;
    /// assert_eq!(doubled, 42);
    ///
    /// // Call function with multiple arguments
    /// let sum: i32 = sandbox.call_guest_function_by_name("Add", (10, 32))?;
    /// assert_eq!(sum, 42);
    ///
    /// // Call function returning string
    /// let message: String = sandbox.call_guest_function_by_name("Echo", "Hello, World!".to_string())?;
    /// assert_eq!(message, "Hello, World!");
    /// # Ok(())
    /// # }
    /// ```
    #[doc(hidden)]
    #[deprecated(
        since = "0.8.0",
        note = "Deprecated in favour of call and snapshot/restore."
    )]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_guest_function_by_name<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        let snapshot = self.snapshot()?;
        let res = self.call(func_name, args);
        self.restore(snapshot)?;
        res
    }

    /// Calls a guest function by name with the specified arguments.
    ///
    /// Changes made to the sandbox during execution are persisted.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is already poisoned before the call. Use [`restore()`](Self::restore) to recover from
    /// a poisoned state.
    ///
    /// ## Sandbox Poisoning
    ///
    /// If this method returns an error, the sandbox may be poisoned if the guest was not run
    /// to completion (due to panic, abort, memory violation, stack/heap exhaustion, or forced
    /// termination). Use [`poisoned()`](Self::poisoned) to check the poison state and
    /// [`restore()`](Self::restore) to recover if needed.
    ///
    /// If this method returns `Ok`, the sandbox is guaranteed to **not** be poisoned - the guest
    /// function completed successfully and the sandbox state is consistent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Call function with no arguments
    /// let result: i32 = sandbox.call("GetCounter", ())?;
    ///
    /// // Call function with single argument
    /// let doubled: i32 = sandbox.call("Double", 21)?;
    /// assert_eq!(doubled, 42);
    ///
    /// // Call function with multiple arguments
    /// let sum: i32 = sandbox.call("Add", (10, 32))?;
    /// assert_eq!(sum, 42);
    ///
    /// // Call function returning string
    /// let message: String = sandbox.call("Echo", "Hello, World!".to_string())?;
    /// assert_eq!(message, "Hello, World!");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Handling Potential Poisoning
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Take snapshot before risky operation
    /// let snapshot = sandbox.snapshot()?;
    ///
    /// // Call potentially unsafe guest function
    /// let result = sandbox.call::<String>("RiskyOperation", "input".to_string());
    ///
    /// // Check if the call failed and poisoned the sandbox
    /// if let Err(e) = result {
    ///     eprintln!("Guest function failed: {}", e);
    ///     
    ///     if sandbox.poisoned() {
    ///         eprintln!("Sandbox was poisoned, restoring from snapshot");
    ///         sandbox.restore(snapshot.clone())?;
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;
        maybe_time_and_emit_guest_call(func_name, || {
            let ret = self.call_guest_function_by_name_no_reset(
                func_name,
                Output::TYPE,
                args.into_value(),
            );
            // Use the ? operator to allow converting any hyperlight_common::func::Error
            // returned by from_value into a HyperlightError
            let ret = Output::from_value(ret?)?;
            Ok(ret)
        })
    }

    /// Maps a region of host memory into the sandbox address space.
    ///
    /// The base address and length must meet platform alignment requirements
    /// (typically page-aligned). The `region_type` field is ignored as guest
    /// page table entries are not created.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Use [`restore()`](Self::restore) to recover from a poisoned state.
    ///
    /// # Safety
    ///
    /// The caller must ensure the host memory region remains valid and unmodified
    /// for the lifetime of `self`.
    #[instrument(err(Debug), skip(self, rgn), parent = Span::current())]
    pub unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        if rgn.flags.contains(MemoryRegionFlags::WRITE) {
            // TODO: Implement support for writable mappings, which
            // need to be registered with the memory manager so that
            // writes can be rolled back when necessary.
            log_then_return!("TODO: Writable mappings not yet supported");
        }

        // Map first so overlaps are rejected before resetting the snapshot
        unsafe { self.vm.map_region(rgn) }.map_err(HyperlightVmError::MapRegion)?;
        self.snapshot = None;
        Ok(())
    }

    /// Map the contents of a file into the guest at a particular address
    ///
    /// Returns the length of the mapping in bytes.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Use [`restore()`](Self::restore) to recover from a poisoned state.
    #[instrument(err(Debug), skip(self, file_path, guest_base), parent = Span::current())]
    pub fn map_file_cow(&mut self, file_path: &Path, guest_base: u64) -> Result<u64> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }

        // Phase 1: host-side OS work (open file, create mapping)
        let mut prepared = prepare_file_cow(file_path, guest_base)?;

        // Validate that the full mapped range doesn't overlap the
        // sandbox's primary shared memory region.
        let shared_size = self.mem_mgr.shared_mem.mem_size() as u64;
        let base_addr = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64;
        let shared_end = base_addr.checked_add(shared_size).ok_or_else(|| {
            crate::HyperlightError::Error("shared memory end overflow".to_string())
        })?;
        let mapping_end = guest_base
            .checked_add(prepared.size as u64)
            .ok_or_else(|| {
                crate::HyperlightError::Error(format!(
                    "map_file_cow: guest address overflow: {:#x} + {:#x}",
                    guest_base, prepared.size
                ))
            })?;
        if guest_base < shared_end && mapping_end > base_addr {
            return Err(crate::HyperlightError::Error(format!(
                "map_file_cow: mapping [{:#x}..{:#x}) overlaps sandbox shared memory [{:#x}..{:#x})",
                guest_base, mapping_end, base_addr, shared_end,
            )));
        }

        // Phase 2: VM-side work (map into guest address space)
        let region = prepared.to_memory_region()?;

        unsafe { self.vm.map_region(&region) }
            .map_err(HyperlightVmError::MapRegion)
            .map_err(crate::HyperlightError::HyperlightVmError)?;

        self.snapshot = None;

        let size = prepared.size as u64;

        // Mark consumed immediately after map_region succeeds.
        // On Windows, WhpVm::map_memory copies the file mapping handle
        // into its own `file_mappings` vec for cleanup on drop. If we
        // deferred mark_consumed(), both PreparedFileMapping::drop and
        // WhpVm::drop would release the same handle — a double-close.
        // On Linux the hypervisor holds a reference to the host mmap;
        // freeing it here would leave a dangling backing.
        prepared.mark_consumed();

        Ok(size)
    }

    /// Calls a guest function with type-erased parameters and return values.
    ///
    /// This function is used for fuzz testing parameter and return type handling.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Use [`restore()`](Self::restore) to recover from a poisoned state.
    #[cfg(feature = "fuzzing")]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_type_erased_guest_function_by_name(
        &mut self,
        func_name: &str,
        ret_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;
        maybe_time_and_emit_guest_call(func_name, || {
            self.call_guest_function_by_name_no_reset(func_name, ret_type, args)
        })
    }

    fn call_guest_function_by_name_no_reset(
        &mut self,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        // ===== KILL() TIMING POINT 1 =====
        // Clear any stale cancellation from a previous guest function call or if kill() was called too early.
        // Any kill() that completed (even partially) BEFORE this line has NO effect on this call.
        self.vm.clear_cancel();

        let res = (|| {
            let estimated_capacity = estimate_flatbuffer_capacity(function_name, &args);

            let fc = FunctionCall::new(
                function_name.to_string(),
                Some(args),
                FunctionCallType::Guest,
                return_type,
            );

            let mut builder = FlatBufferBuilder::with_capacity(estimated_capacity);
            let buffer = fc.encode(&mut builder);

            self.mem_mgr.write_guest_function_call(buffer)?;

            let dispatch_res = self.vm.dispatch_call_from_host(
                &mut self.mem_mgr,
                &self.host_funcs,
                #[cfg(gdb)]
                self.dbg_mem_access_fn.clone(),
            );

            // Convert dispatch errors to HyperlightErrors to maintain backwards compatibility
            // but first determine if sandbox should be poisoned
            if let Err(e) = dispatch_res {
                let (error, should_poison) = e.promote();
                self.poisoned |= should_poison;
                return Err(error);
            }

            let guest_result = self.mem_mgr.get_guest_function_call_result()?.into_inner();

            match guest_result {
                Ok(val) => Ok(val),
                Err(guest_error) => {
                    metrics::counter!(
                        METRIC_GUEST_ERROR,
                        METRIC_GUEST_ERROR_LABEL_CODE => (guest_error.code as u64).to_string()
                    )
                    .increment(1);

                    Err(HyperlightError::GuestError(
                        guest_error.code,
                        guest_error.message,
                    ))
                }
            }
        })();

        // Clear partial abort bytes so they don't leak across calls.
        self.mem_mgr.abort_buffer.clear();

        // In the happy path we do not need to clear io-buffers from the host because:
        // - the serialized guest function call is zeroed out by the guest during deserialization, see call to `try_pop_shared_input_data_into::<FunctionCall>()`
        // - the serialized guest function result is zeroed out by us (the host) during deserialization, see `get_guest_function_call_result`
        // - any serialized host function call are zeroed out by us (the host) during deserialization, see `get_host_function_call`
        // - any serialized host function result is zeroed out by the guest during deserialization, see `get_host_return_value`
        if let Err(e) = &res {
            self.mem_mgr.clear_io_buffers();

            // Determine if we should poison the sandbox.
            self.poisoned |= e.is_poison_error();
        }

        // Note: clear_call_active() is automatically called when _guard is dropped here

        res
    }

    /// Returns a handle for interrupting guest execution.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # use std::thread;
    /// # use std::time::Duration;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Get interrupt handle before starting long-running operation
    /// let interrupt_handle = sandbox.interrupt_handle();
    ///
    /// // Spawn thread to interrupt after timeout
    /// let handle_clone = interrupt_handle.clone();
    /// thread::spawn(move || {
    ///     thread::sleep(Duration::from_secs(5));
    ///     handle_clone.kill();
    /// });
    ///
    /// // This call may be interrupted by the spawned thread
    /// let result = sandbox.call_guest_function_by_name::<i32>("LongRunningFunction", ());
    /// # Ok(())
    /// # }
    /// ```
    pub fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }

    /// Generate a crash dump of the current state of the VM underlying this sandbox.
    ///
    /// Creates an ELF core dump file that can be used for debugging. The dump
    /// captures the current state of the sandbox including registers, memory regions,
    /// and other execution context.
    ///
    /// The location of the core dump file is determined by the `HYPERLIGHT_CORE_DUMP_DIR`
    /// environment variable. If not set, it defaults to the system's temporary directory.
    ///
    /// This is only available when the `crashdump` feature is enabled and then only if the sandbox
    /// is also configured to allow core dumps (which is the default behavior).
    ///
    /// This can be useful for generating a crash dump from gdb when trying to debug issues in the
    /// guest that dont cause crashes (e.g. a guest function that does not return)
    ///
    /// # Examples
    ///
    /// Attach to your running process with gdb and call this function:
    ///
    /// ```shell
    /// sudo gdb -p <pid_of_your_process>
    /// (gdb) info threads
    /// # find the thread that is running the guest function you want to debug
    /// (gdb) thread <thread_number>
    /// # switch to the frame where you have access to your MultiUseSandbox instance
    /// (gdb) backtrace
    /// (gdb) frame <frame_number>
    /// # get the pointer to your MultiUseSandbox instance
    /// # Get the sandbox pointer
    /// (gdb) print sandbox
    /// # Call the crashdump function
    /// call sandbox.generate_crashdump()
    /// ```
    /// The crashdump should be available in crash dump directory (see `HYPERLIGHT_CORE_DUMP_DIR` env var).
    ///
    #[cfg(crashdump)]
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn generate_crashdump(&mut self) -> Result<()> {
        crate::hypervisor::crashdump::generate_crashdump(&self.vm, &mut self.mem_mgr, None)
    }

    /// Generate a crash dump of the current state of the VM, writing to `dir`.
    ///
    /// Like [`generate_crashdump`](Self::generate_crashdump), but the core dump
    /// file is placed in `dir` instead of consulting the `HYPERLIGHT_CORE_DUMP_DIR`
    /// environment variable.  This avoids the need for callers to use
    /// `unsafe { std::env::set_var(...) }`.
    #[cfg(crashdump)]
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn generate_crashdump_to_dir(&mut self, dir: impl Into<String>) -> Result<()> {
        crate::hypervisor::crashdump::generate_crashdump(
            &self.vm,
            &mut self.mem_mgr,
            Some(dir.into()),
        )
    }

    /// Returns whether the sandbox is currently poisoned.
    ///
    /// A poisoned sandbox is in an inconsistent state due to the guest not running to completion.
    /// All operations will be rejected until the sandbox is restored from a non-poisoned snapshot.
    ///
    /// ## Causes of Poisoning
    ///
    /// The sandbox becomes poisoned when guest execution is interrupted:
    /// - **Panics/Aborts** - Guest code panics or calls `abort()`
    /// - **Invalid Memory Access** - Read/write/execute violations  
    /// - **Stack Overflow** - Guest exhausts stack space
    /// - **Heap Exhaustion** - Guest runs out of heap memory
    /// - **Forced Termination** - [`InterruptHandle::kill()`] called during execution
    ///
    /// ## Recovery
    ///
    /// To clear the poison state, use [`restore()`](Self::restore) with a snapshot
    /// that was taken before the sandbox became poisoned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("guest.bin".into()),
    ///     None
    /// )?.evolve()?;
    ///
    /// // Check if sandbox is poisoned
    /// if sandbox.poisoned() {
    ///     println!("Sandbox is poisoned and needs attention");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
}

impl Callable for MultiUseSandbox {
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }
        self.call(func_name, args)
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox").finish()
    }
}

/// Emit a warning for each memory-layout field in `caller` that
/// disagrees with `snapshot`. Used by [`MultiUseSandbox::from_snapshot`]
/// to surface ignored caller-supplied layout values, since those
/// fields are always taken from the snapshot.
fn warn_on_layout_override(
    caller: &crate::sandbox::SandboxConfiguration,
    snapshot: &crate::mem::layout::SandboxMemoryLayout,
) {
    let mismatches: &[(&str, u64, u64)] = &[
        (
            "input_data_size",
            caller.get_input_data_size() as u64,
            snapshot.input_data_size() as u64,
        ),
        (
            "output_data_size",
            caller.get_output_data_size() as u64,
            snapshot.output_data_size() as u64,
        ),
        (
            "heap_size",
            caller.get_heap_size(),
            snapshot.heap_size() as u64,
        ),
        (
            "scratch_size",
            caller.get_scratch_size() as u64,
            snapshot.get_scratch_size() as u64,
        ),
    ];
    for (name, supplied, snap) in mismatches {
        if supplied != snap {
            tracing::warn!(
                "from_snapshot ignoring caller-supplied {} ({}); using snapshot value ({})",
                name,
                supplied,
                snap
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
    use hyperlight_testing::sandbox_sizes::{LARGE_HEAP_SIZE, MEDIUM_HEAP_SIZE, SMALL_HEAP_SIZE};
    use hyperlight_testing::simple_guest_as_string;

    use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
    use crate::mem::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory as _};
    use crate::sandbox::SandboxConfiguration;
    use crate::{GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

    #[test]
    fn poison() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve()
        }
        .unwrap();
        let snapshot = sbox.snapshot().unwrap();

        // poison on purpose
        let res = sbox
            .call::<()>("guest_panic", "hello".to_string())
            .unwrap_err();
        assert!(
            matches!(res, HyperlightError::GuestAborted(code, context) if code == ErrorCode::UnknownError as u8 && context.contains("hello"))
        );
        assert!(sbox.poisoned());

        // guest calls should fail when poisoned
        let res = sbox
            .call::<()>("guest_panic", "hello2".to_string())
            .unwrap_err();
        assert!(matches!(res, HyperlightError::PoisonedSandbox));

        // snapshot should fail when poisoned
        if let Err(e) = sbox.snapshot() {
            assert!(sbox.poisoned());
            assert!(matches!(e, HyperlightError::PoisonedSandbox));
        } else {
            panic!("Snapshot should fail");
        }

        // map_region should fail when poisoned
        {
            let map_mem = allocate_guest_memory();
            let guest_base = 0x0;
            let region = region_for_memory(&map_mem, guest_base, MemoryRegionFlags::READ);
            let res = unsafe { sbox.map_region(&region) }.unwrap_err();
            assert!(matches!(res, HyperlightError::PoisonedSandbox));
        }

        // map_file_cow should fail when poisoned
        {
            let temp_file = std::env::temp_dir().join("test_poison_map_file.bin");
            let res = sbox.map_file_cow(&temp_file, 0x0).unwrap_err();
            assert!(matches!(res, HyperlightError::PoisonedSandbox));
            std::fs::remove_file(&temp_file).ok(); // Clean up
        }

        // call_guest_function_by_name (deprecated) should fail when poisoned
        #[allow(deprecated)]
        let res = sbox
            .call_guest_function_by_name::<String>("Echo", "test".to_string())
            .unwrap_err();
        assert!(matches!(res, HyperlightError::PoisonedSandbox));

        // restore to non-poisoned snapshot should work and clear poison
        sbox.restore(snapshot.clone()).unwrap();
        assert!(!sbox.poisoned());

        // guest calls should work again after restore
        let res = sbox.call::<String>("Echo", "hello2".to_string()).unwrap();
        assert_eq!(res, "hello2".to_string());
        assert!(!sbox.poisoned());

        // re-poison on purpose
        let res = sbox
            .call::<()>("guest_panic", "hello".to_string())
            .unwrap_err();
        assert!(
            matches!(res, HyperlightError::GuestAborted(code, context) if code == ErrorCode::UnknownError as u8 && context.contains("hello"))
        );
        assert!(sbox.poisoned());

        // restore to non-poisoned snapshot should work again
        sbox.restore(snapshot.clone()).unwrap();
        assert!(!sbox.poisoned());

        // guest calls should work again
        let res = sbox.call::<String>("Echo", "hello3".to_string()).unwrap();
        assert_eq!(res, "hello3".to_string());
        assert!(!sbox.poisoned());

        // snapshot should work again
        let _ = sbox.snapshot().unwrap();
    }

    /// Make sure input/output buffers are properly reset after guest call (with host call)
    #[test]
    fn host_func_error() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
        sandbox
            .register("HostError", || -> Result<()> {
                Err(HyperlightError::Error("hi".to_string()))
            })
            .unwrap();
        let mut sandbox = sandbox.evolve().unwrap();

        // will exhaust io if leaky
        for _ in 0..1000 {
            let result = sandbox
                .call::<i64>(
                    "CallGivenParamlessHostFuncThatReturnsI64",
                    "HostError".to_string(),
                )
                .unwrap_err();

            assert!(
                matches!(result, HyperlightError::GuestError(code, msg) if code == ErrorCode::HostFunctionError && msg == "hi"),
            );
        }
    }

    #[test]
    fn call_host_func_expect_error() {
        let path = simple_guest_as_string().unwrap();
        let sandbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
        let mut sandbox = sandbox.evolve().unwrap();
        sandbox
            .call::<()>("CallHostExpectError", "SomeUnknownHostFunc".to_string())
            .unwrap();
    }

    /// Make sure input/output buffers are properly reset after guest call (with host call)
    #[test]
    fn io_buffer_reset() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_input_data_size(4096);
        cfg.set_output_data_size(4096);
        let path = simple_guest_as_string().unwrap();
        let mut sandbox =
            UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
        sandbox.register("HostAdd", |a: i32, b: i32| a + b).unwrap();
        let mut sandbox = sandbox.evolve().unwrap();

        // will exhaust io if leaky. Tests both success and error paths
        for _ in 0..1000 {
            let result = sandbox.call::<i32>("Add", (5i32, 10i32)).unwrap();
            assert_eq!(result, 15);
            let result = sandbox.call::<i32>("AddToStaticAndFail", ()).unwrap_err();
            assert!(
                matches!(result, HyperlightError::GuestError (code, msg ) if code == ErrorCode::GuestError && msg == "Crash on purpose")
            );
        }
    }

    /// Tests that call_guest_function_by_name restores the state correctly
    #[test]
    fn test_call_guest_function_by_name() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve()
        }
        .unwrap();

        let snapshot = sbox.snapshot().unwrap();

        let _ = sbox.call::<i32>("AddToStatic", 5i32).unwrap();
        let res: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(res, 5);

        sbox.restore(snapshot).unwrap();
        #[allow(deprecated)]
        let _ = sbox
            .call_guest_function_by_name::<i32>("AddToStatic", 5i32)
            .unwrap();
        #[allow(deprecated)]
        let res: i32 = sbox.call_guest_function_by_name("GetStatic", ()).unwrap();
        assert_eq!(res, 0);
    }

    // Tests to ensure that many (1000) function calls can be made in a call context with a small stack (24K) and heap(20K).
    // This test effectively ensures that the stack is being properly reset after each call and we are not leaking memory in the Guest.
    #[test]
    fn test_with_small_stack_and_heap() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_heap_size(20 * 1024);
        // min_scratch_size already includes 1 page (4k on most
        // platforms) of guest stack, so add 20k more to get 24k
        // total, and then add some more for the eagerly-copied page
        // tables on amd64
        let min_scratch = hyperlight_common::layout::min_scratch_size(
            cfg.get_input_data_size(),
            cfg.get_output_data_size(),
        );
        cfg.set_scratch_size(min_scratch + 0x10000 + 0x10000);

        let mut sbox1: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve()
        }
        .unwrap();

        for _ in 0..1000 {
            sbox1.call::<String>("Echo", "hello".to_string()).unwrap();
        }

        let mut sbox2: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve()
        }
        .unwrap();

        for i in 0..1000 {
            sbox2
                .call::<i32>(
                    "PrintUsingPrintf",
                    format!("Hello World {}\n", i).to_string(),
                )
                .unwrap();
        }
    }

    /// Tests that evolving from MultiUseSandbox to MultiUseSandbox creates a new state
    /// and restoring a snapshot from before evolving restores the previous state
    #[test]
    fn snapshot_evolve_restore_handles_state_correctly() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve()
        }
        .unwrap();

        let snapshot = sbox.snapshot().unwrap();

        let _ = sbox.call::<i32>("AddToStatic", 5i32).unwrap();

        let res: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(res, 5);

        sbox.restore(snapshot).unwrap();
        let res: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(res, 0);
    }

    #[test]
    fn test_trigger_exception_on_guest() {
        let usbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        let mut multi_use_sandbox: MultiUseSandbox = usbox.evolve().unwrap();

        let res: Result<()> = multi_use_sandbox.call("TriggerException", ());

        assert!(res.is_err());

        match res.unwrap_err() {
            HyperlightError::GuestAborted(_, msg) => {
                // msg should indicate we got an invalid opcode exception
                #[cfg(target_arch = "x86_64")]
                assert!(msg.contains("InvalidOpcode"));
                #[cfg(target_arch = "aarch64")]
                assert!(msg.contains("0x2000000"));
            }
            e => panic!("Expected HyperlightError::GuestAborted but got {:?}", e),
        }
    }

    #[test]
    fn create_200_sandboxes() {
        const NUM_THREADS: usize = 10;
        const SANDBOXES_PER_THREAD: usize = 20;

        // barrier to make sure all threads start their work simultaneously
        let start_barrier = Arc::new(Barrier::new(NUM_THREADS + 1));
        let mut thread_handles = vec![];

        for _ in 0..NUM_THREADS {
            let barrier = start_barrier.clone();

            let handle = thread::spawn(move || {
                barrier.wait();

                for _ in 0..SANDBOXES_PER_THREAD {
                    let guest_path = simple_guest_as_string().expect("Guest Binary Missing");
                    let uninit =
                        UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None).unwrap();

                    let mut sandbox: MultiUseSandbox = uninit.evolve().unwrap();

                    let result: i32 = sandbox.call("GetStatic", ()).unwrap();
                    assert_eq!(result, 0);
                }
            });

            thread_handles.push(handle);
        }

        start_barrier.wait();

        for handle in thread_handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_mmap() {
        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let expected = b"hello world";
        let map_mem = page_aligned_memory(expected);
        let guest_base = 0x1_0000_0000; // Arbitrary guest base address

        unsafe {
            sbox.map_region(&region_for_memory(
                &map_mem,
                guest_base,
                MemoryRegionFlags::READ,
            ))
            .unwrap();
        }

        let _guard = map_mem.lock.try_read().unwrap();
        let actual: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base as u64, expected.len() as u64, true),
            )
            .unwrap();

        assert_eq!(actual, expected);
    }

    // Makes sure MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE executable but not writable
    #[test]
    fn test_mmap_write_exec() {
        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        #[cfg(target_arch = "x86_64")]
        let expected = &[0x90, 0x90, 0x90, 0xC3]; // NOOP slide to RET
        #[cfg(target_arch = "aarch64")]
        let expected = &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6];
        let map_mem = page_aligned_memory(expected);
        let guest_base = 0x1_0000_0000; // Arbitrary guest base address

        unsafe {
            sbox.map_region(&region_for_memory(
                &map_mem,
                guest_base,
                MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
            ))
            .unwrap();
        }

        let _guard = map_mem.lock.try_read().unwrap();

        // Execute should pass since memory is executable
        let succeed = sbox
            .call::<bool>(
                "ExecMappedBuffer",
                (guest_base as u64, expected.len() as u64),
            )
            .unwrap();
        assert!(succeed, "Expected execution of mapped buffer to succeed");

        // write should fail because the memory is mapped as read-only
        let err = sbox
            .call::<bool>(
                "WriteMappedBuffer",
                (guest_base as u64, expected.len() as u64),
            )
            .unwrap_err();

        match err {
            HyperlightError::MemoryAccessViolation(addr, ..) if addr == guest_base as u64 => {}
            _ => panic!("Expected MemoryAccessViolation error"),
        };
    }

    fn page_aligned_memory(src: &[u8]) -> GuestSharedMemory {
        use hyperlight_common::mem::PAGE_SIZE_USIZE;

        let len = src.len().div_ceil(PAGE_SIZE_USIZE) * PAGE_SIZE_USIZE;

        let mut mem = ExclusiveSharedMemory::new(len).unwrap();
        mem.copy_from_slice(src, 0).unwrap();

        let (_, guest_mem) = mem.build();

        guest_mem
    }

    fn region_for_memory(
        mem: &GuestSharedMemory,
        guest_base: usize,
        flags: MemoryRegionFlags,
    ) -> MemoryRegion {
        let len = mem.mem_size();
        MemoryRegion {
            host_region: mem.host_region_base()..mem.host_region_end(),
            guest_region: guest_base..(guest_base + len),
            flags,
            region_type: MemoryRegionType::Heap,
        }
    }

    fn allocate_guest_memory() -> GuestSharedMemory {
        page_aligned_memory(b"test data for snapshot")
    }

    #[test]
    fn snapshot_restore_handles_remapping_correctly() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // 1. Take snapshot 1 with no additional regions mapped
        let snapshot1 = sbox.snapshot().unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().count(), 0);

        // 2. Map a memory region
        let map_mem = allocate_guest_memory();
        let guest_base = 0x200000000_usize;
        let region = region_for_memory(&map_mem, guest_base, MemoryRegionFlags::READ);

        unsafe { sbox.map_region(&region).unwrap() };
        assert_eq!(sbox.vm.get_mapped_regions().count(), 1);
        let orig_read = sbox
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    guest_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    true,
                ),
            )
            .unwrap();

        // 3. Take snapshot 2 with 1 region mapped
        let snapshot2 = sbox.snapshot().unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().count(), 1);

        // 4. Re(store to snapshot 1 (should unmap the region)
        sbox.restore(snapshot1.clone()).unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().count(), 0);
        let is_mapped = sbox
            .call::<bool>("CheckMapped", (guest_base as u64,))
            .unwrap();
        assert!(!is_mapped);

        // 5. Restore forward to snapshot 2 (should have folded the
        //    region into the snapshot)
        sbox.restore(snapshot2.clone()).unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().count(), 0);
        let is_mapped = sbox
            .call::<bool>("CheckMapped", (guest_base as u64,))
            .unwrap();
        assert!(is_mapped);

        // Verify the region is the same
        let new_read = sbox
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    guest_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    false,
                ),
            )
            .unwrap();
        assert_eq!(new_read, orig_read);
    }

    /// Compaction copies mapped-region pages into the snapshot blob,
    /// so cross-instance restore preserves their contents without the
    /// target ever mapping the region.
    #[test]
    fn snapshot_restore_across_sandboxes_preserves_mapped_region_contents() {
        let mut source: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        let map_mem = allocate_guest_memory();
        let guest_base = 0x200000000_usize;
        let region = region_for_memory(&map_mem, guest_base, MemoryRegionFlags::READ);
        unsafe { source.map_region(&region).unwrap() };

        // do_map=true installs the guest PTE for the region.
        let orig_read = source
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    guest_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    true,
                ),
            )
            .unwrap();

        let snapshot = source.snapshot().unwrap();

        let mut target: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        assert_eq!(target.vm.get_mapped_regions().count(), 0);

        target.restore(snapshot).unwrap();
        assert_eq!(target.vm.get_mapped_regions().count(), 0);

        // Snapshot PTEs resolve to GPAs in the snapshot blob, so the
        // data is readable without re-mapping.
        let new_read = target
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    guest_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    false,
                ),
            )
            .unwrap();
        assert_eq!(new_read, orig_read);
    }

    #[test]
    fn snapshot_restore_across_sandboxes() {
        let mut sandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        let mut sandbox2 = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        sandbox.call::<i32>("AddToStatic", 42i32).unwrap();
        assert_eq!(sandbox2.call::<i32>("GetStatic", ()).unwrap(), 0);

        let snapshot = sandbox.snapshot().unwrap();
        sandbox2.restore(snapshot).unwrap();
        assert_eq!(sandbox2.call::<i32>("GetStatic", ()).unwrap(), 42);
    }

    #[test]
    fn snapshot_restore_rejects_incompatible_layout() {
        let mut sandbox = {
            let path = simple_guest_as_string().unwrap();
            let mut cfg = SandboxConfiguration::default();
            cfg.set_heap_size(0x10_000);
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve().unwrap()
        };

        let mut sandbox2 = {
            let path = simple_guest_as_string().unwrap();
            let mut cfg = SandboxConfiguration::default();
            cfg.set_heap_size(0x20_000);
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve().unwrap()
        };

        let snapshot = sandbox.snapshot().unwrap();
        let err = sandbox2.restore(snapshot);
        assert!(matches!(err, Err(HyperlightError::SnapshotLayoutMismatch)));
    }

    /// Validation runs before any memory or vCPU mutation, so a
    /// rejected `restore` leaves the target usable.
    #[test]
    fn snapshot_restore_failure_leaves_target_usable() {
        let path = simple_guest_as_string().unwrap();
        let mut cfg_a = SandboxConfiguration::default();
        cfg_a.set_heap_size(0x10_000);
        let mut source = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg_a))
            .unwrap()
            .evolve()
            .unwrap();

        let path = simple_guest_as_string().unwrap();
        let mut cfg_b = SandboxConfiguration::default();
        cfg_b.set_heap_size(0x20_000);
        let mut target = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg_b))
            .unwrap()
            .evolve()
            .unwrap();

        target.call::<i32>("AddToStatic", 5i32).unwrap();
        let bad_snapshot = source.snapshot().unwrap();
        let err = target.restore(bad_snapshot);
        assert!(matches!(err, Err(HyperlightError::SnapshotLayoutMismatch)));

        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 5);
        target.call::<i32>("AddToStatic", 3i32).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 8);

        let good_snapshot = target.snapshot().unwrap();
        target.call::<i32>("AddToStatic", 100i32).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 108);
        target.restore(good_snapshot).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 8);
    }

    /// `snapshot.regions()` is empty post-compaction, so restore
    /// unmaps anything the target had mapped.
    #[test]
    fn snapshot_restore_across_sandboxes_target_has_mapped_regions() {
        let mut source: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        source.call::<i32>("AddToStatic", 23i32).unwrap();
        let snapshot = source.snapshot().unwrap();

        let mut target: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        let map_mem = allocate_guest_memory();
        let guest_base = 0x200000000_usize;
        let region = region_for_memory(&map_mem, guest_base, MemoryRegionFlags::READ);
        unsafe { target.map_region(&region).unwrap() };
        assert_eq!(target.vm.get_mapped_regions().count(), 1);

        target.restore(snapshot).unwrap();
        assert_eq!(target.vm.get_mapped_regions().count(), 0);
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 23);
    }

    /// Compacted snapshot data is reachable at the source's GVA even
    /// when the target had a different region mapped at a different
    /// GVA.
    #[test]
    fn snapshot_restore_across_sandboxes_both_have_different_mapped_regions() {
        let mut source: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        let source_mem = allocate_guest_memory();
        let source_base = 0x200000000_usize;
        let source_region = region_for_memory(&source_mem, source_base, MemoryRegionFlags::READ);
        unsafe { source.map_region(&source_region).unwrap() };
        let orig_read = source
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    source_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    true,
                ),
            )
            .unwrap();
        source.call::<i32>("AddToStatic", 9i32).unwrap();
        let snapshot = source.snapshot().unwrap();

        let mut target: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        let target_mem = allocate_guest_memory();
        let target_base = 0x300000000_usize;
        let target_region = region_for_memory(&target_mem, target_base, MemoryRegionFlags::READ);
        unsafe { target.map_region(&target_region).unwrap() };
        assert_eq!(target.vm.get_mapped_regions().count(), 1);

        target.restore(snapshot).unwrap();

        assert_eq!(target.vm.get_mapped_regions().count(), 0);
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 9);

        let new_read = target
            .call::<Vec<u8>>(
                "ReadMappedBuffer",
                (
                    source_base as u64,
                    hyperlight_common::vmem::PAGE_SIZE as u64,
                    false,
                ),
            )
            .unwrap();
        assert_eq!(new_read, orig_read);
    }

    /// Repeated restore of the same snapshot is idempotent.
    #[test]
    fn snapshot_restore_across_sandboxes_repeated() {
        let mut source: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        source.call::<i32>("AddToStatic", 7i32).unwrap();
        let snapshot = source.snapshot().unwrap();

        let mut target: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        target.restore(snapshot.clone()).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 7);

        target.call::<i32>("AddToStatic", 1000i32).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 1007);

        target.restore(snapshot).unwrap();
        assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 7);
    }

    /// Test that snapshot restore properly resets vCPU debug registers. This test verifies
    /// that restore() calls reset_vcpu().
    #[test]
    fn snapshot_restore_resets_debug_registers() {
        let mut sandbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        let snapshot = sandbox.snapshot().unwrap();

        // Verify DR0 is initially 0 (clean state)
        let dr0_initial: u64 = sandbox.call("GetDr0", ()).unwrap();
        assert_eq!(dr0_initial, 0, "DR0 should initially be 0");

        // Dirty DR0 by setting it to a known non-zero value, avoiding
        // bits that are reserved in aarch64 DBGBVR0_EL1
        const DIRTY_VALUE: u64 = 0xFFFF_FEDC_7654_3210;
        sandbox.call::<()>("SetDr0", DIRTY_VALUE).unwrap();
        let dr0_dirty: u64 = sandbox.call("GetDr0", ()).unwrap();
        assert_eq!(
            dr0_dirty, DIRTY_VALUE,
            "DR0 should be dirty after SetDr0 call"
        );

        // Restore to the snapshot - this should reset vCPU state including debug registers
        sandbox.restore(snapshot).unwrap();

        let dr0_after_restore: u64 = sandbox.call("GetDr0", ()).unwrap();
        assert_eq!(
            dr0_after_restore, 0,
            "DR0 should be 0 after restore (reset_vcpu should have been called)"
        );
    }

    /// Test that stale abort buffer bytes from a previous call don't
    /// leak into the next call.
    #[test]
    fn stale_abort_buffer_does_not_leak_across_calls() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // Simulate a partial abort
        sbox.mem_mgr.abort_buffer.extend_from_slice(&[0xAA; 1020]);

        let res = sbox.call::<String>("Echo", "hello".to_string());
        assert!(
            res.is_ok(),
            "Expected Ok after stale abort buffer, got: {:?}",
            res.unwrap_err()
        );

        // The buffer should be empty after the call.
        assert!(
            sbox.mem_mgr.abort_buffer.is_empty(),
            "abort_buffer should be empty after a guest call"
        );
    }

    /// Test that sandboxes can be created and evolved with different heap sizes
    #[test]
    fn test_sandbox_creation_various_sizes() {
        let test_cases: [(&str, u64); 3] = [
            ("small (8MB heap)", SMALL_HEAP_SIZE),
            ("medium (64MB heap)", MEDIUM_HEAP_SIZE),
            ("large (256MB heap)", LARGE_HEAP_SIZE),
        ];

        for (name, heap_size) in test_cases {
            let mut cfg = SandboxConfiguration::default();
            cfg.set_heap_size(heap_size);
            cfg.set_scratch_size(0x100000);

            let path = simple_guest_as_string().unwrap();
            let sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg))
                .unwrap_or_else(|e| panic!("Failed to create {} sandbox: {}", name, e))
                .evolve()
                .unwrap_or_else(|e| panic!("Failed to evolve {} sandbox: {}", name, e));

            drop(sbox);
        }
    }

    /// Helper: create a MultiUseSandbox from the simple guest with default config.
    #[cfg(feature = "trace_guest")]
    fn sandbox_for_gva_tests() -> MultiUseSandbox {
        let path = simple_guest_as_string().unwrap();
        UninitializedSandbox::new(GuestBinary::FilePath(path), None)
            .unwrap()
            .evolve()
            .unwrap()
    }

    /// Helper: read memory at `gva` of length `len` from the guest side via
    /// `ReadMappedBuffer(gva, len, false)` and from the host side via
    /// `read_guest_memory_by_gva`, then assert both views are identical.
    #[cfg(feature = "trace_guest")]
    fn assert_gva_read_matches(sbox: &mut MultiUseSandbox, gva: u64, len: usize) {
        // Guest reads via its own page tables
        let expected: Vec<u8> = sbox
            .call("ReadMappedBuffer", (gva, len as u64, true))
            .unwrap();
        assert_eq!(expected.len(), len);

        // Host reads by walking the same page tables
        let root_pt = sbox.vm.get_root_pt().unwrap();
        let actual = sbox
            .mem_mgr
            .read_guest_memory_by_gva(gva, len, root_pt)
            .unwrap();

        assert_eq!(
            actual, expected,
            "read_guest_memory_by_gva at GVA {:#x} (len {}) differs from guest ReadMappedBuffer",
            gva, len,
        );
    }

    /// Test reading a small buffer (< 1 page) from guest memory via GVA.
    /// Uses the guest code section which is already identity-mapped.
    #[test]
    #[cfg(feature = "trace_guest")]
    fn read_guest_memory_by_gva_single_page() {
        let mut sbox = sandbox_for_gva_tests();
        let code_gva = sbox.mem_mgr.layout.get_guest_code_address() as u64;
        assert_gva_read_matches(&mut sbox, code_gva, 128);
    }

    /// Test reading exactly one full page (4096 bytes) from guest memory.
    /// Uses the guest code section
    #[test]
    #[cfg(feature = "trace_guest")]
    fn read_guest_memory_by_gva_full_page() {
        let mut sbox = sandbox_for_gva_tests();
        let code_gva = sbox.mem_mgr.layout.get_guest_code_address() as u64;
        assert_gva_read_matches(&mut sbox, code_gva, 4096);
    }

    /// Test that a read starting at an odd (non-page-aligned) address and
    /// spanning two page boundaries returns correct data.
    #[test]
    #[cfg(feature = "trace_guest")]
    fn read_guest_memory_by_gva_unaligned_cross_page() {
        let mut sbox = sandbox_for_gva_tests();
        let code_gva = sbox.mem_mgr.layout.get_guest_code_address() as u64;
        // Start 1 byte before the second page boundary and read 4097 bytes
        // (spans 2 full page boundaries).
        let start = code_gva + 4096 - 1;
        println!(
            "Testing unaligned cross-page read starting at {:#x} spanning 4097 bytes",
            start
        );
        assert_gva_read_matches(&mut sbox, start, 4097);
    }

    /// Test reading exactly two full pages (8192 bytes) from guest memory.
    #[test]
    #[cfg(feature = "trace_guest")]
    fn read_guest_memory_by_gva_two_full_pages() {
        let mut sbox = sandbox_for_gva_tests();
        let code_gva = sbox.mem_mgr.layout.get_guest_code_address() as u64;
        assert_gva_read_matches(&mut sbox, code_gva, 4096 * 2);
    }

    /// Test reading a region that spans across a page boundary: starts
    /// 100 bytes before the end of the first page and reads 200 bytes
    /// into the second page.
    #[test]
    #[cfg(feature = "trace_guest")]
    fn read_guest_memory_by_gva_cross_page_boundary() {
        let mut sbox = sandbox_for_gva_tests();
        let code_gva = sbox.mem_mgr.layout.get_guest_code_address() as u64;
        // Start 100 bytes before the first page boundary, read across it.
        let start = code_gva + 4096 - 100;
        assert_gva_read_matches(&mut sbox, start, 200);
    }

    /// Helper: create a temp file with known content, padded to be
    /// at least page-aligned (4096 bytes). Returns the path and the
    /// *original* content bytes (before padding).
    fn create_test_file(name: &str, content: &[u8]) -> (std::path::PathBuf, Vec<u8>) {
        use std::io::Write;

        let page_size = page_size::get();
        let padded_len = content.len().max(page_size).div_ceil(page_size) * page_size;
        let mut padded = vec![0u8; padded_len];
        padded[..content.len()].copy_from_slice(content);

        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(name);
        let _ = std::fs::remove_file(&path); // clean up from previous runs
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&padded).unwrap();
        (path, content.to_vec())
    }

    /// Tests the basic `map_file_cow` flow: map a file, read its content
    /// from the guest, and verify it matches.
    #[test]
    fn test_map_file_cow_basic() {
        let expected = b"hello world from map_file_cow";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_basic.bin", expected);

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let guest_base: u64 = 0x1_0000_0000;
        let mapped_size = sbox.map_file_cow(&path, guest_base).unwrap();
        assert!(mapped_size > 0, "mapped_size should be positive");
        assert!(
            mapped_size >= expected.len() as u64,
            "mapped_size should be >= file content length"
        );

        // Read the content back from the guest
        let actual: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();

        assert_eq!(
            actual, expected_bytes,
            "Guest should read back the exact file content"
        );

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `map_file_cow` enforces read-only access: writing to
    /// the mapped region from the guest should cause a MemoryAccessViolation.
    #[test]
    fn test_map_file_cow_read_only_enforcement() {
        let content = &[0xBB; 4096];
        let (path, _) = create_test_file("hyperlight_test_map_file_cow_readonly.bin", content);

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let guest_base: u64 = 0x1_0000_0000;
        sbox.map_file_cow(&path, guest_base).unwrap();

        // Writing to the mapped region should fail with MemoryAccessViolation
        let err = sbox
            .call::<bool>("WriteMappedBuffer", (guest_base, content.len() as u64))
            .unwrap_err();

        match err {
            HyperlightError::MemoryAccessViolation(addr, ..) if addr == guest_base => {}
            _ => panic!(
                "Expected MemoryAccessViolation at guest_base, got: {:?}",
                err
            ),
        };

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `map_file_cow` returns `PoisonedSandbox` when the
    /// sandbox is poisoned.
    #[test]
    fn test_map_file_cow_poisoned() {
        let (path, _) = create_test_file("hyperlight_test_map_file_cow_poison.bin", &[0xCC; 4096]);

        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve()
        }
        .unwrap();
        let snapshot = sbox.snapshot().unwrap();

        // Poison the sandbox
        let _ = sbox
            .call::<()>("guest_panic", "hello".to_string())
            .unwrap_err();
        assert!(sbox.poisoned());

        // map_file_cow should fail with PoisonedSandbox
        let err = sbox.map_file_cow(&path, 0x1_0000_0000).unwrap_err();
        assert!(matches!(err, HyperlightError::PoisonedSandbox));

        // Restore and verify map_file_cow works again
        sbox.restore(snapshot).unwrap();
        assert!(!sbox.poisoned());
        let result = sbox.map_file_cow(&path, 0x1_0000_0000);
        assert!(result.is_ok());

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that two separate sandboxes can map the same file
    /// simultaneously and both read it correctly.
    #[test]
    fn test_map_file_cow_multi_vm_same_file() {
        let expected = b"shared file content across VMs";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_multi_vm.bin", expected);

        let guest_base: u64 = 0x1_0000_0000;

        let mut sbox1 = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let mut sbox2 = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        // Map the same file into both sandboxes
        sbox1.map_file_cow(&path, guest_base).unwrap();
        sbox2.map_file_cow(&path, guest_base).unwrap();

        // Both should read the correct content
        let actual1: Vec<u8> = sbox1
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();
        let actual2: Vec<u8> = sbox2
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();

        assert_eq!(
            actual1, expected_bytes,
            "Sandbox 1 should read correct content"
        );
        assert_eq!(
            actual2, expected_bytes,
            "Sandbox 2 should read correct content"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that multiple threads can each create a sandbox, map the
    /// same file, read it, and drop without errors.
    #[test]
    fn test_map_file_cow_multi_vm_threaded() {
        let expected = b"threaded file mapping test data";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_threaded.bin", expected);

        const NUM_THREADS: usize = 5;
        let path = Arc::new(path);
        let expected_bytes = Arc::new(expected_bytes);
        let barrier = Arc::new(Barrier::new(NUM_THREADS));
        let mut handles = vec![];

        for _ in 0..NUM_THREADS {
            let path = path.clone();
            let expected_bytes = expected_bytes.clone();
            let barrier = barrier.clone();

            handles.push(thread::spawn(move || {
                barrier.wait();

                let mut sbox = UninitializedSandbox::new(
                    GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                    None,
                )
                .unwrap()
                .evolve()
                .unwrap();

                let guest_base: u64 = 0x1_0000_0000;
                sbox.map_file_cow(&path, guest_base).unwrap();

                let actual: Vec<u8> = sbox
                    .call(
                        "ReadMappedBuffer",
                        (guest_base, expected_bytes.len() as u64, true),
                    )
                    .unwrap();

                assert_eq!(actual, *expected_bytes);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let _ = std::fs::remove_file(&*path);
    }

    /// Tests that file cleanup works after dropping a sandbox that used
    /// `map_file_cow` — the file should be deletable (no leaked handles).
    #[test]
    #[cfg(target_os = "windows")]
    fn test_map_file_cow_cleanup_no_handle_leak() {
        let (path, _) = create_test_file("hyperlight_test_map_file_cow_cleanup.bin", &[0xDD; 4096]);

        {
            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            sbox.map_file_cow(&path, 0x1_0000_0000).unwrap();
            // sandbox dropped here
        }

        std::fs::remove_file(&path)
            .expect("File should be deletable after sandbox with map_file_cow is dropped");
    }

    /// Tests snapshot/restore cycle with map_file_cow:
    /// snapshot₁ (no file) → map file → snapshot₂ → restore₁ (unmapped)
    /// → restore₂ (data folded into snapshot).
    #[test]
    fn test_map_file_cow_snapshot_remapping_cycle() {
        let expected = b"snapshot remapping cycle test!";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_snapshot_remap.bin", expected);

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let guest_base: u64 = 0x1_0000_0000;

        // 1. snapshot₁ — no file mapped
        let snapshot1 = sbox.snapshot().unwrap();

        // 2. Map the file
        sbox.map_file_cow(&path, guest_base).unwrap();

        // Verify we can read it
        let actual: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();
        assert_eq!(actual, expected_bytes);

        // 3. snapshot₂ — file mapped (data folded into snapshot)
        let snapshot2 = sbox.snapshot().unwrap();

        // 4. Restore to snapshot₁ — file should be unmapped
        sbox.restore(snapshot1.clone()).unwrap();
        let is_mapped: bool = sbox.call("CheckMapped", (guest_base,)).unwrap();
        assert!(
            !is_mapped,
            "Region should be unmapped after restoring to snapshot₁"
        );

        // 5. Restore to snapshot₂ — data should still be readable
        //    (folded into snapshot memory, not the original file mapping)
        sbox.restore(snapshot2).unwrap();
        let is_mapped: bool = sbox.call("CheckMapped", (guest_base,)).unwrap();
        assert!(
            is_mapped,
            "Region should be mapped after restoring to snapshot₂"
        );
        let actual2: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, false),
            )
            .unwrap();
        assert_eq!(
            actual2, expected_bytes,
            "Data should be intact after snapshot₂ restore"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that snapshot correctly captures map_file_cow data and
    /// restore brings it back.
    #[test]
    fn test_map_file_cow_snapshot_restore() {
        let expected = b"snapshot restore basic test!!";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_snap_restore.bin", expected);

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let guest_base: u64 = 0x1_0000_0000;
        sbox.map_file_cow(&path, guest_base).unwrap();

        // Read the content to verify mapping works
        let actual: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();
        assert_eq!(actual, expected_bytes);

        // Take snapshot — folds file data into snapshot memory
        let snapshot = sbox.snapshot().unwrap();

        // Restore — the file-backed region is unmapped but data is in snapshot
        sbox.restore(snapshot).unwrap();

        // Data should still be readable from snapshot memory
        let actual2: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, false),
            )
            .unwrap();
        assert_eq!(
            actual2, expected_bytes,
            "Data should be readable after restore from snapshot"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests the deferred `map_file_cow` flow: map a file on
    /// `UninitializedSandbox` (before evolve), then evolve and verify
    /// the guest can read the mapped content.
    #[test]
    fn test_map_file_cow_deferred_basic() {
        let expected = b"deferred map_file_cow test data";
        let (path, expected_bytes) =
            create_test_file("hyperlight_test_map_file_cow_deferred.bin", expected);

        let guest_base: u64 = 0x1_0000_0000;

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // Map the file before evolving — this defers the VM-side work.
        let mapped_size = u_sbox.map_file_cow(&path, guest_base).unwrap();
        assert!(mapped_size > 0, "mapped_size should be positive");
        assert!(
            mapped_size >= expected.len() as u64,
            "mapped_size should be >= file content length"
        );

        // Evolve — deferred mappings are applied during this step.
        let mut sbox: MultiUseSandbox = u_sbox.evolve().unwrap();

        // Verify the guest can read the mapped content.
        let actual: Vec<u8> = sbox
            .call(
                "ReadMappedBuffer",
                (guest_base, expected_bytes.len() as u64, true),
            )
            .unwrap();

        assert_eq!(
            actual, expected_bytes,
            "Guest should read back the exact file content after deferred mapping"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that dropping an `UninitializedSandbox` with pending
    /// deferred file mappings does not leak or crash — the
    /// `PreparedFileMapping::Drop` should clean up host resources.
    #[test]
    fn test_map_file_cow_deferred_drop_without_evolve() {
        let (path, _) = create_test_file(
            "hyperlight_test_map_file_cow_deferred_drop.bin",
            &[0xAA; 4096],
        );

        let guest_base: u64 = 0x1_0000_0000;

        {
            let mut u_sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap();

            u_sbox.map_file_cow(&path, guest_base).unwrap();
            // u_sbox dropped here without evolving — PreparedFileMapping::drop
            // should clean up host-side OS resources.
        }

        // If we get here without a crash/hang, cleanup worked.
        // On Windows, also verify the file handle was released.
        #[cfg(target_os = "windows")]
        std::fs::remove_file(&path)
            .expect("File should be deletable after dropping UninitializedSandbox");
        #[cfg(not(target_os = "windows"))]
        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `prepare_file_cow` rejects unaligned `guest_base`
    /// addresses eagerly, before allocating any OS resources.
    #[test]
    fn test_map_file_cow_unaligned_guest_base() {
        let (path, _) =
            create_test_file("hyperlight_test_map_file_cow_unaligned.bin", &[0xBB; 4096]);

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // Use an intentionally unaligned address (page_size + 1).
        let unaligned_base: u64 = (page_size::get() + 1) as u64;
        let result = u_sbox.map_file_cow(&path, unaligned_base);
        assert!(
            result.is_err(),
            "map_file_cow should reject unaligned guest_base"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `prepare_file_cow` rejects empty files.
    #[test]
    fn test_map_file_cow_empty_file() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("hyperlight_test_map_file_cow_empty.bin");
        let _ = std::fs::remove_file(&path);
        std::fs::File::create(&path).unwrap(); // create empty file

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        let guest_base: u64 = 0x1_0000_0000;
        let result = u_sbox.map_file_cow(&path, guest_base);
        assert!(result.is_err(), "map_file_cow should reject empty files");

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that mapping two files to overlapping GPA ranges is rejected.
    #[test]
    fn test_map_file_cow_overlapping_mappings() {
        let (path1, _) =
            create_test_file("hyperlight_test_map_file_cow_overlap1.bin", &[0xAA; 4096]);
        let (path2, _) =
            create_test_file("hyperlight_test_map_file_cow_overlap2.bin", &[0xBB; 4096]);

        let guest_base: u64 = 0x1_0000_0000;

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // First mapping should succeed.
        u_sbox.map_file_cow(&path1, guest_base).unwrap();

        // Second mapping at the same address should fail (overlap).
        let result = u_sbox.map_file_cow(&path2, guest_base);
        assert!(
            result.is_err(),
            "map_file_cow should reject overlapping guest address ranges"
        );

        let _ = std::fs::remove_file(&path1);
        let _ = std::fs::remove_file(&path2);
    }

    /// Tests that `map_file_cow` rejects a guest_base that overlaps
    /// the sandbox's shared memory region.
    #[test]
    fn test_map_file_cow_shared_mem_overlap() {
        let (path, _) = create_test_file(
            "hyperlight_test_map_file_cow_overlap_shm.bin",
            &[0xCC; 4096],
        );

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // Use BASE_ADDRESS itself — smack in the middle of shared memory.
        let base_addr = crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS as u64;
        // page-align it (BASE_ADDRESS is 0x1000, already page-aligned)
        let result = u_sbox.map_file_cow(&path, base_addr);
        assert!(
            result.is_err(),
            "map_file_cow should reject guest_base inside shared memory"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn map_region_rejects_overlapping_regions() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        let mem1 = allocate_guest_memory();
        let mem2 = allocate_guest_memory();
        let guest_base: usize = 0x200000000;
        let region1 = region_for_memory(&mem1, guest_base, MemoryRegionFlags::READ);

        // First mapping should succeed
        unsafe { sbox.map_region(&region1).unwrap() };

        // Exact same range should fail
        let region2 = region_for_memory(&mem2, guest_base, MemoryRegionFlags::READ);
        let err = unsafe { sbox.map_region(&region2) }.unwrap_err();
        assert!(
            format!("{err:?}").contains("Overlapping"),
            "Expected Overlapping error, got: {err:?}"
        );
    }

    #[test]
    fn map_region_rejects_partial_overlap() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // Use multi-page regions so partial overlap is geometrically possible
        let mem1 = page_aligned_memory(&[0xAA; 8192]); // 2 pages
        let mem2 = page_aligned_memory(&[0xBB; 8192]); // 2 pages
        let guest_base: usize = 0x200000000;
        let region1 = region_for_memory(&mem1, guest_base, MemoryRegionFlags::READ);

        unsafe { sbox.map_region(&region1).unwrap() };

        // region2 starts one page before region1, overlapping by one page
        let overlap_base = guest_base - 0x1000;
        let region2 = region_for_memory(&mem2, overlap_base, MemoryRegionFlags::READ);
        let err = unsafe { sbox.map_region(&region2) }.unwrap_err();
        assert!(
            format!("{err:?}").contains("verlap"),
            "Expected overlap error for partial overlap, got: {err:?}"
        );
    }

    #[test]
    fn map_region_allows_adjacent_non_overlapping() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        let mem1 = allocate_guest_memory();
        let mem2 = allocate_guest_memory();
        let guest_base: usize = 0x200000000;
        let region1 = region_for_memory(&mem1, guest_base, MemoryRegionFlags::READ);
        let region_size = mem1.mem_size();

        unsafe { sbox.map_region(&region1).unwrap() };

        // Adjacent region (starts right after the first one ends) should succeed
        let adjacent_base = guest_base + region_size;
        let region2 = region_for_memory(&mem2, adjacent_base, MemoryRegionFlags::READ);
        unsafe { sbox.map_region(&region2).unwrap() };
    }

    #[test]
    fn map_region_rejects_overlap_with_snapshot() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // Try to map at BASE_ADDRESS (0x1000) which overlaps the snapshot region
        let mem = allocate_guest_memory();
        let region = region_for_memory(
            &mem,
            crate::mem::layout::SandboxMemoryLayout::BASE_ADDRESS,
            MemoryRegionFlags::READ,
        );
        let err = unsafe { sbox.map_region(&region) }.unwrap_err();
        assert!(
            format!("{err:?}").contains("Overlapping"),
            "Expected Overlapping error for snapshot overlap, got: {err:?}"
        );
    }

    #[test]
    fn map_region_rejects_overlap_with_scratch() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // The scratch region occupies the top of the GPA space
        let scratch_addr = hyperlight_common::layout::scratch_base_gpa(
            crate::sandbox::SandboxConfiguration::DEFAULT_SCRATCH_SIZE,
        ) as usize;
        let mem = allocate_guest_memory();
        let region = region_for_memory(&mem, scratch_addr, MemoryRegionFlags::READ);
        let err = unsafe { sbox.map_region(&region) }.unwrap_err();
        assert!(
            format!("{err:?}").contains("verlap"),
            "Expected overlap error for scratch region, got: {err:?}"
        );
    }

    #[cfg(target_arch = "x86_64")]
    mod msr_tests {
        use super::*;
        use crate::HostFunctions;
        use crate::hypervisor::hyperlight_vm::{CreateHyperlightVmError, HyperlightVmError};
        use crate::hypervisor::virtual_machine::{
            CreateVmError, RegisterError, ResetVcpuError, VmError,
        };
        use crate::sandbox::snapshot::Snapshot;

        const KERNEL_GS_BASE: u32 = 0xC000_0102;
        const SYSENTER_CS: u32 = 0x174;

        fn assert_msr_not_allowable(error: &HyperlightError, expected: u32) {
            assert!(
                matches!(
                    error,
                    HyperlightError::HyperlightVmError(HyperlightVmError::Create(
                        CreateHyperlightVmError::Vm(VmError::CreateVm(
                            CreateVmError::MsrNotAllowable { msr, .. }
                        ))
                    )) if *msr == expected
                ),
                "expected MsrNotAllowable for {expected:#x}, got: {error:?}"
            );
        }

        fn assert_invalid_snapshot_msr(error: &HyperlightError) {
            assert!(
                matches!(
                    error,
                    HyperlightError::HyperlightVmError(HyperlightVmError::Restore(
                        ResetVcpuError::Register(RegisterError::InvalidSnapshotMsrIndex { .. })
                    ))
                ),
                "expected InvalidSnapshotMsrIndex, got: {error:?}"
            );
        }

        fn assert_msr_not_allowed(error: &HyperlightError) {
            assert!(
                matches!(
                    error,
                    HyperlightError::HyperlightVmError(HyperlightVmError::Restore(
                        ResetVcpuError::Register(RegisterError::SnapshotMsrNotAllowed { .. })
                    ))
                ),
                "expected SnapshotMsrNotAllowed, got: {error:?}"
            );
        }

        #[test]
        fn kernel_gs_base_does_not_leak_through_swapgs() {
            let mut sandbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let original: u64 = sandbox.call("ReadKernelGsBaseViaSwapgs", ()).unwrap();
            let sentinel = if original == 0x0000_7AAA_5555_AAAA {
                0x0000_6BBB_4444_BBBB
            } else {
                0x0000_7AAA_5555_AAAA
            };
            let snapshot = sandbox.snapshot().unwrap();

            sandbox
                .call::<()>("WriteKernelGsBaseViaSwapgs", sentinel)
                .unwrap();
            assert_eq!(
                sandbox
                    .call::<u64>("ReadKernelGsBaseViaSwapgs", ())
                    .unwrap(),
                sentinel
            );

            sandbox.restore(snapshot).unwrap();
            assert_eq!(
                sandbox
                    .call::<u64>("ReadKernelGsBaseViaSwapgs", ())
                    .unwrap(),
                original,
                "KERNEL_GS_BASE leaked across restore"
            );
        }

        #[test]
        fn snapshot_msr_values_survive_full_in_memory_lifecycle() {
            let mut config = SandboxConfiguration::default();
            config.allow_msrs(&[KERNEL_GS_BASE]).unwrap();
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            let first = 0x1111;
            let second = 0x2222;
            let third = 0x3333;

            source
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, first))
                .unwrap();
            assert_eq!(
                source.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                first
            );
            let first_snapshot = source.snapshot().unwrap();

            source
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, second))
                .unwrap();
            assert_eq!(
                source.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                second
            );
            source.restore(first_snapshot.clone()).unwrap();
            assert_eq!(
                source.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                first
            );

            let mut clone = MultiUseSandbox::from_snapshot(
                first_snapshot.clone(),
                HostFunctions::default(),
                Some(config),
            )
            .unwrap();
            assert_eq!(clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(), first);

            clone
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, third))
                .unwrap();
            assert_eq!(clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(), third);
            let third_snapshot = clone.snapshot().unwrap();
            source.restore(third_snapshot.clone()).unwrap();
            assert_eq!(
                source.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                third
            );

            let mut second_clone = MultiUseSandbox::from_snapshot(
                third_snapshot,
                HostFunctions::default(),
                Some(config),
            )
            .unwrap();
            assert_eq!(
                second_clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                third
            );
            second_clone.restore(first_snapshot).unwrap();
            assert_eq!(
                second_clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                first
            );
        }

        #[test]
        fn equivalent_msr_configs_are_order_independent_across_sandboxes() {
            let source_order = [KERNEL_GS_BASE, SYSENTER_CS];
            let target_order = [SYSENTER_CS, KERNEL_GS_BASE];
            let mut source_config = SandboxConfiguration::default();
            source_config.allow_msrs(&source_order).unwrap();
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(source_config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            source
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, 0x4444u64))
                .unwrap();
            assert_eq!(
                source.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                0x4444
            );
            source
                .call::<()>("WriteMSR", (SYSENTER_CS, 0x5555u64))
                .unwrap();
            assert_eq!(source.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(), 0x5555);
            let snapshot = source.snapshot().unwrap();

            let mut target_config = SandboxConfiguration::default();
            target_config.allow_msrs(&target_order).unwrap();
            let mut target = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(target_config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            target
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, 0xAAAAu64))
                .unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                0xAAAA
            );
            target
                .call::<()>("WriteMSR", (SYSENTER_CS, 0xBBBBu64))
                .unwrap();
            assert_eq!(target.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(), 0xBBBB);
            target.restore(snapshot.clone()).unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                0x4444
            );
            assert_eq!(target.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(), 0x5555);

            let mut clone = MultiUseSandbox::from_snapshot(
                snapshot,
                HostFunctions::default(),
                Some(target_config),
            )
            .unwrap();
            assert_eq!(
                clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                0x4444
            );
            assert_eq!(clone.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(), 0x5555);
        }

        /// A restore succeeds when the destination allow list is a superset
        /// of the snapshot's. The snapshot's allowed MSR keeps its captured
        /// value. An MSR the destination adds resets to the baseline.
        #[test]
        fn snapshot_restores_into_superset_allow_list() {
            const SYSENTER_ESP: u32 = 0x175;
            let sentinel: u64 = 0x1234;
            let mut source_config = SandboxConfiguration::default();
            source_config.allow_msrs(&[SYSENTER_CS]).unwrap();
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(source_config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            source
                .call::<()>("WriteMSR", (SYSENTER_CS, sentinel))
                .unwrap();
            let snapshot = source.snapshot().unwrap();

            let mut dest_config = SandboxConfiguration::default();
            dest_config
                .allow_msrs(&[SYSENTER_CS, SYSENTER_ESP])
                .unwrap();

            let mut clone = MultiUseSandbox::from_snapshot(
                snapshot.clone(),
                HostFunctions::default(),
                Some(dest_config),
            )
            .unwrap();
            assert_eq!(clone.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(), sentinel);
            let baseline: u64 = clone.call("ReadMSR", SYSENTER_ESP).unwrap();

            let mut target = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(dest_config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            target
                .call::<()>("WriteMSR", (SYSENTER_ESP, baseline ^ 0x55))
                .unwrap();
            target.restore(snapshot).unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", SYSENTER_CS).unwrap(),
                sentinel
            );
            // An MSR the destination adds resets to its baseline.
            assert_eq!(
                target.call::<u64>("ReadMSR", SYSENTER_ESP).unwrap(),
                baseline
            );
        }

        /// A restore is rejected when the snapshot allows an MSR the
        /// destination does not. Both restore paths fail and poison the
        /// sandbox.
        #[test]
        fn snapshot_rejects_non_superset_allow_list() {
            const SYSENTER_ESP: u32 = 0x175;
            let mut source_config = SandboxConfiguration::default();
            source_config.allow_msrs(&[SYSENTER_CS]).unwrap();
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(source_config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            source
                .call::<()>("WriteMSR", (SYSENTER_CS, 0x1234u64))
                .unwrap();
            let snapshot = source.snapshot().unwrap();

            // A destination that allows nothing, and one that allows a
            // disjoint MSR, both fail the superset check.
            for dest in [&[][..], &[SYSENTER_ESP][..]] {
                let mut config = SandboxConfiguration::default();
                config.allow_msrs(dest).unwrap();

                let err = MultiUseSandbox::from_snapshot(
                    snapshot.clone(),
                    HostFunctions::default(),
                    Some(config),
                )
                .expect_err("from_snapshot must reject a non-superset allow list");
                assert_msr_not_allowed(&err);

                let mut target = UninitializedSandbox::new(
                    GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                    Some(config),
                )
                .unwrap()
                .evolve()
                .unwrap();
                let err = target
                    .restore(snapshot.clone())
                    .expect_err("restore must reject a non-superset allow list");
                assert_msr_not_allowed(&err);
                assert!(target.poisoned());
                assert!(matches!(
                    target.call::<String>("Echo", "hi".to_string()),
                    Err(HyperlightError::PoisonedSandbox)
                ));
            }
        }

        #[test]
        fn from_pre_init_snapshot_uses_local_msr_reset_set() {
            let mut config = SandboxConfiguration::default();
            config.allow_msrs(&[KERNEL_GS_BASE]).unwrap();
            let snapshot = Arc::new(
                Snapshot::from_env(
                    GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                    config,
                )
                .unwrap(),
            );
            assert!(snapshot.msrs().is_none());

            let mut sandbox = MultiUseSandbox::from_snapshot(
                snapshot.clone(),
                HostFunctions::default(),
                Some(config),
            )
            .unwrap();
            let baseline: u64 = sandbox.call("ReadMSR", KERNEL_GS_BASE).unwrap();
            sandbox
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, baseline ^ 0x55))
                .unwrap();
            assert_eq!(
                sandbox.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                baseline ^ 0x55
            );
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn snapshot_without_msrs_uses_destination_reset_set() {
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();
            let snapshot = source.snapshot().unwrap();
            source.snapshot = None;
            let Ok(mut snap) = Arc::try_unwrap(snapshot) else {
                panic!("snapshot should be uniquely owned");
            };
            // A snapshot without MSRs uses the destination baseline.
            snap.set_msrs(None);
            snap.set_allowed_msrs(None);
            let snapshot = Arc::new(snap);

            let mut config = SandboxConfiguration::default();
            config.allow_msrs(&[KERNEL_GS_BASE]).unwrap();
            let mut target = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            let baseline: u64 = target.call("ReadMSR", KERNEL_GS_BASE).unwrap();
            target
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, baseline ^ 0x55))
                .unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                baseline ^ 0x55
            );
            target.restore(snapshot.clone()).unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                baseline
            );
            target
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, baseline ^ 0xAA))
                .unwrap();
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                baseline ^ 0xAA
            );

            let mut clone =
                MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), Some(config))
                    .unwrap();
            let clone_baseline: u64 = clone.call("ReadMSR", KERNEL_GS_BASE).unwrap();
            clone
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, clone_baseline ^ 0xCC))
                .unwrap();
            assert_eq!(
                clone.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                clone_baseline ^ 0xCC
            );
        }

        #[test]
        fn malformed_snapshot_msrs_poison_and_trusted_restore_recovers() {
            let indices = [SYSENTER_CS, KERNEL_GS_BASE];
            let mut config = SandboxConfiguration::default();
            config.allow_msrs(&indices).unwrap();
            let mut source = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            let snapshot = source.snapshot().unwrap();
            source.snapshot = None;
            let Ok(mut snapshot) = Arc::try_unwrap(snapshot) else {
                panic!("snapshot should be uniquely owned");
            };
            let mut msrs = snapshot.msrs().unwrap().clone();
            msrs[0].index = 0xDEAD;
            snapshot.set_msrs(Some(msrs));
            let snapshot = Arc::new(snapshot);

            let error = MultiUseSandbox::from_snapshot(
                snapshot.clone(),
                HostFunctions::default(),
                Some(config),
            )
            .expect_err("from_snapshot must reject malformed snapshot MSRs");
            assert_invalid_snapshot_msr(&error);

            let mut target = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(config),
            )
            .unwrap()
            .evolve()
            .unwrap();
            let trusted_value: u64 = target.call("ReadMSR", KERNEL_GS_BASE).unwrap();
            let recovery_snapshot = target.snapshot().unwrap();
            target
                .call::<()>("WriteMSR", (KERNEL_GS_BASE, trusted_value ^ 0x55))
                .unwrap();
            let error = target
                .restore(snapshot)
                .expect_err("restore must reject malformed snapshot MSRs");
            assert_invalid_snapshot_msr(&error);
            assert!(target.poisoned());
            assert!(matches!(
                target.call::<String>("Echo", "hi".to_string()),
                Err(HyperlightError::PoisonedSandbox)
            ));

            target.restore(recovery_snapshot).unwrap();
            assert!(!target.poisoned());
            assert_eq!(
                target.call::<u64>("ReadMSR", KERNEL_GS_BASE).unwrap(),
                trusted_value
            );
        }

        #[test]
        #[cfg(kvm)]
        fn denied_msr_access_poisons_sandbox() {
            use crate::hypervisor::virtual_machine::{HypervisorType, get_available_hypervisor};

            match get_available_hypervisor() {
                Some(HypervisorType::Kvm) => {}
                _ => {
                    return;
                }
            }

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let snapshot = sbox.snapshot().unwrap();
            let msr_index: u32 = 0xC000_0102; // IA32_KERNEL_GS_BASE

            let result = sbox.call::<u64>("ReadMSR", msr_index);
            assert!(
                matches!(
                    &result,
                    Err(HyperlightError::MsrReadViolation(idx)) if *idx == msr_index
                ),
                "RDMSR 0x{:X}: expected MsrReadViolation, got: {:?}",
                msr_index,
                result
            );
            assert!(sbox.poisoned());

            sbox.restore(snapshot.clone()).unwrap();

            let result = sbox.call::<()>("WriteMSR", (msr_index, 0x5u64));
            assert!(
                matches!(
                    &result,
                    Err(HyperlightError::MsrWriteViolation(idx, _)) if *idx == msr_index
                ),
                "WRMSR 0x{:X}: expected MsrWriteViolation, got: {:?}",
                msr_index,
                result
            );
            assert!(sbox.poisoned());
        }

        /// A write-only command cannot enter the reset set.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_allow_non_resettable_msr_fails_creation() {
            let mut cfg = SandboxConfiguration::default();
            cfg.allow_msrs(&[0x49]).unwrap(); // IA32_PRED_CMD, a write-only command MSR

            let err = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(cfg),
            )
            .unwrap()
            .evolve()
            .unwrap_err();

            assert_msr_not_allowable(&err, 0x49);
        }

        /// Host support cannot authorize an unclassified MSR.
        #[test]
        #[cfg(kvm)]
        fn unclassified_allowed_msr_rejected_at_creation() {
            use crate::hypervisor::virtual_machine::{HypervisorType, get_available_hypervisor};

            if !matches!(get_available_hypervisor(), Some(HypervisorType::Kvm)) {
                return;
            }

            let mut cfg = SandboxConfiguration::default();
            cfg.allow_msrs(&[0x1A0]).unwrap(); // IA32_MISC_ENABLE: host-probeable, not in MSR_TABLE

            let err = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(cfg),
            )
            .unwrap()
            .evolve()
            .expect_err("an unclassified allowed MSR must be rejected at creation");

            assert_msr_not_allowable(&err, 0x1A0);
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_multiple_allowed_msrs_reset_across_restore() {
            // Resettable MSRs the guest may write once allowed.
            let msrs: [u32; 4] = [0x174, 0x175, 0x176, 0xC000_0102];
            let mut cfg = SandboxConfiguration::default();
            cfg.allow_msrs(&msrs).unwrap();

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(cfg),
            )
            .unwrap()
            .evolve()
            .unwrap();

            let baseline_snapshot = sbox.snapshot().unwrap();

            let value: u64 = 0x1000;
            for &msr in &msrs {
                sbox.call::<()>("WriteMSR", (msr, value)).unwrap();
                let read_value: u64 = sbox.call("ReadMSR", msr).unwrap();
                assert_eq!(read_value, value, "MSR 0x{msr:X} should be writable");
            }

            sbox.restore(baseline_snapshot).unwrap();
            for &msr in &msrs {
                let read_value: u64 = sbox.call("ReadMSR", msr).unwrap();
                assert_ne!(
                    read_value, value,
                    "MSR 0x{msr:X} should be reset to baseline across restore"
                );
            }
        }

        /// An allowed guest write must not survive restore.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn test_allowed_msr_does_not_leak_across_restore() {
            let msr_index: u32 = 0xC000_0102; // IA32_KERNEL_GS_BASE
            let sentinel: u64 = 0xCAFE_F00D;

            let mut cfg = SandboxConfiguration::default();
            cfg.allow_msrs(&[msr_index]).unwrap();
            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                Some(cfg),
            )
            .unwrap()
            .evolve()
            .unwrap();

            let baseline = sbox.snapshot().unwrap();
            let original: u64 = sbox.call("ReadMSR", msr_index).unwrap();
            assert_ne!(
                original, sentinel,
                "test sentinel must differ from the baseline value"
            );

            sbox.call::<()>("WriteMSR", (msr_index, sentinel)).unwrap();
            assert_eq!(
                sbox.call::<u64>("ReadMSR", msr_index).unwrap(),
                sentinel,
                "sentinel should be observable before restore"
            );
            sbox.restore(baseline).unwrap();

            let after: u64 = sbox.call("ReadMSR", msr_index).unwrap();
            assert_ne!(after, sentinel, "sentinel leaked across restore");
            assert_eq!(after, original, "MSR not reset to its baseline value");
        }

        /// KVM denies DEBUGCTL through its filter and x2APIC through xAPIC mode.
        #[test]
        #[cfg(all(kvm, target_arch = "x86_64"))]
        fn test_debugctl_and_x2apic_msr_denied_by_default() {
            use crate::hypervisor::virtual_machine::{HypervisorType, get_available_hypervisor};

            if !matches!(get_available_hypervisor(), Some(HypervisorType::Kvm)) {
                return;
            }

            let cases: [(u32, bool); 2] = [(0x1D9, true), (0x800, false)];
            for (msr_index, expect_filter_violation) in cases {
                let mut sbox = UninitializedSandbox::new(
                    GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                    None,
                )
                .unwrap()
                .evolve()
                .unwrap();

                let result = sbox.call::<()>("WriteMSR", (msr_index, 0x1u64));
                if expect_filter_violation {
                    assert!(
                        matches!(
                            &result,
                            Err(HyperlightError::MsrWriteViolation(idx, _)) if *idx == msr_index
                        ),
                        "WRMSR 0x{msr_index:X}: expected MsrWriteViolation, got: {result:?}"
                    );
                } else {
                    assert!(
                        matches!(&result, Err(HyperlightError::GuestAborted(_, _))),
                        "WRMSR 0x{msr_index:X}: expected direct #GP, got: {result:?}"
                    );
                }
                assert!(
                    sbox.poisoned(),
                    "sandbox should be poisoned after a denied WRMSR to 0x{msr_index:X}"
                );
            }
        }

        /// A rejected MSR restore poisons the sandbox on every backend.
        ///
        /// The host register set rejects the noncanonical KERNEL_GS_BASE value
        /// on KVM, MSHV, and WHP alike, leaving the sandbox poisoned.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn rejected_msr_restore_poisons_sandbox() {
            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let baseline = sbox.snapshot().unwrap();
            sbox.snapshot = None;
            let Ok(mut snap) = Arc::try_unwrap(baseline) else {
                panic!("snapshot should be uniquely owned after clearing the cache");
            };
            // A noncanonical KERNEL_GS_BASE value the host set rejects.
            let mut msrs = snap.msrs().unwrap().clone();
            let kernel_gs_base = msrs
                .iter_mut()
                .find(|entry| entry.index == 0xC000_0102)
                .expect("KERNEL_GS_BASE should be in the reset set");
            kernel_gs_base.value = 0xDEAD_0000_0000_0000;
            snap.set_msrs(Some(msrs));
            let snap = Arc::new(snap);

            let err = sbox
                .restore(snap)
                .expect_err("restore should fail on a rejected MSR set");
            assert!(
                format!("{err:?}").to_lowercase().contains("msr")
                    || format!("{err:?}").to_lowercase().contains("restore"),
                "expected an MSR restore error, got: {err:?}"
            );
            assert!(
                sbox.poisoned(),
                "sandbox should be poisoned after failed restore"
            );

            let call = sbox.call::<String>("Echo", "hi".to_string());
            assert!(
                matches!(call, Err(HyperlightError::PoisonedSandbox)),
                "poisoned sandbox should reject guest calls, got: {call:?}"
            );
        }

        /// Unresettable feature-class MSRs must not retain guest writes. PMU,
        /// LBR, and FRED are perfmon or feature gated. The AMD virtualization
        /// MSRs are gated on nested-virt capability the sandbox never requests.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn unresettable_msr_classes_do_not_leak() {
            let cases: &[(u32, &str)] = &[
                (0xC1, "PMU IA32_PMC0"),
                (0x186, "PMU IA32_PERFEVTSEL0"),
                (0x38F, "PMU IA32_PERF_GLOBAL_CTRL"),
                (0x1C8, "LBR_SELECT"),
                (0x14CE, "arch-LBR IA32_LBR_CTL"),
                (0x1D4, "FRED IA32_FRED_CONFIG"),
                (0xC001_0114, "AMD VM_CR"),
                (0xC001_0117, "AMD VM_HSAVE_PA"),
            ];

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            for &(msr, _name) in cases {
                assert_msr_write_does_not_survive_restore(&mut sbox, msr, 0x1);
            }
        }

        /// A guest write to IA32_MISC_ENABLE leaves no retained state. Hyper-V
        /// drops the write on Intel and faults it on AMD.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn misc_enable_guest_write_does_not_survive_restore() {
            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();
            assert_msr_write_does_not_survive_restore(&mut sbox, 0x1A0, 1u64 << 40);
        }

        /// Every stateful table entry needs runtime reset coverage.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn runtime_msr_table_entries_are_justified() {
            use crate::hypervisor::regs::core_reset_indices;

            #[cfg(kvm)]
            let kernel_gs_uses_instruction_side_effect = matches!(
                crate::hypervisor::virtual_machine::get_available_hypervisor(),
                Some(crate::hypervisor::virtual_machine::HypervisorType::Kvm)
            );
            #[cfg(not(kvm))]
            let kernel_gs_uses_instruction_side_effect = false;

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let reset_indices: Vec<u32> = sbox
                .snapshot()
                .unwrap()
                .msrs()
                .expect("filterless backend should have an MSR reset set")
                .iter()
                .map(|entry| entry.index)
                .collect();

            for index in core_reset_indices() {
                if !reset_indices.contains(&index) {
                    assert_omitted_msr_does_not_retain(&mut sbox, index);
                } else if kernel_gs_uses_instruction_side_effect && index == KERNEL_GS_BASE {
                    // Direct WRMSR is denied. The dedicated SWAPGS test proves
                    // the instruction-side mutation is restored.
                } else if (index == 0x10 && !kernel_gs_uses_instruction_side_effect)
                    || matches!(index, 0xE7 | 0xE8)
                {
                    assert_guest_counter_is_writable_and_restored(&mut sbox, index);
                } else if let Some(sentinel) = positive_write_sentinel(index) {
                    assert_guest_msr_is_writable_and_restored(&mut sbox, index, sentinel);
                } else {
                    assert!(
                        reset_exception_reason(index).is_some(),
                        "MSR 0x{index:X} is in the reset set without positive guest-write coverage or an explicit reason"
                    );
                }
            }
        }

        fn assert_omitted_msr_does_not_retain(sbox: &mut MultiUseSandbox, index: u32) {
            let baseline = sbox.snapshot().unwrap();
            let original: u64 = match sbox.call("ReadMSR", index) {
                Ok(value) => value,
                Err(_) => {
                    assert!(sbox.poisoned(), "0x{index:X}: fault did not poison sandbox");
                    sbox.restore(baseline).unwrap();
                    return;
                }
            };
            let preferred = positive_write_sentinel(index).unwrap_or(original ^ 1);
            let candidates = [preferred, original ^ 1, original ^ 2, 0, 1, 0x1000];

            for candidate in candidates {
                if candidate == original {
                    continue;
                }
                if sbox.call::<()>("WriteMSR", (index, candidate)).is_err() {
                    assert!(sbox.poisoned(), "0x{index:X}: fault did not poison sandbox");
                    sbox.restore(baseline.clone()).unwrap();
                    continue;
                }
                let written: u64 = sbox.call("ReadMSR", index).unwrap_or_else(|error| {
                    panic!("0x{index:X}: read after successful write failed: {error:?}")
                });
                if written != original {
                    sbox.restore(baseline).unwrap();
                    let after: u64 = sbox.call("ReadMSR", index).unwrap();
                    assert_eq!(
                        after, original,
                        "0x{index:X}: guest retained a write but the MSR is absent from the reset set"
                    );
                    return;
                }
                sbox.restore(baseline.clone()).unwrap();
            }
        }

        fn positive_write_sentinel(index: u32) -> Option<u64> {
            match index {
                0x174 => Some(0x10),                          // SYSENTER_CS
                0x175 | 0x176 => Some(0x1000),                // SYSENTER_ESP/EIP
                0x277 => Some(0x0007_0406_0007_0406),         // PAT
                0xC000_0081 => Some(0x001B_0008_0000_0000),   // STAR
                0xC000_0082 | 0xC000_0083 => Some(0x1000),    // LSTAR/CSTAR
                0xC000_0084 => Some(0x200),                   // SFMASK
                0xC000_0102 => Some(0x1000),                  // KERNEL_GS_BASE
                0x3B => Some(0x1000),                         // TSC_ADJUST
                0xC000_0103 => Some(0x5),                     // TSC_AUX
                0x2FF => Some(0xC00),                         // MTRR_DEF_TYPE
                0x200..=0x21F if index & 1 == 0 => Some(0x6), // MTRR_PHYSBASEn
                0x200..=0x21F => Some(0x800),                 // MTRR_PHYSMASKn
                0x250 | 0x258 | 0x259 | 0x268..=0x26F => Some(0x0606_0606_0606_0606),
                _ => None,
            }
        }

        fn reset_exception_reason(index: u32) -> Option<&'static str> {
            match index {
                0x10 => Some("KVM denies direct guest TSC MSR access"),
                0x1D9 => Some("DEBUGCTL support depends on exposed debug features"),
                0x48 => Some("SPEC_CTRL writable bits depend on mitigation features"),
                0x6A0 | 0x6A2 | 0x6A4..=0x6A8 => {
                    Some("CET writable state depends on exposed CET features")
                }
                0x122 => Some("TSX_CTRL writable bits depend on exposed TSX features"),
                0x1C4 | 0x1C5 => Some("XFD writable bits depend on exposed XSAVE features"),
                0xE1 => Some("UMWAIT_CONTROL writable bits depend on exposed WAITPKG features"),
                0x6E0 => Some("TSC_DEADLINE writable bits depend on exposed APIC-timer features"),
                0xD90 => Some("BNDCFGS writable bits depend on exposed MPX features"),
                0xDA0 => Some("XSS writable bits depend on exposed XSAVE features"),
                0xC001_011F => {
                    Some("VIRT_SPEC_CTRL writable bits depend on exposed AMD SSBD virtualization")
                }
                _ => None,
            }
        }

        fn assert_guest_msr_is_writable_and_restored(
            sbox: &mut MultiUseSandbox,
            index: u32,
            sentinel: u64,
        ) {
            let baseline = sbox.snapshot().unwrap();
            let original: u64 = sbox
                .call("ReadMSR", index)
                .unwrap_or_else(|error| panic!("0x{index:X}: guest RDMSR failed: {error:?}"));
            let value = if original == sentinel { 0 } else { sentinel };

            sbox.call::<()>("WriteMSR", (index, value))
                .unwrap_or_else(|error| panic!("0x{index:X}: guest WRMSR failed: {error:?}"));
            let written: u64 = sbox
                .call("ReadMSR", index)
                .unwrap_or_else(|error| panic!("0x{index:X}: guest read-back failed: {error:?}"));
            assert_eq!(written, value, "0x{index:X}: guest write did not stick");

            sbox.restore(baseline).unwrap();
            let restored: u64 = sbox.call("ReadMSR", index).unwrap();
            assert_eq!(
                restored, original,
                "0x{index:X}: restore did not recover the baseline"
            );
        }

        fn assert_guest_counter_is_writable_and_restored(sbox: &mut MultiUseSandbox, index: u32) {
            let baseline = sbox.snapshot().unwrap();
            let original: u64 = sbox.call("ReadMSR", index).unwrap();
            let jump = original.wrapping_add(1 << 60);

            sbox.call::<()>("WriteMSR", (index, jump)).unwrap();
            let written: u64 = sbox.call("ReadMSR", index).unwrap();
            assert!(
                written >= jump / 2,
                "0x{index:X}: guest write did not stick"
            );

            sbox.restore(baseline).unwrap();
            let restored: u64 = sbox.call("ReadMSR", index).unwrap();
            assert!(
                restored < jump / 2,
                "0x{index:X}: restore did not pull the counter below the guest-written jump"
            );
        }

        /// Verifies that a guest MSR write faults or resets to its baseline.
        #[cfg(target_arch = "x86_64")]
        fn assert_msr_write_does_not_survive_restore(
            sbox: &mut MultiUseSandbox,
            msr: u32,
            sentinel: u64,
        ) {
            let baseline = sbox.snapshot().unwrap();
            let original: u64 = match sbox.call("ReadMSR", msr) {
                Ok(v) => v,
                Err(_) => {
                    assert!(
                        sbox.poisoned(),
                        "0x{msr:X}: a faulting RDMSR should poison the sandbox"
                    );
                    sbox.restore(baseline).unwrap();
                    return;
                }
            };
            assert_ne!(
                original, sentinel,
                "0x{msr:X}: sentinel must differ from baseline"
            );

            if sbox.call::<()>("WriteMSR", (msr, sentinel)).is_err() {
                assert!(
                    sbox.poisoned(),
                    "0x{msr:X}: a faulting WRMSR should poison the sandbox"
                );
                sbox.restore(baseline).unwrap();
                return;
            }

            sbox.restore(baseline).unwrap();
            let after: u64 = sbox.call("ReadMSR", msr).unwrap();
            assert_eq!(
                after, original,
                "0x{msr:X}: MSR leaked across restore (expected 0x{original:X}, got 0x{after:X})"
            );
        }

        /// Audits Hyper-V MSR bitmap ranges for guest state retained by restore.
        #[test]
        #[ignore = "slow host-dependent hardware MSR audit"]
        #[cfg(target_arch = "x86_64")]
        fn test_no_msr_leaks_across_restore_full_window_sweep() {
            // Free-running counters use a magnitude check after restore.
            const FREE_RUNNING: &[u32] = &[
                0x10, // IA32_TIME_STAMP_COUNTER
                0xE7, // IA32_MPERF
                0xE8, // IA32_APERF
            ];

            #[cfg(kvm)]
            if matches!(
                crate::hypervisor::virtual_machine::get_available_hypervisor(),
                Some(crate::hypervisor::virtual_machine::HypervisorType::Kvm)
            ) {
                return;
            }

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let baseline = sbox.snapshot().unwrap();

            // At least one retained write must exercise restore.
            let mut readable = 0usize;
            let mut exercised: Vec<u32> = Vec::new();
            let mut read_only: Vec<u32> = Vec::new();
            let mut masked_only: Vec<u32> = Vec::new();
            // Collect all free-running leaks for one diagnostic.
            let mut free_running_leaked: Vec<u32> = Vec::new();

            // Architectural and low model-specific indices.
            let low = 0x0000_0000u32..=0x0000_1FFF;
            // Hyper-V synthetic indices.
            let hyperv_synthetic = 0x4000_0000u32..=0x4000_1FFF;
            // Extended and AMD model-specific indices.
            let extended = 0xC000_0000u32..=0xC001_FFFF;
            let windows = low.chain(hyperv_synthetic).chain(extended);
            for msr in windows {
                let original: u64 = match sbox.call("ReadMSR", msr) {
                    Ok(v) => v,
                    Err(_) => {
                        sbox.restore(baseline.clone()).unwrap();
                        continue;
                    }
                };
                readable += 1;

                // A large jump distinguishes reset from normal counter progress.
                if FREE_RUNNING.contains(&msr) {
                    let jump = original.wrapping_add(1 << 60);
                    if sbox.call::<()>("WriteMSR", (msr, jump)).is_err() {
                        sbox.restore(baseline.clone()).unwrap();
                        read_only.push(msr);
                        continue;
                    }
                    let planted = match sbox.call::<u64>("ReadMSR", msr) {
                        Ok(v) => v,
                        Err(_) => {
                            sbox.restore(baseline.clone()).unwrap();
                            masked_only.push(msr);
                            continue;
                        }
                    };
                    if planted < jump / 2 {
                        sbox.restore(baseline.clone()).unwrap();
                        masked_only.push(msr);
                        continue;
                    }
                    sbox.restore(baseline.clone()).unwrap();
                    let after: u64 = sbox.call("ReadMSR", msr).unwrap();
                    if after < jump / 2 {
                        exercised.push(msr);
                    } else {
                        free_running_leaked.push(msr);
                    }
                    continue;
                }

                // Multiple candidates cover MSRs with restricted writable bits.
                let candidates = [
                    original ^ 0x55,
                    original ^ 0x1,
                    original ^ (1 << 12),
                    original ^ (1 << 20),
                    original ^ (1 << 32),
                    original.wrapping_add(1),
                    0,
                ];
                let mut planted = false;
                let mut saw_write = false;
                for cand in candidates {
                    if cand == original {
                        continue;
                    }
                    if sbox.call::<()>("WriteMSR", (msr, cand)).is_err() {
                        sbox.restore(baseline.clone()).unwrap();
                        continue;
                    }
                    saw_write = true;
                    match sbox.call::<u64>("ReadMSR", msr) {
                        Ok(v) if v != original => {
                            planted = true;
                            break;
                        }
                        _ => {
                            sbox.restore(baseline.clone()).unwrap();
                        }
                    }
                }

                if planted {
                    sbox.restore(baseline.clone()).unwrap();
                    match sbox.call::<u64>("ReadMSR", msr) {
                        Ok(after) => assert_eq!(
                            after, original,
                            "0x{msr:X}: a guest MSR write leaked across restore \
                         (expected 0x{original:X}, got 0x{after:X})"
                        ),
                        Err(e) => panic!("0x{msr:X}: read-back after restore failed: {e:?}"),
                    }
                    exercised.push(msr);
                } else if saw_write {
                    masked_only.push(msr);
                } else {
                    read_only.push(msr);
                }
            }

            let fmt = |v: &[u32]| {
                v.iter()
                    .map(|m| format!("0x{m:X}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            eprintln!(
                "full-window MSR sweep: readable={readable} exercised={} masked_only={} read_only={}",
                exercised.len(),
                masked_only.len(),
                read_only.len()
            );
            eprintln!("  exercised:   [{}]", fmt(&exercised));
            eprintln!("  masked_only: [{}]", fmt(&masked_only));
            eprintln!("  read_only:   [{}]", fmt(&read_only));
            eprintln!("  free_running_leaked: [{}]", fmt(&free_running_leaked));
            assert!(
                free_running_leaked.is_empty(),
                "free-running MSRs not reset across restore on this backend: [{}]",
                fmt(&free_running_leaked)
            );
            assert!(
                !exercised.is_empty(),
                "sweep was vacuous: no guest MSR write ever retained a value that restore \
             then rolled back, so the rollback path was never exercised"
            );
        }

        /// A host TSC write must reset the guest-visible MSHV counter.
        #[test]
        #[cfg(all(mshv3, target_arch = "x86_64"))]
        fn mshv_host_tsc_writeback_resets_guest_tsc() {
            use crate::hypervisor::virtual_machine::{HypervisorType, get_available_hypervisor};

            if !matches!(get_available_hypervisor(), Some(HypervisorType::Mshv)) {
                return;
            }

            let mut sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap()
            .evolve()
            .unwrap();

            let base = sbox.vm.capture_msrs_for_test(&[0x10]).unwrap()[0].value;

            let jump = base.wrapping_add(1 << 60);
            sbox.call::<()>("WriteMSR", (0x10u32, jump)).unwrap();
            let planted: u64 = sbox.call("ReadMSR", 0x10u32).unwrap();
            assert!(
                planted >= jump,
                "guest TSC write did not take (planted=0x{planted:X} jump=0x{jump:X})"
            );

            assert!(
                sbox.vm.try_set_msr_for_test(0x10, base),
                "host set of HV_X64_REGISTER_TSC failed"
            );

            let after: u64 = sbox.call("ReadMSR", 0x10u32).unwrap();
            eprintln!(
                "mshv TSC writeback probe: base=0x{base:X} jump=0x{jump:X} planted=0x{planted:X} after=0x{after:X}"
            );
            assert!(
                after < jump / 2,
                "host TSC write-back did NOT reset the guest TSC (after=0x{after:X} still near \
                 jump=0x{jump:X}); the reset approach is not viable on this host"
            );
        }
    }

    /// Tests for [`MultiUseSandbox::from_snapshot`] in-memory.
    mod from_snapshot {
        use std::sync::Arc;

        use hyperlight_testing::simple_guest_as_string;

        use crate::func::Registerable;
        use crate::sandbox::SandboxConfiguration;
        use crate::sandbox::snapshot::Snapshot;
        use crate::{
            GuestBinary, HostFunctions, HyperlightError, MultiUseSandbox, UninitializedSandbox,
        };

        fn make_sandbox() -> MultiUseSandbox {
            let path = simple_guest_as_string().unwrap();
            UninitializedSandbox::new(GuestBinary::FilePath(path), None)
                .unwrap()
                .evolve()
                .unwrap()
        }

        /// Sandbox with an extra `Add(i32, i32) -> i32` host function.
        fn make_sandbox_with_add() -> MultiUseSandbox {
            let path = simple_guest_as_string().unwrap();
            let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
                .unwrap();
            u.evolve().unwrap()
        }

        fn host_funcs_with_matching_add() -> HostFunctions {
            let mut hf = HostFunctions::default();
            hf.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
                .unwrap();
            hf
        }

        #[test]
        fn round_trip_running_sandbox() {
            let mut sbox = make_sandbox();
            sbox.call::<i32>("AddToStatic", 11i32).unwrap();
            let snapshot = sbox.snapshot().unwrap();
            let mut sbox2 =
                MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None).unwrap();
            assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 11);
            let echoed: String = sbox2.call("Echo", "hi".to_string()).unwrap();
            assert_eq!(echoed, "hi");
        }

        #[test]
        fn round_trip_pre_init_snapshot() {
            let path = simple_guest_as_string().unwrap();
            let snap =
                Snapshot::from_env(GuestBinary::FilePath(path), SandboxConfiguration::default())
                    .unwrap();
            let mut sbox =
                MultiUseSandbox::from_snapshot(Arc::new(snap), HostFunctions::default(), None)
                    .unwrap();
            assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
        }

        /// Two sandboxes built from clones of one `Arc<Snapshot>` can
        /// each `restore` back to it, and stay memory-isolated from
        /// each other in between.
        #[test]
        fn arc_clone_isolation_and_restore_compat() {
            let mut sbox = make_sandbox();
            sbox.call::<i32>("AddToStatic", 3i32).unwrap();
            let snapshot = sbox.snapshot().unwrap();

            let mut a =
                MultiUseSandbox::from_snapshot(snapshot.clone(), HostFunctions::default(), None)
                    .unwrap();
            let mut b =
                MultiUseSandbox::from_snapshot(snapshot.clone(), HostFunctions::default(), None)
                    .unwrap();
            assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 3);
            assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 3);

            a.call::<i32>("AddToStatic", 7i32).unwrap();
            assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 10);
            assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 3);

            a.restore(snapshot.clone()).unwrap();
            b.restore(snapshot).unwrap();
            assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 3);
            assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 3);
        }

        #[test]
        fn accepts_matching_host_functions() {
            let mut sbox = make_sandbox_with_add();
            sbox.call::<i32>("AddToStatic", 5i32).unwrap();
            let snap = sbox.snapshot().unwrap();
            let mut sbox2 =
                MultiUseSandbox::from_snapshot(snap, host_funcs_with_matching_add(), None).unwrap();
            assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 5);
        }

        #[test]
        fn rejects_missing_host_function() {
            let mut sbox = make_sandbox_with_add();
            let snap = sbox.snapshot().unwrap();
            let err = MultiUseSandbox::from_snapshot(snap, HostFunctions::default(), None)
                .expect_err("missing `Add` must be rejected");
            assert!(
                matches!(
                    &err,
                    HyperlightError::SnapshotHostFunctionMismatch { missing, signature_mismatches }
                        if missing.iter().any(|n| n == "Add") && signature_mismatches.is_empty()
                ),
                "got: {:?}",
                err
            );
        }

        /// `restore` must also reject a snapshot whose required host
        /// functions are not a subset of the target sandbox's. This
        /// matters across sandboxes: a snapshot taken from a sandbox
        /// with `Add` registered cannot be restored into a layout
        /// compatible sandbox that lacks `Add`.
        #[test]
        fn restore_rejects_missing_host_function() {
            let mut sbox_with_add = make_sandbox_with_add();
            let snap = sbox_with_add.snapshot().unwrap();
            let mut sbox_without_add = make_sandbox();
            let err = sbox_without_add
                .restore(snap)
                .expect_err("missing `Add` must be rejected on restore");
            assert!(
                matches!(
                    &err,
                    HyperlightError::SnapshotHostFunctionMismatch { missing, .. }
                        if missing.iter().any(|n| n == "Add")
                ),
                "got: {:?}",
                err
            );
        }

        /// `restore` rejects a snapshot whose required host function
        /// shares a name with the target's but disagrees on signature.
        #[test]
        fn restore_rejects_signature_mismatch() {
            let mut sbox_with_add = make_sandbox_with_add();
            let snap = sbox_with_add.snapshot().unwrap();
            let path = simple_guest_as_string().unwrap();
            let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u.register_host_function("Add", |a: String, b: String| Ok(format!("{a}{b}")))
                .unwrap();
            let mut sbox_wrong_add = u.evolve().unwrap();
            let err = sbox_wrong_add
                .restore(snap)
                .expect_err("signature mismatch on `Add` must be rejected on restore");
            assert!(
                matches!(
                    &err,
                    HyperlightError::SnapshotHostFunctionMismatch { missing, signature_mismatches }
                        if missing.is_empty() && signature_mismatches.iter().any(|s| s.contains("Add"))
                ),
                "got: {:?}",
                err
            );
        }

        /// Cross-instance `restore` succeeds when the target registers
        /// a strict superset of the snapshot's host functions.
        #[test]
        fn restore_across_sandboxes_with_superset_host_funcs() {
            let mut source = make_sandbox_with_add();
            source.call::<i32>("AddToStatic", 17i32).unwrap();
            let snap = source.snapshot().unwrap();

            let path = simple_guest_as_string().unwrap();
            let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
                .unwrap();
            u.register_host_function("Mul", |a: i32, b: i32| Ok(a * b))
                .unwrap();
            let mut target = u.evolve().unwrap();

            target.restore(snap).unwrap();
            assert_eq!(target.call::<i32>("GetStatic", ()).unwrap(), 17);
        }

        #[test]
        fn rejects_signature_mismatch() {
            let mut sbox = make_sandbox_with_add();
            let snap = sbox.snapshot().unwrap();
            let mut hf = HostFunctions::default();
            hf.register_host_function("Add", |a: String, b: String| Ok(format!("{a}{b}")))
                .unwrap();
            let err = MultiUseSandbox::from_snapshot(snap, hf, None)
                .expect_err("signature mismatch on `Add` must be rejected");
            assert!(
                matches!(
                    &err,
                    HyperlightError::SnapshotHostFunctionMismatch { missing, signature_mismatches }
                        if missing.is_empty() && signature_mismatches.iter().any(|s| s.contains("Add"))
                ),
                "got: {:?}",
                err
            );
        }

        /// Supplied host-function set may be a strict superset of the
        /// snapshot's required set.
        #[test]
        fn accepts_extra_host_functions() {
            let mut sbox = make_sandbox_with_add();
            sbox.call::<i32>("AddToStatic", 9i32).unwrap();
            let snap = sbox.snapshot().unwrap();
            let mut hf = host_funcs_with_matching_add();
            hf.register_host_function("Mul", |a: i32, b: i32| Ok(a * b))
                .unwrap();
            let mut sbox2 = MultiUseSandbox::from_snapshot(snap, hf, None).unwrap();
            assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 9);
        }

        /// A sandbox built via `from_snapshot` can itself be snapshotted
        /// and restored, and its snapshots are restore-compatible with it.
        #[test]
        fn re_snapshot_after_from_snapshot() {
            let mut sbox = make_sandbox();
            sbox.call::<i32>("AddToStatic", 4i32).unwrap();
            let snap1 = sbox.snapshot().unwrap();

            let mut sbox2 =
                MultiUseSandbox::from_snapshot(snap1, HostFunctions::default(), None).unwrap();
            sbox2.call::<i32>("AddToStatic", 6i32).unwrap();
            let snap2 = sbox2.snapshot().unwrap();

            sbox2.call::<i32>("AddToStatic", 100i32).unwrap();
            assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 110);

            sbox2.restore(snap2.clone()).unwrap();
            assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 10);

            let mut sbox3 =
                MultiUseSandbox::from_snapshot(snap2, HostFunctions::default(), None).unwrap();
            assert_eq!(sbox3.call::<i32>("GetStatic", ()).unwrap(), 10);
        }

        /// The host function closure supplied to `from_snapshot` (not the
        /// original sandbox's closure) is the one invoked at runtime.
        #[test]
        fn supplied_host_function_is_callable() {
            let path = simple_guest_as_string().unwrap();
            let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u.register_host_function("Echo42", || Ok(1i64)).unwrap();
            let mut sbox = u.evolve().unwrap();
            let snap = sbox.snapshot().unwrap();

            let mut hf = HostFunctions::default();
            hf.register_host_function("Echo42", || Ok(42i64)).unwrap();
            let mut sbox2 = MultiUseSandbox::from_snapshot(snap, hf, None).unwrap();

            let got: i64 = sbox2
                .call(
                    "CallGivenParamlessHostFuncThatReturnsI64",
                    "Echo42".to_string(),
                )
                .unwrap();
            assert_eq!(got, 42);
        }

        /// Pre-init snapshots record no required host functions, so any
        /// `HostFunctions` set is accepted.
        #[test]
        fn pre_init_snapshot_accepts_arbitrary_host_functions() {
            let path = simple_guest_as_string().unwrap();
            let snap =
                Snapshot::from_env(GuestBinary::FilePath(path), SandboxConfiguration::default())
                    .unwrap();
            let mut hf = HostFunctions::default();
            hf.register_host_function("Unrelated", |a: i32| Ok(a + 1))
                .unwrap();
            let mut sbox = MultiUseSandbox::from_snapshot(Arc::new(snap), hf, None).unwrap();
            assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
        }

        /// Snapshots taken from a sandbox built via `from_snapshot`
        /// must continue the generation counter of the snapshot they
        /// were constructed from, matching `restore`.
        #[test]
        fn snapshot_generation_propagates() {
            let mut sbox = make_sandbox();
            sbox.call::<i32>("AddToStatic", 1i32).unwrap();
            let snap1 = sbox.snapshot().unwrap();
            let gen1 = snap1.snapshot_generation();
            sbox.call::<i32>("AddToStatic", 1i32).unwrap();
            let snap2 = sbox.snapshot().unwrap();
            let gen2 = snap2.snapshot_generation();
            assert_eq!(gen2, gen1 + 1);

            let mut sbox2 =
                MultiUseSandbox::from_snapshot(snap2, HostFunctions::default(), None).unwrap();
            sbox2.call::<i32>("AddToStatic", 1i32).unwrap();
            let snap3 = sbox2.snapshot().unwrap();
            assert_eq!(snap3.snapshot_generation(), gen2 + 1);
        }

        /// Registering a host function on an already-evolved
        /// `MultiUseSandbox` must invalidate its cached snapshot, so
        /// that the next `snapshot()` reflects the new required
        /// host-function set.
        #[test]
        fn late_register_invalidates_snapshot_cache() {
            let mut sbox = make_sandbox();
            // Force a cached snapshot to exist.
            let _ = sbox.snapshot().unwrap();

            sbox.register_host_function("Echo42", || Ok(42i64)).unwrap();

            // The next snapshot must include `Echo42` as a required
            // host function, so building a sandbox from it without
            // `Echo42` must fail.
            let snap = sbox.snapshot().unwrap();
            let err = MultiUseSandbox::from_snapshot(snap, HostFunctions::default(), None)
                .expect_err("late-registered `Echo42` must be required by the new snapshot");
            let msg = format!("{}", err);
            assert!(msg.contains("Echo42"), "got: {}", msg);
        }
    }
}
