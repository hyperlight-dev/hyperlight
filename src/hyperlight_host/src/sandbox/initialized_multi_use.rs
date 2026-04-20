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

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
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
use crate::HyperlightError::{self, SnapshotSandboxMismatch};
use crate::func::{ParameterTuple, SupportedReturnType};
use crate::hypervisor::InterruptHandle;
use crate::hypervisor::hyperlight_vm::{HyperlightVm, HyperlightVmError};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{HostSharedMemory, SharedMemory as _};
use crate::metrics::{
    METRIC_GUEST_ERROR, METRIC_GUEST_ERROR_LABEL_CODE, maybe_time_and_emit_guest_call,
};
use crate::{Result, log_then_return};

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
    /// Unique identifier for this sandbox instance
    id: u64,
    /// Whether this sandbox is poisoned
    poisoned: bool,
    pub(crate) host_funcs: Arc<Mutex<FunctionRegistry>>,
    pub(crate) mem_mgr: SandboxMemoryManager<HostSharedMemory>,
    vm: HyperlightVm,
    #[cfg(gdb)]
    dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    /// If the current state of the sandbox has been captured in a snapshot,
    /// that snapshot is stored here.
    snapshot: Option<Arc<Snapshot>>,
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
            id: super::snapshot::SANDBOX_CONFIGURATION_COUNTER.fetch_add(1, Ordering::Relaxed),
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
    /// A default `HostPrint` host function is registered automatically.
    /// Registering additional host functions is not currently supported
    /// on this path; use the [`evolve()`](crate::UninitializedSandbox::evolve)
    /// path if you need custom host functions.
    ///
    /// # Examples
    ///
    /// From a snapshot taken on another sandbox:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
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
    /// let mut sandbox2 = MultiUseSandbox::from_snapshot(snapshot)?;
    /// let result: i32 = sandbox2.call("GetValue", ())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// From a snapshot loaded from disk:
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use hyperlight_host::MultiUseSandbox;
    /// # use hyperlight_host::sandbox::snapshot::Snapshot;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let snapshot = Arc::new(Snapshot::from_file("guest_snapshot.hls")?);
    /// let mut sandbox = MultiUseSandbox::from_snapshot(snapshot)?;
    /// let result: String = sandbox.call("Echo", "hello".to_string())?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub fn from_snapshot(snapshot: Arc<Snapshot>) -> Result<Self> {
        use rand::RngExt;

        use crate::mem::ptr::RawPtr;
        use crate::sandbox::uninitialized_evolve::set_up_hypervisor_partition;

        let host_funcs = Arc::new(Mutex::new(FunctionRegistry::with_default_host_print()?));

        let stack_top_gva = snapshot.stack_top_gva();
        let mut config = crate::sandbox::SandboxConfiguration::default();
        config.set_input_data_size(snapshot.layout().input_data_size);
        config.set_output_data_size(snapshot.layout().output_data_size);
        config.set_heap_size(snapshot.layout().heap_size as u64);
        config.set_scratch_size(snapshot.layout().get_scratch_size());
        let load_info = snapshot.load_info();

        let mgr = crate::mem::mgr::SandboxMemoryManager::from_snapshot(&snapshot)?;
        let (mut hshm, gshm) = mgr.build()?;

        let page_size = u32::try_from(page_size::get())? as usize;

        #[cfg(target_os = "linux")]
        crate::signal_handlers::setup_signal_handlers(&config)?;

        let mut vm = set_up_hypervisor_partition(
            gshm,
            &config,
            stack_top_gva,
            page_size,
            #[cfg(any(crashdump, gdb))]
            Default::default(),
            load_info,
        )?;

        let seed = {
            let mut rng = rand::rng();
            rng.random::<u64>()
        };
        let peb_addr = RawPtr::from(u64::try_from(hshm.layout.peb_address())?);

        #[cfg(gdb)]
        let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

        vm.initialise(
            peb_addr,
            seed,
            page_size as u32,
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
        #[cfg(not(feature = "nanvix-unstable"))]
        if matches!(snapshot.entrypoint(), super::snapshot::NextAction::Call(_)) {
            let sregs = snapshot.sregs().cloned().unwrap_or_else(|| {
                crate::hypervisor::regs::CommonSpecialRegisters::standard_64bit_defaults(
                    hshm.layout.get_pt_base_gpa(),
                )
            });
            vm.apply_sregs(hshm.layout.get_pt_base_gpa(), &sregs)
                .map_err(|e| {
                    crate::HyperlightError::HyperlightVmError(
                        crate::hypervisor::hyperlight_vm::HyperlightVmError::Restore(e),
                    )
                })?;
        }

        #[cfg(gdb)]
        let dbg_mem_wrapper = Arc::new(Mutex::new(hshm.clone()));

        // Inherit the snapshot's sandbox id, and treat the loaded
        // snapshot as this sandbox's active snapshot. Without this,
        // a caller who does `from_snapshot(s)` and then immediately
        // `restore(s)` hits `SnapshotSandboxMismatch`: the new
        // sandbox would get a fresh id from `from_uninit` while the
        // snapshot still carries the originating sandbox's id.
        // Conceptually the snapshot IS this sandbox's identity when
        // loaded from disk, so the ids should agree from the start.
        let mut sbox = MultiUseSandbox::from_uninit(
            host_funcs,
            hshm,
            vm,
            #[cfg(gdb)]
            dbg_mem_wrapper,
        );
        sbox.id = snapshot.sandbox_id();
        sbox.snapshot = Some(snapshot.clone());
        Ok(sbox)
    }

    /// Creates a snapshot of the sandbox's current memory state.
    ///
    /// The snapshot is tied to this specific sandbox instance and can only be
    /// restored to the same sandbox it was created from.
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
    /// // Create snapshot belonging to this sandbox
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
        let entrypoint = self.vm.get_entrypoint();
        let memory_snapshot = self.mem_mgr.snapshot(
            self.id,
            mapped_regions_vec,
            &root_pt_gpas,
            stack_top_gpa,
            sregs,
            entrypoint,
        )?;
        let snapshot = Arc::new(memory_snapshot);
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Restores the sandbox's memory to a previously captured snapshot state.
    ///
    /// The snapshot must have been created from this same sandbox instance.
    /// Attempting to restore a snapshot from a different sandbox will return
    /// a [`SnapshotSandboxMismatch`](crate::HyperlightError::SnapshotSandboxMismatch) error.
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

        if self.id != snapshot.sandbox_id() {
            return Err(SnapshotSandboxMismatch);
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

        self.vm.set_stack_top(snapshot.stack_top_gva());
        self.vm.set_entrypoint(snapshot.entrypoint());

        let current_regions: HashSet<_> = self.vm.get_mapped_regions().cloned().collect();
        let snapshot_regions: HashSet<_> = snapshot.regions().iter().cloned().collect();

        let regions_to_unmap = current_regions.difference(&snapshot_regions);
        let regions_to_map = snapshot_regions.difference(&current_regions);

        for region in regions_to_unmap {
            self.vm
                .unmap_region(region)
                .map_err(HyperlightVmError::UnmapRegion)?;
        }

        for region in regions_to_map {
            // Safety: The region has been mapped before, and at that point the caller promised that the memory region is valid
            // in their call to `MultiUseSandbox::map_region`
            unsafe { self.vm.map_region(region) }.map_err(HyperlightVmError::MapRegion)?;
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
        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;
        unsafe { self.vm.map_region(rgn) }.map_err(HyperlightVmError::MapRegion)?;
        self.mem_mgr.mapped_rgns += 1;
        Ok(())
    }

    /// Map the contents of a file into the guest at a particular address
    ///
    /// An optional `label` identifies this mapping in the PEB's
    /// `FileMappingInfo` array (max 63 bytes, defaults to the file name).
    ///
    /// Returns the length of the mapping in bytes.
    ///
    /// ## Poisoned Sandbox
    ///
    /// This method will return [`crate::HyperlightError::PoisonedSandbox`] if the sandbox
    /// is currently poisoned. Use [`restore()`](Self::restore) to recover from a poisoned state.
    #[instrument(err(Debug), skip(self, file_path, guest_base, label), parent = Span::current())]
    pub fn map_file_cow(
        &mut self,
        file_path: &Path,
        guest_base: u64,
        label: Option<&str>,
    ) -> Result<u64> {
        if self.poisoned {
            return Err(crate::HyperlightError::PoisonedSandbox);
        }

        // Pre-check the file mapping limit before doing any expensive
        // OS or VM work. The PEB count is the source of truth.
        #[cfg(feature = "nanvix-unstable")]
        let current_count = self
            .mem_mgr
            .shared_mem
            .read::<u64>(self.mem_mgr.layout.get_file_mappings_size_offset())?
            as usize;
        #[cfg(feature = "nanvix-unstable")]
        if current_count >= hyperlight_common::mem::MAX_FILE_MAPPINGS {
            return Err(crate::HyperlightError::Error(format!(
                "map_file_cow: file mapping limit reached ({} of {})",
                current_count,
                hyperlight_common::mem::MAX_FILE_MAPPINGS,
            )));
        }

        // Phase 1: host-side OS work (open file, create mapping)
        let mut prepared = prepare_file_cow(file_path, guest_base, label)?;

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

        // Check for overlaps with existing file mappings in the VM.
        for existing_region in self.vm.get_mapped_regions() {
            let ex_start = existing_region.guest_region.start as u64;
            let ex_end = existing_region.guest_region.end as u64;
            if guest_base < ex_end && mapping_end > ex_start {
                return Err(crate::HyperlightError::Error(format!(
                    "map_file_cow: mapping [{:#x}..{:#x}) overlaps existing mapping [{:#x}..{:#x})",
                    guest_base, mapping_end, ex_start, ex_end,
                )));
            }
        }

        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;

        unsafe { self.vm.map_region(&region) }
            .map_err(HyperlightVmError::MapRegion)
            .map_err(crate::HyperlightError::HyperlightVmError)?;

        let size = prepared.size as u64;

        // Mark consumed immediately after map_region succeeds.
        // On Windows, WhpVm::map_memory copies the file mapping handle
        // into its own `file_mappings` vec for cleanup on drop. If we
        // deferred mark_consumed(), both PreparedFileMapping::drop and
        // WhpVm::drop would release the same handle — a double-close.
        // On Linux the hypervisor holds a reference to the host mmap;
        // freeing it here would leave a dangling backing.
        prepared.mark_consumed();
        self.mem_mgr.mapped_rgns += 1;

        // Record the mapping metadata in the PEB. If this fails the VM
        // still holds a valid mapping but the PEB won't list it — the
        // limit was already pre-checked above so this should not fail
        // in practice.
        #[cfg(feature = "nanvix-unstable")]
        self.mem_mgr
            .write_file_mapping_entry(prepared.guest_base, size, &prepared.label)?;

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
            let res = sbox.map_file_cow(&temp_file, 0x0, None).unwrap_err();
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
                assert!(msg.contains("InvalidOpcode"));
            }
            e => panic!(
                "Expected HyperlightError::GuestExecutionError but got {:?}",
                e
            ),
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

        let expected = &[0x90, 0x90, 0x90, 0xC3]; // NOOP slide to RET
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

    #[test]
    fn snapshot_different_sandbox() {
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
        assert_ne!(sandbox.id, sandbox2.id);

        let snapshot = sandbox.snapshot().unwrap();
        let err = sandbox2.restore(snapshot.clone());
        assert!(matches!(err, Err(HyperlightError::SnapshotSandboxMismatch)));

        let sandbox_id = sandbox.id;
        drop(sandbox);
        drop(sandbox2);
        drop(snapshot);

        let sandbox3 = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };
        assert_ne!(sandbox3.id, sandbox_id);
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

        // Dirty DR0 by setting it to a known non-zero value
        const DIRTY_VALUE: u64 = 0xDEAD_BEEF_CAFE_BABE;
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
        let mapped_size = sbox.map_file_cow(&path, guest_base, None).unwrap();
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
        sbox.map_file_cow(&path, guest_base, None).unwrap();

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
        let err = sbox.map_file_cow(&path, 0x1_0000_0000, None).unwrap_err();
        assert!(matches!(err, HyperlightError::PoisonedSandbox));

        // Restore and verify map_file_cow works again
        sbox.restore(snapshot).unwrap();
        assert!(!sbox.poisoned());
        let result = sbox.map_file_cow(&path, 0x1_0000_0000, None);
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
        sbox1.map_file_cow(&path, guest_base, None).unwrap();
        sbox2.map_file_cow(&path, guest_base, None).unwrap();

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
                sbox.map_file_cow(&path, guest_base, None).unwrap();

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

            sbox.map_file_cow(&path, 0x1_0000_0000, None).unwrap();
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
        sbox.map_file_cow(&path, guest_base, None).unwrap();

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
        sbox.map_file_cow(&path, guest_base, None).unwrap();

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
        let mapped_size = u_sbox.map_file_cow(&path, guest_base, None).unwrap();
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

            u_sbox.map_file_cow(&path, guest_base, None).unwrap();
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
        let result = u_sbox.map_file_cow(&path, unaligned_base, None);
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
        let result = u_sbox.map_file_cow(&path, guest_base, None);
        assert!(result.is_err(), "map_file_cow should reject empty files");

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `map_file_cow` with a custom label succeeds.
    #[test]
    fn test_map_file_cow_custom_label() {
        let (path, _) = create_test_file("hyperlight_test_map_file_cow_label.bin", &[0xDD; 4096]);

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        let result = sbox.map_file_cow(&path, 0x1_0000_0000, Some("my_ramfs"));
        assert!(
            result.is_ok(),
            "map_file_cow with custom label should succeed"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that `map_file_cow` on a MultiUseSandbox correctly writes
    /// the FileMappingInfo entry (count, guest_addr, size, label) into
    /// the PEB.
    #[test]
    #[cfg(feature = "nanvix-unstable")]
    fn test_map_file_cow_peb_entry_multiuse() {
        use std::mem::offset_of;

        use hyperlight_common::mem::{FILE_MAPPING_LABEL_MAX_LEN, FileMappingInfo};

        let (path, _) = create_test_file("hyperlight_test_peb_entry_multiuse.bin", &[0xDD; 4096]);

        let guest_base: u64 = 0x1_0000_0000;
        let label = "my_ramfs";

        let mut sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap()
        .evolve()
        .unwrap();

        // Map with an explicit label.
        let mapped_size = sbox.map_file_cow(&path, guest_base, Some(label)).unwrap();

        // Read back the PEB file_mappings count.
        let count = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(sbox.mem_mgr.layout.get_file_mappings_size_offset())
            .unwrap();
        assert_eq!(
            count, 1,
            "PEB file_mappings count should be 1 after one mapping"
        );

        // Read back the first FileMappingInfo entry.
        let entry_offset = sbox.mem_mgr.layout.get_file_mappings_array_offset();

        let stored_addr = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(entry_offset + offset_of!(FileMappingInfo, guest_addr))
            .unwrap();
        assert_eq!(stored_addr, guest_base, "PEB entry guest_addr should match");

        let stored_size = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(entry_offset + offset_of!(FileMappingInfo, size))
            .unwrap();
        assert_eq!(
            stored_size, mapped_size,
            "PEB entry size should match mapped_size"
        );

        // Read back the label bytes and verify.
        let label_offset = entry_offset + offset_of!(FileMappingInfo, label);
        let mut label_buf = [0u8; FILE_MAPPING_LABEL_MAX_LEN + 1];
        for (i, byte) in label_buf.iter_mut().enumerate() {
            *byte = sbox
                .mem_mgr
                .shared_mem
                .read::<u8>(label_offset + i)
                .unwrap();
        }
        let label_len = label_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(label_buf.len());
        let stored_label = std::str::from_utf8(&label_buf[..label_len]).unwrap();
        assert_eq!(stored_label, label, "PEB entry label should match");

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that deferred `map_file_cow` (before evolve) correctly
    /// writes FileMappingInfo entries into the PEB during evolve.
    #[test]
    #[cfg(feature = "nanvix-unstable")]
    fn test_map_file_cow_peb_entry_deferred() {
        use std::mem::offset_of;

        use hyperlight_common::mem::{FILE_MAPPING_LABEL_MAX_LEN, FileMappingInfo};

        let (path, _) = create_test_file("hyperlight_test_peb_entry_deferred.bin", &[0xEE; 4096]);

        let guest_base: u64 = 0x1_0000_0000;
        let label = "deferred_fs";

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        let mapped_size = u_sbox.map_file_cow(&path, guest_base, Some(label)).unwrap();

        // Evolve — PEB entries should be written during this step.
        let sbox: MultiUseSandbox = u_sbox.evolve().unwrap();

        // Read back count.
        let count = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(sbox.mem_mgr.layout.get_file_mappings_size_offset())
            .unwrap();
        assert_eq!(count, 1, "PEB file_mappings count should be 1 after evolve");

        // Read back the entry.
        let entry_offset = sbox.mem_mgr.layout.get_file_mappings_array_offset();

        let stored_addr = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(entry_offset + offset_of!(FileMappingInfo, guest_addr))
            .unwrap();
        assert_eq!(stored_addr, guest_base);

        let stored_size = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(entry_offset + offset_of!(FileMappingInfo, size))
            .unwrap();
        assert_eq!(stored_size, mapped_size);

        // Verify the label.
        let label_offset = entry_offset + offset_of!(FileMappingInfo, label);
        let mut label_buf = [0u8; FILE_MAPPING_LABEL_MAX_LEN + 1];
        for (i, byte) in label_buf.iter_mut().enumerate() {
            *byte = sbox
                .mem_mgr
                .shared_mem
                .read::<u8>(label_offset + i)
                .unwrap();
        }
        let label_len = label_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(label_buf.len());
        let stored_label = std::str::from_utf8(&label_buf[..label_len]).unwrap();
        assert_eq!(
            stored_label, label,
            "PEB entry label should match after evolve"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that mapping 5 files (3 deferred + 2 post-evolve) correctly
    /// populates all PEB FileMappingInfo slots with the right guest_addr,
    /// size, and label for each entry.
    #[test]
    #[cfg(feature = "nanvix-unstable")]
    fn test_map_file_cow_peb_multiple_entries() {
        use std::mem::{offset_of, size_of};

        use hyperlight_common::mem::{FILE_MAPPING_LABEL_MAX_LEN, FileMappingInfo};

        const NUM_FILES: usize = 5;
        const DEFERRED_COUNT: usize = 3;

        // Create 5 test files with distinct content.
        let mut paths = Vec::new();
        let mut labels: Vec<String> = Vec::new();
        for i in 0..NUM_FILES {
            let name = format!("hyperlight_test_peb_multi_{}.bin", i);
            let content = vec![i as u8 + 0xA0; 4096];
            let (path, _) = create_test_file(&name, &content);
            paths.push(path);
            labels.push(format!("file_{}", i));
        }

        // Each file gets a unique guest base, spaced 1 page apart
        // (well outside the shared memory region).
        let page_size = page_size::get() as u64;
        let base: u64 = 0x1_0000_0000;
        let guest_bases: Vec<u64> = (0..NUM_FILES as u64)
            .map(|i| base + i * page_size)
            .collect();

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // Map 3 files before evolve (deferred path).
        let mut mapped_sizes = Vec::new();
        for i in 0..DEFERRED_COUNT {
            let size = u_sbox
                .map_file_cow(&paths[i], guest_bases[i], Some(&labels[i]))
                .unwrap();
            mapped_sizes.push(size);
        }

        // Evolve — deferred mappings applied + PEB entries written.
        let mut sbox: MultiUseSandbox = u_sbox.evolve().unwrap();

        // Map 2 more files post-evolve (MultiUseSandbox path).
        for i in DEFERRED_COUNT..NUM_FILES {
            let size = sbox
                .map_file_cow(&paths[i], guest_bases[i], Some(&labels[i]))
                .unwrap();
            mapped_sizes.push(size);
        }

        // Verify PEB count equals 5.
        let count = sbox
            .mem_mgr
            .shared_mem
            .read::<u64>(sbox.mem_mgr.layout.get_file_mappings_size_offset())
            .unwrap();
        assert_eq!(
            count, NUM_FILES as u64,
            "PEB should have {NUM_FILES} entries"
        );

        // Verify each entry's guest_addr, size, and label.
        let array_base = sbox.mem_mgr.layout.get_file_mappings_array_offset();
        for i in 0..NUM_FILES {
            let entry_offset = array_base + i * size_of::<FileMappingInfo>();

            let stored_addr = sbox
                .mem_mgr
                .shared_mem
                .read::<u64>(entry_offset + offset_of!(FileMappingInfo, guest_addr))
                .unwrap();
            assert_eq!(
                stored_addr, guest_bases[i],
                "Entry {i}: guest_addr mismatch"
            );

            let stored_size = sbox
                .mem_mgr
                .shared_mem
                .read::<u64>(entry_offset + offset_of!(FileMappingInfo, size))
                .unwrap();
            assert_eq!(stored_size, mapped_sizes[i], "Entry {i}: size mismatch");

            // Read and verify the label.
            let label_base = entry_offset + offset_of!(FileMappingInfo, label);
            let mut label_buf = [0u8; FILE_MAPPING_LABEL_MAX_LEN + 1];
            for (j, byte) in label_buf.iter_mut().enumerate() {
                *byte = sbox.mem_mgr.shared_mem.read::<u8>(label_base + j).unwrap();
            }
            let label_len = label_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(label_buf.len());
            let stored_label = std::str::from_utf8(&label_buf[..label_len]).unwrap();
            assert_eq!(stored_label, labels[i], "Entry {i}: label mismatch");
        }

        // Clean up.
        for path in &paths {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Tests that an explicitly provided label exceeding 63 bytes is rejected.
    #[test]
    fn test_map_file_cow_label_too_long() {
        let (path, _) =
            create_test_file("hyperlight_test_map_file_cow_long_label.bin", &[0xEE; 4096]);

        let guest_base: u64 = 0x1_0000_0000;

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        // A label of exactly 64 bytes exceeds the 63-byte max.
        let long_label = "A".repeat(64);
        let result = u_sbox.map_file_cow(&path, guest_base, Some(&long_label));
        assert!(
            result.is_err(),
            "map_file_cow should reject labels longer than 63 bytes"
        );

        // Labels at exactly 63 bytes should be fine.
        let ok_label = "B".repeat(63);
        let result = u_sbox.map_file_cow(&path, guest_base, Some(&ok_label));
        assert!(
            result.is_ok(),
            "map_file_cow should accept labels of exactly 63 bytes"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that labels containing null bytes are rejected.
    #[test]
    fn test_map_file_cow_label_null_byte() {
        let (path, _) =
            create_test_file("hyperlight_test_map_file_cow_null_label.bin", &[0xFF; 4096]);

        let guest_base: u64 = 0x1_0000_0000;

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        let result = u_sbox.map_file_cow(&path, guest_base, Some("has\0null"));
        assert!(
            result.is_err(),
            "map_file_cow should reject labels containing null bytes"
        );

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
        u_sbox.map_file_cow(&path1, guest_base, None).unwrap();

        // Second mapping at the same address should fail (overlap).
        let result = u_sbox.map_file_cow(&path2, guest_base, None);
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
        let result = u_sbox.map_file_cow(&path, base_addr, None);
        assert!(
            result.is_err(),
            "map_file_cow should reject guest_base inside shared memory"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Tests that exceeding MAX_FILE_MAPPINGS on UninitializedSandbox
    /// is rejected at registration time.
    #[test]
    fn test_map_file_cow_max_limit() {
        use hyperlight_common::mem::MAX_FILE_MAPPINGS;

        let mut u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
            None,
        )
        .unwrap();

        let page_size = page_size::get() as u64;
        // Base well outside shared memory.
        let base: u64 = 0x1_0000_0000;

        // Register MAX_FILE_MAPPINGS files — each needs a distinct file
        // and a non-overlapping GPA.
        let mut paths = Vec::new();
        for i in 0..MAX_FILE_MAPPINGS {
            let name = format!("hyperlight_test_max_limit_{}.bin", i);
            let (path, _) = create_test_file(&name, &[0xAA; 4096]);
            let guest_base = base + (i as u64) * page_size;
            u_sbox.map_file_cow(&path, guest_base, None).unwrap();
            paths.push(path);
        }

        // The (MAX_FILE_MAPPINGS + 1)th should fail.
        let name = format!("hyperlight_test_max_limit_{}.bin", MAX_FILE_MAPPINGS);
        let (path, _) = create_test_file(&name, &[0xBB; 4096]);
        let guest_base = base + (MAX_FILE_MAPPINGS as u64) * page_size;
        let result = u_sbox.map_file_cow(&path, guest_base, None);
        assert!(
            result.is_err(),
            "map_file_cow should reject after MAX_FILE_MAPPINGS registrations"
        );

        // Clean up.
        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_file(&path);
    }
}
