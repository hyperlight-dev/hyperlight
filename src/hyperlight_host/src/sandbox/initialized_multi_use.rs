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
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use flatbuffers::FlatBufferBuilder;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::util::estimate_flatbuffer_capacity;
use tracing::{Span, instrument};

use super::Callable;
use super::host_funcs::FunctionRegistry;
use super::snapshot::Snapshot;
use crate::HyperlightError::SnapshotSandboxMismatch;
use crate::func::guest_err::check_for_guest_error;
use crate::func::{ParameterTuple, SupportedReturnType};
use crate::hypervisor::{Hypervisor, InterruptHandle};
#[cfg(unix)]
use crate::mem::memory_region::MemoryRegionType;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::maybe_time_and_emit_guest_call;
use crate::{Result, log_then_return};

/// Global counter for assigning unique IDs to sandboxes
static SANDBOX_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fully initialized sandbox that can execute guest functions multiple times.
///
/// Guest functions can be called repeatedly while maintaining state between calls.
/// The sandbox supports creating snapshots and restoring to previous states.
pub struct MultiUseSandbox {
    /// Unique identifier for this sandbox instance
    id: u64,
    // We need to keep a reference to the host functions, even if the compiler marks it as unused. The compiler cannot detect our dynamic usages of the host function in `HyperlightFunction::call`.
    pub(super) _host_funcs: Arc<Mutex<FunctionRegistry>>,
    pub(crate) mem_mgr: SandboxMemoryManager<HostSharedMemory>,
    vm: Box<dyn Hypervisor>,
    dispatch_ptr: RawPtr,
    #[cfg(gdb)]
    dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    /// If the current state of the sandbox has been captured in a snapshot,
    /// that snapshot is stored here.
    snapshot: Option<Snapshot>,
}

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
        vm: Box<dyn Hypervisor>,
        dispatch_ptr: RawPtr,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> MultiUseSandbox {
        Self {
            id: SANDBOX_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            _host_funcs: host_funcs,
            mem_mgr: mgr,
            vm,
            dispatch_ptr,
            #[cfg(gdb)]
            dbg_mem_access_fn,
            snapshot: None,
        }
    }

    /// Creates a snapshot of the sandbox's current memory state.
    ///
    /// The snapshot is tied to this specific sandbox instance and can only be
    /// restored to the same sandbox it was created from.
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
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        if let Some(snapshot) = &self.snapshot {
            return Ok(snapshot.clone());
        }
        let mapped_regions_iter = self.vm.get_mapped_regions();
        let mapped_regions_vec: Vec<MemoryRegion> = mapped_regions_iter.cloned().collect();
        let memory_snapshot = self.mem_mgr.snapshot(self.id, mapped_regions_vec)?;
        let inner = Arc::new(memory_snapshot);
        let snapshot = Snapshot { inner };
        self.snapshot = Some(snapshot.clone());
        Ok(snapshot)
    }

    /// Restores the sandbox's memory to a previously captured snapshot state.
    ///
    /// The snapshot must have been created from this same sandbox instance.
    /// Attempting to restore a snapshot from a different sandbox will return
    /// a [`SnapshotSandboxMismatch`](crate::HyperlightError::SnapshotSandboxMismatch) error.
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
    /// sandbox.restore(&snapshot)?;
    /// let restored_value: i32 = sandbox.call_guest_function_by_name("GetValue", ())?;
    /// assert_eq!(restored_value, 0); // Back to initial state
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn restore(&mut self, snapshot: &Snapshot) -> Result<()> {
        if let Some(snap) = &self.snapshot
            && Arc::ptr_eq(&snap.inner, &snapshot.inner)
        {
            // If the snapshot is already the current one, no need to restore
            return Ok(());
        }

        if self.id != snapshot.inner.sandbox_id() {
            return Err(SnapshotSandboxMismatch);
        }

        self.mem_mgr.restore_snapshot(&snapshot.inner)?;

        let current_regions: HashSet<_> = self.vm.get_mapped_regions().cloned().collect();
        let snapshot_regions: HashSet<_> = snapshot.inner.regions().iter().cloned().collect();

        let regions_to_unmap = current_regions.difference(&snapshot_regions);
        let regions_to_map = snapshot_regions.difference(&current_regions);

        for region in regions_to_unmap {
            unsafe { self.vm.unmap_region(region)? };
        }

        for region in regions_to_map {
            unsafe { self.vm.map_region(region)? };
        }

        // The restored snapshot is now our most current snapshot
        self.snapshot = Some(snapshot.clone());

        Ok(())
    }

    /// Calls a guest function by name with the specified arguments.
    ///
    /// Changes made to the sandbox during execution are *not* persisted.
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
        let snapshot = self.snapshot()?;
        let res = self.call(func_name, args);
        self.restore(&snapshot)?;
        res
    }

    /// Calls a guest function by name with the specified arguments.
    ///
    /// Changes made to the sandbox during execution are persisted.
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
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;
        maybe_time_and_emit_guest_call(func_name, || {
            let ret = self.call_guest_function_by_name_no_reset(
                func_name,
                Output::TYPE,
                args.into_value(),
            );
            Output::from_value(ret?)
        })
    }

    /// Maps a region of host memory into the sandbox address space.
    ///
    /// The base address and length must meet platform alignment requirements
    /// (typically page-aligned). The `region_type` field is ignored as guest
    /// page table entries are not created.
    ///
    /// # Safety
    ///
    /// The caller must ensure the host memory region remains valid and unmodified
    /// for the lifetime of `self`.
    #[instrument(err(Debug), skip(self, rgn), parent = Span::current())]
    pub unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()> {
        if rgn.flags.contains(MemoryRegionFlags::STACK_GUARD) {
            // Stack guard pages are an internal implementation detail
            // (which really should be moved into the guest)
            log_then_return!("Cannot map host memory as a stack guard page");
        }
        if rgn.flags.contains(MemoryRegionFlags::WRITE) {
            // TODO: Implement support for writable mappings, which
            // need to be registered with the memory manager so that
            // writes can be rolled back when necessary.
            log_then_return!("TODO: Writable mappings not yet supported");
        }
        // Reset snapshot since we are mutating the sandbox state
        self.snapshot = None;
        unsafe { self.vm.map_region(rgn) }?;
        self.mem_mgr.mapped_rgns += 1;
        Ok(())
    }

    /// Map the contents of a file into the guest at a particular address
    ///
    /// Returns the length of the mapping in bytes.
    #[instrument(err(Debug), skip(self, _fp, _guest_base), parent = Span::current())]
    pub fn map_file_cow(&mut self, _fp: &Path, _guest_base: u64) -> Result<u64> {
        #[cfg(windows)]
        log_then_return!("mmap'ing a file into the guest is not yet supported on Windows");
        #[cfg(unix)]
        unsafe {
            let file = std::fs::File::options().read(true).write(true).open(_fp)?;
            let file_size = file.metadata()?.st_size();
            let page_size = page_size::get();
            let size = (file_size as usize).div_ceil(page_size) * page_size;
            let base = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            );
            if base == libc::MAP_FAILED {
                log_then_return!("mmap error: {:?}", std::io::Error::last_os_error());
            }

            if let Err(err) = self.map_region(&MemoryRegion {
                host_region: base as usize..base.wrapping_add(size) as usize,
                guest_region: _guest_base as usize.._guest_base as usize + size,
                flags: MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE,
                region_type: MemoryRegionType::Heap,
            }) {
                libc::munmap(base, size);
                return Err(err);
            };

            Ok(size as u64)
        }
    }

    /// Calls a guest function with type-erased parameters and return values.
    ///
    /// This function is used for fuzz testing parameter and return type handling.
    #[cfg(feature = "fuzzing")]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_type_erased_guest_function_by_name(
        &mut self,
        func_name: &str,
        ret_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
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

            self.vm.dispatch_call_from_host(
                self.dispatch_ptr.clone(),
                #[cfg(gdb)]
                self.dbg_mem_access_fn.clone(),
            )?;

            self.mem_mgr.check_stack_guard()?;
            check_for_guest_error(&mut self.mem_mgr)?;

            self.mem_mgr.get_guest_function_call_result()
        })();

        // In the happy path we do not need to clear io-buffers from the host because:
        // - the serialized guest function call is zeroed out by the guest during deserialization, see call to `try_pop_shared_input_data_into::<FunctionCall>()`
        // - the serialized guest function result is zeroed out by us (the host) during deserialization, see `get_guest_function_call_result`
        // - any serialized host function call are zeroed out by us (the host) during deserialization, see `get_host_function_call`
        // - any serialized host function result is zeroed out by the guest during deserialization, see `get_host_return_value`
        if res.is_err() {
            self.mem_mgr.clear_io_buffers();
        }
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
}

impl Callable for MultiUseSandbox {
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        self.call(func_name, args)
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox")
            .field("stack_guard", &self.mem_mgr.get_stack_cookie())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
    use hyperlight_testing::simple_guest_as_string;

    #[cfg(target_os = "linux")]
    use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
    #[cfg(target_os = "linux")]
    use crate::mem::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory as _};
    use crate::sandbox::SandboxConfiguration;
    use crate::{GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

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

        sbox.restore(&snapshot).unwrap();
        #[allow(deprecated)]
        let _ = sbox
            .call_guest_function_by_name::<i32>("AddToStatic", 5i32)
            .unwrap();
        #[allow(deprecated)]
        let res: i32 = sbox.call_guest_function_by_name("GetStatic", ()).unwrap();
        assert_eq!(res, 0);
    }

    // Tests to ensure that many (1000) function calls can be made in a call context with a small stack (1K) and heap(14K).
    // This test effectively ensures that the stack is being properly reset after each call and we are not leaking memory in the Guest.
    #[test]
    fn test_with_small_stack_and_heap() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_heap_size(20 * 1024);
        cfg.set_stack_size(16 * 1024);

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

        sbox.restore(&snapshot).unwrap();
        let res: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(res, 0);
    }

    #[test]
    // TODO: Investigate why this test fails with an incorrect error when run alongside other tests
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_violate_seccomp_filters() -> Result<()> {
        fn make_get_pid_syscall() -> Result<u64> {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            Ok(pid as u64)
        }

        // First, run  to make sure it fails.
        {
            let mut usbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap();

            usbox.register("MakeGetpidSyscall", make_get_pid_syscall)?;

            let mut sbox: MultiUseSandbox = usbox.evolve()?;

            let res: Result<u64> = sbox.call("ViolateSeccompFilters", ());

            #[cfg(seccomp)]
            match res {
                Ok(_) => panic!("Expected to fail due to seccomp violation"),
                Err(e) => match e {
                    HyperlightError::DisallowedSyscall => {}
                    _ => panic!("Expected DisallowedSyscall error: {}", e),
                },
            }

            #[cfg(not(seccomp))]
            match res {
                Ok(_) => (),
                Err(e) => panic!("Expected to succeed without seccomp: {}", e),
            }
        }

        // Second, run with allowing `SYS_getpid`
        #[cfg(seccomp)]
        {
            let mut usbox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap();

            usbox.register_with_extra_allowed_syscalls(
                "MakeGetpidSyscall",
                make_get_pid_syscall,
                vec![libc::SYS_getpid],
            )?;
            // ^^^ note, we are allowing SYS_getpid

            let mut sbox: MultiUseSandbox = usbox.evolve()?;

            let res: Result<u64> = sbox.call("ViolateSeccompFilters", ());

            match res {
                Ok(_) => {}
                Err(e) => panic!("Expected to succeed due to seccomp violation: {}", e),
            }
        }

        Ok(())
    }

    // We have a secomp specifically for `openat`, but we don't want to crash on `openat`, but rather make sure `openat` returns `EACCES`
    #[test]
    #[cfg(target_os = "linux")]
    fn violate_seccomp_filters_openat() -> Result<()> {
        // Hostcall to call `openat`.
        fn make_openat_syscall() -> Result<i64> {
            use std::ffi::CString;

            let path = CString::new("/proc/sys/vm/overcommit_memory").unwrap();

            let fd_or_err = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    libc::O_RDONLY,
                )
            };

            if fd_or_err == -1 {
                Ok((-std::io::Error::last_os_error().raw_os_error().unwrap()).into())
            } else {
                Ok(fd_or_err)
            }
        }
        {
            // First make sure a regular call to `openat` on /proc/sys/vm/overcommit_memory succeeds
            let ret = make_openat_syscall()?;
            assert!(
                ret >= 0,
                "Expected openat syscall to succeed, got: {:?}",
                ret
            );

            let mut ubox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap();
            ubox.register("Openat_Hostfunc", make_openat_syscall)?;

            let mut sbox = ubox.evolve().unwrap();
            let host_func_result = sbox
                .call::<i64>(
                    "CallGivenParamlessHostFuncThatReturnsI64",
                    "Openat_Hostfunc".to_string(),
                )
                .expect("Expected to call host function that returns i64");

            if cfg!(seccomp) {
                // If seccomp is enabled, we expect the syscall to return EACCES, as setup by our seccomp filter
                assert_eq!(host_func_result, -libc::EACCES as i64);
            } else {
                // If seccomp is not enabled, we expect the syscall to succeed
                assert!(host_func_result >= 0);
            }
        }

        #[cfg(seccomp)]
        {
            // Now let's make sure if we register the `openat` syscall as an extra allowed syscall, it will succeed
            let mut ubox = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
                None,
            )
            .unwrap();
            ubox.register_with_extra_allowed_syscalls(
                "Openat_Hostfunc",
                make_openat_syscall,
                [libc::SYS_openat],
            )?;
            let mut sbox = ubox.evolve().unwrap();
            let host_func_result: i64 = sbox
                .call::<i64>(
                    "CallGivenParamlessHostFuncThatReturnsI64",
                    "Openat_Hostfunc".to_string(),
                )
                .expect("Expected to call host function that returns i64");

            // should pass regardless of seccomp feature
            assert!(host_func_result >= 0);
        }

        Ok(())
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
    #[ignore] // this test runs by itself because it uses a lot of system resources
    fn create_1000_sandboxes() {
        let barrier = Arc::new(Barrier::new(21));

        let mut handles = vec![];

        for _ in 0..20 {
            let c = barrier.clone();

            let handle = thread::spawn(move || {
                c.wait();

                for _ in 0..50 {
                    let usbox = UninitializedSandbox::new(
                        GuestBinary::FilePath(
                            simple_guest_as_string().expect("Guest Binary Missing"),
                        ),
                        None,
                    )
                    .unwrap();

                    let mut multi_use_sandbox: MultiUseSandbox = usbox.evolve().unwrap();

                    let res: i32 = multi_use_sandbox.call("GetStatic", ()).unwrap();

                    assert_eq!(res, 0);
                }
            });

            handles.push(handle);
        }

        barrier.wait();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[cfg(target_os = "linux")]
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
                (guest_base as u64, expected.len() as u64),
            )
            .unwrap();

        assert_eq!(actual, expected);
    }

    // Makes sure MemoryRegionFlags::READ | MemoryRegionFlags::EXECUTE executable but not writable
    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
    fn page_aligned_memory(src: &[u8]) -> GuestSharedMemory {
        use hyperlight_common::mem::PAGE_SIZE_USIZE;

        let len = src.len().div_ceil(PAGE_SIZE_USIZE) * PAGE_SIZE_USIZE;

        let mut mem = ExclusiveSharedMemory::new(len).unwrap();
        mem.copy_from_slice(src, 0).unwrap();

        let (_, guest_mem) = mem.build();

        guest_mem
    }

    #[cfg(target_os = "linux")]
    fn region_for_memory(
        mem: &GuestSharedMemory,
        guest_base: usize,
        flags: MemoryRegionFlags,
    ) -> MemoryRegion {
        let ptr = mem.base_addr();
        let len = mem.mem_size();
        MemoryRegion {
            host_region: ptr..(ptr + len),
            guest_region: guest_base..(guest_base + len),
            flags,
            region_type: MemoryRegionType::Heap,
        }
    }

    #[cfg(target_os = "linux")]
    fn allocate_guest_memory() -> GuestSharedMemory {
        page_aligned_memory(b"test data for snapshot")
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn snapshot_restore_handles_remapping_correctly() {
        let mut sbox: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve().unwrap()
        };

        // 1. Take snapshot 1 with no additional regions mapped
        let snapshot1 = sbox.snapshot().unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().len(), 0);

        // 2. Map a memory region
        let map_mem = allocate_guest_memory();
        let guest_base = 0x200000000_usize;
        let region = region_for_memory(&map_mem, guest_base, MemoryRegionFlags::READ);

        unsafe { sbox.map_region(&region).unwrap() };
        assert_eq!(sbox.vm.get_mapped_regions().len(), 1);

        // 3. Take snapshot 2 with 1 region mapped
        let snapshot2 = sbox.snapshot().unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().len(), 1);

        // 4. Restore to snapshot 1 (should unmap the region)
        sbox.restore(&snapshot1).unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().len(), 0);

        // 5. Restore forward to snapshot 2 (should remap the region)
        sbox.restore(&snapshot2).unwrap();
        assert_eq!(sbox.vm.get_mapped_regions().len(), 1);

        // Verify the region is the same
        let mut restored_regions = sbox.vm.get_mapped_regions();
        assert_eq!(*restored_regions.next().unwrap(), region);
        assert!(restored_regions.next().is_none());
        drop(restored_regions);

        // 6. Try map the region again (should fail since already mapped)
        let err = unsafe { sbox.map_region(&region) };
        assert!(
            err.is_err(),
            "Expected error when remapping existing region: {:?}",
            err
        );
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
        let err = sandbox2.restore(&snapshot);
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
}
