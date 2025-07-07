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

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use tracing::{Span, instrument};

use super::host_funcs::FunctionRegistry;
use super::snapshot::Snapshot;
use super::{MemMgrWrapper, WrapperGetter};
use crate::func::call_ctx::MultiUseGuestCallContext;
use crate::func::guest_err::check_for_guest_error;
use crate::func::{ParameterTuple, SupportedReturnType};
#[cfg(gdb)]
use crate::hypervisor::handlers::DbgMemAccessHandlerWrapper;
use crate::hypervisor::handlers::{MemAccessHandlerCaller, OutBHandlerCaller};
use crate::hypervisor::{Hypervisor, InterruptHandle};
#[cfg(unix)]
use crate::mem::memory_region::MemoryRegionType;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::HostSharedMemory;
use crate::metrics::maybe_time_and_emit_guest_call;
use crate::sandbox_state::sandbox::{EvolvableSandbox, Sandbox};
use crate::sandbox_state::transition::MultiUseContextCallback;
use crate::{HyperlightError, Result, log_then_return};

/// A sandbox that supports being used Multiple times.
/// The implication of being used multiple times is two-fold:
///
/// 1. The sandbox can be used to call guest functions multiple times, each time a
///    guest function is called the state of the sandbox is reset to the state it was in before the call was made.
///
/// 2. A MultiUseGuestCallContext can be created from the sandbox and used to make multiple guest function calls to the Sandbox.
///    in this case the state of the sandbox is not reset until the context is finished and the `MultiUseSandbox` is returned.
pub struct MultiUseSandbox {
    // We need to keep a reference to the host functions, even if the compiler marks it as unused. The compiler cannot detect our dynamic usages of the host function in `HyperlightFunction::call`.
    pub(super) _host_funcs: Arc<Mutex<FunctionRegistry>>,
    pub(crate) mem_mgr: MemMgrWrapper<HostSharedMemory>,
    vm: Box<dyn Hypervisor>,
    out_hdl: Arc<Mutex<dyn OutBHandlerCaller>>,
    mem_hdl: Arc<Mutex<dyn MemAccessHandlerCaller>>,
    dispatch_ptr: RawPtr,
    #[cfg(gdb)]
    dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
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
        mgr: MemMgrWrapper<HostSharedMemory>,
        vm: Box<dyn Hypervisor>,
        out_hdl: Arc<Mutex<dyn OutBHandlerCaller>>,
        mem_hdl: Arc<Mutex<dyn MemAccessHandlerCaller>>,
        dispatch_ptr: RawPtr,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> MultiUseSandbox {
        Self {
            _host_funcs: host_funcs,
            mem_mgr: mgr,
            vm,
            out_hdl,
            mem_hdl,
            dispatch_ptr,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        }
    }

    /// Create a new `MultiUseCallContext` suitable for making 0 or more
    /// calls to guest functions within the same context.
    ///
    /// Since this function consumes `self`, the returned
    /// `MultiUseGuestCallContext` is guaranteed mutual exclusion for calling
    /// functions within the sandbox. This guarantee is enforced at compile
    /// time, and no locks, atomics, or any other mutual exclusion mechanisms
    /// are used at runtime.
    ///
    /// If you have called this function, have a `MultiUseGuestCallContext`,
    /// and wish to "return" it to a `MultiUseSandbox`, call the `finish`
    /// method on the context.
    ///
    /// Example usage (compiled as a "no_run" doctest since the test binary
    /// will not be found):
    ///
    /// ```no_run
    /// use hyperlight_host::sandbox::{UninitializedSandbox, MultiUseSandbox};
    /// use hyperlight_common::flatbuffer_wrappers::function_types::{ReturnType, ParameterValue, ReturnValue};
    /// use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
    /// use hyperlight_host::sandbox_state::transition::Noop;
    /// use hyperlight_host::GuestBinary;
    ///
    /// // First, create a new uninitialized sandbox, then evolve it to become
    /// // an initialized, single-use one.
    /// let u_sbox = UninitializedSandbox::new(
    ///     GuestBinary::FilePath("some_guest_binary".to_string()),
    ///     None,
    /// ).unwrap();
    /// let sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();
    /// // Next, create a new call context from the single-use sandbox.
    /// // After this line, your code will not compile if you try to use the
    /// // original `sbox` variable.
    /// let mut ctx = sbox.new_call_context();
    ///
    /// // Do a guest call with the context. Assumes that the loaded binary
    /// // ("some_guest_binary") has a function therein called "SomeGuestFunc"
    /// // that takes a single integer argument and returns an integer.
    /// match ctx.call(
    ///     "SomeGuestFunc",
    ///     ReturnType::Int,
    ///     Some(vec![ParameterValue::Int(1)])
    /// ) {
    ///     Ok(ReturnValue::Int(i)) => println!(
    ///         "got successful return value {}",
    ///         i,
    ///     ),
    ///     other => panic!(
    ///         "failed to get return value as expected ({:?})",
    ///         other,
    ///     ),
    /// };
    /// // You can make further calls with the same context if you want.
    /// // Otherwise, `ctx` will be dropped and all resources, including the
    /// // underlying `MultiUseSandbox`, will be released and no further
    /// // contexts can be created from that sandbox.
    /// //
    /// // If you want to avoid
    /// // that behavior, call `finish` to convert the context back to
    /// // the original `MultiUseSandbox`, as follows:
    /// let _orig_sbox = ctx.finish();
    /// // Now, you can operate on the original sandbox again (i.e. add more
    /// // host functions etc...), create new contexts, and so on.
    /// ```
    #[instrument(skip_all, parent = Span::current())]
    pub fn new_call_context(self) -> MultiUseGuestCallContext {
        MultiUseGuestCallContext::start(self)
    }

    /// Create a snapshot of the current state of the sandbox's memory.
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn snapshot(&mut self) -> Result<Snapshot> {
        let snapshot = self.mem_mgr.unwrap_mgr_mut().snapshot()?;
        Ok(Snapshot { inner: snapshot })
    }

    /// Restore the sandbox's memory to the state captured in the given snapshot.
    #[instrument(err(Debug), skip_all, parent = Span::current())]
    pub fn restore(&mut self, snapshot: &Snapshot) -> Result<()> {
        let rgns_to_unmap = self.mem_mgr
            .unwrap_mgr_mut()
            .restore_snapshot(&snapshot.inner)?;
        unsafe { self.vm.unmap_regions(rgns_to_unmap)? };
        Ok(())
    }

    /// Call a guest function by name, with the given return type and arguments.
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_guest_function_by_name<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        maybe_time_and_emit_guest_call(func_name, || {
            let ret = self.call_guest_function_by_name_no_reset(
                func_name,
                Output::TYPE,
                args.into_value(),
            );
            self.restore_state()?;
            Output::from_value(ret?)
        })
    }

    /// Map a region of host memory into the sandbox.
    ///
    /// Depending on the host platform, there are likely alignment
    /// requirements of at least one page for base and len.
    ///
    /// `rgn.region_type` is ignored, since guest PTEs are not created
    /// for the new memory.
    ///
    /// It is the caller's responsibility to ensure that the host side
    /// of the region remains intact and is not written to until this
    /// mapping is removed, either due to the destruction of the
    /// sandbox or due to a state rollback
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
        unsafe { self.vm.map_region(rgn) }?;
        self.mem_mgr.unwrap_mgr_mut().mapped_rgns += 1;
        Ok(())
    }

    /// Map the contents of a file into the guest at a particular address
    ///
    /// Returns the length of the mapping
    #[instrument(err(Debug), skip(self, _fp, _guest_base), parent = Span::current())]
    pub(crate) fn map_file_cow(&mut self, _fp: &Path, _guest_base: u64) -> Result<u64> {
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

    /// This function is kept here for fuzz testing the parameter and return types
    #[cfg(feature = "fuzzing")]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_type_erased_guest_function_by_name(
        &mut self,
        func_name: &str,
        ret_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        maybe_time_and_emit_guest_call(func_name, || {
            let ret = self.call_guest_function_by_name_no_reset(func_name, ret_type, args);
            self.restore_state()?;
            ret
        })
    }

    /// Restore the Sandbox's state
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn restore_state(&mut self) -> Result<()> {
        let mem_mgr = self.mem_mgr.unwrap_mgr_mut();
        let rgns_to_unmap = mem_mgr.restore_state_from_last_snapshot()?;
        unsafe { self.vm.unmap_regions(rgns_to_unmap)? };
        Ok(())
    }

    pub(crate) fn call_guest_function_by_name_no_reset(
        &mut self,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        let fc = FunctionCall::new(
            function_name.to_string(),
            Some(args),
            FunctionCallType::Guest,
            return_type,
        );

        let buffer: Vec<u8> = fc
            .try_into()
            .map_err(|_| HyperlightError::Error("Failed to serialize FunctionCall".to_string()))?;

        self.get_mgr_wrapper_mut()
            .as_mut()
            .write_guest_function_call(&buffer)?;

        self.vm.dispatch_call_from_host(
            self.dispatch_ptr.clone(),
            self.out_hdl.clone(),
            self.mem_hdl.clone(),
            #[cfg(gdb)]
            self.dbg_mem_access_fn.clone(),
        )?;

        self.check_stack_guard()?;
        check_for_guest_error(self.get_mgr_wrapper_mut())?;

        self.get_mgr_wrapper_mut()
            .as_mut()
            .get_guest_function_call_result()
    }

    /// Get a handle to the interrupt handler for this sandbox,
    /// capable of interrupting guest execution.
    pub fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.vm.interrupt_handle()
    }
}

impl WrapperGetter for MultiUseSandbox {
    fn get_mgr_wrapper(&self) -> &MemMgrWrapper<HostSharedMemory> {
        &self.mem_mgr
    }
    fn get_mgr_wrapper_mut(&mut self) -> &mut MemMgrWrapper<HostSharedMemory> {
        &mut self.mem_mgr
    }
}

impl Sandbox for MultiUseSandbox {
    fn check_stack_guard(&self) -> Result<bool> {
        self.mem_mgr.check_stack_guard()
    }
}

impl std::fmt::Debug for MultiUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiUseSandbox")
            .field("stack_guard", &self.mem_mgr.get_stack_cookie())
            .finish()
    }
}

impl<'a, F>
    EvolvableSandbox<
        MultiUseSandbox,
        MultiUseSandbox,
        MultiUseContextCallback<'a, MultiUseSandbox, F>,
    > for MultiUseSandbox
where
    F: FnOnce(&mut MultiUseGuestCallContext) -> Result<()> + 'a,
{
    /// The purpose of this function is to allow multiple states to be associated with a single MultiUseSandbox.
    ///
    /// An implementation such as HyperlightJs or HyperlightWasm can use this to call guest functions to load JS or WASM code and then evolve the sandbox causing state to be captured.
    /// The new MultiUseSandbox can then be used to call guest functions to execute the loaded code.
    ///
    /// The evolve function creates a new MultiUseCallContext which is then passed to a callback function  allowing the
    /// callback function to call guest functions as part of the evolve process, once the callback function  is complete
    /// the context is finished using a crate internal method that does not restore the prior state of the Sandbox.
    /// It then creates a mew  memory snapshot on the snapshot stack and returns the MultiUseSandbox
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn evolve(
        self,
        transition_func: MultiUseContextCallback<'a, MultiUseSandbox, F>,
    ) -> Result<MultiUseSandbox> {
        let mut ctx = self.new_call_context();
        transition_func.call(&mut ctx)?;
        let mut sbox = ctx.finish_no_reset();
        sbox.mem_mgr.unwrap_mgr_mut().push_state()?;
        Ok(sbox)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use hyperlight_testing::simple_guest_as_string;

    use crate::func::call_ctx::MultiUseGuestCallContext;
    #[cfg(target_os = "linux")]
    use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
    #[cfg(target_os = "linux")]
    use crate::mem::shared_mem::{ExclusiveSharedMemory, GuestSharedMemory, SharedMemory as _};
    use crate::sandbox::{Callable, SandboxConfiguration};
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::{MultiUseContextCallback, Noop};
    use crate::{GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox};

    // Tests to ensure that many (1000) function calls can be made in a call context with a small stack (1K) and heap(14K).
    // This test effectively ensures that the stack is being properly reset after each call and we are not leaking memory in the Guest.
    #[test]
    fn test_with_small_stack_and_heap() {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_heap_size(20 * 1024);
        cfg.set_stack_size(16 * 1024);

        let sbox1: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve(Noop::default())
        }
        .unwrap();

        let mut ctx = sbox1.new_call_context();

        for _ in 0..1000 {
            ctx.call::<String>("Echo", "hello".to_string()).unwrap();
        }

        let sbox2: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), Some(cfg)).unwrap();
            u_sbox.evolve(Noop::default())
        }
        .unwrap();

        let mut ctx = sbox2.new_call_context();

        for i in 0..1000 {
            ctx.call::<i32>(
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
            u_sbox.evolve(Noop::default())
        }
        .unwrap();

        let snapshot = sbox.snapshot().unwrap();

        let func = Box::new(|call_ctx: &mut MultiUseGuestCallContext| {
            call_ctx.call::<i32>("AddToStatic", 5i32)?;
            Ok(())
        });
        let transition_func = MultiUseContextCallback::from(func);
        let mut sbox = sbox.evolve(transition_func).unwrap();

        let res: i32 = sbox.call_guest_function_by_name("GetStatic", ()).unwrap();
        assert_eq!(res, 5);

        sbox.restore(&snapshot).unwrap();
        let res: i32 = sbox.call_guest_function_by_name("GetStatic", ()).unwrap();
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

            let mut sbox: MultiUseSandbox = usbox.evolve(Noop::default())?;

            let res: Result<u64> = sbox.call_guest_function_by_name("ViolateSeccompFilters", ());

            #[cfg(feature = "seccomp")]
            match res {
                Ok(_) => panic!("Expected to fail due to seccomp violation"),
                Err(e) => match e {
                    HyperlightError::DisallowedSyscall => {}
                    _ => panic!("Expected DisallowedSyscall error: {}", e),
                },
            }

            #[cfg(not(feature = "seccomp"))]
            match res {
                Ok(_) => (),
                Err(e) => panic!("Expected to succeed without seccomp: {}", e),
            }
        }

        // Second, run with allowing `SYS_getpid`
        #[cfg(feature = "seccomp")]
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

            let mut sbox: MultiUseSandbox = usbox.evolve(Noop::default())?;

            let res: Result<u64> = sbox.call_guest_function_by_name("ViolateSeccompFilters", ());

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

            let mut sbox = ubox.evolve(Noop::default()).unwrap();
            let host_func_result = sbox
                .call_guest_function_by_name::<i64>(
                    "CallGivenParamlessHostFuncThatReturnsI64",
                    "Openat_Hostfunc".to_string(),
                )
                .expect("Expected to call host function that returns i64");

            if cfg!(feature = "seccomp") {
                // If seccomp is enabled, we expect the syscall to return EACCES, as setup by our seccomp filter
                assert_eq!(host_func_result, -libc::EACCES as i64);
            } else {
                // If seccomp is not enabled, we expect the syscall to succeed
                assert!(host_func_result >= 0);
            }
        }

        #[cfg(feature = "seccomp")]
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
            let mut sbox = ubox.evolve(Noop::default()).unwrap();
            let host_func_result = sbox
                .call_guest_function_by_name::<i64>(
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

        let mut multi_use_sandbox: MultiUseSandbox = usbox.evolve(Noop::default()).unwrap();

        let res: Result<()> = multi_use_sandbox.call_guest_function_by_name("TriggerException", ());

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

                    let mut multi_use_sandbox: MultiUseSandbox =
                        usbox.evolve(Noop::default()).unwrap();

                    let res: i32 = multi_use_sandbox
                        .call_guest_function_by_name("GetStatic", ())
                        .unwrap();

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
        .evolve(Noop::default())
        .unwrap();

        let expected = b"hello world";
        let map_mem = page_aligned_memory(expected);
        let guest_base = 0x1_0000_0000; // Arbitrary guest base address

        unsafe {
            sbox.map_region(&region_for_memory(&map_mem, guest_base))
                .unwrap();
        }

        let _guard = map_mem.lock.try_read().unwrap();
        let actual: Vec<u8> = sbox
            .call_guest_function_by_name(
                "ReadMappedBuffer",
                (guest_base as u64, expected.len() as u64),
            )
            .unwrap();

        assert_eq!(actual, expected);
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
    fn region_for_memory(mem: &GuestSharedMemory, guest_base: usize) -> MemoryRegion {
        let ptr = mem.base_addr();
        let len = mem.mem_size();
        MemoryRegion {
            host_region: ptr..(ptr + len),
            guest_region: guest_base..(guest_base + len),
            flags: MemoryRegionFlags::READ,
            region_type: MemoryRegionType::Heap,
        }
    }
}
