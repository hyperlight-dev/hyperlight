/*
Copyright 2024 The Hyperlight Authors.

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

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use tracing::{instrument, Span};

use super::host_funcs::FunctionRegistry;
use super::{MemMgrWrapper, WrapperGetter};
use crate::func::call_ctx::MultiUseGuestCallContext;
use crate::func::guest_dispatch::call_function_on_guest;
use crate::func::{ParameterTuple, SupportedReturnType};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox_state::sandbox::{DevolvableSandbox, EvolvableSandbox, Sandbox};
use crate::sandbox_state::transition::{MultiUseContextCallback, Noop};
use crate::Result;

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
    hv_handler: HypervisorHandler,
}

// We need to implement drop to join the
// threads, because, otherwise, we will
// be leaking a thread with every
// sandbox that is dropped. This was initially
// caught by our benchmarks that created a ton of
// sandboxes and caused the system to run out of
// resources. Now, this is covered by the test:
// `create_1000_sandboxes`.
impl Drop for MultiUseSandbox {
    fn drop(&mut self) {
        match self.hv_handler.kill_hypervisor_handler_thread() {
            Ok(_) => {}
            Err(e) => {
                log::error!("[POTENTIAL THREAD LEAK] Potentially failed to kill hypervisor handler thread when dropping MultiUseSandbox: {:?}", e);
            }
        }
    }
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
        hv_handler: HypervisorHandler,
    ) -> MultiUseSandbox {
        Self {
            _host_funcs: host_funcs,
            mem_mgr: mgr,
            hv_handler,
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

    /// Call a guest function by name, with the given return type and arguments.
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_guest_function_by_name<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output> {
        let ret = call_function_on_guest(self, func_name, Output::TYPE, args.into_value());
        self.restore_state()?;
        Output::from_value(ret?)
    }

    /// This function is kept here for fuzz testing
    #[doc(hidden)]
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_type_erased_guest_function_by_name(
        &mut self,
        func_name: &str,
        ret_type: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        let ret = call_function_on_guest(self, func_name, ret_type, args);
        self.restore_state()?;
        ret
    }

    /// Restore the Sandbox's state
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn restore_state(&mut self) -> Result<()> {
        let mem_mgr = self.mem_mgr.unwrap_mgr_mut();
        mem_mgr.restore_state_from_last_snapshot()
    }
}

impl WrapperGetter for MultiUseSandbox {
    fn get_mgr_wrapper(&self) -> &MemMgrWrapper<HostSharedMemory> {
        &self.mem_mgr
    }
    fn get_mgr_wrapper_mut(&mut self) -> &mut MemMgrWrapper<HostSharedMemory> {
        &mut self.mem_mgr
    }
    fn get_hv_handler(&self) -> &HypervisorHandler {
        &self.hv_handler
    }
    fn get_hv_handler_mut(&mut self) -> &mut HypervisorHandler {
        &mut self.hv_handler
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

impl DevolvableSandbox<MultiUseSandbox, MultiUseSandbox, Noop<MultiUseSandbox, MultiUseSandbox>>
    for MultiUseSandbox
{
    /// Consume `self` and move it back to a `MultiUseSandbox` with previous state.
    ///
    /// The purpose of this function is to allow multiple states to be associated with a single MultiUseSandbox.
    ///
    /// An implementation such as HyperlightJs or HyperlightWasm can use this to call guest functions to load JS or WASM code and then evolve the sandbox causing state to be captured.
    /// The new MultiUseSandbox can then be used to call guest functions to execute the loaded code.
    /// The devolve can be used to return the MultiUseSandbox to the state before the code was loaded. Thus avoiding initialisation overhead
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn devolve(mut self, _tsn: Noop<MultiUseSandbox, MultiUseSandbox>) -> Result<MultiUseSandbox> {
        self.mem_mgr
            .unwrap_mgr_mut()
            .pop_and_restore_state_from_snapshot()?;
        Ok(self)
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
    use hyperlight_testing::simple_guest_as_string;

    use crate::func::call_ctx::MultiUseGuestCallContext;
    use crate::sandbox::SandboxConfiguration;
    use crate::sandbox_state::sandbox::{DevolvableSandbox, EvolvableSandbox};
    use crate::sandbox_state::transition::{MultiUseContextCallback, Noop};
    use crate::{GuestBinary, MultiUseSandbox, UninitializedSandbox};

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
    /// and devolving from MultiUseSandbox to MultiUseSandbox restores the previous state
    #[test]
    fn evolve_devolve_handles_state_correctly() {
        let sbox1: MultiUseSandbox = {
            let path = simple_guest_as_string().unwrap();
            let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
            u_sbox.evolve(Noop::default())
        }
        .unwrap();

        let func = Box::new(|call_ctx: &mut MultiUseGuestCallContext| {
            call_ctx.call::<i32>("AddToStatic", 5i32)?;
            Ok(())
        });
        let transition_func = MultiUseContextCallback::from(func);
        let mut sbox2 = sbox1.evolve(transition_func).unwrap();
        let res: i32 = sbox2.call_guest_function_by_name("GetStatic", ()).unwrap();
        assert_eq!(res, 5);
        let mut sbox3: MultiUseSandbox = sbox2.devolve(Noop::default()).unwrap();
        let res: i32 = sbox3.call_guest_function_by_name("GetStatic", ()).unwrap();
        assert_eq!(res, 0);
    }
}
