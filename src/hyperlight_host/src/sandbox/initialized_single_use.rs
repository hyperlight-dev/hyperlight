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

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};
use tracing::{instrument, Span};

use super::{MemMgrWrapper, WrapperGetter};
use crate::func::call_ctx::SingleUseGuestCallContext;
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox_state::sandbox::Sandbox;
use crate::Result;

/// A sandbox implementation that supports calling no more than 1 guest
/// function
pub struct SingleUseSandbox {
    pub(super) mem_mgr: MemMgrWrapper<HostSharedMemory>,
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
impl Drop for SingleUseSandbox {
    fn drop(&mut self) {
        match self.hv_handler.kill_hypervisor_handler_thread() {
            Ok(_) => {}
            Err(e) => {
                log::error!("[POTENTIAL THREAD LEAK] Potentially failed to kill hypervisor handler thread when dropping MultiUseSandbox: {:?}", e);
            }
        }
    }
}

impl SingleUseSandbox {
    /// Move an `UninitializedSandbox` into a new `SingleUseSandbox` instance.
    ///
    /// This function is not equivalent to doing an `evolve` from uninitialized
    /// to initialized. It only copies values from `val` to the new returned
    /// `SingleUseSandbox` instance, and does not execute any initialization
    /// logic on the guest. We want to ensure that, when users request to
    /// convert an `UninitializedSandbox` to a `SingleUseSandbox`,
    /// initialization logic is always run, so we are purposely making this
    /// function not publicly exposed. Finally, although it looks like it should be
    /// in a `From` implementation, it is purposely not, because external
    /// users would then see it and be able to use it.
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn from_uninit(
        mgr: MemMgrWrapper<HostSharedMemory>,
        hv_handler: HypervisorHandler,
    ) -> SingleUseSandbox {
        Self {
            mem_mgr: mgr,
            hv_handler,
        }
    }

    /// Create a new `SingleUseCallContext` . The main purpose of the
    /// a SingleUseSandbox is to allow multiple calls to guest functions from within a callback function.
    ///
    /// Since this function consumes `self`, the returned
    /// `SingleUseGuestCallContext` is guaranteed mutual exclusion for calling
    /// functions within the sandbox.
    ///
    /// Since this is a `SingleUseSandbox`, the returned
    /// context cannot be converted back into the original `SingleUseSandbox`.
    /// When it's dropped, all the resources of the context and sandbox are
    /// released at once.
    ///
    /// Example usage (compiled as a "no_run" doctest since the test binary
    /// will not be found):
    ///
    /// ```no_run
    /// use hyperlight_host::sandbox::{UninitializedSandbox, SingleUseSandbox};
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
    ///     None,
    /// ).unwrap();
    /// let sbox: SingleUseSandbox = u_sbox.evolve(Noop::default()).unwrap();
    /// // Next, create a new call context from the single-use sandbox.
    /// // After this line, your code will not compile if you try to use the
    /// // original `sbox` variable.
    /// let mut ctx = sbox.new_call_context();
    ///
    ///
    /// // Create a closure to call multiple guest functions usings the contexts
    /// // call_from-func method. Assues that the loaded binary
    /// // ("some_guest_binary") has a function therein called "SomeGuestFunc" and another called "SomeOtherGuestFunc"
    /// // that take a single integer argument and return an integer.
    ///
    ///
    /// let result = ctx.call_from_func( |call_ctx| {
    ///
    /// match call_ctx.call(
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
    /// }
    ///
    /// match call_ctx.call(
    ///     "SomeOtherGuestFunc",
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
    /// }
    ///
    /// Ok(ReturnValue::Int(0))
    ///
    /// });
    ///
    /// // After the call context is dropped, the sandbox is also dropped.
    /// ```
    #[instrument(skip_all, parent = Span::current())]
    pub fn new_call_context(self) -> SingleUseGuestCallContext {
        SingleUseGuestCallContext::start(self)
    }

    /// Convenience for the following:
    ///
    /// `self.new_call_context().call(name, ret, args)`
    #[instrument(err(Debug), skip(self, args), parent = Span::current())]
    pub fn call_guest_function_by_name(
        self,
        name: &str,
        ret: ReturnType,
        args: Option<Vec<ParameterValue>>,
    ) -> Result<ReturnValue> {
        self.new_call_context().call(name, ret, args)
    }
}

impl WrapperGetter for SingleUseSandbox {
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

impl Sandbox for SingleUseSandbox {
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn check_stack_guard(&self) -> Result<bool> {
        self.mem_mgr.check_stack_guard()
    }
}

impl std::fmt::Debug for SingleUseSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleUseSandbox")
            .field("stack_guard", &self.mem_mgr.get_stack_cookie())
            .finish()
    }
}
