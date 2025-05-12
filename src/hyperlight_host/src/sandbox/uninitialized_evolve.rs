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

use core::time::Duration;
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use rand::Rng;
use tracing::{instrument, Span};

#[cfg(gdb)]
use super::mem_access::dbg_mem_access_handler_wrapper;
use crate::hypervisor::hypervisor_handler::{
    HvHandlerConfig, HypervisorHandler, HypervisorHandlerAction,
};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::GuestSharedMemory;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::mem_access::mem_access_handler_wrapper;
use crate::sandbox::outb::outb_handler_wrapper;
use crate::sandbox::{HostSharedMemory, MemMgrWrapper};
use crate::sandbox_state::sandbox::Sandbox;
use crate::{new_error, MultiUseSandbox, Result, UninitializedSandbox};

/// The implementation for evolving `UninitializedSandbox`es to
/// `Sandbox`es.
///
/// Note that `cb_opt`'s type has been carefully considered.
/// Particularly, it's not using a constrained generic to define
/// the type of the callback because if it did, you'd have to provide
/// type hints to the compiler if you want to pass `None` to the function.
/// With this type signature, you can pass `None` without having to do that.
///
/// If this doesn't make sense, and you want to change this type,
/// please reach out to a Hyperlight developer before making the change.
#[instrument(err(Debug), skip_all, , parent = Span::current(), level = "Trace")]
fn evolve_impl<TransformFunc, ResSandbox: Sandbox>(
    u_sbox: UninitializedSandbox,
    transform: TransformFunc,
) -> Result<ResSandbox>
where
    TransformFunc: Fn(
        Arc<Mutex<FunctionRegistry>>,
        MemMgrWrapper<HostSharedMemory>,
        HypervisorHandler,
    ) -> Result<ResSandbox>,
{
    let (hshm, gshm) = u_sbox.mgr.build();

    let hv_handler = {
        let mut hv_handler = hv_init(
            &hshm,
            gshm,
            u_sbox.host_funcs.clone(),
            u_sbox.max_initialization_time,
            u_sbox.max_execution_time,
            u_sbox.max_wait_for_cancellation,
            u_sbox.max_guest_log_level,
            #[cfg(gdb)]
            u_sbox.debug_info,
        )?;

        {
            let dispatch_function_addr = hshm.as_ref().get_pointer_to_dispatch_function()?;
            if dispatch_function_addr == 0 {
                return Err(new_error!("Dispatch function address is null"));
            }
            hv_handler.set_dispatch_function_addr(RawPtr::from(dispatch_function_addr))?;
        }

        hv_handler
    };

    transform(u_sbox.host_funcs, hshm, hv_handler)
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn evolve_impl_multi_use(u_sbox: UninitializedSandbox) -> Result<MultiUseSandbox> {
    evolve_impl(u_sbox, |hf, mut hshm, hv_handler| {
        {
            hshm.as_mut().push_state()?;
        }
        Ok(MultiUseSandbox::from_uninit(hf, hshm, hv_handler))
    })
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
#[allow(clippy::too_many_arguments)]
fn hv_init(
    hshm: &MemMgrWrapper<HostSharedMemory>,
    gshm: SandboxMemoryManager<GuestSharedMemory>,
    host_funcs: Arc<Mutex<FunctionRegistry>>,
    max_init_time: Duration,
    max_exec_time: Duration,
    max_wait_for_cancellation: Duration,
    max_guest_log_level: Option<LevelFilter>,
    #[cfg(gdb)] debug_info: Option<DebugInfo>,
) -> Result<HypervisorHandler> {
    let outb_hdl = outb_handler_wrapper(hshm.clone(), host_funcs);
    let mem_access_hdl = mem_access_handler_wrapper(hshm.clone());
    #[cfg(gdb)]
    let dbg_mem_access_hdl = dbg_mem_access_handler_wrapper(hshm.clone());

    let seed = {
        let mut rng = rand::rng();
        rng.random::<u64>()
    };
    let peb_addr = {
        let peb_u64 = u64::try_from(gshm.layout.peb_address)?;
        RawPtr::from(peb_u64)
    };
    let page_size = u32::try_from(page_size::get())?;
    let hv_handler_config = HvHandlerConfig {
        outb_handler: outb_hdl,
        mem_access_handler: mem_access_hdl,
        #[cfg(gdb)]
        dbg_mem_access_handler: dbg_mem_access_hdl,
        seed,
        page_size,
        peb_addr,
        dispatch_function_addr: Arc::new(Mutex::new(None)),
        max_init_time,
        max_exec_time,
        max_wait_for_cancellation,
        max_guest_log_level,
    };
    // Note: `dispatch_function_addr` is set by the Hyperlight guest library, and so it isn't in
    // shared memory at this point in time. We will set it after the execution of `hv_init`.

    let mut hv_handler = HypervisorHandler::new(hv_handler_config);

    hv_handler.start_hypervisor_handler(
        gshm,
        #[cfg(gdb)]
        debug_info,
    )?;

    hv_handler
        .execute_hypervisor_handler_action(HypervisorHandlerAction::Initialise)
        .map_err(|exec_e| match hv_handler.kill_hypervisor_handler_thread() {
            Ok(_) => exec_e,
            Err(kill_e) => new_error!("{}", format!("{}, {}", exec_e, kill_e)),
        })?;

    Ok(hv_handler)
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

    use super::evolve_impl_multi_use;
    use crate::sandbox::uninitialized::GuestBinary;
    use crate::UninitializedSandbox;

    #[test]
    fn test_evolve() {
        let guest_bin_paths = vec![
            simple_guest_as_string().unwrap(),
            callback_guest_as_string().unwrap(),
        ];
        for guest_bin_path in guest_bin_paths {
            let u_sbox = UninitializedSandbox::new(
                GuestBinary::FilePath(guest_bin_path.clone()),
                None,
                None,
                None,
            )
            .unwrap();
            evolve_impl_multi_use(u_sbox).unwrap();
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_evolve_in_proc() {
        use crate::SandboxRunOptions;

        let guest_bin_paths = vec![
            simple_guest_as_string().unwrap(),
            callback_guest_as_string().unwrap(),
        ];
        for guest_bin_path in guest_bin_paths {
            let u_sbox: UninitializedSandbox = UninitializedSandbox::new(
                GuestBinary::FilePath(guest_bin_path.clone()),
                None,
                Some(SandboxRunOptions::RunInHypervisor),
                None,
            )
            .unwrap();
            let err = format!("error evolving sandbox with guest binary {guest_bin_path}");
            let err_str = err.as_str();
            evolve_impl_multi_use(u_sbox).expect(err_str);
        }
    }
}
