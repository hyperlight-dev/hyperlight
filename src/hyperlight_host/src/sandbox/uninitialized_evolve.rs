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

use std::sync::{Arc, Mutex};

use rand::Rng;
use tracing::{Span, instrument};

use super::SandboxConfiguration;
use super::hypervisor::{HypervisorType, get_available_hypervisor};
#[cfg(gdb)]
use super::mem_access::dbg_mem_access_handler_wrapper;
#[cfg(any(crashdump, gdb))]
use super::uninitialized::SandboxRuntimeConfig;
use crate::HyperlightError::NoHypervisorFound;
use crate::hypervisor::Hypervisor;
use crate::mem::exe::LoadInfo;
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::ptr_offset::Offset;
use crate::mem::shared_mem::GuestSharedMemory;
#[cfg(any(feature = "init-paging", target_os = "windows"))]
use crate::mem::shared_mem::SharedMemory;
#[cfg(feature = "trace_guest")]
use crate::sandbox::TraceInfo;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::{HostSharedMemory, MemMgrWrapper};
#[cfg(target_os = "linux")]
use crate::signal_handlers::setup_signal_handlers;
use crate::{Result, Sandbox, UninitializedSandbox, log_then_return, new_error};

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
fn evolve_impl<TransformFunc, ResSandbox>(
    u_sbox: UninitializedSandbox,
    transform: TransformFunc,
) -> Result<ResSandbox>
where
    TransformFunc: Fn(
        Arc<Mutex<FunctionRegistry>>,
        MemMgrWrapper<HostSharedMemory>,
        Box<dyn Hypervisor>,
        RawPtr,
    ) -> Result<ResSandbox>,
{
    let (hshm, mut gshm) = u_sbox.mgr.build();
    let mut vm = set_up_hypervisor_partition(
        &mut gshm,
        &u_sbox.config,
        #[cfg(any(crashdump, gdb))]
        &u_sbox.rt_cfg,
        u_sbox.load_info,
    )?;

    let seed = {
        let mut rng = rand::rng();
        rng.random::<u64>()
    };
    let peb_addr = {
        let peb_u64 = u64::try_from(gshm.layout.peb_address)?;
        RawPtr::from(peb_u64)
    };

    let page_size = u32::try_from(page_size::get())?;

    #[cfg(gdb)]
    let dbg_mem_access_hdl = dbg_mem_access_handler_wrapper(hshm.clone());

    #[cfg(target_os = "linux")]
    setup_signal_handlers(&u_sbox.config)?;

    vm.initialise(
        peb_addr,
        seed,
        page_size,
        hshm.clone(),
        u_sbox.host_funcs.clone(),
        u_sbox.max_guest_log_level,
        #[cfg(gdb)]
        dbg_mem_access_hdl,
    )?;

    let dispatch_function_addr = hshm.as_ref().get_pointer_to_dispatch_function()?;
    if dispatch_function_addr == 0 {
        return Err(new_error!("Dispatch function address is null"));
    }

    transform(
        u_sbox.host_funcs,
        hshm,
        vm,
        RawPtr::from(dispatch_function_addr),
    )
}

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn evolve_impl_multi_use(u_sbox: UninitializedSandbox) -> Result<Sandbox> {
    evolve_impl(u_sbox, |hf, hshm, vm, dispatch_ptr| {
        #[cfg(gdb)]
        let dbg_mem_wrapper = dbg_mem_access_handler_wrapper(hshm.clone());
        Ok(Sandbox::from_uninit(
            hf,
            hshm,
            vm,
            dispatch_ptr,
            #[cfg(gdb)]
            dbg_mem_wrapper,
        ))
    })
}

pub(crate) fn set_up_hypervisor_partition(
    mgr: &mut SandboxMemoryManager<GuestSharedMemory>,
    #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
    #[cfg(any(crashdump, gdb))] rt_cfg: &SandboxRuntimeConfig,
    _load_info: LoadInfo,
) -> Result<Box<dyn Hypervisor>> {
    #[cfg(feature = "init-paging")]
    let rsp_ptr = {
        let mut regions = mgr.layout.get_memory_regions(&mgr.shared_mem)?;
        let mem_size = u64::try_from(mgr.shared_mem.mem_size())?;
        let rsp_u64 = mgr.set_up_shared_memory(mem_size, &mut regions)?;
        let rsp_raw = RawPtr::from(rsp_u64);
        GuestPtr::try_from(rsp_raw)
    }?;
    #[cfg(not(feature = "init-paging"))]
    let rsp_ptr = GuestPtr::try_from(Offset::from(0))?;
    let regions = mgr.layout.get_memory_regions(&mgr.shared_mem)?;
    let base_ptr = GuestPtr::try_from(Offset::from(0))?;
    let pml4_ptr = {
        let pml4_offset_u64 = u64::try_from(SandboxMemoryLayout::PML4_OFFSET)?;
        base_ptr + Offset::from(pml4_offset_u64)
    };
    let entrypoint_ptr = {
        let entrypoint_total_offset = mgr.load_addr.clone() + mgr.entrypoint_offset;
        GuestPtr::try_from(entrypoint_total_offset)
    }?;

    if base_ptr != pml4_ptr {
        log_then_return!(
            "Error: base_ptr ({:#?}) does not equal pml4_ptr ({:#?})",
            base_ptr,
            pml4_ptr
        );
    }
    if entrypoint_ptr <= pml4_ptr {
        log_then_return!(
            "Error: entrypoint_ptr ({:#?}) is not greater than pml4_ptr ({:#?})",
            entrypoint_ptr,
            pml4_ptr
        );
    }

    // Create gdb thread if gdb is enabled and the configuration is provided
    #[cfg(gdb)]
    let gdb_conn = if let Some(DebugInfo { port }) = rt_cfg.debug_info {
        use crate::hypervisor::gdb::create_gdb_thread;

        let gdb_conn = create_gdb_thread(port);

        // in case the gdb thread creation fails, we still want to continue
        // without gdb
        match gdb_conn {
            Ok(gdb_conn) => Some(gdb_conn),
            Err(e) => {
                log::error!("Could not create gdb connection: {:#}", e);

                None
            }
        }
    } else {
        None
    };

    #[cfg(feature = "trace_guest")]
    let trace_info = TraceInfo::new(
        #[cfg(feature = "unwind_guest")]
        _load_info,
    )?;

    match *get_available_hypervisor() {
        #[cfg(mshv)]
        Some(HypervisorType::Mshv) => {
            let hv = crate::hypervisor::hyperv_linux::HypervLinuxDriver::new(
                regions,
                entrypoint_ptr,
                rsp_ptr,
                pml4_ptr,
                config,
                #[cfg(gdb)]
                gdb_conn,
                #[cfg(crashdump)]
                rt_cfg.clone(),
                #[cfg(feature = "trace_guest")]
                trace_info,
            )?;
            Ok(Box::new(hv))
        }

        #[cfg(kvm)]
        Some(HypervisorType::Kvm) => {
            let hv = crate::hypervisor::kvm::KVMDriver::new(
                regions,
                pml4_ptr.absolute()?,
                entrypoint_ptr.absolute()?,
                rsp_ptr.absolute()?,
                config,
                #[cfg(gdb)]
                gdb_conn,
                #[cfg(crashdump)]
                rt_cfg.clone(),
                #[cfg(feature = "trace_guest")]
                trace_info,
            )?;
            Ok(Box::new(hv))
        }

        #[cfg(target_os = "windows")]
        Some(HypervisorType::Whp) => {
            use crate::hypervisor::wrappers::HandleWrapper;

            let mmap_file_handle = mgr
                .shared_mem
                .with_exclusivity(|e| e.get_mmap_file_handle())?;
            let hv = crate::hypervisor::hyperv_windows::HypervWindowsDriver::new(
                regions,
                mgr.shared_mem.raw_mem_size(), // we use raw_* here because windows driver requires 64K aligned addresses,
                pml4_ptr.absolute()?,
                entrypoint_ptr.absolute()?,
                rsp_ptr.absolute()?,
                HandleWrapper::from(mmap_file_handle),
                #[cfg(gdb)]
                gdb_conn,
                #[cfg(crashdump)]
                rt_cfg.clone(),
                #[cfg(feature = "trace_guest")]
                trace_info,
            )?;
            Ok(Box::new(hv))
        }

        _ => {
            log_then_return!(NoHypervisorFound());
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::{callback_guest_as_string, simple_guest_as_string};

    use super::evolve_impl_multi_use;
    use crate::UninitializedSandbox;
    use crate::sandbox::uninitialized::GuestBinary;

    #[test]
    fn test_evolve() {
        let guest_bin_paths = vec![
            simple_guest_as_string().unwrap(),
            callback_guest_as_string().unwrap(),
        ];
        for guest_bin_path in guest_bin_paths {
            let u_sbox =
                UninitializedSandbox::new(GuestBinary::FilePath(guest_bin_path.clone()), None)
                    .unwrap();
            evolve_impl_multi_use(u_sbox).unwrap();
        }
    }
}
