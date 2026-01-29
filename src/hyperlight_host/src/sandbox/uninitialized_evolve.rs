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

#[cfg(gdb)]
use std::sync::{Arc, Mutex};

use rand::Rng;
use tracing::{Span, instrument};

use super::SandboxConfiguration;
#[cfg(any(crashdump, gdb))]
use super::uninitialized::SandboxRuntimeConfig;
use crate::hypervisor::hyperlight_vm::{HyperlightVm, HyperlightVmError};
use crate::mem::exe::LoadInfo;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::ptr_offset::Offset;
use crate::mem::shared_mem::GuestSharedMemory;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(target_os = "linux")]
use crate::signal_handlers::setup_signal_handlers;
use crate::{MultiUseSandbox, Result, UninitializedSandbox, new_error};

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn evolve_impl_multi_use(u_sbox: UninitializedSandbox) -> Result<MultiUseSandbox> {
    let (mut hshm, gshm) = u_sbox.mgr.build()?;
    let mut vm = set_up_hypervisor_partition(
        gshm,
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
        let peb_u64 = u64::try_from(hshm.layout.peb_address)?;
        RawPtr::from(peb_u64)
    };

    let page_size = u32::try_from(page_size::get())?;

    #[cfg(gdb)]
    let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

    #[cfg(target_os = "linux")]
    setup_signal_handlers(&u_sbox.config)?;

    vm.initialise(
        peb_addr,
        seed,
        page_size,
        &mut hshm,
        &u_sbox.host_funcs,
        u_sbox.max_guest_log_level,
        #[cfg(gdb)]
        dbg_mem_access_hdl,
    )
    .map_err(HyperlightVmError::Initialize)?;

    let dispatch_function_addr = hshm.get_pointer_to_dispatch_function()?;
    if dispatch_function_addr == 0 {
        return Err(new_error!("Dispatch function address is null"));
    }

    let dispatch_ptr = RawPtr::from(dispatch_function_addr);

    #[cfg(gdb)]
    let dbg_mem_wrapper = Arc::new(Mutex::new(hshm.clone()));

    Ok(MultiUseSandbox::from_uninit(
        u_sbox.host_funcs,
        hshm,
        vm,
        dispatch_ptr,
        #[cfg(gdb)]
        dbg_mem_wrapper,
    ))
}

pub(crate) fn set_up_hypervisor_partition(
    mgr: SandboxMemoryManager<GuestSharedMemory>,
    #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
    #[cfg(any(crashdump, gdb))] rt_cfg: &SandboxRuntimeConfig,
    _load_info: LoadInfo,
) -> Result<HyperlightVm> {
    let base_ptr = GuestPtr::try_from(Offset::from(0))?;
    #[cfg(feature = "init-paging")]
    let rsp_ptr = {
        let rsp_offset_u64 = mgr.layout.get_rsp_offset() as u64;
        base_ptr + Offset::from(rsp_offset_u64)
    };

    #[cfg(not(feature = "init-paging"))]
    let rsp_ptr = GuestPtr::try_from(Offset::from(0))?;

    let pml4_ptr = {
        let pml4_offset_u64 = mgr.layout.get_pt_offset() as u64;
        base_ptr + Offset::from(pml4_offset_u64)
    };
    let entrypoint_ptr = mgr
        .entrypoint_offset
        .map(|x| {
            let entrypoint_total_offset = mgr.load_addr.clone() + x;
            GuestPtr::try_from(entrypoint_total_offset)
                .and_then(|x| x.absolute())
        })
        .transpose()?;

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

    #[cfg(feature = "mem_profile")]
    let trace_info = MemTraceInfo::new(_load_info.info)?;

    Ok(HyperlightVm::new(
        mgr.shared_mem,
        mgr.scratch_mem,
        pml4_ptr.absolute()?,
        entrypoint_ptr,
        rsp_ptr.absolute()?,
        config,
        #[cfg(gdb)]
        gdb_conn,
        #[cfg(crashdump)]
        rt_cfg.clone(),
        #[cfg(feature = "mem_profile")]
        trace_info,
    )
    .map_err(HyperlightVmError::Create)?)
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::simple_guest_as_string;

    use super::evolve_impl_multi_use;
    use crate::UninitializedSandbox;
    use crate::sandbox::uninitialized::GuestBinary;

    #[test]
    fn test_evolve() {
        let guest_bin_paths = vec![simple_guest_as_string().unwrap()];
        for guest_bin_path in guest_bin_paths {
            let u_sbox =
                UninitializedSandbox::new(GuestBinary::FilePath(guest_bin_path.clone()), None)
                    .unwrap();
            evolve_impl_multi_use(u_sbox).unwrap();
        }
    }
}
