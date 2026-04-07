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

use rand::RngExt;
use tracing::{Span, instrument};

use super::SandboxConfiguration;
#[cfg(any(crashdump, gdb))]
use super::uninitialized::SandboxRuntimeConfig;
use crate::hypervisor::hyperlight_vm::{HyperlightVm, HyperlightVmError};
use crate::mem::exe::LoadInfo;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::RawPtr;
use crate::mem::shared_mem::GuestSharedMemory;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(target_os = "linux")]
use crate::signal_handlers::setup_signal_handlers;
use crate::{MultiUseSandbox, Result, UninitializedSandbox};

#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn evolve_impl_multi_use(u_sbox: UninitializedSandbox) -> Result<MultiUseSandbox> {
    let (mut hshm, gshm) = u_sbox.mgr.build()?;

    // Publish the HostSharedMemory for scratch so any pre-existing
    // GuestCounter can begin issuing volatile writes.
    #[cfg(feature = "guest-counter")]
    {
        #[allow(clippy::unwrap_used)]
        // The mutex can only be poisoned if a previous lock holder
        // panicked.  Since we are the only writer at this point (the
        // GuestCounter only reads inside `increment`/`decrement`),
        // poisoning cannot happen.
        {
            *u_sbox.deferred_hshm.lock().unwrap() = Some(hshm.scratch_mem.clone());
        }
    }

    // Get the host page size. Narrowed to u32 because the guest ABI
    // passes it via a 32-bit register (rdx), but widened back to usize
    // for host-side alignment calculations in set_up_hypervisor_partition.
    let page_size = u32::try_from(page_size::get())?;

    let mut vm = set_up_hypervisor_partition(
        gshm,
        &u_sbox.config,
        u_sbox.stack_top_gva,
        page_size as usize,
        #[cfg(any(crashdump, gdb))]
        u_sbox.rt_cfg,
        u_sbox.load_info,
    )?;

    let seed = {
        let mut rng = rand::rng();
        rng.random::<u64>()
    };
    let peb_addr = {
        let peb_u64 = u64::try_from(hshm.layout.peb_address())?;
        RawPtr::from(peb_u64)
    };

    #[cfg(gdb)]
    let dbg_mem_access_hdl = Arc::new(Mutex::new(hshm.clone()));

    #[cfg(target_os = "linux")]
    setup_signal_handlers(&u_sbox.config)?;

    // Apply any file mappings that were prepared before evolve.
    // This must happen before vm.initialise() so the mapped data is
    // visible to the guest's init code.
    //
    // Each PreparedFileMapping is marked consumed immediately after
    // its map_region succeeds — on Windows, WhpVm::map_memory copies
    // the handle into its own cleanup list, so we must not let
    // PreparedFileMapping::drop also release it (double-close).
    // Unconsumed mappings (those after a failed map_region) are
    // cleaned up by Drop when `pending` goes out of scope.
    let pending = u_sbox.pending_file_mappings;
    for mut prepared in pending {
        let region = prepared.to_memory_region()?;
        unsafe { vm.map_region(&region) }.map_err(|e| {
            crate::HyperlightError::HyperlightVmError(HyperlightVmError::MapRegion(e))
        })?;

        // Mark consumed immediately after map_region succeeds.
        // On Windows, WhpVm::map_memory copies the file mapping handle
        // into its own `file_mappings` vec for cleanup on drop. If we
        // deferred mark_consumed(), both PreparedFileMapping::drop and
        // WhpVm::drop would release the same handle — a double-close.
        // For linux see https://github.com/hyperlight-dev/hyperlight/issues/1290.
        prepared.mark_consumed();
        // Record the mapping metadata in the PEB. This runs after
        // mark_consumed() because map_region already transferred
        // resource ownership to the VM layer. If this write fails,
        // the VM still holds a valid mapping but the PEB won't list
        // it — acceptable since we're about to return Err and the
        // VM will be dropped. The limit was already validated in
        // UninitializedSandbox::map_file_cow.
        #[cfg(feature = "nanvix-unstable")]
        hshm.write_file_mapping_entry(prepared.guest_base, prepared.size as u64, &prepared.label)?;
        hshm.mapped_rgns += 1;
    }

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

    #[cfg(gdb)]
    let dbg_mem_wrapper = Arc::new(Mutex::new(hshm.clone()));

    Ok(MultiUseSandbox::from_uninit(
        u_sbox.host_funcs,
        hshm,
        vm,
        #[cfg(gdb)]
        dbg_mem_wrapper,
    ))
}

pub(crate) fn set_up_hypervisor_partition(
    mgr: SandboxMemoryManager<GuestSharedMemory>,
    #[cfg_attr(target_os = "windows", allow(unused_variables))] config: &SandboxConfiguration,
    stack_top_gva: u64,
    page_size: usize,
    #[cfg(any(crashdump, gdb))] rt_cfg: SandboxRuntimeConfig,
    _load_info: LoadInfo,
) -> Result<HyperlightVm> {
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
                tracing::error!("Could not create gdb connection: {:#}", e);

                None
            }
        }
    } else {
        None
    };

    #[cfg(feature = "mem_profile")]
    let trace_info = MemTraceInfo::new(_load_info.info)?;

    // Store the original entry point address in the runtime config for core dumps.
    // This is needed because `entrypoint` transitions from `Initialise(addr)` to
    // `Call(dispatch_addr)` after guest initialisation, losing the original value
    // that GDB needs to compute the PIE binary's load offset.
    #[cfg(crashdump)]
    let rt_cfg = {
        let mut rt_cfg = rt_cfg;
        if let crate::sandbox::snapshot::NextAction::Initialise(addr) = mgr.entrypoint {
            rt_cfg.entry_point = Some(addr);
        }
        rt_cfg
    };

    Ok(HyperlightVm::new(
        mgr.shared_mem,
        mgr.scratch_mem,
        mgr.layout.get_pt_base_gpa(),
        mgr.entrypoint,
        stack_top_gva,
        page_size,
        config,
        #[cfg(gdb)]
        gdb_conn,
        #[cfg(crashdump)]
        rt_cfg,
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
