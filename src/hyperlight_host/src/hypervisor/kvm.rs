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

use std::convert::TryFrom;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

#[cfg(feature = "trace_guest")]
use super::TraceRegister;
use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, GuestDebug, KvmDebug, VcpuStopReason};
#[cfg(feature = "init-paging")]
use super::{
    CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE,
    EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use super::{HyperlightExit, Hypervisor, InterruptHandle, LinuxInterruptHandle, VirtualCPU};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::hypervisor::get_memory_access_violation;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::SandboxConfiguration;
#[cfg(feature = "trace_guest")]
use crate::sandbox::TraceInfo;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::handle_outb;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{Result, log_then_return, new_error};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = Kvm::new() {
        let api_version = kvm.get_api_version();
        match api_version {
            version if version == 12 && kvm.check_extension(UserMemory) => true,
            12 => {
                log::info!("KVM does not have KVM_CAP_USER_MEMORY capability");
                false
            }
            version => {
                log::info!("KVM GET_API_VERSION returned {}, expected 12", version);
                false
            }
        }
    } else {
        log::info!("KVM is not available on this system");
        false
    }
}

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use kvm_bindings::kvm_debug_exit_arch;

    use super::KVMDriver;
    use crate::hypervisor::gdb::{
        DebugMsg, DebugResponse, GuestDebug, KvmDebug, VcpuStopReason, X86_64Regs,
    };
    use crate::mem::mgr::SandboxMemoryManager;
    use crate::mem::shared_mem::HostSharedMemory;
    use crate::{Result, new_error};

    impl KVMDriver {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = KvmDebug::default();

            debug.set_single_step(&self.vcpu_fd, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        /// Get the reason the vCPU has stopped
        pub(crate) fn get_stop_reason(
            &mut self,
            debug_exit: kvm_debug_exit_arch,
        ) -> Result<VcpuStopReason> {
            let debug = self
                .debug
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            debug.get_stop_reason(&self.vcpu_fd, debug_exit, self.entrypoint)
        }

        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        ) -> Result<DebugResponse> {
            if let Some(debug) = self.debug.as_mut() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        debug
                            .add_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        debug
                            .add_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        debug.set_single_step(&self.vcpu_fd, false).map_err(|e| {
                            log::error!("Failed to continue execution: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Continue)
                    }
                    DebugMsg::DisableDebug => {
                        self.disable_debug().map_err(|e| {
                            log::error!("Failed to disable debugging: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::DisableDebug)
                    }
                    DebugMsg::GetCodeSectionOffset => {
                        let offset = dbg_mem_access_fn
                            .try_lock()
                            .map_err(|e| {
                                new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                            })?
                            .layout
                            .get_guest_code_address();

                        Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                    }
                    DebugMsg::ReadAddr(addr, len) => {
                        let mut data = vec![0u8; len];

                        debug
                            .read_addrs(&self.vcpu_fd, addr, &mut data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to read from address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => {
                        let mut regs = X86_64Regs::default();

                        debug
                            .read_regs(&self.vcpu_fd, &mut regs)
                            .map_err(|e| {
                                log::error!("Failed to read registers: {:?}", e);

                                e
                            })
                            .map(|_| DebugResponse::ReadRegisters(regs))
                    }
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        debug
                            .remove_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        debug
                            .remove_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        debug.set_single_step(&self.vcpu_fd, true).map_err(|e| {
                            log::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        debug
                            .write_addrs(&self.vcpu_fd, addr, &data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to write to address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(regs) => debug
                        .write_regs(&self.vcpu_fd, &regs)
                        .map_err(|e| {
                            log::error!("Failed to write registers: {:?}", e);

                            e
                        })
                        .map(|_| DebugResponse::WriteRegisters),
                }
            } else {
                Err(new_error!("Debugging is not enabled"))
            }
        }

        pub(crate) fn recv_dbg_msg(&mut self) -> Result<DebugMsg> {
            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.recv().map_err(|e| {
                new_error!(
                    "Got an error while waiting to receive a message from the gdb thread: {:?}",
                    e
                )
            })
        }

        pub(crate) fn send_dbg_msg(&mut self, cmd: DebugResponse) -> Result<()> {
            log::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.send(cmd).map_err(|e| {
                new_error!(
                    "Got an error while sending a response message to the gdb thread: {:?}",
                    e
                )
            })
        }
    }
}

/// A Hypervisor driver for KVM on Linux
pub(crate) struct KVMDriver {
    _kvm: Kvm,
    vm_fd: VmFd,
    page_size: usize,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    interrupt_handle: Arc<LinuxInterruptHandle>,
    mem_mgr: Option<SandboxMemoryManager<HostSharedMemory>>,
    host_funcs: Option<Arc<Mutex<FunctionRegistry>>>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<(MemoryRegion, u32)>, // Later mapped regions (region, slot number)
    next_slot: u32,                     // Monotonically increasing slot number
    freed_slots: Vec<u32>,              // Reusable slots from unmapped regions

    #[cfg(gdb)]
    debug: Option<KvmDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
    #[cfg(feature = "trace_guest")]
    #[allow(dead_code)]
    trace_info: TraceInfo,
}

impl KVMDriver {
    /// Create a new instance of a `KVMDriver`, with only control registers
    /// set. Standard registers will not be set, and `initialise` must
    /// be called to do so.
    #[allow(clippy::too_many_arguments)]
    // TODO: refactor this function to take fewer arguments. Add trace_info to rt_cfg
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        config: &SandboxConfiguration,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
    ) -> Result<Self> {
        let kvm = Kvm::new()?;

        let vm_fd = kvm.create_vm_with_type(0)?;

        mem_regions.iter().enumerate().try_for_each(|(i, region)| {
            let mut kvm_region: kvm_userspace_memory_region = region.clone().into();
            kvm_region.slot = i as u32;
            unsafe { vm_fd.set_user_memory_region(kvm_region) }
        })?;

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;
        Self::setup_initial_sregs(&mut vcpu_fd, pml4_addr)?;

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            let mut debug = KvmDebug::new();
            // Add breakpoint to the entry point address
            debug.add_hw_breakpoint(&vcpu_fd, entrypoint)?;

            (Some(debug), Some(gdb_conn))
        } else {
            (None, None)
        };

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;

        let interrupt_handle = Arc::new(LinuxInterruptHandle {
            running: AtomicU64::new(0),
            cancel_requested: AtomicBool::new(false),
            #[cfg(gdb)]
            debug_interrupt: AtomicBool::new(false),
            #[cfg(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            ))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() as u64 }),
            #[cfg(not(all(
                target_arch = "x86_64",
                target_vendor = "unknown",
                target_os = "linux",
                target_env = "musl"
            )))]
            tid: AtomicU64::new(unsafe { libc::pthread_self() }),
            retry_delay: config.get_interrupt_retry_delay(),
            dropped: AtomicBool::new(false),
            sig_rt_min_offset: config.get_interrupt_vcpu_sigrtmin_offset(),
        });

        #[allow(unused_mut)]
        let mut hv = Self {
            _kvm: kvm,
            vm_fd,
            page_size: 0,
            vcpu_fd,
            entrypoint,
            orig_rsp: rsp_gp,
            next_slot: mem_regions.len() as u32,
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            freed_slots: Vec::new(),
            interrupt_handle: interrupt_handle.clone(),
            mem_mgr: None,
            host_funcs: None,
            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            #[cfg(crashdump)]
            rt_cfg,
            #[cfg(feature = "trace_guest")]
            trace_info,
        };

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if hv.debug.is_some() {
            hv.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(hv)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu_fd: &mut VcpuFd, _pml4_addr: u64) -> Result<()> {
        // setup paging and IA-32e (64-bit) mode
        let mut sregs = vcpu_fd.get_sregs()?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "init-paging")] {
                sregs.cr3 = _pml4_addr;
                sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
                sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
                sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
                sregs.cs.l = 1; // required for 64-bit mode
            } else {
                sregs.cs.base = 0;
                sregs.cs.selector = 0;
            }
        }
        vcpu_fd.set_sregs(&sregs)?;
        Ok(())
    }
}

impl Debug for KVMDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("KVM Driver");
        // Output each memory region

        for region in &self.sandbox_regions {
            f.field("Sandbox Memory Region", &region);
        }
        for region in &self.mmap_regions {
            f.field("Mapped Memory Region", &region);
        }
        let regs = self.vcpu_fd.get_regs();
        // check that regs is OK and then set field in debug struct

        if let Ok(regs) = regs {
            f.field("Registers", &regs);
        }

        let sregs = self.vcpu_fd.get_sregs();

        // check that sregs is OK and then set field in debug struct

        if let Ok(sregs) = sregs {
            f.field("Special Registers", &sregs);
        }

        f.finish()
    }
}

impl Hypervisor for KVMDriver {
    /// Implementation of initialise for Hypervisor trait.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        self.mem_mgr = Some(mem_mgr);
        self.host_funcs = Some(host_funcs);
        self.page_size = page_size as usize;

        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = kvm_regs {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rdi: peb_addr.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,

            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn map_region(&mut self, region: &MemoryRegion) -> Result<()> {
        if [
            region.guest_region.start,
            region.guest_region.end,
            region.host_region.start,
            region.host_region.end,
        ]
        .iter()
        .any(|x| x % self.page_size != 0)
        {
            log_then_return!(
                "region is not page-aligned {:x}, {region:?}",
                self.page_size
            );
        }

        let mut kvm_region: kvm_userspace_memory_region = region.clone().into();

        // Try to reuse a freed slot first, otherwise use next_slot
        let slot = if let Some(freed_slot) = self.freed_slots.pop() {
            freed_slot
        } else {
            let slot = self.next_slot;
            self.next_slot += 1;
            slot
        };

        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }?;
        self.mmap_regions.push((region.to_owned(), slot));
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn unmap_region(&mut self, region: &MemoryRegion) -> Result<()> {
        if let Some(idx) = self.mmap_regions.iter().position(|(r, _)| r == region) {
            let (region, slot) = self.mmap_regions.remove(idx);
            let mut kvm_region: kvm_userspace_memory_region = region.into();
            kvm_region.slot = slot;
            // Setting memory_size to 0 unmaps the slot's region
            // From https://docs.kernel.org/virt/kvm/api.html
            // > Deleting a slot is done by passing zero for memory_size.
            kvm_region.memory_size = 0;
            unsafe { self.vm_fd.set_user_memory_region(kvm_region) }?;

            // Add the freed slot to the reuse list
            self.freed_slots.push(slot);

            Ok(())
        } else {
            Err(new_error!("Tried to unmap region that is not mapped"))
        }
    }

    fn get_mapped_regions(&self) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_> {
        Box::new(self.mmap_regions.iter().map(|(region, _)| region))
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = kvm_regs {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        // reset fpu state
        let fpu = kvm_fpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vcpu_fd.set_fpu(&fpu)?;

        // run
        VirtualCPU::run(
            self.as_mut_hypervisor(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        _rip: u64,
        _instruction_length: u64,
    ) -> Result<()> {
        // KVM does not need RIP or instruction length, as it automatically sets the RIP

        // The payload param for the outb_handle_fn is the first byte
        // of the data array cast to an u64. Thus, we need to make sure
        // the data array has at least one u8, then convert that to an u64
        if data.is_empty() {
            log_then_return!("no data was given in IO interrupt");
        } else {
            let mut padded = [0u8; 4];
            let copy_len = data.len().min(4);
            padded[..copy_len].copy_from_slice(&data[..copy_len]);
            let value = u32::from_le_bytes(padded);

            #[cfg(feature = "trace_guest")]
            {
                // We need to handle the borrow checker issue where we need both:
                // - &mut SandboxMemoryManager (from self.mem_mgr.as_mut())
                // - &mut dyn Hypervisor (from self)
                // We'll use a temporary approach to extract the mem_mgr temporarily
                let mem_mgr_option = self.mem_mgr.take();
                let mut mem_mgr =
                    mem_mgr_option.ok_or_else(|| new_error!("mem_mgr not initialized"))?;
                let host_funcs = self
                    .host_funcs
                    .as_ref()
                    .ok_or_else(|| new_error!("host_funcs not initialized"))?
                    .clone();

                handle_outb(&mut mem_mgr, host_funcs, self, port, value)?;

                // Put the mem_mgr back
                self.mem_mgr = Some(mem_mgr);
            }

            #[cfg(not(feature = "trace_guest"))]
            {
                let mem_mgr = self
                    .mem_mgr
                    .as_mut()
                    .ok_or_else(|| new_error!("mem_mgr not initialized"))?;
                let host_funcs = self
                    .host_funcs
                    .as_ref()
                    .ok_or_else(|| new_error!("host_funcs not initialized"))?
                    .clone();

                handle_outb(mem_mgr, host_funcs, port, value)?;
            }
        }

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<HyperlightExit> {
        self.interrupt_handle
            .tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Relaxed);
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
        self.interrupt_handle
            .set_running_and_increment_generation()
            .map_err(|e| {
                new_error!(
                    "Error setting running state and incrementing generation: {}",
                    e
                )
            })?;
        #[cfg(not(gdb))]
        let debug_interrupt = false;
        #[cfg(gdb)]
        let debug_interrupt = self
            .interrupt_handle
            .debug_interrupt
            .load(Ordering::Relaxed);
        // Don't run the vcpu if `cancel_requested` is true
        //
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
        let exit_reason = if self
            .interrupt_handle
            .cancel_requested
            .load(Ordering::Relaxed)
            || debug_interrupt
        {
            Err(kvm_ioctls::Error::new(libc::EINTR))
        } else {
            #[cfg(feature = "trace_guest")]
            if self.trace_info.guest_start_epoch.is_none() {
                // Store the guest start epoch and cycles to trace the guest execution time
                crate::debug!("KVM - Guest Start Epoch set");
                self.trace_info.guest_start_epoch = Some(std::time::Instant::now());
                self.trace_info.guest_start_tsc =
                    Some(hyperlight_guest_tracing::invariant_tsc::read_tsc());
            }

            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then the vcpu will run, but we will keep sending signals to this thread
            // to interrupt it until `running` is set to false. The `vcpu_fd::run()` call will
            // return either normally with an exit reason, or from being "kicked" by out signal handler, with an EINTR error,
            // both of which are fine.
            self.vcpu_fd.run()
        };
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then signals will be sent to this thread until `running` is set to false.
        // This is fine since the signal handler is a no-op.
        let cancel_requested = self
            .interrupt_handle
            .cancel_requested
            .load(Ordering::Relaxed);
        #[cfg(gdb)]
        let debug_interrupt = self
            .interrupt_handle
            .debug_interrupt
            .load(Ordering::Relaxed);
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then `cancel_requested` will be set to true again, which will cancel the **next vcpu run**.
        // Additionally signals will be sent to this thread until `running` is set to false.
        // This is fine since the signal handler is a no-op.
        self.interrupt_handle.clear_running_bit();
        // At this point, `running` is false so no more signals will be sent to this thread,
        // but we may still receive async signals that were sent before this point.
        // To prevent those signals from interrupting subsequent calls to `run()` (on other vms!),
        // we make sure to check `cancel_requested` before cancelling (see `libc::EINTR` match-arm below).
        let result = match exit_reason {
            Ok(VcpuExit::Hlt) => {
                crate::debug!("KVM - Halt Details : {:#?}", &self);
                HyperlightExit::Halt()
            }
            Ok(VcpuExit::IoOut(port, data)) => {
                // because vcpufd.run() mutably borrows self we cannot pass self to crate::debug! macro here
                crate::debug!("KVM IO Details : \nPort : {}\nData : {:?}", port, data);
                // KVM does not need to set RIP or instruction length so these are set to 0
                HyperlightExit::IoOut(port, data.to_vec(), 0, 0)
            }
            Ok(VcpuExit::MmioRead(addr, _)) => {
                crate::debug!("KVM MMIO Read -Details: Address: {} \n {:#?}", addr, &self);

                match get_memory_access_violation(
                    addr as usize,
                    self.sandbox_regions
                        .iter()
                        .chain(self.mmap_regions.iter().map(|(r, _)| r)),
                    MemoryRegionFlags::READ,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            Ok(VcpuExit::MmioWrite(addr, _)) => {
                crate::debug!("KVM MMIO Write -Details: Address: {} \n {:#?}", addr, &self);

                match get_memory_access_violation(
                    addr as usize,
                    self.sandbox_regions
                        .iter()
                        .chain(self.mmap_regions.iter().map(|(r, _)| r)),
                    MemoryRegionFlags::WRITE,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            #[cfg(gdb)]
            // KVM provides architecture specific information about the vCPU state when exiting
            Ok(VcpuExit::Debug(debug_exit)) => match self.get_stop_reason(debug_exit) {
                Ok(reason) => HyperlightExit::Debug(reason),
                Err(e) => {
                    log_then_return!("Error getting stop reason: {:?}", e);
                }
            },
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                libc::EINTR => {
                    // If cancellation was not requested for this specific vm, the vcpu was interrupted because of debug interrupt or
                    // a stale signal that meant to be delivered to a previous/other vcpu on this same thread, so let's ignore it
                    if cancel_requested {
                        self.interrupt_handle
                            .cancel_requested
                            .store(false, Ordering::Relaxed);
                        HyperlightExit::Cancelled()
                    } else {
                        #[cfg(gdb)]
                        if debug_interrupt {
                            self.interrupt_handle
                                .debug_interrupt
                                .store(false, Ordering::Relaxed);

                            // If the vCPU was stopped because of an interrupt, we need to
                            // return a special exit reason so that the gdb thread can handle it
                            // and resume execution
                            HyperlightExit::Debug(VcpuStopReason::Interrupt)
                        } else {
                            HyperlightExit::Retry()
                        }

                        #[cfg(not(gdb))]
                        HyperlightExit::Retry()
                    }
                }
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                let err_msg = format!("Unexpected KVM Exit {:?}", other);
                crate::debug!("KVM Other Exit Details: {:#?}", &self);
                HyperlightExit::Unknown(err_msg)
            }
        };
        Ok(result)
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext<'_>>> {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.vcpu_fd.get_regs()?;
            let sregs = self.vcpu_fd.get_sregs()?;
            let xsave = self.vcpu_fd.get_xsave()?;

            // Set the registers in the order expected by the crashdump context
            regs[0] = vcpu_regs.r15; // r15
            regs[1] = vcpu_regs.r14; // r14
            regs[2] = vcpu_regs.r13; // r13
            regs[3] = vcpu_regs.r12; // r12
            regs[4] = vcpu_regs.rbp; // rbp
            regs[5] = vcpu_regs.rbx; // rbx
            regs[6] = vcpu_regs.r11; // r11
            regs[7] = vcpu_regs.r10; // r10
            regs[8] = vcpu_regs.r9; // r9
            regs[9] = vcpu_regs.r8; // r8
            regs[10] = vcpu_regs.rax; // rax
            regs[11] = vcpu_regs.rcx; // rcx
            regs[12] = vcpu_regs.rdx; // rdx
            regs[13] = vcpu_regs.rsi; // rsi
            regs[14] = vcpu_regs.rdi; // rdi
            regs[15] = 0; // orig rax
            regs[16] = vcpu_regs.rip; // rip
            regs[17] = sregs.cs.selector as u64; // cs
            regs[18] = vcpu_regs.rflags; // eflags
            regs[19] = vcpu_regs.rsp; // rsp
            regs[20] = sregs.ss.selector as u64; // ss
            regs[21] = sregs.fs.base; // fs_base
            regs[22] = sregs.gs.base; // gs_base
            regs[23] = sregs.ds.selector as u64; // ds
            regs[24] = sregs.es.selector as u64; // es
            regs[25] = sregs.fs.selector as u64; // fs
            regs[26] = sregs.gs.selector as u64; // gs

            // Get the filename from the runtime config
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            // The [`CrashDumpContext`] accepts xsave as a vector of u8, so we need to convert the
            // xsave region to a vector of u8
            Ok(Some(crashdump::CrashDumpContext::new(
                &self.sandbox_regions,
                regs,
                xsave
                    .region
                    .iter()
                    .flat_map(|item| item.to_le_bytes())
                    .collect::<Vec<u8>>(),
                self.entrypoint,
                self.rt_cfg.binary_path.clone(),
                filename,
            )))
        } else {
            Ok(None)
        }
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
        if self.debug.is_none() {
            return Err(new_error!("Debugging is not enabled"));
        }

        match stop_reason {
            // If the vCPU stopped because of a crash, we need to handle it differently
            // We do not want to allow resuming execution or placing breakpoints
            // because the guest has crashed.
            // We only allow reading registers and memory
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    // Flag to store if we should deny continue or step requests
                    let mut deny_continue = false;
                    // Flag to store if we should detach from the gdb session
                    let mut detach = false;

                    let response = match req {
                        // Allow the detach request to disable debugging by continuing resuming
                        // hypervisor crash error reporting
                        DebugMsg::DisableDebug => {
                            detach = true;
                            DebugResponse::DisableDebug
                        }
                        // Do not allow continue or step requests
                        DebugMsg::Continue | DebugMsg::Step => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        // Do not allow adding/removing breakpoints and writing to memory or registers
                        DebugMsg::AddHwBreakpoint(_)
                        | DebugMsg::AddSwBreakpoint(_)
                        | DebugMsg::RemoveHwBreakpoint(_)
                        | DebugMsg::RemoveSwBreakpoint(_)
                        | DebugMsg::WriteAddr(_, _)
                        | DebugMsg::WriteRegisters(_) => DebugResponse::NotAllowed,

                        // For all other requests, we will process them normally
                        _ => {
                            let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());
                            match result {
                                Ok(response) => response,
                                Err(HyperlightError::TranslateGuestAddress(_)) => {
                                    // Treat non fatal errors separately so the guest doesn't fail
                                    DebugResponse::ErrorOccurred
                                }
                                Err(e) => {
                                    log::error!("Error processing debug request: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    };

                    // Send the response to the request back to gdb
                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // If we are denying continue or step requests, the debugger assumes the
                    // execution started so we need to report a stop reason as a crash and let
                    // it request to read registers/memory to figure out what happened
                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))
                            .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;
                    }

                    // If we are detaching, we will break the loop and the Hypervisor will continue
                    // to handle the Crash reason
                    if detach {
                        break;
                    }
                }
            }
            // If the vCPU stopped because of any other reason except a crash, we can handle it
            // normally
            _ => {
                // Send the stop reason to the gdb thread
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());

                    let response = match result {
                        Ok(response) => response,
                        // Treat non fatal errors separately so the guest doesn't fail
                        Err(HyperlightError::TranslateGuestAddress(_)) => {
                            DebugResponse::ErrorOccurred
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    };

                    let cont = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::Step | DebugResponse::DisableDebug
                    );

                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // Check if we should continue execution
                    // We continue if the response is one of the following: Step, Continue, or DisableDebug
                    if cont {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn check_stack_guard(&self) -> Result<bool> {
        if let Some(mgr) = self.mem_mgr.as_ref() {
            mgr.check_stack_guard()
        } else {
            Err(new_error!("Memory manager is not initialized"))
        }
    }

    #[cfg(feature = "trace_guest")]
    fn read_trace_reg(&self, reg: TraceRegister) -> Result<u64> {
        let regs = self.vcpu_fd.get_regs()?;
        Ok(match reg {
            TraceRegister::RAX => regs.rax,
            TraceRegister::RCX => regs.rcx,
            TraceRegister::RIP => regs.rip,
            TraceRegister::RSP => regs.rsp,
            TraceRegister::RBP => regs.rbp,
        })
    }

    #[cfg(feature = "trace_guest")]
    fn trace_info_as_ref(&self) -> &TraceInfo {
        &self.trace_info
    }
    #[cfg(feature = "trace_guest")]
    fn trace_info_as_mut(&mut self) -> &mut TraceInfo {
        &mut self.trace_info
    }
}

impl Drop for KVMDriver {
    fn drop(&mut self) {
        self.interrupt_handle.dropped.store(true, Ordering::Relaxed);
    }
}
