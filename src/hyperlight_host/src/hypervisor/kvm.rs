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

use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

#[cfg(gdb)]
use super::gdb::{
    DebugCommChannel, DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, KvmDebug,
    VcpuStopReason,
};
use super::{Hypervisor, LinuxInterruptHandle};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl, VmExit};
use crate::mem::memory_region::MemoryRegion;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
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
    use super::KVMDriver;
    use crate::hypervisor::gdb::{
        DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, KvmDebug,
    };
    use crate::{Result, new_error};

    impl KVMDriver {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = KvmDebug::default();

            debug.set_single_step(&self.vcpu_fd, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            mem_access: &DebugMemoryAccess,
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
                            .add_sw_breakpoint(&self.vcpu_fd, addr, mem_access)
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
                        let offset = mem_access
                            .dbg_mem_access_fn
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

                        debug.read_addrs(&self.vcpu_fd, addr, &mut data, mem_access)?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => debug
                        .read_regs(&self.vcpu_fd)
                        .map_err(|e| {
                            log::error!("Failed to read registers: {:?}", e);

                            e
                        })
                        .map(|(regs, fpu)| DebugResponse::ReadRegisters(Box::new((regs, fpu)))),
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
                            .remove_sw_breakpoint(&self.vcpu_fd, addr, mem_access)
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
                        debug.write_addrs(&self.vcpu_fd, addr, &data, mem_access)?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(boxed_regs) => {
                        let (regs, fpu) = boxed_regs.as_ref();
                        debug
                            .write_regs(&self.vcpu_fd, regs, fpu)
                            .map_err(|e| {
                                log::error!("Failed to write registers: {:?}", e);

                                e
                            })
                            .map(|_| DebugResponse::WriteRegisters)
                    }
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
    interrupt_handle: Arc<dyn InterruptHandleImpl>,

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
    #[cfg(feature = "mem_profile")]
    trace_info: MemTraceInfo,
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
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        let kvm = Kvm::new()?;

        let vm_fd = kvm.create_vm_with_type(0)?;

        mem_regions.iter().enumerate().try_for_each(|(i, region)| {
            let mut kvm_region: kvm_userspace_memory_region = region.clone().into();
            kvm_region.slot = i as u32;
            unsafe { vm_fd.set_user_memory_region(kvm_region) }
        })?;

        let vcpu_fd = vm_fd.create_vcpu(0)?;

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

        let interrupt_handle: Arc<dyn InterruptHandleImpl> = Arc::new(LinuxInterruptHandle {
            running: AtomicU64::new(0),
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
            sig_rt_min_offset: config.get_interrupt_vcpu_sigrtmin_offset(),
            dropped: AtomicBool::new(false),
        });

        let mut kvm = Self {
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
            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            #[cfg(crashdump)]
            rt_cfg,
            #[cfg(feature = "mem_profile")]
            trace_info,
        };

        kvm.setup_initial_sregs(pml4_addr)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if kvm.debug.is_some() {
            kvm.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(kvm)
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
        mut mem_mgr: SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        self.page_size = page_size as usize;

        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = CommonRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rdi: peb_addr.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,

            ..Default::default()
        };
        self.set_regs(&regs)?;

        self.run(
            self.entrypoint,
            self.interrupt_handle.clone(),
            &self.sandbox_regions.clone(),
            &self
                .mmap_regions
                .iter()
                .map(|(r, _)| r.clone())
                .collect::<Vec<_>>(),
            &mut mem_mgr,
            host_funcs.clone(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
            #[cfg(crashdump)]
            &self.rt_cfg.clone(),
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
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        #[cfg(gdb)] dbg_mem_access_fn: Arc<Mutex<SandboxMemoryManager<HostSharedMemory>>>,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = CommonRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        };
        self.set_regs(&regs)?;

        // reset fpu state
        self.set_fpu(&CommonFpu::default())?;

        self.run(
            self.entrypoint,
            self.interrupt_handle.clone(),
            &self.sandbox_regions.clone(),
            &self
                .mmap_regions
                .iter()
                .map(|(r, _)| r.clone())
                .collect::<Vec<_>>(),
            mem_mgr,
            host_funcs.clone(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
            #[cfg(crashdump)]
            &self.rt_cfg.clone(),
        )
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run_vcpu(&mut self) -> Result<VmExit> {
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(VmExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(VmExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(VmExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(VmExit::MmioWrite(addr)),
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(debug_exit)) => Ok(VmExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            }),
            Err(e) => match e.errno() {
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),

                other => Ok(VmExit::Unknown(format!(
                    "Unknown KVM VCPU error: {}",
                    other
                ))),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }

    fn regs(&self) -> Result<super::regs::CommonRegisters> {
        let kvm_regs = self.vcpu_fd.get_regs()?;
        Ok((&kvm_regs).into())
    }

    fn set_regs(&mut self, regs: &super::regs::CommonRegisters) -> Result<()> {
        let kvm_regs: kvm_regs = regs.into();
        self.vcpu_fd.set_regs(&kvm_regs)?;
        Ok(())
    }

    fn fpu(&self) -> Result<super::regs::CommonFpu> {
        let kvm_fpu = self.vcpu_fd.get_fpu()?;
        Ok((&kvm_fpu).into())
    }

    fn set_fpu(&mut self, fpu: &super::regs::CommonFpu) -> Result<()> {
        let kvm_fpu: kvm_fpu = fpu.into();
        self.vcpu_fd.set_fpu(&kvm_fpu)?;
        Ok(())
    }

    fn sregs(&self) -> Result<super::regs::CommonSpecialRegisters> {
        let kvm_sregs = self.vcpu_fd.get_sregs()?;
        Ok((&kvm_sregs).into())
    }

    fn set_sregs(&mut self, sregs: &super::regs::CommonSpecialRegisters) -> Result<()> {
        let kvm_sregs: kvm_sregs = sregs.into();
        self.vcpu_fd.set_sregs(&kvm_sregs)?;
        Ok(())
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>> {
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
            // Also include mapped regions in addition to the initial sandbox regions
            let mut regions: Vec<MemoryRegion> = self.sandbox_regions.clone();
            regions.extend(self.mmap_regions.iter().map(|(r, _)| r.clone()));
            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
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

        let mem_access = DebugMemoryAccess {
            dbg_mem_access_fn,
            guest_mmap_regions: self.mmap_regions.iter().map(|(r, _)| r.clone()).collect(),
        };

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
                            let result = self.process_dbg_request(req, &mem_access);
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
                // Temporary spot to remove hw breakpoints on exit
                // TODO: remove in future PR
                if stop_reason == VcpuStopReason::EntryPointBp {
                    #[allow(clippy::unwrap_used)] // we checked this above
                    self.debug
                        .as_mut()
                        .unwrap()
                        .remove_hw_breakpoint(&self.vcpu_fd, self.entrypoint)?;
                }

                // Send the stop reason to the gdb thread
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, &mem_access);

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

    #[cfg(gdb)]
    fn gdb_connection(&self) -> Option<&DebugCommChannel<DebugResponse, DebugMsg>> {
        self.gdb_conn.as_ref()
    }

    #[cfg(gdb)]
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        let tr = self
            .vcpu_fd
            .translate_gva(gva)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

        if tr.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(tr.physical_address)
        }
    }

    #[cfg(feature = "trace_guest")]
    fn handle_trace(
        &mut self,
        tc: &mut crate::sandbox::trace::TraceContext,
        mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    ) -> Result<()> {
        let regs = self.regs()?;
        tc.handle_trace(&regs, mem_mgr)
    }

    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo {
        &mut self.trace_info
    }
}

impl Drop for KVMDriver {
    fn drop(&mut self) {
        self.interrupt_handle.set_dropped();
    }
}
