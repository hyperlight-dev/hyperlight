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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_sregs, kvm_userspace_memory_region};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

#[cfg(gdb)]
use super::gdb::{
    DebugCommChannel, DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, KvmDebug,
    VcpuStopReason,
};
use super::{HyperlightExit, Hypervisor, LinuxInterruptHandle, VirtualCPU};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};
use crate::hypervisor::{InterruptHandle, InterruptHandleImpl, get_memory_access_violation};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::SandboxConfiguration;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::handle_outb;
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


/// A KVM implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct KvmVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,

    // KVM as opposed to mshv/whp has no way to get current debug regs, so need to keep a copy here
    #[cfg(gdb)]
    debug_regs: kvm_guest_debug,
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
            state: AtomicU8::new(0),
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
    unsafe fn map_memory(&mut self, (slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region)? };
        Ok(())
    }

    fn unmap_memory(&mut self, (slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        // Setting memory_size to 0 unmaps the slot's region
        // From https://docs.kernel.org/virt/kvm/api.html
        // > Deleting a slot is done by passing zero for memory_size.
        kvm_region.memory_size = 0;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }?;
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(HyperlightExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(HyperlightExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(HyperlightExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(HyperlightExit::MmioWrite(addr)),
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(debug_exit)) => Ok(HyperlightExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            }),
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => Ok(HyperlightExit::Cancelled()),
                libc::EAGAIN => Ok(HyperlightExit::Retry()),
                _ => Ok(HyperlightExit::Unknown(format!(
                    "Unknown KVM VCPU error: {}",
                    e
                ))),
            },
            Ok(other) => Ok(HyperlightExit::Unknown(format!(
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

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    fn clear_cancel(&self) {
        self.interrupt_handle.clear_cancel();
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

#[cfg(gdb)]
impl DebuggableVm for KvmVm {
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use crate::HyperlightError;

        let gpa = self.vcpu_fd.translate_gva(gva)?;
        if gpa.valid == 0 {
            Err(HyperlightError::TranslateGuestAddress(gva))
        } else {
            Ok(gpa.physical_address)
        }
    }

    fn set_debug(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP};

        log::info!("Setting debug to {}", enable);
        if enable {
            self.debug_regs.control |=
                KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
        } else {
            self.debug_regs.control &=
                !(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP);
        }
        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> Result<()> {
        use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug_regs.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug_regs.control &= !KVM_GUESTDBG_SINGLESTEP;
        }
        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;

        // Set TF Flag to enable Traps
        let mut regs = self.regs()?;
        if enable {
            regs.rflags |= 1 << 8;
        } else {
            regs.rflags &= !(1 << 8);
        }
        self.set_regs(&regs)?;
        Ok(())
    }

    fn add_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        use crate::hypervisor::gdb::arch::MAX_NO_OF_HW_BP;

        // Check if breakpoint already exists
        if self.debug_regs.arch.debugreg[..4].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| self.debug_regs.arch.debugreg[7] & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        self.debug_regs.arch.debugreg[i] = addr;

        // Enable LOCAL bit
        self.debug_regs.arch.debugreg[7] |= 1 << (i * 2);

        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        // Find the index of the breakpoint
        let index = self.debug_regs.arch.debugreg[..4]
            .iter()
            .position(|&a| a == addr)
            .ok_or_else(|| new_error!("Tried to remove non-existing hw-breakpoint"))?;

        // Clear the address
        self.debug_regs.arch.debugreg[index] = 0;

        // Disable LOCAL bit
        self.debug_regs.arch.debugreg[7] &= !(1 << (index * 2));

        self.vcpu_fd.set_guest_debug(&self.debug_regs)?;
        Ok(())
    }
}
