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

use std::sync::LazyLock;

#[cfg(gdb)]
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::{
    kvm_debugregs, kvm_enable_cap, kvm_fpu, kvm_regs, kvm_sregs, kvm_userspace_memory_region,
    kvm_xsave,
};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{
    Cap, Kvm, MsrExitReason, MsrFilterDefaultAction, MsrFilterRange, MsrFilterRangeFlags, VcpuExit,
    VcpuFd, VmFd,
};
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebuggableVm};
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters, FP_CONTROL_WORD_DEFAULT,
    MXCSR_DEFAULT,
};
#[cfg(all(test, feature = "init-paging"))]
use crate::hypervisor::virtual_machine::XSAVE_BUFFER_SIZE;
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VirtualMachine,
    VmExit,
};
use crate::mem::memory_region::MemoryRegion;
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// On KVM x86-64 only, we have to set this in order to set the guest
/// physical address width.
///
/// The requirement to set this to configure the guest physical
/// address width for KVM is not well documented, but see e.g. Linux
/// v6.18.6 arch/x86/kvm/cpuid.c:kvm_vcpu_after_set_cpuid()
/// (https://elixir.bootlin.com/linux/v6.18.6/source/arch/x86/kvm/cpuid.c#L444)
/// for how it is processed.
///
/// For the architectural definition and format of the system register:
/// See AMD64 Architecture Programmer's Manual, Volume 3: General-Purpose and
///                                                       System Instructions
///     Appendix E: Obtaining Processor Information Via the CPUID Instruction
///         E.4.7: Function 8000_0008h---Processor Capacity Parameters and
///                Extended Feature Identification, pp. 627--628
const CPUID_FUNCTION_PROCESSOR_CAPACITY_PARAMETERS_AND_EXTENDED_FEATURE_IDENTIFICATION: u32 =
    0x8000_0008;

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

    // KVM, as opposed to mshv/whp, has no get_guest_debug() ioctl, so we must track the state ourselves
    #[cfg(gdb)]
    debug_regs: kvm_guest_debug,
}

static KVM: LazyLock<std::result::Result<Kvm, CreateVmError>> =
    LazyLock::new(|| Kvm::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

impl KvmVm {
    /// Create a new instance of a `KvmVm`
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let hv = KVM.as_ref().map_err(|e| e.clone())?;

        let vm_fd = hv
            .create_vm_with_type(0)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
        let vcpu_fd = vm_fd
            .create_vcpu(0)
            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

        // Set the CPUID leaf for MaxPhysAddr. KVM allows this to
        // easily be overridden by the hypervisor and defaults it very
        // low, while mshv passes it through from hardware unless an
        // intercept is installed.
        let mut kvm_cpuid = hv
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
        for entry in kvm_cpuid.as_mut_slice().iter_mut() {
            if entry.function
                == CPUID_FUNCTION_PROCESSOR_CAPACITY_PARAMETERS_AND_EXTENDED_FEATURE_IDENTIFICATION
            {
                entry.eax &= !0xff;
                entry.eax |= hyperlight_common::layout::MAX_GPA.ilog2() + 1;
            }
        }
        vcpu_fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        Ok(Self {
            vm_fd,
            vcpu_fd,
            #[cfg(gdb)]
            debug_regs: kvm_guest_debug::default(),
        })
    }
}

impl VirtualMachine for KvmVm {
    fn enable_msr_intercept(&mut self) -> std::result::Result<(), CreateVmError> {
        let cap = kvm_enable_cap {
            cap: Cap::X86UserSpaceMsr as u32,
            args: [MsrExitReason::Filter.bits() as u64, 0, 0, 0],
            ..Default::default()
        };
        self.vm_fd
            .enable_cap(&cap)
            .map_err(|e| CreateVmError::EnableMsrIntercept(e.into()))?;

        // Install a deny-all MSR filter (KVM_X86_SET_MSR_FILTER).
        // At least one range is required when using KVM_MSR_FILTER_DEFAULT_DENY;
        // from the docs: "Calling this ioctl with an empty set of ranges
        // (all nmsrs == 0) disables MSR filtering. In that mode,
        // KVM_MSR_FILTER_DEFAULT_DENY is invalid and causes an error."
        let bitmap = [0u8; 1]; // 1 byte covers 8 MSRs, all bits 0 (deny)
        self.vm_fd
            .set_msr_filter(
                MsrFilterDefaultAction::DENY,
                &[MsrFilterRange {
                    flags: MsrFilterRangeFlags::READ | MsrFilterRangeFlags::WRITE,
                    base: 0,
                    msr_count: 1,
                    bitmap: &bitmap,
                }],
            )
            .map_err(|e| CreateVmError::EnableMsrIntercept(e.into()))?;
        Ok(())
    }

    unsafe fn map_memory(
        &mut self,
        (slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        let mut kvm_region: kvm_userspace_memory_region = region.into();
        kvm_region.slot = slot;
        // Setting memory_size to 0 unmaps the slot's region
        // From https://docs.kernel.org/virt/kvm/api.html
        // > Deleting a slot is done by passing zero for memory_size.
        kvm_region.memory_size = 0;
        unsafe { self.vm_fd.set_user_memory_region(kvm_region) }
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        // setup_trace_guest must be called right before vcpu_run.run() call, because
        // it sets the guest span, no other traces or spans must be setup in between these calls.
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());
        match self.vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => Ok(VmExit::Halt()),
            Ok(VcpuExit::IoOut(port, data)) => Ok(VmExit::IoOut(port, data.to_vec())),
            Ok(VcpuExit::MmioRead(addr, _)) => Ok(VmExit::MmioRead(addr)),
            Ok(VcpuExit::MmioWrite(addr, _)) => Ok(VmExit::MmioWrite(addr)),
            // KVM_EXIT_X86_RDMSR / KVM_EXIT_X86_WRMSR (KVM API §5, kvm_run structure):
            //
            //   The "index" field tells userspace which MSR the guest wants to
            //   read/write.  If the request was unsuccessful, userspace indicates
            //   that with a "1" in the "error" field.  "This will inject a #GP
            //   into the guest when the VCPU is executed again."
            //
            //   "for KVM_EXIT_IO, KVM_EXIT_MMIO, [...] KVM_EXIT_X86_RDMSR and
            //    KVM_EXIT_X86_WRMSR the corresponding operations are complete
            //    (and guest state is consistent) only after userspace has
            //    re-entered the kernel with KVM_RUN."
            //
            // We set error=1 and then re-run with `immediate_exit` to let KVM
            // inject the #GP without executing further guest code. From the
            // kvm_run docs: "[immediate_exit] is polled once when KVM_RUN
            // starts; if non-zero, KVM_RUN exits immediately, returning
            // -EINTR."
            Ok(VcpuExit::X86Rdmsr(msr_exit)) => {
                let msr_index = msr_exit.index;
                *msr_exit.error = 1;
                self.vcpu_fd.set_kvm_immediate_exit(1);
                let _ = self.vcpu_fd.run();
                self.vcpu_fd.set_kvm_immediate_exit(0);
                Ok(VmExit::MsrRead(msr_index))
            }
            Ok(VcpuExit::X86Wrmsr(msr_exit)) => {
                let msr_index = msr_exit.index;
                let value = msr_exit.data;
                *msr_exit.error = 1;
                self.vcpu_fd.set_kvm_immediate_exit(1);
                let _ = self.vcpu_fd.run();
                self.vcpu_fd.set_kvm_immediate_exit(0);
                Ok(VmExit::MsrWrite { msr_index, value })
            }
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(debug_exit)) => Ok(VmExit::Debug {
                dr6: debug_exit.dr6,
                exception: debug_exit.exception,
            }),
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => Ok(VmExit::Cancelled()),
                libc::EAGAIN => Ok(VmExit::Retry()),
                _ => Err(RunVcpuError::Unknown(e.into())),
            },
            Ok(other) => Ok(VmExit::Unknown(format!(
                "Unknown KVM VCPU exit: {:?}",
                other
            ))),
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let kvm_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok((&kvm_regs).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let kvm_regs: kvm_regs = regs.into();
        self.vcpu_fd
            .set_regs(&kvm_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        // Note: On KVM this ignores MXCSR.
        // See https://github.com/torvalds/linux/blob/d358e5254674b70f34c847715ca509e46eb81e6f/arch/x86/kvm/x86.c#L12554-L12599
        let kvm_fpu = self
            .vcpu_fd
            .get_fpu()
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        Ok((&kvm_fpu).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let kvm_fpu: kvm_fpu = fpu.into();
        // Note: On KVM this ignores MXCSR.
        // See https://github.com/torvalds/linux/blob/d358e5254674b70f34c847715ca509e46eb81e6f/arch/x86/kvm/x86.c#L12554-L12599
        self.vcpu_fd
            .set_fpu(&kvm_fpu)
            .map_err(|e| RegisterError::SetFpu(e.into()))?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let kvm_sregs = self
            .vcpu_fd
            .get_sregs()
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        Ok((&kvm_sregs).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let kvm_sregs: kvm_sregs = sregs.into();
        self.vcpu_fd
            .set_sregs(&kvm_sregs)
            .map_err(|e| RegisterError::SetSregs(e.into()))?;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        let kvm_debug_regs = self
            .vcpu_fd
            .get_debug_regs()
            .map_err(|e| RegisterError::GetDebugRegs(e.into()))?;
        Ok(kvm_debug_regs.into())
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        let kvm_debug_regs: kvm_debugregs = drs.into();
        self.vcpu_fd
            .set_debug_regs(&kvm_debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        let xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        Ok(xsave
            .region
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect())
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        let mut xsave = kvm_xsave::default(); // default is zeroed 4KB buffer with no FAM

        // XSAVE legacy region layout (Intel SDM Vol. 1 Section 13.4.1):
        // - Bytes 0-1: FCW, 2-3: FSW
        // - Bytes 24-27: MXCSR
        // - Bytes 512-519: XSTATE_BV
        // - Bytes 520-527: XCOMP_BV (compaction format indicator)
        //
        // kvm_xsave.region is [u32], so region[0] covers FCW (low 16) and FSW (high 16, stays 0).
        xsave.region[0] = FP_CONTROL_WORD_DEFAULT as u32;
        xsave.region[6] = MXCSR_DEFAULT;
        // XSTATE_BV = 0x3: bits 0,1 = x87 + SSE valid. This tells KVM to apply
        // the legacy region from this buffer. Without this, some KVM versions
        // may ignore set_xsave entirely when XSTATE_BV=0.
        xsave.region[128] = 0x3;
        // Note: Unlike MSHV/WHP, we don't preserve XCOMP_BV because KVM uses
        // standard (non-compacted) XSAVE format where XCOMP_BV remains 0.

        // SAFETY: No dynamic features enabled, 4KB is sufficient
        unsafe {
            self.vcpu_fd
                .set_xsave(&xsave)
                .map_err(|e| RegisterError::SetXsave(e.into()))?
        };

        Ok(())
    }

    #[cfg(test)]
    #[cfg(feature = "init-paging")]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        if std::mem::size_of_val(xsave) != XSAVE_BUFFER_SIZE {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_BUFFER_SIZE as u32,
                actual: std::mem::size_of_val(xsave) as u32,
            });
        }
        let xsave = kvm_xsave {
            region: xsave.try_into().expect("xsave slice has correct length"),
            ..Default::default()
        };
        // Safety: Safe because we only copy 4096 bytes
        // and have not enabled any dynamic xsave features
        unsafe {
            self.vcpu_fd
                .set_xsave(&xsave)
                .map_err(|e| RegisterError::SetXsave(e.into()))?
        };

        Ok(())
    }

    fn reset_msrs(&self) -> std::result::Result<(), RegisterError> {
        // The KVM MSR filter (KVM_MSR_FILTER_DEFAULT_DENY) blocks all guest
        // MSR access at the hardware level, so no MSRs can be modified by the
        // guest and there is nothing to reset.
        Ok(())
    }
}

#[cfg(gdb)]
impl DebuggableVm for KvmVm {
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError> {
        let gpa = self
            .vcpu_fd
            .translate_gva(gva)
            .map_err(|_| DebugError::TranslateGva(gva))?;
        if gpa.valid == 0 {
            Err(DebugError::TranslateGva(gva))
        } else {
            Ok(gpa.physical_address)
        }
    }

    fn set_debug(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
        use kvm_bindings::{KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP};

        log::info!("Setting debug to {}", enable);
        if enable {
            self.debug_regs.control |=
                KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
        } else {
            self.debug_regs.control &=
                !(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP);
        }
        self.vcpu_fd
            .set_guest_debug(&self.debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
        use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;

        log::info!("Setting single step to {}", enable);
        if enable {
            self.debug_regs.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug_regs.control &= !KVM_GUESTDBG_SINGLESTEP;
        }
        self.vcpu_fd
            .set_guest_debug(&self.debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;

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

    fn add_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        use crate::hypervisor::gdb::arch::MAX_NO_OF_HW_BP;

        // Check if breakpoint already exists
        if self.debug_regs.arch.debugreg[..4].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| self.debug_regs.arch.debugreg[7] & (1 << (i * 2)) == 0)
            .ok_or(DebugError::TooManyHwBreakpoints(MAX_NO_OF_HW_BP))?;

        // Assign to corresponding debug register
        self.debug_regs.arch.debugreg[i] = addr;

        // Enable LOCAL bit
        self.debug_regs.arch.debugreg[7] |= 1 << (i * 2);

        self.vcpu_fd
            .set_guest_debug(&self.debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        // Find the index of the breakpoint
        let index = self.debug_regs.arch.debugreg[..4]
            .iter()
            .position(|&a| a == addr)
            .ok_or(DebugError::HwBreakpointNotFound(addr))?;

        // Clear the address
        self.debug_regs.arch.debugreg[index] = 0;

        // Disable LOCAL bit
        self.debug_regs.arch.debugreg[7] &= !(1 << (index * 2));

        self.vcpu_fd
            .set_guest_debug(&self.debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }
}
