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
use std::fmt::Debug;
#[cfg(feature = "hw-interrupts")]
use std::sync::Arc;
use std::sync::LazyLock;

use hyperlight_common::outb::VmAction;
#[cfg(feature = "hw-interrupts")]
use mshv_bindings::LapicState;
#[cfg(gdb)]
use mshv_bindings::{DebugRegisters, hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT};
use mshv_bindings::{
    FloatingPointUnit, SpecialRegisters, StandardRegisters, XSave, hv_message_type,
    hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_create_partition_v2,
    mshv_user_mem_region,
};
#[cfg(feature = "hw-interrupts")]
use mshv_bindings::{
    hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED, hv_register_name_HV_X64_REGISTER_RAX,
};
#[cfg(feature = "hw-interrupts")]
use mshv_ioctls::InterruptRequest;
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebuggableVm};
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters, FP_CONTROL_WORD_DEFAULT,
    MXCSR_DEFAULT,
};
#[cfg(all(test, not(feature = "i686-guest")))]
use crate::hypervisor::virtual_machine::XSAVE_BUFFER_SIZE;
#[cfg(feature = "hw-interrupts")]
use crate::hypervisor::virtual_machine::x86_64::hw_interrupts::TimerThread;
use crate::hypervisor::virtual_machine::{
    CreateVmError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError, VirtualMachine,
    VmExit, XSAVE_MIN_SIZE,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

/// Determine whether the HyperV for Linux hypervisor API is present
/// and functional.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    match Mshv::new() {
        Ok(_) => true,
        Err(_) => {
            tracing::info!("MSHV is not available on this system");
            false
        }
    }
}

/// A MSHV implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct MshvVm {
    /// VmFd wrapped in Arc so the timer thread can call
    /// `request_virtual_interrupt` from a background thread.
    #[cfg(feature = "hw-interrupts")]
    vm_fd: Arc<VmFd>,
    #[cfg(not(feature = "hw-interrupts"))]
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    /// Handle to the background timer (if started).
    #[cfg(feature = "hw-interrupts")]
    timer: Option<TimerThread>,
}

static MSHV: LazyLock<std::result::Result<Mshv, CreateVmError>> =
    LazyLock::new(|| Mshv::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let mshv = MSHV.as_ref().map_err(|e| e.clone())?;

        #[allow(unused_mut)]
        let mut pr: mshv_create_partition_v2 = Default::default();
        // Enable LAPIC for hw-interrupts — required for interrupt delivery
        // via request_virtual_interrupt.
        #[cfg(feature = "hw-interrupts")]
        {
            use mshv_bindings::MSHV_PT_BIT_LAPIC;
            pr.pt_flags = 1u64 << MSHV_PT_BIT_LAPIC;
        }
        // It's important to use create_vm_with_args() (not create_vm()),
        // because create_vm() sets up a SynIC partition by default.
        let vm_fd = mshv
            .create_vm_with_args(&pr)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        let vcpu_fd = {
            let features: hv_partition_synthetic_processor_features = Default::default();

            vm_fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                    unsafe { features.as_uint64[0] },
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

            vm_fd
                .initialize()
                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

            vm_fd
                .create_vcpu(0)
                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?
        };

        // Initialize the virtual LAPIC when hw-interrupts is enabled.
        // LAPIC defaults to disabled (SVR bit 8 = 0), which means no APIC
        // interrupts can be delivered (request_virtual_interrupt would fail).
        #[cfg(feature = "hw-interrupts")]
        Self::init_lapic(&vcpu_fd)?;

        Ok(Self {
            #[cfg(feature = "hw-interrupts")]
            vm_fd: Arc::new(vm_fd),
            #[cfg(not(feature = "hw-interrupts"))]
            vm_fd,
            vcpu_fd,
            #[cfg(feature = "hw-interrupts")]
            timer: None,
        })
    }
}

impl VirtualMachine for MshvVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .map_user_memory(mshv_region)
            .map_err(|e| MapMemoryError::Hypervisor(e.into()))
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd
            .unmap_user_memory(mshv_region)
            .map_err(|e| UnmapMemoryError::Hypervisor(e.into()))
    }

    #[cfg_attr(not(feature = "hw-interrupts"), allow(clippy::never_loop))]
    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        const HALT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT_INTERCEPT_MESSAGE: hv_message_type =
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        // setup_trace_guest must be called right before vcpu_run.run() call, because
        // it sets the guest span, no other traces or spans must be setup in between these calls.
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        loop {
            let exit_reason = self.vcpu_fd.run();

            match exit_reason {
                Ok(m) => {
                    let msg_type = m.header.message_type;
                    match msg_type {
                        HALT_MESSAGE => {
                            // With timer thread active, re-enter the guest.
                            // The hypervisor will deliver pending timer
                            // interrupts on the next run(), waking the
                            // vCPU from HLT.
                            #[cfg(feature = "hw-interrupts")]
                            if self.timer.as_ref().is_some_and(|t| t.is_active()) {
                                continue;
                            }
                            return Ok(VmExit::Halt());
                        }
                        IO_PORT_INTERCEPT_MESSAGE => {
                            let io_message = m
                                .to_ioport_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let port_number = io_message.port_number;
                            let rip = io_message.header.rip;
                            let rax = io_message.rax;
                            let instruction_length = io_message.header.instruction_length() as u64;
                            let is_write = io_message.header.intercept_access_type != 0;

                            // mshv, unlike kvm, does not automatically increment RIP
                            self.vcpu_fd
                                .set_reg(&[hv_register_assoc {
                                    name: hv_register_name_HV_X64_REGISTER_RIP,
                                    value: hv_register_value {
                                        reg64: rip + instruction_length,
                                    },
                                    ..Default::default()
                                }])
                                .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                            // VmAction::Halt always means "I'm done", regardless
                            // of whether a timer is active.
                            if is_write && port_number == VmAction::Halt as u16 {
                                // Stop the timer thread before returning.
                                #[cfg(feature = "hw-interrupts")]
                                {
                                    if let Some(mut t) = self.timer.take() {
                                        t.stop();
                                    }
                                }
                                return Ok(VmExit::Halt());
                            }

                            #[cfg(feature = "hw-interrupts")]
                            {
                                if is_write {
                                    let data = rax.to_le_bytes();
                                    if self.handle_hw_io_out(port_number, &data) {
                                        continue;
                                    }
                                } else if let Some(val) =
                                    super::super::x86_64::hw_interrupts::handle_io_in(port_number)
                                {
                                    self.vcpu_fd
                                        .set_reg(&[hv_register_assoc {
                                            name: hv_register_name_HV_X64_REGISTER_RAX,
                                            value: hv_register_value { reg64: val },
                                            ..Default::default()
                                        }])
                                        .map_err(|e| RunVcpuError::Unknown(e.into()))?;
                                    continue;
                                }
                            }

                            // Suppress unused variable warning when hw-interrupts is disabled
                            let _ = is_write;

                            return Ok(VmExit::IoOut(port_number, rax.to_le_bytes().to_vec()));
                        }
                        UNMAPPED_GPA_MESSAGE => {
                            let mimo_message = m
                                .to_memory_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let addr = mimo_message.guest_physical_address;
                            return match MemoryRegionFlags::try_from(mimo_message)
                                .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?
                            {
                                MemoryRegionFlags::READ => Ok(VmExit::MmioRead(addr)),
                                MemoryRegionFlags::WRITE => Ok(VmExit::MmioWrite(addr)),
                                _ => Ok(VmExit::Unknown("Unknown MMIO access".to_string())),
                            };
                        }
                        INVALID_GPA_ACCESS_MESSAGE => {
                            let mimo_message = m
                                .to_memory_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let gpa = mimo_message.guest_physical_address;
                            let access_info = MemoryRegionFlags::try_from(mimo_message)
                                .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?;
                            return match access_info {
                                MemoryRegionFlags::READ => Ok(VmExit::MmioRead(gpa)),
                                MemoryRegionFlags::WRITE => Ok(VmExit::MmioWrite(gpa)),
                                _ => Ok(VmExit::Unknown("Unknown MMIO access".to_string())),
                            };
                        }
                        #[cfg(gdb)]
                        EXCEPTION_INTERCEPT => {
                            let ex_info = m
                                .to_exception_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let DebugRegisters { dr6, .. } = self
                                .vcpu_fd
                                .get_debug_regs()
                                .map_err(|e| RunVcpuError::GetDr6(e.into()))?;
                            return Ok(VmExit::Debug {
                                dr6,
                                exception: ex_info.exception_vector as u32,
                            });
                        }
                        other => {
                            return Ok(VmExit::Unknown(format!(
                                "Unknown MSHV VCPU exit: {:?}",
                                other
                            )));
                        }
                    }
                }
                Err(e) => match e.errno() {
                    // InterruptHandle::kill() sends a signal to interrupt the vcpu,
                    // which causes EINTR. Always honour it as cancellation.
                    libc::EINTR => {
                        return Ok(VmExit::Cancelled());
                    }
                    libc::EAGAIN => {
                        #[cfg(not(feature = "hw-interrupts"))]
                        {
                            return Ok(VmExit::Retry());
                        }
                        #[cfg(feature = "hw-interrupts")]
                        continue;
                    }
                    _ => return Err(RunVcpuError::Unknown(e.into())),
                },
            }
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mshv_regs = self
            .vcpu_fd
            .get_regs()
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        Ok((&mshv_regs).into())
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let mshv_regs: StandardRegisters = regs.into();
        self.vcpu_fd
            .set_regs(&mshv_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mshv_fpu = self
            .vcpu_fd
            .get_fpu()
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        Ok((&mshv_fpu).into())
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let mshv_fpu: FloatingPointUnit = fpu.into();
        self.vcpu_fd
            .set_fpu(&mshv_fpu)
            .map_err(|e| RegisterError::SetFpu(e.into()))?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let mshv_sregs = self
            .vcpu_fd
            .get_sregs()
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        Ok((&mshv_sregs).into())
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let mshv_sregs: SpecialRegisters = sregs.into();
        self.vcpu_fd
            .set_sregs(&mshv_sregs)
            .map_err(|e| RegisterError::SetSregs(e.into()))?;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        let debug_regs = self
            .vcpu_fd
            .get_debug_regs()
            .map_err(|e| RegisterError::GetDebugRegs(e.into()))?;
        Ok(debug_regs.into())
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        let mshv_debug_regs = drs.into();
        self.vcpu_fd
            .set_debug_regs(&mshv_debug_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        let xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        Ok(xsave.buffer.to_vec())
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        let current_xsave = self
            .vcpu_fd
            .get_xsave()
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        if current_xsave.buffer.len() < XSAVE_MIN_SIZE {
            // Minimum: 512 legacy + 64 header
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_MIN_SIZE as u32,
                actual: current_xsave.buffer.len() as u32,
            });
        }

        let mut buf = XSave::default(); // default is zeroed 4KB buffer

        // Copy XCOMP_BV (offset 520-527) - preserves feature mask + compacted bit
        buf.buffer[520..528].copy_from_slice(&current_xsave.buffer[520..528]);

        // XSAVE area layout from Intel SDM Vol. 1 Section 13.4.1:
        // - Bytes 0-1: FCW (x87 FPU Control Word)
        // - Bytes 24-27: MXCSR
        // - Bytes 512-519: XSTATE_BV (bitmap of valid state components)
        buf.buffer[0..2].copy_from_slice(&FP_CONTROL_WORD_DEFAULT.to_le_bytes());
        buf.buffer[24..28].copy_from_slice(&MXCSR_DEFAULT.to_le_bytes());
        // XSTATE_BV = 0x3: bits 0,1 = x87 + SSE valid. Explicitly tell hypervisor
        // to apply the legacy region from this buffer for consistent behavior.
        buf.buffer[512..520].copy_from_slice(&0x3u64.to_le_bytes());

        self.vcpu_fd
            .set_xsave(&buf)
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        Ok(())
    }

    #[cfg(test)]
    #[cfg(not(feature = "i686-guest"))]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        if std::mem::size_of_val(xsave) != XSAVE_BUFFER_SIZE {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_BUFFER_SIZE as u32,
                actual: std::mem::size_of_val(xsave) as u32,
            });
        }

        // Safety: all valid u32 values are 4 valid u8 values
        let (prefix, bytes, suffix) = unsafe { xsave.align_to() };
        if !prefix.is_empty() || !suffix.is_empty() {
            return Err(RegisterError::InvalidXsaveAlignment);
        }
        let buf = XSave {
            buffer: bytes
                .try_into()
                .expect("xsave slice has correct length and prefix and suffix are empty"),
        };
        self.vcpu_fd
            .set_xsave(&buf)
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        Ok(())
    }
}

#[cfg(gdb)]
impl DebuggableVm for MshvVm {
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError> {
        use mshv_bindings::HV_TRANSLATE_GVA_VALIDATE_READ;

        // Do not use HV_TRANSLATE_GVA_VALIDATE_WRITE, since many
        // things that are interesting to debug are not in fact
        // writable from the guest's point of view.
        let flags = HV_TRANSLATE_GVA_VALIDATE_READ as u64;
        let (addr, _) = self
            .vcpu_fd
            .translate_gva(gva, flags)
            .map_err(|_| DebugError::TranslateGva(gva))?;

        Ok(addr)
    }

    fn set_debug(&mut self, enabled: bool) -> std::result::Result<(), DebugError> {
        use mshv_bindings::{
            HV_INTERCEPT_ACCESS_MASK_EXECUTE, HV_INTERCEPT_ACCESS_MASK_NONE,
            hv_intercept_parameters, hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
            mshv_install_intercept,
        };

        use crate::hypervisor::gdb::arch::{BP_EX_ID, DB_EX_ID};

        let access_type_mask = if enabled {
            HV_INTERCEPT_ACCESS_MASK_EXECUTE
        } else {
            HV_INTERCEPT_ACCESS_MASK_NONE
        };

        for vector in [DB_EX_ID, BP_EX_ID] {
            self.vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: vector as u16,
                    },
                })
                .map_err(|e| DebugError::Intercept {
                    enable: enabled,
                    inner: e.into(),
                })?;
        }
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
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

        let mut regs = self.debug_regs()?;

        // Check if breakpoint already exists
        if [regs.dr0, regs.dr1, regs.dr2, regs.dr3].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or(DebugError::TooManyHwBreakpoints(MAX_NO_OF_HW_BP))?;

        // Assign to corresponding debug register
        *[&mut regs.dr0, &mut regs.dr1, &mut regs.dr2, &mut regs.dr3][i] = addr;

        // Enable LOCAL bit
        regs.dr7 |= 1 << (i * 2);

        self.set_debug_regs(&regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> std::result::Result<(), DebugError> {
        let mut debug_regs = self.debug_regs()?;

        let regs = [
            &mut debug_regs.dr0,
            &mut debug_regs.dr1,
            &mut debug_regs.dr2,
            &mut debug_regs.dr3,
        ];

        if let Some(i) = regs.iter().position(|&&mut reg| reg == addr) {
            // Clear the address
            *regs[i] = 0;
            // Disable LOCAL bit
            debug_regs.dr7 &= !(1 << (i * 2));
            self.set_debug_regs(&debug_regs)?;
            Ok(())
        } else {
            Err(DebugError::HwBreakpointNotFound(addr))
        }
    }
}

/// Cast MSHV `LapicState.regs` (`[c_char; 1024]`) to a `&[u8]` slice
/// for use with the shared LAPIC helpers.
#[cfg(feature = "hw-interrupts")]
fn lapic_regs_as_u8(regs: &[::std::os::raw::c_char; 1024]) -> &[u8] {
    // Safety: c_char (i8) and u8 have the same size and alignment;
    // LAPIC register values are treated as raw bytes.
    unsafe { &*(regs as *const [::std::os::raw::c_char; 1024] as *const [u8; 1024]) }
}

/// Cast MSHV `LapicState.regs` (`[c_char; 1024]`) to a `&mut [u8]` slice
/// for use with the shared LAPIC helpers.
#[cfg(feature = "hw-interrupts")]
fn lapic_regs_as_u8_mut(regs: &mut [::std::os::raw::c_char; 1024]) -> &mut [u8] {
    // Safety: same as above.
    unsafe { &mut *(regs as *mut [::std::os::raw::c_char; 1024] as *mut [u8; 1024]) }
}

#[cfg(feature = "hw-interrupts")]
impl MshvVm {
    /// Standard x86 APIC base MSR value: base address 0xFEE00000 +
    /// BSP flag (bit 8) + global enable (bit 11).
    const APIC_BASE_DEFAULT: u64 = 0xFEE00900;

    /// Initialize the virtual LAPIC to sensible defaults.
    fn init_lapic(vcpu_fd: &VcpuFd) -> std::result::Result<(), CreateVmError> {
        use super::super::x86_64::hw_interrupts::init_lapic_registers;

        let mut lapic: LapicState = vcpu_fd
            .get_lapic()
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

        init_lapic_registers(lapic_regs_as_u8_mut(&mut lapic.regs));

        vcpu_fd
            .set_lapic(&lapic)
            .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
        Ok(())
    }

    /// Perform LAPIC EOI: clear the highest-priority in-service bit.
    /// Called when the guest sends PIC EOI, since the timer thread
    /// delivers interrupts through the LAPIC and the guest only
    /// acknowledges via PIC.
    fn do_lapic_eoi(&self) {
        if let Ok(mut lapic) = self.vcpu_fd.get_lapic() {
            super::super::x86_64::hw_interrupts::lapic_eoi(lapic_regs_as_u8_mut(&mut lapic.regs));
            let _ = self.vcpu_fd.set_lapic(&lapic);
        }
    }

    fn handle_hw_io_out(&mut self, port: u16, data: &[u8]) -> bool {
        if port == VmAction::PvTimerConfig as u16 {
            // Re-enable LAPIC if the guest disabled it (via WRMSR
            // to MSR 0x1B clearing bit 11).  Some guests clear
            // the global APIC enable when no I/O APIC is detected.
            //
            // The hypervisor may return 0 for APIC_BASE when the
            // APIC is globally disabled, so we always restore the
            // standard value (0xFEE00900).
            if self.timer.is_none() {
                use mshv_bindings::hv_register_name_HV_X64_REGISTER_APIC_BASE;
                let mut apic_base_reg = [hv_register_assoc {
                    name: hv_register_name_HV_X64_REGISTER_APIC_BASE,
                    value: hv_register_value { reg64: 0 },
                    ..Default::default()
                }];
                if self.vcpu_fd.get_reg(&mut apic_base_reg).is_ok() {
                    let cur = unsafe { apic_base_reg[0].value.reg64 };
                    if cur & (1 << 11) == 0 {
                        let _ = self.vcpu_fd.set_reg(&[hv_register_assoc {
                            name: hv_register_name_HV_X64_REGISTER_APIC_BASE,
                            value: hv_register_value {
                                reg64: Self::APIC_BASE_DEFAULT,
                            },
                            ..Default::default()
                        }]);
                    }
                }
                // Re-initialize LAPIC SVR (may have been zeroed when
                // guest disabled the APIC globally)
                if let Ok(mut lapic) = self.vcpu_fd.get_lapic() {
                    let regs = lapic_regs_as_u8(&lapic.regs);
                    let svr = super::super::x86_64::hw_interrupts::read_lapic_u32(regs, 0xF0);
                    if svr & 0x100 == 0 {
                        let regs_mut = lapic_regs_as_u8_mut(&mut lapic.regs);
                        super::super::x86_64::hw_interrupts::write_lapic_u32(regs_mut, 0xF0, 0x1FF);
                        super::super::x86_64::hw_interrupts::write_lapic_u32(regs_mut, 0x80, 0); // TPR
                        let _ = self.vcpu_fd.set_lapic(&lapic);
                    }
                }
            }

            let vm_fd = Arc::clone(&self.vm_fd);
            let vector = super::super::x86_64::hw_interrupts::TIMER_VECTOR;
            super::super::x86_64::hw_interrupts::handle_pv_timer_config(
                &mut self.timer,
                data,
                move || {
                    if let Err(e) = vm_fd.request_virtual_interrupt(&InterruptRequest {
                        interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED,
                        apic_id: 0,
                        vector,
                        level_triggered: false,
                        logical_destination_mode: false,
                        long_mode: false,
                    }) {
                        tracing::warn!("MSHV request_virtual_interrupt failed: {e}");
                    }
                },
            );
            return true;
        }
        let timer_active = self.timer.as_ref().is_some_and(|t| t.is_active());
        super::super::x86_64::hw_interrupts::handle_common_io_out(port, data, timer_active, || {
            self.do_lapic_eoi()
        })
    }
}

#[cfg(test)]
#[cfg(feature = "hw-interrupts")]
mod hw_interrupt_tests {
    use super::*;

    #[test]
    fn lapic_regs_conversion_roundtrip() {
        let mut regs = [0i8; 1024];
        let bytes = lapic_regs_as_u8_mut(&mut regs);
        super::super::super::x86_64::hw_interrupts::write_lapic_u32(bytes, 0xF0, 0xDEAD_BEEF);
        let bytes = lapic_regs_as_u8(&regs);
        assert_eq!(
            super::super::super::x86_64::hw_interrupts::read_lapic_u32(bytes, 0xF0),
            0xDEAD_BEEF
        );
    }

    #[test]
    fn apic_base_default_value() {
        let base = MshvVm::APIC_BASE_DEFAULT;
        assert_ne!(base & (1 << 8), 0, "BSP flag should be set");
        assert_ne!(base & (1 << 11), 0, "global enable should be set");
        assert_eq!(
            base & 0xFFFFF000,
            0xFEE00000,
            "base address should be 0xFEE00000"
        );
    }
}
