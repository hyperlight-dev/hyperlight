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
#[cfg(feature = "hw-interrupts")]
use std::sync::atomic::{AtomicBool, Ordering};

use hyperlight_common::outb::OutBAction;
#[cfg(feature = "hw-interrupts")]
use mshv_bindings::LapicState;
#[cfg(gdb)]
use mshv_bindings::{DebugRegisters, hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT};
use mshv_bindings::{
    FloatingPointUnit, SpecialRegisters, StandardRegisters, XSave, hv_message_type,
    hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_create_partition_v2,
    mshv_user_mem_region,
};
#[cfg(feature = "hw-interrupts")]
use mshv_bindings::{
    HV_INTERCEPT_ACCESS_MASK_WRITE, hv_intercept_parameters,
    hv_intercept_type_HV_INTERCEPT_TYPE_X64_MSR_INDEX, hv_message_type_HVMSG_X64_MSR_INTERCEPT,
    mshv_install_intercept,
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
#[cfg(feature = "hw-interrupts")]
use crate::hypervisor::pic::Pic;
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters, FP_CONTROL_WORD_DEFAULT,
    MXCSR_DEFAULT,
};
#[cfg(all(test, not(feature = "nanvix-unstable")))]
use crate::hypervisor::virtual_machine::XSAVE_BUFFER_SIZE;
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
pub(crate) struct MshvVm {
    /// VmFd wrapped in Arc so the timer thread can call
    /// `request_virtual_interrupt` from a background thread.
    #[cfg(feature = "hw-interrupts")]
    vm_fd: Arc<VmFd>,
    #[cfg(not(feature = "hw-interrupts"))]
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    #[cfg(feature = "hw-interrupts")]
    pic: Pic,
    /// Signals the timer thread to stop.
    #[cfg(feature = "hw-interrupts")]
    timer_stop: Arc<AtomicBool>,
    /// Handle to the background timer thread (if started).
    #[cfg(feature = "hw-interrupts")]
    timer_thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for MshvVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MshvVm")
            .field("vm_fd", &self.vm_fd)
            .field("vcpu_fd", &self.vcpu_fd)
            .finish_non_exhaustive()
    }
}

static MSHV: LazyLock<std::result::Result<Mshv, CreateVmError>> =
    LazyLock::new(|| Mshv::new().map_err(|e| CreateVmError::HypervisorNotAvailable(e.into())));

/// Write a u32 to a LAPIC register at the given APIC offset.
#[cfg(feature = "hw-interrupts")]
fn write_lapic_u32(regs: &mut [::std::os::raw::c_char; 1024], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    regs[offset] = bytes[0] as _;
    regs[offset + 1] = bytes[1] as _;
    regs[offset + 2] = bytes[2] as _;
    regs[offset + 3] = bytes[3] as _;
}

/// Read a u32 from a LAPIC register at the given APIC offset.
#[cfg(feature = "hw-interrupts")]
fn read_lapic_u32(regs: &[::std::os::raw::c_char; 1024], offset: usize) -> u32 {
    u32::from_le_bytes([
        regs[offset] as u8,
        regs[offset + 1] as u8,
        regs[offset + 2] as u8,
        regs[offset + 3] as u8,
    ])
}

impl MshvVm {
    /// Create a new instance of a MshvVm
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new() -> std::result::Result<Self, CreateVmError> {
        let mshv = MSHV.as_ref().map_err(|e| e.clone())?;

        #[allow(unused_mut)]
        let mut pr: mshv_create_partition_v2 = Default::default();
        // Enable LAPIC for hw-interrupts — required for interrupt delivery
        // via request_virtual_interrupt. MSHV_PT_BIT_LAPIC = bit 0.
        #[cfg(feature = "hw-interrupts")]
        {
            pr.pt_flags = 1u64; // LAPIC
        }
        let vm_fd = mshv
            .create_vm_with_args(&pr)
            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;

        let vcpu_fd = {
            // No synthetic features needed — timer interrupts are injected
            // directly via request_virtual_interrupt(), not through SynIC.
            // The LAPIC (enabled via pt_flags) handles interrupt delivery.
            #[cfg(feature = "hw-interrupts")]
            let feature_val = 0u64;
            #[cfg(not(feature = "hw-interrupts"))]
            let feature_val = 0u64;

            vm_fd
                .set_partition_property(
                    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                    feature_val,
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
        {
            let mut lapic: LapicState = vcpu_fd
                .get_lapic()
                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

            // SVR (offset 0xF0): bit 8 = enable APIC, bits 0-7 = spurious vector
            write_lapic_u32(&mut lapic.regs, 0xF0, 0x1FF);
            // TPR (offset 0x80): 0 = accept all interrupt priorities
            write_lapic_u32(&mut lapic.regs, 0x80, 0);
            // DFR (offset 0xE0): 0xFFFFFFFF = flat model
            write_lapic_u32(&mut lapic.regs, 0xE0, 0xFFFF_FFFF);
            // LDR (offset 0xD0): set logical APIC ID for flat model
            write_lapic_u32(&mut lapic.regs, 0xD0, 1 << 24);
            // LINT0 (offset 0x350): masked — we don't forward PIC through LAPIC;
            // our PIC is emulated in userspace and not wired to LINT0.
            write_lapic_u32(&mut lapic.regs, 0x350, 0x0001_0000);
            // LINT1 (offset 0x360): NMI delivery, not masked
            write_lapic_u32(&mut lapic.regs, 0x360, 0x400);
            // LVT Timer (offset 0x320): masked — we use host timer thread instead
            write_lapic_u32(&mut lapic.regs, 0x320, 0x0001_0000);
            // LVT Error (offset 0x370): masked
            write_lapic_u32(&mut lapic.regs, 0x370, 0x0001_0000);

            vcpu_fd
                .set_lapic(&lapic)
                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;

            // Install MSR intercept for IA32_APIC_BASE (MSR 0x1B) to prevent
            // the guest from globally disabling the LAPIC. The Nanvix kernel
            // disables the APIC when no I/O APIC is detected, but we need
            // the LAPIC enabled for request_virtual_interrupt delivery.
            //
            // This may fail with AccessDenied on some kernel versions; in
            // that case we fall back to re-enabling the LAPIC in the timer
            // setup path (handle_hw_io_out).
            let _ = vm_fd.install_intercept(mshv_install_intercept {
                access_type_mask: HV_INTERCEPT_ACCESS_MASK_WRITE,
                intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_X64_MSR_INDEX,
                intercept_parameter: hv_intercept_parameters {
                    msr_index: 0x1B, // IA32_APIC_BASE
                },
            });
        }

        Ok(Self {
            #[cfg(feature = "hw-interrupts")]
            vm_fd: Arc::new(vm_fd),
            #[cfg(not(feature = "hw-interrupts"))]
            vm_fd,
            vcpu_fd,
            #[cfg(feature = "hw-interrupts")]
            pic: Pic::new(),
            #[cfg(feature = "hw-interrupts")]
            timer_stop: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "hw-interrupts")]
            timer_thread: None,
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
        #[cfg(feature = "hw-interrupts")]
        const MSR_INTERCEPT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_MSR_INTERCEPT;
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
                            if self.timer_thread.is_some() {
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

                            // OutBAction::Halt always means "I'm done", regardless
                            // of whether a timer is active.
                            if is_write && port_number == OutBAction::Halt as u16 {
                                // Stop the timer thread before returning.
                                #[cfg(feature = "hw-interrupts")]
                                {
                                    self.timer_stop.store(true, Ordering::Relaxed);
                                    if let Some(h) = self.timer_thread.take() {
                                        let _ = h.join();
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
                                } else if let Some(val) = self.handle_hw_io_in(port_number) {
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
                        #[cfg(feature = "hw-interrupts")]
                        MSR_INTERCEPT_MESSAGE => {
                            // Guest is writing to MSR 0x1B (IA32_APIC_BASE).
                            // Force bit 11 (global APIC enable) to stay set,
                            // preventing the guest from disabling the LAPIC.
                            let msr_msg = m
                                .to_msr_info()
                                .map_err(|_| RunVcpuError::DecodeIOMessage(msg_type))?;
                            let rip = msr_msg.header.rip;
                            let instruction_length = msr_msg.header.instruction_length() as u64;
                            let msr_val = (msr_msg.rdx << 32) | (msr_msg.rax & 0xFFFF_FFFF);

                            // Force APIC global enable (bit 11) to remain set,
                            // preserving the standard base address.
                            let forced_val = msr_val | (1 << 11) | 0xFEE00000;
                            self.vcpu_fd
                                .set_reg(&[hv_register_assoc {
                                    name: hv_register_name_HV_X64_REGISTER_RIP,
                                    value: hv_register_value {
                                        reg64: rip + instruction_length,
                                    },
                                    ..Default::default()
                                }])
                                .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                            use mshv_bindings::hv_register_name_HV_X64_REGISTER_APIC_BASE;
                            let _ = self.vcpu_fd.set_reg(&[hv_register_assoc {
                                name: hv_register_name_HV_X64_REGISTER_APIC_BASE,
                                value: hv_register_value { reg64: forced_val },
                                ..Default::default()
                            }]);
                            continue;
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
                    libc::EINTR => {
                        // When the timer thread is active, EINTR may be
                        // a spurious signal. Continue the run loop to
                        // let the hypervisor deliver any pending timer
                        // interrupt.
                        #[cfg(feature = "hw-interrupts")]
                        if self.timer_thread.is_some() {
                            continue;
                        }
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
    #[cfg(not(feature = "nanvix-unstable"))]
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

#[cfg(feature = "hw-interrupts")]
impl MshvVm {
    /// Standard x86 APIC base MSR value: base address 0xFEE00000 +
    /// BSP flag (bit 8) + global enable (bit 11).
    const APIC_BASE_DEFAULT: u64 = 0xFEE00900;

    /// Perform LAPIC EOI: clear the highest-priority in-service bit.
    /// Called when the guest sends PIC EOI, since the timer thread
    /// delivers interrupts through the LAPIC and the guest only
    /// acknowledges via PIC.
    fn do_lapic_eoi(&self) {
        if let Ok(mut lapic) = self.vcpu_fd.get_lapic() {
            // ISR is at offset 0x100, 8 x 32-bit words (one per 16 bytes).
            // Scan from highest priority (ISR[7]) to lowest (ISR[0]).
            for i in (0u32..8).rev() {
                let offset = 0x100 + (i as usize) * 0x10;
                let isr_val = read_lapic_u32(&lapic.regs, offset);
                if isr_val != 0 {
                    let bit = 31 - isr_val.leading_zeros();
                    write_lapic_u32(&mut lapic.regs, offset, isr_val & !(1u32 << bit));
                    let _ = self.vcpu_fd.set_lapic(&lapic);
                    break;
                }
            }
        }
    }

    /// Handle a hardware-interrupt IO IN request.
    /// Returns `Some(value)` if the port was handled (PIC or PIT read),
    /// `None` if the port should be passed through to the guest handler.
    fn handle_hw_io_in(&self, port: u16) -> Option<u64> {
        if let Some(val) = self.pic.handle_io_in(port) {
            return Some(val as u64);
        }
        // PIT data port read -- return 0
        if port == 0x40 {
            return Some(0);
        }
        None
    }

    fn handle_hw_io_out(&mut self, port: u16, data: &[u8]) -> bool {
        if port == OutBAction::PvTimerConfig as u16 {
            if data.len() >= 4 {
                let period_us = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                if period_us > 0 && self.timer_thread.is_none() {
                    // Re-enable LAPIC if the guest disabled it (via WRMSR
                    // to MSR 0x1B clearing bit 11). This happens when the
                    // Nanvix kernel doesn't detect an I/O APIC.
                    //
                    // The hypervisor may return 0 for APIC_BASE when the
                    // APIC is globally disabled, so we always restore the
                    // standard value (0xFEE00900).
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
                        let svr = read_lapic_u32(&lapic.regs, 0xF0);
                        if svr & 0x100 == 0 {
                            write_lapic_u32(&mut lapic.regs, 0xF0, 0x1FF);
                            write_lapic_u32(&mut lapic.regs, 0x80, 0); // TPR
                            let _ = self.vcpu_fd.set_lapic(&lapic);
                        }
                    }

                    // Start a host timer thread that periodically injects
                    // interrupts via request_virtual_interrupt (HVCALL 148).
                    // This replaces the SynIC timer approach and makes MSHV
                    // consistent with the KVM irqfd and WHP software timer
                    // patterns.
                    let vm_fd = self.vm_fd.clone();
                    let vector = self.pic.master_vector_base() as u32;
                    let stop = self.timer_stop.clone();
                    let period = std::time::Duration::from_micros(period_us as u64);
                    self.timer_thread = Some(std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            std::thread::sleep(period);
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let _ = vm_fd.request_virtual_interrupt(&InterruptRequest {
                                interrupt_type: hv_interrupt_type_HV_X64_INTERRUPT_TYPE_FIXED,
                                apic_id: 0,
                                vector,
                                level_triggered: false,
                                logical_destination_mode: false,
                                long_mode: false,
                            });
                        }
                    }));
                }
            }
            return true;
        }
        if !data.is_empty() && self.pic.handle_io_out(port, data[0]) {
            // When the guest sends PIC EOI (port 0x20, OCW2 non-specific EOI),
            // also perform LAPIC EOI since the timer thread delivers via LAPIC
            // and the guest only acknowledges via PIC.
            if port == 0x20 && (data[0] & 0xE0) == 0x20 && self.timer_thread.is_some() {
                self.do_lapic_eoi();
            }
            return true;
        }
        if port == 0x43 || port == 0x40 {
            return true;
        }
        if port == 0x61 {
            return true;
        }
        if port == 0x80 {
            return true;
        }
        false
    }
}

#[cfg(feature = "hw-interrupts")]
impl Drop for MshvVm {
    fn drop(&mut self) {
        self.timer_stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.timer_thread.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
#[cfg(feature = "hw-interrupts")]
mod hw_interrupt_tests {
    use super::*;

    #[test]
    fn write_read_lapic_u32_roundtrip() {
        let mut regs = [0i8; 1024];
        write_lapic_u32(&mut regs, 0xF0, 0xDEAD_BEEF);
        assert_eq!(read_lapic_u32(&regs, 0xF0), 0xDEAD_BEEF);
    }

    #[test]
    fn write_read_lapic_u32_multiple_offsets() {
        let mut regs = [0i8; 1024];
        write_lapic_u32(&mut regs, 0x80, 0x1234_5678);
        write_lapic_u32(&mut regs, 0xF0, 0xABCD_EF01);
        write_lapic_u32(&mut regs, 0xE0, 0xFFFF_FFFF);
        assert_eq!(read_lapic_u32(&regs, 0x80), 0x1234_5678);
        assert_eq!(read_lapic_u32(&regs, 0xF0), 0xABCD_EF01);
        assert_eq!(read_lapic_u32(&regs, 0xE0), 0xFFFF_FFFF);
    }

    #[test]
    fn write_read_lapic_u32_zero() {
        let mut regs = [0xFFu8 as i8; 1024];
        write_lapic_u32(&mut regs, 0x80, 0);
        assert_eq!(read_lapic_u32(&regs, 0x80), 0);
    }

    #[test]
    fn write_read_lapic_u32_does_not_clobber_neighbors() {
        let mut regs = [0i8; 1024];
        write_lapic_u32(&mut regs, 0x80, 0xAAAA_BBBB);
        // Check that bytes before and after are untouched
        assert_eq!(regs[0x7F], 0);
        assert_eq!(regs[0x84], 0);
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

    #[test]
    fn lapic_svr_init_value() {
        // SVR = 0x1FF: bit 8 = enable APIC, bits 0-7 = spurious vector 0xFF
        let svr: u32 = 0x1FF;
        assert_ne!(svr & 0x100, 0, "APIC enable bit should be set");
        assert_eq!(svr & 0xFF, 0xFF, "spurious vector should be 0xFF");
    }

    #[test]
    fn lapic_lvt_masked_value() {
        // Masked LVT entry: bit 16 = 1
        let masked: u32 = 0x0001_0000;
        assert_ne!(masked & (1 << 16), 0, "mask bit should be set");
    }
}
