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

use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex};

use log::{LevelFilter, error};
use mshv_bindings::{
    FloatingPointUnit, SpecialRegisters, StandardRegisters, hv_message_type,
    hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_user_mem_region,
};
#[cfg(gdb)]
use mshv_bindings::{
    HV_INTERCEPT_ACCESS_MASK_EXECUTE, hv_intercept_parameters,
    hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION, hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT,
    mshv_install_intercept,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

#[cfg(gdb)]
use super::gdb::{
    DebugCommChannel, DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, MshvDebug,
    VcpuStopReason,
};
use super::{HyperlightExit, Hypervisor, LinuxInterruptHandle, VirtualCPU};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::hypervisor::regs::CommonFpu;
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



/// Determine whether the HyperV for Linux hypervisor API is present
/// and functional.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    match Mshv::new() {
        Ok(_) => true,
        Err(_) => {
            log::info!("MSHV is not available on this system");
            false
        }
    }
}

/// A MSHV implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct MshvVm {
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
}

impl HypervLinuxDriver {
    /// Create a new `HypervLinuxDriver`, complete with all registers
    /// set up to execute a Hyperlight binary inside a HyperV-powered
    /// sandbox on Linux.
    ///
    /// While registers are set up, they will not have been applied to
    /// the underlying virtual CPU after this function returns. Call the
    /// `apply_registers` method to do that, or more likely call
    /// `initialise` to do it for you.
    #[allow(clippy::too_many_arguments)]
    // TODO: refactor this function to take fewer arguments. Add trace_info to rt_cfg
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        entrypoint_ptr: GuestPtr,
        rsp_ptr: GuestPtr,
        pml4_ptr: GuestPtr,
        config: &SandboxConfiguration,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        let mshv = Mshv::new()?;
        let pr = Default::default();

        let vm_fd = {
            // It's important to avoid create_vm() and explicitly use
            // create_vm_with_args() with an empty arguments structure
            // here, because otherwise the partition is set up with a SynIC.

            let vm_fd = mshv.create_vm_with_args(&pr)?;
            let features: hv_partition_synthetic_processor_features = Default::default();
            vm_fd.set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                unsafe { features.as_uint64[0] },
            )?;
            vm_fd.initialize()?;
            vm_fd
        };

        let vcpu_fd = vm_fd.create_vcpu(0)?;

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            let mut debug = MshvDebug::new();
            debug.add_hw_breakpoint(&vcpu_fd, entrypoint_ptr.absolute()?)?;

            // The bellow intercepts make the vCPU exit with the Exception Intercept exit code
            // Check Table 6-1. Exceptions and Interrupts at Page 6-13 Vol. 1
            // of Intel 64 and IA-32 Architectures Software Developer's Manual
            // Install intercept for #DB (1) exception
            vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    // Exception handler #DB (1)
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: 0x1,
                    },
                })
                .map_err(|e| new_error!("Cannot install debug exception intercept: {}", e))?;

            // Install intercept for #BP (3) exception
            vm_fd
                .install_intercept(mshv_install_intercept {
                    access_type_mask: HV_INTERCEPT_ACCESS_MASK_EXECUTE,
                    intercept_type: hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION,
                    // Exception handler #BP (3)
                    intercept_parameter: hv_intercept_parameters {
                        exception_vector: 0x3,
                    },
                })
                .map_err(|e| new_error!("Cannot install breakpoint exception intercept: {}", e))?;

            (Some(debug), Some(gdb_conn))
        } else {
            (None, None)
        };

        mem_regions.iter().try_for_each(|region| {
            let mshv_region = region.to_owned().into();
            vm_fd.map_user_memory(mshv_region)
        })?;

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

        let mut hv = Self {
            _mshv: mshv,
            page_size: 0,
            vm_fd,
            vcpu_fd,
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            entrypoint: entrypoint_ptr.absolute()?,
            orig_rsp: rsp_ptr,
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

        hv.setup_initial_sregs(pml4_ptr.absolute()?)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if hv.debug.is_some() {
            hv.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(hv)
    }
}

impl Debug for HypervLinuxDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Hyperv Linux Driver");

        f.field("Entrypoint", &self.entrypoint)
            .field("Original RSP", &self.orig_rsp);

        for region in &self.sandbox_regions {
            f.field("Sandbox Memory Region", &region);
        }
        for region in &self.mmap_regions {
            f.field("Mapped Memory Region", &region);
        }

        let regs = self.vcpu_fd.get_regs();

        if let Ok(regs) = regs {
            f.field("Registers", &regs);
        }

        let sregs = self.vcpu_fd.get_sregs();

        if let Ok(sregs) = sregs {
            f.field("Special Registers", &sregs);
        }

        f.finish()
    }
}

impl Hypervisor for HypervLinuxDriver {
    unsafe fn map_memory(&mut self, (_slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd.map_user_memory(mshv_region)?;
        Ok(())
    }

    fn unmap_memory(&mut self, (_slot, region): (u32, &MemoryRegion)) -> Result<()> {
        let mshv_region: mshv_user_mem_region = region.into();
        self.vm_fd.unmap_user_memory(mshv_region)?;
        Ok(())
    }


    

        fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        const HALT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT_INTERCEPT_MESSAGE: hv_message_type =
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        let exit_reason = self.vcpu_fd.run();

        let result = match exit_reason {
            Ok(m) => match m.header.message_type {
                HALT_MESSAGE => HyperlightExit::Halt(),
                IO_PORT_INTERCEPT_MESSAGE => {
                    let io_message = m.to_ioport_info().map_err(mshv_ioctls::MshvError::from)?;
                    let port_number = io_message.port_number;
                    let rip = io_message.header.rip;
                    let rax = io_message.rax;
                    let instruction_length = io_message.header.instruction_length() as u64;

                    // mshv, unlike kvm, does not automatically increment RIP
                    self.vcpu_fd.set_reg(&[hv_register_assoc {
                        name: hv_register_name_HV_X64_REGISTER_RIP,
                        value: hv_register_value {
                            reg64: rip + instruction_length,
                        },
                        ..Default::default()
                    }])?;
                    HyperlightExit::IoOut(port_number, rax.to_le_bytes().to_vec())
                }
                UNMAPPED_GPA_MESSAGE => {
                    let mimo_message = m.to_memory_info().map_err(mshv_ioctls::MshvError::from)?;
                    let addr = mimo_message.guest_physical_address;
                    match MemoryRegionFlags::try_from(mimo_message)? {
                        MemoryRegionFlags::READ => HyperlightExit::MmioRead(addr),
                        MemoryRegionFlags::WRITE => HyperlightExit::MmioWrite(addr),
                        _ => HyperlightExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                INVALID_GPA_ACCESS_MESSAGE => {
                    let mimo_message = m.to_memory_info().map_err(mshv_ioctls::MshvError::from)?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)?;
                    match access_info {
                        MemoryRegionFlags::READ => HyperlightExit::MmioRead(gpa),
                        MemoryRegionFlags::WRITE => HyperlightExit::MmioWrite(gpa),
                        _ => HyperlightExit::Unknown("Unknown MMIO access".to_string()),
                    }
                }
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    let ex_info = m
                        .to_exception_info()
                        .map_err(mshv_ioctls::MshvError::from)?;
                    let DebugRegisters { dr6, .. } = self.vcpu_fd.get_debug_regs()?;
                    HyperlightExit::Debug {
                        dr6,
                        exception: ex_info.exception_vector as u32,
                    }
                }
                other => HyperlightExit::Unknown(format!("Unknown MSHV VCPU exit: {:?}", other)),
            },
            Err(e) => match e.errno() {
                // InterruptHandle::kill() sends a signal (SIGRTMIN+offset) to interrupt the vcpu, which causes EINTR
                libc::EINTR => HyperlightExit::Cancelled(),
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => HyperlightExit::Unknown(format!("Unknown MSHV VCPU error: {}", e)),
            },
        };
        Ok(result)
    }

    fn regs(&self) -> Result<super::regs::CommonRegisters> {
        let mshv_regs = self.vcpu_fd.get_regs()?;
        Ok((&mshv_regs).into())
    }

    fn set_regs(&mut self, regs: &super::regs::CommonRegisters) -> Result<()> {
        let mshv_regs: StandardRegisters = regs.into();
        self.vcpu_fd.set_regs(&mshv_regs)?;
        Ok(())
    }

    fn fpu(&self) -> Result<super::regs::CommonFpu> {
        let mshv_fpu = self.vcpu_fd.get_fpu()?;
        Ok((&mshv_fpu).into())
    }

    fn set_fpu(&mut self, fpu: &super::regs::CommonFpu) -> Result<()> {
        let mshv_fpu: FloatingPointUnit = fpu.into();
        self.vcpu_fd.set_fpu(&mshv_fpu)?;
        Ok(())
    }

    fn sregs(&self) -> Result<super::regs::CommonSpecialRegisters> {
        let mshv_sregs = self.vcpu_fd.get_sregs()?;
        Ok((&mshv_sregs).into())
    }

    fn set_sregs(&mut self, sregs: &super::regs::CommonSpecialRegisters) -> Result<()> {
        let mshv_sregs: SpecialRegisters = sregs.into();
        self.vcpu_fd.set_sregs(&mshv_sregs)?;
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
    fn xsave(&self) -> Result<Vec<u8>> {
        let xsave = self.vcpu_fd.get_xsave()?;
        Ok(xsave.buffer.to_vec())
    }

    #[cfg(feature = "mem_profile")]
    fn trace_info_mut(&mut self) -> &mut MemTraceInfo {
        &mut self.trace_info
    }
}

impl Drop for HypervLinuxDriver {
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn drop(&mut self) {
        self.interrupt_handle.set_dropped();
        for region in self.sandbox_regions.iter().chain(self.mmap_regions.iter()) {
            let mshv_region: mshv_user_mem_region = region.to_owned().into();
            match self.vm_fd.unmap_user_memory(mshv_region) {
                Ok(_) => (),
                Err(e) => error!("Failed to unmap user memory in HyperVOnLinux ({:?})", e),
            }
        }
    }
}

#[cfg(gdb)]
impl DebuggableVm for MshvVm {
    fn translate_gva(&self, gva: u64) -> Result<u64> {
        use mshv_bindings::{HV_TRANSLATE_GVA_VALIDATE_READ, HV_TRANSLATE_GVA_VALIDATE_WRITE};

        use crate::HyperlightError;

        let flags = (HV_TRANSLATE_GVA_VALIDATE_READ | HV_TRANSLATE_GVA_VALIDATE_WRITE) as u64;
        let (addr, _) = self
            .vcpu_fd
            .translate_gva(gva, flags)
            .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

        Ok(addr)
    }

    fn set_debug(&mut self, enabled: bool) -> Result<()> {
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
                .map_err(|e| {
                    new_error!(
                        "Cannot {} exception intercept for vector {}: {}",
                        if enabled { "install" } else { "remove" },
                        vector,
                        e
                    )
                })?;
        }
        Ok(())
    }

    fn set_single_step(&mut self, enable: bool) -> Result<()> {
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

        let mut debug_regs = self.vcpu_fd.get_debug_regs()?;

        // Check if breakpoint already exists
        if [
            debug_regs.dr0,
            debug_regs.dr1,
            debug_regs.dr2,
            debug_regs.dr3,
        ]
        .contains(&addr)
        {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| debug_regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        *[
            &mut debug_regs.dr0,
            &mut debug_regs.dr1,
            &mut debug_regs.dr2,
            &mut debug_regs.dr3,
        ][i] = addr;

        // Enable LOCAL bit
        debug_regs.dr7 |= 1 << (i * 2);

        self.vcpu_fd.set_debug_regs(&debug_regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        let mut debug_regs = self.vcpu_fd.get_debug_regs()?;

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
            self.vcpu_fd.set_debug_regs(&debug_regs)?;
            Ok(())
        } else {
            Err(new_error!("Tried to remove non-existing hw-breakpoint"))
        }
    }
}
