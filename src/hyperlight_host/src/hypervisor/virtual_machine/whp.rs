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

use std::os::raw::c_void;

use hyperlight_common::outb::VmAction;
#[cfg(feature = "trace_guest")]
use tracing::Span;
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::{MEMORY_MAPPED_VIEW_ADDRESS, UnmapViewOfFile};
use windows::core::s;
use windows_result::HRESULT;

#[cfg(gdb)]
use crate::hypervisor::gdb::{DebugError, DebuggableVm};
use crate::hypervisor::regs::{
    Align16, CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
    FP_CONTROL_WORD_DEFAULT, MXCSR_DEFAULT, WHP_DEBUG_REGS_NAMES, WHP_DEBUG_REGS_NAMES_LEN,
    WHP_FPU_NAMES, WHP_FPU_NAMES_LEN, WHP_REGS_NAMES, WHP_REGS_NAMES_LEN, WHP_SREGS_NAMES,
    WHP_SREGS_NAMES_LEN,
};
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::get_surrogate_process_manager;
#[cfg(feature = "hw-interrupts")]
use crate::hypervisor::virtual_machine::x86_64::hw_interrupts::TimerThread;
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit, XSAVE_MIN_SIZE,
};
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
#[cfg(feature = "trace_guest")]
use crate::sandbox::trace::TraceContext as SandboxTraceContext;

#[allow(dead_code)] // Will be used for runtime hypervisor detection
pub(crate) fn is_hypervisor_present() -> bool {
    let mut capability: WHV_CAPABILITY = Default::default();
    let written_size: Option<*mut u32> = None;

    match unsafe {
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &mut capability as *mut _ as *mut c_void,
            std::mem::size_of::<WHV_CAPABILITY>() as u32,
            written_size,
        )
    } {
        Ok(_) => unsafe { capability.HypervisorPresent.as_bool() },
        Err(_) => {
            tracing::info!("Windows Hypervisor Platform is not available on this system");
            false
        }
    }
}

/// Helper: release a host-side file mapping view and its handle.
/// Called from both `unmap_memory` and `WhpVm::drop`.
fn release_file_mapping(view_base: *mut c_void, mapping_handle: HandleWrapper) {
    unsafe {
        if let Err(e) = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view_base }) {
            tracing::error!("Failed to unmap file view at {:?}: {:?}", view_base, e);
        }
        if let Err(e) = CloseHandle(mapping_handle.into()) {
            tracing::error!(
                "Failed to close file mapping handle {:?}: {:?}",
                mapping_handle,
                e
            );
        }
    }
}

/// A Windows Hypervisor Platform implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    // Surrogate process for memory mapping
    surrogate_process: SurrogateProcess,
    /// Tracks host-side file mappings (view_base, mapping_handle) for
    /// cleanup on unmap or drop. Only populated for MappedFile regions.
    file_mappings: Vec<(HandleWrapper, *mut c_void)>,
    /// Handle to the background timer (if started).
    #[cfg(feature = "hw-interrupts")]
    timer: Option<TimerThread>,
}

// Safety: `WhpVm` is !Send because it holds `SurrogateProcess` which contains a raw pointer
// `allocated_address` (*mut c_void). This pointer represents a memory mapped view address
// in the surrogate process. It is never dereferenced, only used for address arithmetic and
// resource management (unmapping). This is a system resource that is not bound to the creating
// thread and can be safely transferred between threads.
// `file_mappings` contains raw pointers that are also kernel resource handles,
// safe to use from any thread.
unsafe impl Send for WhpVm {}

impl WhpVm {
    pub(crate) fn new() -> Result<Self, CreateVmError> {
        const NUM_CPU: u32 = 1;

        let partition = unsafe {
            #[cfg(feature = "hw-interrupts")]
            Self::check_lapic_emulation_support()?;

            let p = WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
            WHvSetPartitionProperty(
                p,
                WHvPartitionPropertyCodeProcessorCount,
                &NUM_CPU as *const _ as *const _,
                std::mem::size_of_val(&NUM_CPU) as _,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

            #[cfg(feature = "hw-interrupts")]
            Self::enable_lapic_emulation(p)?;

            WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
            WHvCreateVirtualProcessor(p, 0, 0)
                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;

            // Initialize the LAPIC via the bulk interrupt-controller
            // state API (individual APIC register writes via
            // WHvSetVirtualProcessorRegisters fail with ACCESS_DENIED).
            #[cfg(feature = "hw-interrupts")]
            Self::init_lapic_bulk(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;

            p
        };

        let mgr = get_surrogate_process_manager()
            .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;
        let surrogate_process = mgr
            .get_surrogate_process()
            .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;

        Ok(WhpVm {
            partition,
            surrogate_process,
            file_mappings: Vec::new(),
            #[cfg(feature = "hw-interrupts")]
            timer: None,
        })
    }

    /// Helper for setting arbitrary registers. Makes sure the same number
    /// of names and values are passed (at the expense of some performance).
    fn set_registers(
        &self,
        registers: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> windows_result::Result<()> {
        let (names, values): (Vec<_>, Vec<_>) = registers.iter().copied().unzip();

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE, // Casting Align16 away
            )
        }
    }
}

impl VirtualMachine for WhpVm {
    unsafe fn map_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), MapMemoryError> {
        // Calculate the surrogate process address for this region
        let surrogate_base = self
            .surrogate_process
            .map(
                region.host_region.start.from_handle,
                region.host_region.start.handle_base,
                region.host_region.start.handle_size,
                &region.region_type.surrogate_mapping(),
            )
            .map_err(|e| MapMemoryError::SurrogateProcess(e.to_string()))?;
        let surrogate_addr = surrogate_base.wrapping_add(region.host_region.start.offset);

        let flags = region
            .flags
            .iter()
            .map(|flag| match flag {
                MemoryRegionFlags::NONE => Ok(WHvMapGpaRangeFlagNone),
                MemoryRegionFlags::READ => Ok(WHvMapGpaRangeFlagRead),
                MemoryRegionFlags::WRITE => Ok(WHvMapGpaRangeFlagWrite),
                MemoryRegionFlags::EXECUTE => Ok(WHvMapGpaRangeFlagExecute),
                _ => Err(MapMemoryError::InvalidFlags(format!(
                    "Invalid memory region flag: {:?}",
                    flag
                ))),
            })
            .collect::<std::result::Result<Vec<WHV_MAP_GPA_RANGE_FLAGS>, MapMemoryError>>()?
            .iter()
            .fold(WHvMapGpaRangeFlagNone, |acc, flag| acc | *flag);

        let whvmapgparange2_func = unsafe {
            match try_load_whv_map_gpa_range2() {
                Ok(func) => func,
                Err(e) => {
                    return Err(MapMemoryError::LoadApi {
                        api_name: "WHvMapGpaRange2",
                        source: e,
                    });
                }
            }
        };

        let res = unsafe {
            whvmapgparange2_func(
                self.partition,
                self.surrogate_process.process_handle.into(),
                surrogate_addr,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            )
        };
        if res.is_err() {
            return Err(MapMemoryError::Hypervisor(HypervisorError::WindowsError(
                windows_result::Error::from_hresult(res),
            )));
        }

        // Track host-side file mappings for cleanup on unmap or drop.
        if region.region_type == MemoryRegionType::MappedFile {
            self.file_mappings.push((
                region.host_region.start.from_handle,
                region.host_region.start.handle_base as *mut c_void,
            ));
        }

        Ok(())
    }

    fn unmap_memory(
        &mut self,
        (_slot, region): (u32, &MemoryRegion),
    ) -> Result<(), UnmapMemoryError> {
        unsafe {
            WHvUnmapGpaRange(
                self.partition,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
            )
            .map_err(|e| UnmapMemoryError::Hypervisor(HypervisorError::WindowsError(e)))?;
        }
        self.surrogate_process
            .unmap(region.host_region.start.handle_base);

        // Clean up host-side file mapping resources for MappedFile regions.
        if region.region_type == MemoryRegionType::MappedFile {
            let handle_base = region.host_region.start.handle_base as *mut c_void;
            if let Some(pos) = self
                .file_mappings
                .iter()
                .position(|(_, vb)| *vb == handle_base)
            {
                let (handle, view) = self.file_mappings.swap_remove(pos);
                release_file_mapping(view, handle);
            }
        }

        Ok(())
    }

    #[expect(non_upper_case_globals, reason = "Windows API constant are lower case")]
    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = Default::default();

        // setup_trace_guest must be called right before WHvRunVirtualProcessor() call, because
        // it sets the guest span, no other traces or spans must be setup in between these calls.
        #[cfg(feature = "trace_guest")]
        tc.setup_guest_trace(Span::current().context());

        loop {
            unsafe {
                WHvRunVirtualProcessor(
                    self.partition,
                    0,
                    &mut exit_context as *mut _ as *mut c_void,
                    std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
                )
                .map_err(|e| RunVcpuError::Unknown(e.into()))?;
            }

            match exit_context.ExitReason {
                WHvRunVpExitReasonX64IoPortAccess => unsafe {
                    let instruction_length = exit_context.VpContext._bitfield & 0xF;
                    let rip = exit_context.VpContext.Rip + instruction_length as u64;
                    let port = exit_context.Anonymous.IoPortAccess.PortNumber;
                    let rax = exit_context.Anonymous.IoPortAccess.Rax;
                    let access_info_bits = exit_context
                        .Anonymous
                        .IoPortAccess
                        .AccessInfo
                        .Anonymous
                        ._bitfield;
                    let is_write = access_info_bits & 1 != 0;
                    // Bits 1..3 of AccessInfo encode the operand width in
                    // bytes (1 for outb, 2 for outw, 4 for outl). Clamp to
                    // 1..=8 to avoid a zero-length slice.
                    let access_size = (((access_info_bits >> 1) & 0x7) as usize).clamp(1, 8);

                    self.set_registers(&[(
                        WHvX64RegisterRip,
                        Align16(WHV_REGISTER_VALUE { Reg64: rip }),
                    )])
                    .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                    // VmAction::Halt always means "I'm done", regardless
                    // of whether a timer is active.
                    if is_write && port == VmAction::Halt as u16 {
                        // Stop the timer thread before returning.
                        #[cfg(feature = "hw-interrupts")]
                        if let Some(mut t) = self.timer.take() {
                            t.stop();
                        }
                        return Ok(VmExit::Halt());
                    }

                    #[cfg(feature = "hw-interrupts")]
                    {
                        if is_write {
                            let data = rax.to_le_bytes();
                            if self.handle_hw_io_out(port, &data) {
                                continue;
                            }
                        } else if let Some(val) = super::x86_64::hw_interrupts::handle_io_in(port) {
                            self.set_registers(&[(
                                WHvX64RegisterRax,
                                Align16(WHV_REGISTER_VALUE { Reg64: val }),
                            )])
                            .map_err(|e| RunVcpuError::Unknown(e.into()))?;
                            continue;
                        }
                    }

                    // Suppress unused variable warnings when hw-interrupts is disabled
                    let _ = is_write;

                    // Only return the bytes that the guest actually wrote
                    // (1 for outb, 2 for outw, 4 for outl). Previously all
                    // 8 RAX bytes were returned, producing garbled output
                    // for single-byte console writes.
                    let data = rax.to_le_bytes();
                    return Ok(VmExit::IoOut(port, data[..access_size].to_vec()));
                },
                WHvRunVpExitReasonX64Halt => {
                    // With software timer active, re-enter the guest.
                    // WHvRunVirtualProcessor will block until the timer
                    // thread injects an interrupt via WHvRequestInterrupt,
                    // waking the vCPU from HLT.
                    #[cfg(feature = "hw-interrupts")]
                    if self.timer.as_ref().is_some_and(|t| t.is_active()) {
                        continue;
                    }
                    return Ok(VmExit::Halt());
                }
                WHvRunVpExitReasonMemoryAccess => {
                    let gpa = unsafe { exit_context.Anonymous.MemoryAccess.Gpa };
                    let access_info = unsafe {
                        WHV_MEMORY_ACCESS_TYPE(
                            (exit_context.Anonymous.MemoryAccess.AccessInfo.AsUINT32 & 0b11) as i32,
                        )
                    };
                    let access_info = MemoryRegionFlags::try_from(access_info)
                        .map_err(|_| RunVcpuError::ParseGpaAccessInfo)?;
                    return match access_info {
                        MemoryRegionFlags::READ => Ok(VmExit::MmioRead(gpa)),
                        MemoryRegionFlags::WRITE => Ok(VmExit::MmioWrite(gpa)),
                        _ => Ok(VmExit::Unknown("Unknown memory access type".to_string())),
                    };
                }
                // Execution was cancelled by the host.
                WHvRunVpExitReasonCanceled => {
                    return Ok(VmExit::Cancelled());
                }
                #[cfg(gdb)]
                WHvRunVpExitReasonException => {
                    let exception = unsafe { exit_context.Anonymous.VpException };

                    // Get the DR6 register to see which breakpoint was hit
                    let dr6 = {
                        let names = [WHvX64RegisterDr6];
                        let mut out: [Align16<WHV_REGISTER_VALUE>; 1] =
                            unsafe { std::mem::zeroed() };
                        unsafe {
                            WHvGetVirtualProcessorRegisters(
                                self.partition,
                                0,
                                names.as_ptr(),
                                1,
                                out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
                            )
                            .map_err(|e| RunVcpuError::GetDr6(e.into()))?;
                        }
                        unsafe { out[0].0.Reg64 }
                    };

                    return Ok(VmExit::Debug {
                        dr6,
                        exception: exception.ExceptionType as u32,
                    });
                }
                WHV_RUN_VP_EXIT_REASON(_) => {
                    let rip = exit_context.VpContext.Rip;
                    tracing::error!(
                        "WHP unknown exit reason {}: RIP={:#x}",
                        exit_context.ExitReason.0,
                        rip,
                    );
                    if let Ok(regs) = self.regs() {
                        tracing::error!(
                            "  RAX={:#x} RCX={:#x} RDX={:#x}",
                            regs.rax,
                            regs.rcx,
                            regs.rdx
                        );
                    }
                    if let Ok(sregs) = self.sregs() {
                        tracing::error!(
                            "  CR0={:#x} CR4={:#x} EFER={:#x} APIC_BASE={:#x}",
                            sregs.cr0,
                            sregs.cr4,
                            sregs.efer,
                            sregs.apic_base
                        );
                    }
                    return Ok(VmExit::Unknown(format!(
                        "Unknown exit reason '{}' at RIP={:#x}",
                        exit_context.ExitReason.0, rip
                    )));
                }
            }
        }
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        let mut whv_regs_values: [Align16<WHV_REGISTER_VALUE>; WHP_REGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_REGS_NAMES.as_ptr(),
                whv_regs_values.len() as u32,
                whv_regs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetRegs(e.into()))?;
        }

        WHP_REGS_NAMES
            .into_iter()
            .zip(whv_regs_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                RegisterError::ConversionFailed(format!(
                    "Failed to convert WHP registers to CommonRegisters: {:?}",
                    e
                ))
            })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            regs.into();
        self.set_registers(&whp_regs)
            .map_err(|e| RegisterError::SetRegs(e.into()))?;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        let mut whp_fpu_values: [Align16<WHV_REGISTER_VALUE>; WHP_FPU_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_FPU_NAMES.as_ptr(),
                whp_fpu_values.len() as u32,
                whp_fpu_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetFpu(e.into()))?;
        }

        WHP_FPU_NAMES
            .into_iter()
            .zip(whp_fpu_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                RegisterError::ConversionFailed(format!(
                    "Failed to convert WHP registers to CommonFpu: {:?}",
                    e
                ))
            })
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        let whp_fpu: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_FPU_NAMES_LEN] =
            fpu.into();
        self.set_registers(&whp_fpu)
            .map_err(|e| RegisterError::SetFpu(e.into()))?;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        let mut whp_sregs_values: [Align16<WHV_REGISTER_VALUE>; WHP_SREGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_SREGS_NAMES.as_ptr(),
                whp_sregs_values.len() as u32,
                whp_sregs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetSregs(e.into()))?;
        }

        WHP_SREGS_NAMES
            .into_iter()
            .zip(whp_sregs_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                RegisterError::ConversionFailed(format!(
                    "Failed to convert WHP registers to CommonSpecialRegisters: {:?}",
                    e
                ))
            })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> std::result::Result<(), RegisterError> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            sregs.into();

        // When LAPIC emulation is active (always with hw-interrupts),
        // skip writing APIC_BASE. The generic CommonSpecialRegisters
        // defaults APIC_BASE to 0 which would globally disable the LAPIC.
        // On some WHP hosts, host-side APIC register writes are blocked
        // entirely (ACCESS_DENIED).
        #[cfg(feature = "hw-interrupts")]
        {
            let filtered: Vec<_> = whp_regs
                .iter()
                .copied()
                .filter(|(name, _)| *name != WHvX64RegisterApicBase)
                .collect();
            self.set_registers(&filtered)
                .map_err(|e| RegisterError::SetSregs(e.into()))?;
            Ok(())
        }

        #[cfg(not(feature = "hw-interrupts"))]
        {
            self.set_registers(&whp_regs)
                .map_err(|e| RegisterError::SetSregs(e.into()))?;
            Ok(())
        }
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        let mut whp_debug_regs_values: [Align16<WHV_REGISTER_VALUE>; WHP_DEBUG_REGS_NAMES_LEN] =
            Default::default();

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_DEBUG_REGS_NAMES.as_ptr(),
                whp_debug_regs_values.len() as u32,
                whp_debug_regs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )
            .map_err(|e| RegisterError::GetDebugRegs(e.into()))?;
        }

        let whp_debug_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>);
            WHP_DEBUG_REGS_NAMES_LEN] =
            std::array::from_fn(|i| (WHP_DEBUG_REGS_NAMES[i], whp_debug_regs_values[i]));
        whp_debug_regs.as_slice().try_into().map_err(|e| {
            RegisterError::ConversionFailed(format!(
                "Failed to convert WHP registers to CommonDebugRegs: {:?}",
                e
            ))
        })
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_DEBUG_REGS_NAMES_LEN] =
            drs.into();
        self.set_registers(&whp_regs)
            .map_err(|e| RegisterError::SetDebugRegs(e.into()))?;
        Ok(())
    }

    #[allow(dead_code)]
    fn xsave(&self) -> std::result::Result<Vec<u8>, RegisterError> {
        // Get the required buffer size by calling with NULL buffer.
        // If the buffer is not large enough (0 won't be), WHvGetVirtualProcessorXsaveState returns
        // WHV_E_INSUFFICIENT_BUFFER and sets buffer_size_needed to the required size.
        let mut buffer_size_needed: u32 = 0;

        let result = unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.partition,
                0,
                std::ptr::null_mut(),
                0,
                &mut buffer_size_needed,
            )
        };

        // Expect insufficient buffer error; any other error is unexpected
        if let Err(e) = result
            && e.code() != windows::Win32::Foundation::WHV_E_INSUFFICIENT_BUFFER
        {
            return Err(RegisterError::GetXsave(e.into()));
        }

        // Allocate buffer with the required size
        let mut xsave_buffer = vec![0u8; buffer_size_needed as usize];
        let mut written_bytes = 0;

        // Get the actual Xsave state
        unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.partition,
                0,
                xsave_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size_needed,
                &mut written_bytes,
            )
        }
        .map_err(|e| RegisterError::GetXsave(e.into()))?;

        // Verify the number of written bytes matches the expected size
        if written_bytes != buffer_size_needed {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: buffer_size_needed,
                actual: written_bytes,
            });
        }

        Ok(xsave_buffer)
    }

    fn reset_xsave(&self) -> std::result::Result<(), RegisterError> {
        // WHP uses compacted XSAVE format (bit 63 of XCOMP_BV set).
        // We cannot just zero out the xsave area, we need to preserve the XCOMP_BV.

        // Get the required buffer size by calling with NULL buffer.
        let mut buffer_size_needed: u32 = 0;

        let result = unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.partition,
                0,
                std::ptr::null_mut(),
                0,
                &mut buffer_size_needed,
            )
        };

        // Expect insufficient buffer error; any other error is unexpected
        if let Err(e) = result
            && e.code() != windows::Win32::Foundation::WHV_E_INSUFFICIENT_BUFFER
        {
            return Err(RegisterError::GetXsaveSize(e.into()));
        }

        if buffer_size_needed < XSAVE_MIN_SIZE as u32 {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: XSAVE_MIN_SIZE as u32,
                actual: buffer_size_needed,
            });
        }

        // Create a buffer to hold the current state (to get the correct XCOMP_BV)
        let mut current_state = vec![0u8; buffer_size_needed as usize];
        let mut written_bytes = 0;
        unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.partition,
                0,
                current_state.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size_needed,
                &mut written_bytes,
            )
            .map_err(|e| RegisterError::GetXsave(e.into()))?;
        };

        // Zero out most of the buffer, preserving only XCOMP_BV (520-528).
        // Extended components with XSTATE_BV bit=0 will use their init values.
        //
        // - Legacy region (0-512): x87 FPU + SSE state
        // - XSTATE_BV (512-520): Feature bitmap
        // - XCOMP_BV (520-528): Compaction bitmap + format bit (KEEP)
        // - Reserved (528-576): Header padding
        // - Extended (576+): AVX, AVX-512, MPX, PKRU, AMX, etc.
        current_state[0..520].fill(0);
        current_state[528..].fill(0);

        // XSAVE area layout from Intel SDM Vol. 1 Section 13.4.1:
        // - Bytes 0-1: FCW (x87 FPU Control Word)
        // - Bytes 24-27: MXCSR
        // - Bytes 512-519: XSTATE_BV (bitmap of valid state components)
        current_state[0..2].copy_from_slice(&FP_CONTROL_WORD_DEFAULT.to_le_bytes());
        current_state[24..28].copy_from_slice(&MXCSR_DEFAULT.to_le_bytes());
        // XSTATE_BV = 0x3: bits 0,1 = x87 + SSE valid. Explicitly tell hypervisor
        // to apply the legacy region from this buffer for consistent behavior.
        current_state[512..520].copy_from_slice(&0x3u64.to_le_bytes());

        unsafe {
            WHvSetVirtualProcessorXsaveState(
                self.partition,
                0,
                current_state.as_ptr() as *const std::ffi::c_void,
                buffer_size_needed,
            )
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        }

        Ok(())
    }

    #[cfg(test)]
    #[cfg(not(feature = "nanvix-unstable"))]
    fn set_xsave(&self, xsave: &[u32]) -> std::result::Result<(), RegisterError> {
        // Get the required buffer size by calling with NULL buffer.
        // If the buffer is not large enough (0 won't be), WHvGetVirtualProcessorXsaveState returns
        // WHV_E_INSUFFICIENT_BUFFER and sets buffer_size_needed to the required size.
        let mut buffer_size_needed: u32 = 0;

        let result = unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.partition,
                0,
                std::ptr::null_mut(),
                0,
                &mut buffer_size_needed,
            )
        };

        // Expect insufficient buffer error; any other error is unexpected
        if let Err(e) = result
            && e.code() != windows::Win32::Foundation::WHV_E_INSUFFICIENT_BUFFER
        {
            return Err(RegisterError::GetXsaveSize(e.into()));
        }

        let provided_size = std::mem::size_of_val(xsave) as u32;
        if provided_size != buffer_size_needed {
            return Err(RegisterError::XsaveSizeMismatch {
                expected: buffer_size_needed,
                actual: provided_size,
            });
        }

        unsafe {
            WHvSetVirtualProcessorXsaveState(
                self.partition,
                0,
                xsave.as_ptr() as *const std::ffi::c_void,
                buffer_size_needed,
            )
            .map_err(|e| RegisterError::SetXsave(e.into()))?;
        }

        Ok(())
    }

    /// Get the partition handle for this VM
    fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.partition
    }
}

#[cfg(gdb)]
impl DebuggableVm for WhpVm {
    fn translate_gva(&self, gva: u64) -> std::result::Result<u64, DebugError> {
        let mut gpa = 0;
        let mut result = WHV_TRANSLATE_GVA_RESULT::default();

        // Only validate read access because the write access is handled through the
        // host memory mapping
        let translateflags = WHvTranslateGvaFlagValidateRead;

        unsafe {
            WHvTranslateGva(
                self.partition,
                0,
                gva,
                translateflags,
                &mut result,
                &mut gpa,
            )
            .map_err(|_| DebugError::TranslateGva(gva))?;
        }

        Ok(gpa)
    }

    fn set_debug(&mut self, enable: bool) -> std::result::Result<(), DebugError> {
        let extended_vm_exits = if enable { 1 << 2 } else { 0 };
        let exception_exit_bitmap = if enable {
            (1 << WHvX64ExceptionTypeDebugTrapOrFault.0)
                | (1 << WHvX64ExceptionTypeBreakpointTrap.0)
        } else {
            0
        };

        let properties = [
            (
                WHvPartitionPropertyCodeExtendedVmExits,
                WHV_PARTITION_PROPERTY {
                    ExtendedVmExits: WHV_EXTENDED_VM_EXITS {
                        AsUINT64: extended_vm_exits,
                    },
                },
            ),
            (
                WHvPartitionPropertyCodeExceptionExitBitmap,
                WHV_PARTITION_PROPERTY {
                    ExceptionExitBitmap: exception_exit_bitmap,
                },
            ),
        ];

        for (code, property) in properties {
            unsafe {
                WHvSetPartitionProperty(
                    self.partition,
                    code,
                    &property as *const _ as *const c_void,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                )
                .map_err(|e| DebugError::Intercept {
                    enable,
                    inner: e.into(),
                })?;
            }
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

        // Get current debug registers
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
        // Get current debug registers
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
impl WhpVm {
    /// Maximum size for the interrupt controller state blob.
    const LAPIC_STATE_MAX_SIZE: u32 = 4096;

    /// Check whether the WHP host supports LAPIC emulation.
    /// Bit 1 of WHV_CAPABILITY_FEATURES = LocalApicEmulation.
    /// LAPIC emulation is required for timer interrupt delivery.
    fn check_lapic_emulation_support() -> Result<(), CreateVmError> {
        const LAPIC_EMULATION_BIT: u64 = 1 << 1;

        let mut capability: WHV_CAPABILITY = Default::default();
        let has_lapic = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeFeatures,
                &mut capability as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_CAPABILITY>() as u32,
                None,
            )
            .is_ok()
                && (capability.Features.AsUINT64 & LAPIC_EMULATION_BIT != 0)
        };

        if !has_lapic {
            return Err(CreateVmError::InitializeVm(
                windows_result::Error::new(
                    HRESULT::from_win32(0x32), // ERROR_NOT_SUPPORTED
                    "WHP LocalApicEmulation capability is required for hw-interrupts",
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// Enable LAPIC emulation on the given partition.
    fn enable_lapic_emulation(partition: WHV_PARTITION_HANDLE) -> Result<(), CreateVmError> {
        let apic_mode = WHvX64LocalApicEmulationModeXApic;
        unsafe {
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeLocalApicEmulationMode,
                &apic_mode as *const _ as *const _,
                std::mem::size_of_val(&apic_mode) as _,
            )
            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
        }
        Ok(())
    }

    /// Initialize the LAPIC via the bulk interrupt-controller state API.
    /// Individual APIC register writes via `WHvSetVirtualProcessorRegisters`
    /// fail with ACCESS_DENIED on WHP when LAPIC emulation is enabled,
    /// so we use `WHvGet/SetVirtualProcessorInterruptControllerState2`
    /// to read-modify-write the entire LAPIC register page.
    unsafe fn init_lapic_bulk(partition: WHV_PARTITION_HANDLE) -> windows_result::Result<()> {
        let mut state = vec![0u8; Self::LAPIC_STATE_MAX_SIZE as usize];
        let mut written: u32 = 0;

        unsafe {
            WHvGetVirtualProcessorInterruptControllerState2(
                partition,
                0,
                state.as_mut_ptr() as *mut c_void,
                Self::LAPIC_STATE_MAX_SIZE,
                Some(&mut written),
            )?;
        }
        state.truncate(written as usize);

        // init_lapic_registers writes up to offset 0x374 (LVT Error at 0x370).
        // Bail out if the buffer returned by WHP is too small.
        const MIN_LAPIC_STATE_SIZE: usize = 0x374;
        if state.len() < MIN_LAPIC_STATE_SIZE {
            return Err(windows_result::Error::new(
                HRESULT::from_win32(0x32), // ERROR_NOT_SUPPORTED
                "WHP LAPIC state buffer is too small for init_lapic_registers",
            ));
        }

        super::x86_64::hw_interrupts::init_lapic_registers(&mut state);

        unsafe {
            WHvSetVirtualProcessorInterruptControllerState2(
                partition,
                0,
                state.as_ptr() as *const c_void,
                state.len() as u32,
            )?;
        }

        Ok(())
    }

    /// Get the LAPIC state via the bulk interrupt-controller state API.
    fn get_lapic_state(&self) -> windows_result::Result<Vec<u8>> {
        let mut state = vec![0u8; Self::LAPIC_STATE_MAX_SIZE as usize];
        let mut written: u32 = 0;

        unsafe {
            WHvGetVirtualProcessorInterruptControllerState2(
                self.partition,
                0,
                state.as_mut_ptr() as *mut c_void,
                Self::LAPIC_STATE_MAX_SIZE,
                Some(&mut written),
            )?;
        }
        state.truncate(written as usize);
        Ok(state)
    }

    /// Set the LAPIC state via the bulk interrupt-controller state API.
    fn set_lapic_state(&self, state: &[u8]) -> windows_result::Result<()> {
        unsafe {
            WHvSetVirtualProcessorInterruptControllerState2(
                self.partition,
                0,
                state.as_ptr() as *const c_void,
                state.len() as u32,
            )
        }
    }

    /// Perform LAPIC EOI: clear the highest-priority in-service bit.
    /// Called when the guest sends PIC EOI, since the LAPIC timer
    /// delivers through the LAPIC and the guest only acknowledges via PIC.
    fn do_lapic_eoi(&self) {
        if let Ok(mut state) = self.get_lapic_state() {
            super::x86_64::hw_interrupts::lapic_eoi(&mut state);
            if let Err(e) = self.set_lapic_state(&state) {
                tracing::warn!("WHP set_lapic_state (EOI) failed: {e}");
            }
        }
    }

    fn handle_hw_io_out(&mut self, port: u16, data: &[u8]) -> bool {
        if port == VmAction::PvTimerConfig as u16 {
            let partition_raw = self.partition.0;
            let vector = super::x86_64::hw_interrupts::TIMER_VECTOR;
            super::x86_64::hw_interrupts::handle_pv_timer_config(
                &mut self.timer,
                data,
                move || {
                    let partition = WHV_PARTITION_HANDLE(partition_raw);
                    let interrupt = WHV_INTERRUPT_CONTROL {
                        _bitfield: 0, // Type=Fixed, DestMode=Physical, Trigger=Edge
                        Destination: 0,
                        Vector: vector,
                    };
                    let _ = unsafe {
                        WHvRequestInterrupt(
                            partition,
                            &interrupt,
                            std::mem::size_of::<WHV_INTERRUPT_CONTROL>() as u32,
                        )
                    };
                },
            );
            return true;
        }
        let timer_active = self.timer.as_ref().is_some_and(|t| t.is_active());
        super::x86_64::hw_interrupts::handle_common_io_out(port, data, timer_active, || {
            self.do_lapic_eoi()
        })
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        // Clean up any remaining file mappings that weren't explicitly unmapped.
        for (handle, view) in self.file_mappings.drain(..) {
            release_file_mapping(view, handle);
        }

        // Stop the software timer thread before tearing down the partition.
        #[cfg(feature = "hw-interrupts")]
        if let Some(mut t) = self.timer.take() {
            t.stop();
        }

        // HyperlightVm::drop() calls set_dropped() before this runs.
        // set_dropped() ensures no WHvCancelRunVirtualProcessor calls are in progress
        // or will be made in the future, so it's safe to delete the partition.
        // (HyperlightVm::drop() runs before its fields are dropped, so
        // set_dropped() completes before this Drop impl runs.)
        if let Err(e) = unsafe { WHvDeletePartition(self.partition) } {
            tracing::error!("Failed to delete partition: {}", e);
        }
    }
}

// This function dynamically loads the WHvMapGpaRange2 function from the winhvplatform.dll
// WHvMapGpaRange2 only available on Windows 11 or Windows Server 2022 and later
// we do things this way to allow a user trying to load hyperlight on an older version of windows to
// get an error message saying that hyperlight requires a newer version of windows, rather than just failing
// with an error about a missing entrypoint
// This function should always succeed since before we get here we have already checked that the hypervisor is present and
// that we are on a supported version of windows.
type WHvMapGpaRange2Func = unsafe extern "C" fn(
    WHV_PARTITION_HANDLE,
    HANDLE,
    *const c_void,
    u64,
    u64,
    WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT;

unsafe fn try_load_whv_map_gpa_range2() -> windows_result::Result<WHvMapGpaRange2Func> {
    let library = unsafe {
        LoadLibraryExA(
            s!("winhvplatform.dll"),
            None,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    }?;

    let address = unsafe { GetProcAddress(library, s!("WHvMapGpaRange2")) };

    if address.is_none() {
        unsafe { FreeLibrary(library)? };
        return Err(windows_result::Error::new(
            HRESULT::from_win32(127), // ERROR_PROC_NOT_FOUND
            "Failed to find WHvMapGpaRange2 in winhvplatform.dll",
        ));
    }

    unsafe { Ok(std::mem::transmute_copy(&address)) }
}

#[cfg(test)]
#[cfg(feature = "hw-interrupts")]
mod hw_interrupt_tests {
    use super::*;

    #[test]
    fn lapic_register_helpers_delegate() {
        use crate::hypervisor::virtual_machine::x86_64::hw_interrupts;
        let mut state = vec![0u8; 1024];
        hw_interrupts::write_lapic_u32(&mut state, 0xF0, 0x1FF);
        assert_eq!(hw_interrupts::read_lapic_u32(&state, 0xF0), 0x1FF);
    }

    #[test]
    fn check_lapic_emulation_capability() {
        let mut capability: WHV_CAPABILITY = Default::default();
        let result = unsafe {
            WHvGetCapability(
                WHvCapabilityCodeFeatures,
                &mut capability as *mut _ as *mut std::os::raw::c_void,
                std::mem::size_of::<WHV_CAPABILITY>() as u32,
                None,
            )
        };
        assert!(
            result.is_ok(),
            "WHvGetCapability(Features) failed: {result:?}"
        );
        let raw = unsafe { capability.Features.AsUINT64 };
        let has_lapic = raw & (1 << 1) != 0; // bit 1 = LocalApicEmulation
        assert!(
            has_lapic,
            "This host does not support WHP LocalApicEmulation. \
             hw-interrupts requires Windows 11 22H2+ or a recent Windows Server build."
        );
    }
}
