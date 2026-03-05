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
#[cfg(feature = "hw-interrupts")]
use std::sync::Arc;
#[cfg(feature = "hw-interrupts")]
use std::sync::atomic::{AtomicBool, Ordering};

use hyperlight_common::outb::OutBAction;
#[cfg(feature = "trace_guest")]
use tracing::Span;
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
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
use crate::hypervisor::virtual_machine::{
    CreateVmError, HypervisorError, MapMemoryError, RegisterError, RunVcpuError, UnmapMemoryError,
    VirtualMachine, VmExit, XSAVE_MIN_SIZE,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
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

/// A Windows Hypervisor Platform implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    // Surrogate process for memory mapping
    surrogate_process: SurrogateProcess,
    /// Whether the WHP host supports LAPIC emulation mode.
    #[cfg(feature = "hw-interrupts")]
    lapic_emulation: bool,
    /// Whether the LAPIC timer is actively delivering periodic interrupts.
    #[cfg(feature = "hw-interrupts")]
    lapic_timer_active: bool,
    /// Signal to stop the software timer thread.
    #[cfg(feature = "hw-interrupts")]
    timer_stop: Option<Arc<AtomicBool>>,
    /// Handle for the software timer thread.
    #[cfg(feature = "hw-interrupts")]
    timer_thread: Option<std::thread::JoinHandle<()>>,
}

// Safety: `WhpVm` is !Send because it holds `SurrogateProcess` which contains a raw pointer
// `allocated_address` (*mut c_void). This pointer represents a memory mapped view address
// in the surrogate process. It is never dereferenced, only used for address arithmetic and
// resource management (unmapping). This is a system resource that is not bound to the creating
// thread and can be safely transferred between threads.
unsafe impl Send for WhpVm {}

impl WhpVm {
    pub(crate) fn new() -> Result<Self, CreateVmError> {
        const NUM_CPU: u32 = 1;

        // Check whether the WHP host supports LAPIC emulation.
        // Bit 1 of WHV_CAPABILITY_FEATURES corresponds to LocalApicEmulation.
        // LAPIC emulation is required for the LAPIC timer to deliver interrupts.
        #[cfg(feature = "hw-interrupts")]
        const LAPIC_EMULATION_BIT: u64 = 1 << 1;

        #[cfg(feature = "hw-interrupts")]
        let mut lapic_emulation = {
            let mut capability: WHV_CAPABILITY = Default::default();
            let ok = unsafe {
                WHvGetCapability(
                    WHvCapabilityCodeFeatures,
                    &mut capability as *mut _ as *mut c_void,
                    std::mem::size_of::<WHV_CAPABILITY>() as u32,
                    None,
                )
            };
            if ok.is_ok() {
                unsafe { capability.Features.AsUINT64 & LAPIC_EMULATION_BIT != 0 }
            } else {
                false
            }
        };

        // Create partition, set CPU count, setup, and create vCPU.
        // When hw-interrupts is enabled and LAPIC emulation is supported,
        // we create a partition with LAPIC emulation mode.  This is
        // required for the LAPIC timer.
        let partition = unsafe {
            #[cfg(feature = "hw-interrupts")]
            {
                if lapic_emulation {
                    let p =
                        WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
                    WHvSetPartitionProperty(
                        p,
                        WHvPartitionPropertyCodeProcessorCount,
                        &NUM_CPU as *const _ as *const _,
                        std::mem::size_of_val(&NUM_CPU) as _,
                    )
                    .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;

                    let apic_mode: u32 = 1; // WHvX64LocalApicEmulationModeXApic
                    let partition_ok = WHvSetPartitionProperty(
                        p,
                        WHvPartitionPropertyCodeLocalApicEmulationMode,
                        &apic_mode as *const _ as *const _,
                        std::mem::size_of_val(&apic_mode) as _,
                    )
                    .is_ok()
                        && WHvSetupPartition(p).is_ok()
                        && WHvCreateVirtualProcessor(p, 0, 0).is_ok();

                    if partition_ok {
                        log::info!("[WHP] LAPIC partition created, running init_lapic_bulk");
                        // Initialize the LAPIC via the bulk interrupt-controller
                        // state API (individual APIC register writes via
                        // WHvSetVirtualProcessorRegisters fail with ACCESS_DENIED).
                        if let Err(e) = Self::init_lapic_bulk(p) {
                            log::warn!(
                                "[WHP] Bulk LAPIC init failed ({e}); \
                                 falling back to non-LAPIC mode."
                            );
                            let _ = WHvDeleteVirtualProcessor(p, 0);
                            let _ = WHvDeletePartition(p);
                            lapic_emulation = false;

                            let p = WHvCreatePartition()
                                .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
                            WHvSetPartitionProperty(
                                p,
                                WHvPartitionPropertyCodeProcessorCount,
                                &NUM_CPU as *const _ as *const _,
                                std::mem::size_of_val(&NUM_CPU) as _,
                            )
                            .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
                            WHvSetupPartition(p)
                                .map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                            WHvCreateVirtualProcessor(p, 0, 0)
                                .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
                            p
                        } else {
                            log::info!("[WHP] Bulk LAPIC init succeeded, lapic_emulation=true");
                            p
                        }
                    } else {
                        log::warn!("LAPIC emulation setup failed, falling back to non-LAPIC mode");
                        let _ = WHvDeleteVirtualProcessor(p, 0);
                        let _ = WHvDeletePartition(p);
                        lapic_emulation = false;

                        let p = WHvCreatePartition()
                            .map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
                        WHvSetPartitionProperty(
                            p,
                            WHvPartitionPropertyCodeProcessorCount,
                            &NUM_CPU as *const _ as *const _,
                            std::mem::size_of_val(&NUM_CPU) as _,
                        )
                        .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
                        WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                        WHvCreateVirtualProcessor(p, 0, 0)
                            .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
                        p
                    }
                } else {
                    let p =
                        WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
                    WHvSetPartitionProperty(
                        p,
                        WHvPartitionPropertyCodeProcessorCount,
                        &NUM_CPU as *const _ as *const _,
                        std::mem::size_of_val(&NUM_CPU) as _,
                    )
                    .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
                    WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                    WHvCreateVirtualProcessor(p, 0, 0)
                        .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
                    p
                }
            }

            #[cfg(not(feature = "hw-interrupts"))]
            {
                let p = WHvCreatePartition().map_err(|e| CreateVmError::CreateVmFd(e.into()))?;
                WHvSetPartitionProperty(
                    p,
                    WHvPartitionPropertyCodeProcessorCount,
                    &NUM_CPU as *const _ as *const _,
                    std::mem::size_of_val(&NUM_CPU) as _,
                )
                .map_err(|e| CreateVmError::SetPartitionProperty(e.into()))?;
                WHvSetupPartition(p).map_err(|e| CreateVmError::InitializeVm(e.into()))?;
                WHvCreateVirtualProcessor(p, 0, 0)
                    .map_err(|e| CreateVmError::CreateVcpuFd(e.into()))?;
                p
            }
        };

        let vm = WhpVm {
            partition,
            surrogate_process: {
                let mgr = get_surrogate_process_manager()
                    .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?;
                mgr.get_surrogate_process()
                    .map_err(|e| CreateVmError::SurrogateProcess(e.to_string()))?
            },
            #[cfg(feature = "hw-interrupts")]
            lapic_emulation,
            #[cfg(feature = "hw-interrupts")]
            lapic_timer_active: false,
            #[cfg(feature = "hw-interrupts")]
            timer_stop: None,
            #[cfg(feature = "hw-interrupts")]
            timer_thread: None,
        };

        Ok(vm)
    }

    /// Maximum size for the interrupt controller state blob.
    const LAPIC_STATE_MAX_SIZE: u32 = 4096;

    /// Initialize the LAPIC via the bulk interrupt-controller state API.
    /// Individual APIC register writes via `WHvSetVirtualProcessorRegisters`
    /// fail with ACCESS_DENIED on WHP when LAPIC emulation is enabled,
    /// so we use `WHvGet/SetVirtualProcessorInterruptControllerState2`
    /// to read-modify-write the entire LAPIC register page.
    #[cfg(feature = "hw-interrupts")]
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
        log::info!(
            "[WHP] init_lapic_bulk: got {} bytes of LAPIC state",
            written
        );

        // SVR (offset 0xF0): enable APIC (bit 8) + spurious vector 0xFF
        Self::write_lapic_u32(&mut state, 0xF0, 0x1FF);
        // TPR (offset 0x80): 0 = accept all interrupt priorities
        Self::write_lapic_u32(&mut state, 0x80, 0);
        // DFR (offset 0xE0): 0xFFFFFFFF = flat model
        Self::write_lapic_u32(&mut state, 0xE0, 0xFFFF_FFFF);
        // LDR (offset 0xD0): set logical APIC ID for flat model
        Self::write_lapic_u32(&mut state, 0xD0, 1 << 24);
        // LINT0 (offset 0x350): masked
        Self::write_lapic_u32(&mut state, 0x350, 0x0001_0000);
        // LINT1 (offset 0x360): NMI delivery, not masked
        Self::write_lapic_u32(&mut state, 0x360, 0x400);
        // LVT Timer (offset 0x320): masked initially (configured on PvTimerConfig)
        Self::write_lapic_u32(&mut state, 0x320, 0x0001_0000);
        // LVT Error (offset 0x370): masked
        Self::write_lapic_u32(&mut state, 0x370, 0x0001_0000);

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

    /// Read a u32 from a LAPIC register page at the given APIC offset.
    #[cfg(feature = "hw-interrupts")]
    fn read_lapic_u32(state: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            state[offset],
            state[offset + 1],
            state[offset + 2],
            state[offset + 3],
        ])
    }

    /// Write a u32 to a LAPIC register page at the given APIC offset.
    #[cfg(feature = "hw-interrupts")]
    fn write_lapic_u32(state: &mut [u8], offset: usize, val: u32) {
        state[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
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
                    let is_write = exit_context
                        .Anonymous
                        .IoPortAccess
                        .AccessInfo
                        .Anonymous
                        ._bitfield
                        & 1
                        != 0;

                    self.set_registers(&[(
                        WHvX64RegisterRip,
                        Align16(WHV_REGISTER_VALUE { Reg64: rip }),
                    )])
                    .map_err(|e| RunVcpuError::IncrementRip(e.into()))?;

                    // OutBAction::Halt always means "I'm done", regardless
                    // of whether a timer is active.
                    if is_write && port == OutBAction::Halt as u16 {
                        return Ok(VmExit::Halt());
                    }

                    #[cfg(feature = "hw-interrupts")]
                    {
                        if is_write {
                            let data = rax.to_le_bytes();
                            if self.handle_hw_io_out(port, &data) {
                                continue;
                            }
                        } else if let Some(val) = self.handle_hw_io_in(port) {
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

                    return Ok(VmExit::IoOut(port, rax.to_le_bytes().to_vec()));
                },
                WHvRunVpExitReasonX64Halt => {
                    // With software timer active, re-enter the guest.
                    // WHvRunVirtualProcessor will block until the timer
                    // thread injects an interrupt via WHvRequestInterrupt,
                    // waking the vCPU from HLT.
                    #[cfg(feature = "hw-interrupts")]
                    if self.lapic_timer_active {
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
                    log::error!(
                        "WHP unknown exit reason {}: RIP={:#x}",
                        exit_context.ExitReason.0,
                        rip,
                    );
                    if let Ok(regs) = self.regs() {
                        log::error!(
                            "  RAX={:#x} RCX={:#x} RDX={:#x}",
                            regs.rax,
                            regs.rcx,
                            regs.rdx
                        );
                    }
                    if let Ok(sregs) = self.sregs() {
                        log::error!(
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

        // When LAPIC emulation is active, skip writing APIC_BASE.
        // The generic CommonSpecialRegisters defaults APIC_BASE to 0
        // which would globally disable the LAPIC.  On some WHP hosts,
        // host-side APIC register writes are blocked entirely
        // (ACCESS_DENIED), so attempting to write even a valid value
        // would fail and abort set_sregs.  Omitting it lets the VP
        // keep its default APIC_BASE and the guest configures it.
        #[cfg(feature = "hw-interrupts")]
        if self.lapic_emulation {
            let filtered: Vec<_> = whp_regs
                .iter()
                .copied()
                .filter(|(name, _)| *name != WHvX64RegisterApicBase)
                .collect();
            self.set_registers(&filtered)
                .map_err(|e| RegisterError::SetSregs(e.into()))?;
            return Ok(());
        }

        self.set_registers(&whp_regs)
            .map_err(|e| RegisterError::SetSregs(e.into()))?;
        Ok(())
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
    #[cfg(feature = "init-paging")]
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
    /// Hardcoded timer interrupt vector.  The nanvix guest always
    /// remaps IRQ0 to vector 0x20 via PIC ICW2, so we use that same
    /// vector directly — no PIC state machine needed.
    const TIMER_VECTOR: u32 = 0x20;

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
            // ISR is at offset 0x100, 8 x 32-bit words (one per 16 bytes).
            // Scan from highest priority (ISR[7]) to lowest (ISR[0]).
            for i in (0u32..8).rev() {
                let offset = 0x100 + (i as usize) * 0x10;
                let isr_val = Self::read_lapic_u32(&state, offset);
                if isr_val != 0 {
                    let bit = 31 - isr_val.leading_zeros();
                    Self::write_lapic_u32(&mut state, offset, isr_val & !(1u32 << bit));
                    let _ = self.set_lapic_state(&state);
                    break;
                }
            }
        }
    }

    /// Handle a hardware-interrupt IO IN request.
    /// Returns `Some(value)` if the port was handled, `None` if the
    /// port should be passed through to the guest handler.
    ///
    /// No PIC state machine — PIC data ports return 0xFF (all masked),
    /// PIC command ports return 0 (no pending IRQ), PIT returns 0.
    fn handle_hw_io_in(&self, port: u16) -> Option<u64> {
        match port {
            // PIC master/slave data ports — return "all masked"
            0x21 | 0xA1 => Some(0xFF),
            // PIC master/slave command ports — return 0 (ISR/IRR read)
            0x20 | 0xA0 => Some(0),
            // PIT data port read — return 0
            0x40 => Some(0),
            _ => None,
        }
    }

    /// Stop the software timer thread if running.
    fn stop_timer_thread(&mut self) {
        if let Some(stop) = self.timer_stop.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.timer_thread.take() {
            let _ = handle.join();
        }
        self.lapic_timer_active = false;
    }

    fn handle_hw_io_out(&mut self, port: u16, data: &[u8]) -> bool {
        if port == OutBAction::PvTimerConfig as u16 {
            if data.len() >= 4 {
                let period_us = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                log::info!(
                    "[WHP] PvTimerConfig: period_us={period_us}, lapic_emulation={}",
                    self.lapic_emulation
                );

                // Stop any existing timer thread before (re-)configuring.
                self.stop_timer_thread();

                if period_us > 0 && self.lapic_emulation {
                    // WHP's bulk LAPIC state API does not start the LAPIC
                    // timer countdown (CurCount stays 0).  Instead we use a
                    // host-side software timer thread that periodically
                    // injects interrupts via WHvRequestInterrupt.
                    let partition_raw = self.partition.0;
                    let vector = Self::TIMER_VECTOR;
                    let stop = Arc::new(AtomicBool::new(false));
                    let stop_clone = stop.clone();
                    let period = std::time::Duration::from_micros(period_us as u64);

                    let handle = std::thread::spawn(move || {
                        while !stop_clone.load(Ordering::Relaxed) {
                            std::thread::sleep(period);
                            if stop_clone.load(Ordering::Relaxed) {
                                break;
                            }
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
                        }
                    });

                    self.timer_stop = Some(stop);
                    self.timer_thread = Some(handle);
                    self.lapic_timer_active = true;
                    log::info!(
                        "[WHP] Software timer started (period={period_us}us, vector={vector:#x})"
                    );
                }
            }
            return true;
        }
        // PIC ports (0x20, 0x21, 0xA0, 0xA1): accept as no-ops.
        // No PIC state machine — we only need LAPIC EOI bridging when
        // the guest sends a non-specific EOI on the master PIC command
        // port (0x20, OCW2 byte with bits 7:5 = 001).
        if port == 0x20 || port == 0x21 || port == 0xA0 || port == 0xA1 {
            if port == 0x20
                && !data.is_empty()
                && (data[0] & 0xE0) == 0x20
                && self.lapic_timer_active
            {
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

impl Drop for WhpVm {
    fn drop(&mut self) {
        // Stop the software timer thread before tearing down the partition.
        #[cfg(feature = "hw-interrupts")]
        self.stop_timer_thread();

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
    fn lapic_register_helpers() {
        let mut state = vec![0u8; 1024];
        WhpVm::write_lapic_u32(&mut state, 0xF0, 0x1FF);
        assert_eq!(WhpVm::read_lapic_u32(&state, 0xF0), 0x1FF);

        WhpVm::write_lapic_u32(&mut state, 0x320, 0x0002_0020);
        assert_eq!(WhpVm::read_lapic_u32(&state, 0x320), 0x0002_0020);
    }

    #[test]
    fn lapic_lvt_timer_periodic() {
        // LVT Timer: vector 0x20, periodic (bit 17), unmasked
        let vector: u32 = 0x20;
        let lvt = vector | (1 << 17);
        assert_eq!(lvt & 0xFF, 0x20, "vector should be 0x20");
        assert_ne!(lvt & (1 << 17), 0, "periodic bit should be set");
        assert_eq!(lvt & (1 << 16), 0, "mask bit should be clear");
    }

    #[test]
    fn lapic_timer_initial_count() {
        // Hyper-V LAPIC timer is 10 MHz with divide-by-1.
        // 1 tick = 100 ns, so period_us * 10 = initial count.
        let period_us: u32 = 1000; // 1 ms
        let initial_count = period_us * 10;
        assert_eq!(initial_count, 10_000, "1ms should be 10000 ticks");

        let period_us: u32 = 100; // 100 us
        let initial_count = period_us * 10;
        assert_eq!(initial_count, 1_000, "100us should be 1000 ticks");
    }

    #[test]
    fn lapic_svr_value() {
        let svr: u64 = 0x1FF;
        assert_ne!(svr & (1 << 8), 0, "APIC should be enabled");
        assert_eq!(svr & 0xFF, 0xFF, "spurious vector should be 0xFF");
    }

    #[test]
    fn apic_base_re_enable_value() {
        // When re-enabling: base 0xFEE00000 + BSP (bit 8) + enable (bit 11)
        let apic_base: u64 = 0xFEE00900;
        assert_ne!(apic_base & (1 << 8), 0, "BSP flag");
        assert_ne!(apic_base & (1 << 11), 0, "global enable");
        assert_eq!(apic_base & 0xFFFFF000, 0xFEE00000, "base address");
    }

    #[test]
    fn lapic_divide_config() {
        // 0x0B = divide-by-1
        let divide: u32 = 0x0B;
        assert_eq!(divide, 0x0B, "divide config should be 0x0B (divide-by-1)");
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
        println!("WHP Features raw: {raw:#018x}");
        println!("WHP LocalApicEmulation supported: {has_lapic}");
        assert!(
            has_lapic,
            "This host does not support WHP LocalApicEmulation. \
             hw-interrupts LAPIC timer tests will be skipped. \
             Windows 11 22H2+ or a recent Windows Server build is typically required."
        );
    }
}
