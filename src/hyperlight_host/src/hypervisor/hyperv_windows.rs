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

use std::fmt;
use std::fmt::{Debug, Formatter};
use std::string::String;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{Span, instrument};
#[cfg(feature = "trace_guest")]
use tracing_opentelemetry::OpenTelemetrySpanExt;
use windows::Win32::System::Hypervisor::{WHV_MEMORY_ACCESS_TYPE, WHV_RUN_VP_EXIT_REASON};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};
#[cfg(gdb)]
use {
    super::gdb::{
        DebugCommChannel, DebugMemoryAccess, DebugMsg, DebugResponse, GuestDebug, HypervDebug,
        VcpuStopReason,
    },
    crate::HyperlightError,
};

use super::regs::CommonSpecialRegisters;
use super::surrogate_process::SurrogateProcess;
use super::surrogate_process_manager::*;
use super::windows_hypervisor_platform::{VMPartition, VMProcessor};
use super::wrappers::HandleWrapper;
use super::{HyperlightExit, Hypervisor, InterruptHandle, VirtualCPU};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters};
use crate::hypervisor::{InterruptHandleImpl, WindowsInterruptHandle, get_memory_access_violation};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
#[cfg(gdb)]
use crate::new_error;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::outb::handle_outb;
#[cfg(feature = "mem_profile")]
use crate::sandbox::trace::MemTraceInfo;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{Result, debug, log_then_return};

/// A Windows Hypervisor Platform implementation of a single-vcpu VM
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    // Surrogate process for memory mapping
    surrogate_process: SurrogateProcess,
    // Offset between surrogate process and host process addresses (accounting for guard page)
    // Calculated lazily on first map_memory call
    surrogate_offset: Option<isize>,
    // Track if initial memory setup is complete.
    // Used to reject later memory mapping since it's not supported  on windows.
    // TODO remove this flag once memory mapping is supported on windows.
    initial_memory_setup_done: bool,
}
/* This does not automatically impl Send because the host
 * address of the shared memory region is a raw pointer, which are
 * marked as !Send (and !Sync). However, the access patterns used
 * here are safe.
 */
unsafe impl Send for HypervWindowsDriver {}

impl HypervWindowsDriver {
    #[allow(clippy::too_many_arguments)]
    // TODO: refactor this function to take fewer arguments. Add trace_info to rt_cfg
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        raw_size: usize,
        pml4_address: u64,
        entrypoint: u64,
        rsp: u64,
        mmap_file_handle: HandleWrapper,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
        #[cfg(feature = "mem_profile")] trace_info: MemTraceInfo,
    ) -> Result<Self> {
        // create and setup hypervisor partition
        let mut partition = VMPartition::new(1)?;

        // get a surrogate process with preallocated memory of size SharedMemory::raw_mem_size()
        // with guard pages setup
        let surrogate_process = {
            let mgr = get_surrogate_process_manager()?;
            mgr.get_surrogate_process(raw_size, mmap_file_handle)
        }?;

        partition.map_gpa_range(&mem_regions, &surrogate_process)?;

        let proc = VMProcessor::new(partition)?;
        let partition_handle = proc.get_partition_hdl();

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            let mut debug = HypervDebug::new();
            debug.add_hw_breakpoint(&proc, entrypoint)?;

            (Some(debug), Some(gdb_conn))
        } else {
            (None, None)
        };

        let interrupt_handle = Arc::new(WindowsInterruptHandle {
            state: AtomicU8::new(0),
            partition_handle,
            dropped: AtomicBool::new(false),
        });

        let mut hv = Self {
            processor: proc,
            _surrogate_process: surrogate_process,
            entrypoint,
            orig_rsp: GuestPtr::try_from(RawPtr::from(rsp))?,
            interrupt_handle: interrupt_handle.clone(),
            sandbox_regions: mem_regions,
            mmap_regions: Vec::new(),
            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            #[cfg(crashdump)]
            rt_cfg,
            #[cfg(feature = "mem_profile")]
            trace_info,
        };

        hv.setup_initial_sregs(pml4_address)?;

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if hv.debug.is_some() {
            hv.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(hv)
    }

    #[inline]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn get_exit_details(&self, exit_reason: WHV_RUN_VP_EXIT_REASON) -> Result<String> {
        let mut error = String::new();
        error.push_str(&format!(
            "Did not receive a halt from Hypervisor as expected - Received {exit_reason:?}!\n"
        ));
        error.push_str(&format!("Registers: \n{:#?}", self.processor.regs()?));
        Ok(error)
    }
}

impl Debug for HypervWindowsDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut fs = f.debug_struct("HyperV Driver");

        fs.field("Entrypoint", &self.entrypoint)
            .field("Original RSP", &self.orig_rsp);

        for region in &self.sandbox_regions {
            fs.field("Sandbox Memory Region", &region);
        }
        for region in &self.mmap_regions {
            fs.field("Mapped Memory Region", &region);
        }

        // Get the registers
        if let Ok(regs) = self.processor.regs() {
            fs.field("Registers", &regs);
        }

        // Get the special registers
        if let Ok(special_regs) = self.processor.sregs() {
            fs.field("SpecialRegisters", &special_regs);
        }

        fs.finish()
    }
}

impl Hypervisor for HypervWindowsDriver {
    unsafe fn map_memory(&mut self, (_slot, region): (u32, &MemoryRegion)) -> Result<()> {
        // Only allow memory mapping during initial setup (the first batch of regions).
        // After the initial setup is complete, subsequent calls should fail,
        // since it's not yet implemented.
        if self.initial_memory_setup_done {
            // Initial setup already completed - reject this mapping
            log_then_return!(
                "Mapping host memory into the guest not yet supported on this platform"
            );
        }

        // Calculate the offset on first call. The offset accounts for the guard page
        // at the start of the surrogate process memory.
        let offset = if let Some(offset) = self.surrogate_offset {
            offset
        } else {
            // surrogate_address points to the start of the guard page, so add PAGE_SIZE
            // to get to the actual shared memory start
            let surrogate_address =
                self.surrogate_process.allocated_address as usize + PAGE_SIZE_USIZE;
            let host_address = region.host_region.start;
            let offset = isize::try_from(surrogate_address)? - isize::try_from(host_address)?;
            self.surrogate_offset = Some(offset);
            offset
        };

        let process_handle: HANDLE = self.surrogate_process.process_handle.into();

        let whvmapgparange2_func = unsafe {
            match try_load_whv_map_gpa_range2() {
                Ok(func) => func,
                Err(e) => return Err(new_error!("Can't find API: {}", e)),
            }
        };

        let flags = region
            .flags
            .iter()
            .map(|flag| match flag {
                MemoryRegionFlags::NONE => Ok(WHvMapGpaRangeFlagNone),
                MemoryRegionFlags::READ => Ok(WHvMapGpaRangeFlagRead),
                MemoryRegionFlags::WRITE => Ok(WHvMapGpaRangeFlagWrite),
                MemoryRegionFlags::EXECUTE => Ok(WHvMapGpaRangeFlagExecute),
                MemoryRegionFlags::STACK_GUARD => Ok(WHvMapGpaRangeFlagNone),
                _ => Err(new_error!("Invalid Memory Region Flag")),
            })
            .collect::<Result<Vec<WHV_MAP_GPA_RANGE_FLAGS>>>()?
            .iter()
            .fold(WHvMapGpaRangeFlagNone, |acc, flag| acc | *flag);

        // Calculate the surrogate process address for this region
        let surrogate_addr = (isize::try_from(region.host_region.start)? + offset) as *const c_void;

        let res = unsafe {
            whvmapgparange2_func(
                self.partition,
                process_handle,
                surrogate_addr,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            )
        };
        if res.is_err() {
            return Err(new_error!("Call to WHvMapGpaRange2 failed"));
        }

        Ok(())
    }

    fn unmap_memory(&mut self, (_slot, _region): (u32, &MemoryRegion)) -> Result<()> {
        log_then_return!("Mapping host memory into the guest not yet supported on this platform");
    }

    #[expect(non_upper_case_globals, reason = "Windows API constant are lower case")]
    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = Default::default();

        unsafe {
            WHvRunVirtualProcessor(
                self.partition,
                0,
                &mut exit_context as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )?;
        }

        let result = match exit_context.ExitReason {
            WHvRunVpExitReasonX64IoPortAccess => unsafe {
                let instruction_length = exit_context.VpContext._bitfield & 0xF;
                let rip = exit_context.VpContext.Rip + instruction_length as u64;
                self.set_registers(&[(
                    WHvX64RegisterRip,
                    Align16(WHV_REGISTER_VALUE { Reg64: rip }),
                )])?;
                HyperlightExit::IoOut(
                    exit_context.Anonymous.IoPortAccess.PortNumber,
                    exit_context
                        .Anonymous
                        .IoPortAccess
                        .Rax
                        .to_le_bytes()
                        .to_vec(),
                )
            },
            WHvRunVpExitReasonX64Halt => HyperlightExit::Halt(),
            WHvRunVpExitReasonMemoryAccess => {
                let gpa = unsafe { exit_context.Anonymous.MemoryAccess.Gpa };
                let access_info = unsafe {
                    WHV_MEMORY_ACCESS_TYPE(
                        // 2 first bits are the access type, see https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/memoryaccess#syntax
                        (exit_context.Anonymous.MemoryAccess.AccessInfo.AsUINT32 & 0b11) as i32,
                    )
                };
                let access_info = MemoryRegionFlags::try_from(access_info)?;
                match access_info {
                    MemoryRegionFlags::READ => HyperlightExit::MmioRead(gpa),
                    MemoryRegionFlags::WRITE => HyperlightExit::MmioWrite(gpa),
                    _ => HyperlightExit::Unknown("Unknown memory access type".to_string()),
                }
            }
            // Execution was cancelled by the host.
            WHvRunVpExitReasonCanceled => HyperlightExit::Cancelled(),
            #[cfg(gdb)]
            WHvRunVpExitReasonException => {
                let exception = unsafe { exit_context.Anonymous.VpException };

                // Get the DR6 register to see which breakpoint was hit
                let dr6 = {
                    let names = [WHvX64RegisterDr6];
                    let mut out: [Align16<WHV_REGISTER_VALUE>; 1] = unsafe { std::mem::zeroed() };
                    unsafe {
                        WHvGetVirtualProcessorRegisters(
                            self.partition,
                            0,
                            names.as_ptr(),
                            1,
                            out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
                        )?;
                    }
                    unsafe { out[0].0.Reg64 }
                };

                HyperlightExit::Debug {
                    dr6,
                    exception: exception.ExceptionType as u32,
                }
            }
            WHV_RUN_VP_EXIT_REASON(_) => HyperlightExit::Unknown(format!(
                "Unknown exit reason '{}'",
                exit_context.ExitReason.0
            )),
        };
        Ok(result)
    }

    /// Get regs
    #[allow(dead_code)]
    fn regs(&self) -> Result<CommonRegisters> {
        self.processor.regs()
    }
    /// Set regs
    fn set_regs(&mut self, regs: &CommonRegisters) -> Result<()> {
        self.processor.set_regs(regs)
    }
    /// Get fpu regs
    #[allow(dead_code)]
    fn fpu(&self) -> Result<CommonFpu> {
        self.processor.fpu()
    }
    /// Set fpu regs
    fn set_fpu(&mut self, fpu: &CommonFpu) -> Result<()> {
        self.processor.set_fpu(fpu)
    }
    /// Get special regs
    #[allow(dead_code)]
    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        self.processor.sregs()
    }
    /// Set special regs
    #[allow(dead_code)]
    fn set_sregs(&mut self, sregs: &CommonSpecialRegisters) -> Result<()> {
        self.processor.set_sregs(sregs)
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    fn clear_cancel(&self) {
        self.interrupt_handle.clear_cancel();
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>> {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.processor.regs()?;
            let sregs = self.processor.sregs()?;
            let xsave = self.processor.get_xsave()?;

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

            // Get the filename from the config
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            // Include both initial sandbox regions and dynamically mapped regions
            let mut regions: Vec<MemoryRegion> = self.sandbox_regions.clone();
            regions.extend(self.mmap_regions.iter().cloned());
            Ok(Some(crashdump::CrashDumpContext::new(
                regions,
                regs,
                xsave,
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

#[cfg(gdb)]
impl DebuggableVm for WhpVm {
    fn translate_gva(&self, gva: u64) -> Result<u64> {
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
            )?;
        }

        Ok(gpa)
    }

    fn set_debug(&mut self, enable: bool) -> Result<()> {
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
                )?;
            }
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

        // Get current debug registers
        const LEN: usize = 6;
        let names: [WHV_REGISTER_NAME; LEN] = [
            WHvX64RegisterDr0,
            WHvX64RegisterDr1,
            WHvX64RegisterDr2,
            WHvX64RegisterDr3,
            WHvX64RegisterDr6,
            WHvX64RegisterDr7,
        ];

        let mut out: [Align16<WHV_REGISTER_VALUE>; LEN] = unsafe { std::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                LEN as u32,
                out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        let mut dr0 = unsafe { out[0].0.Reg64 };
        let mut dr1 = unsafe { out[1].0.Reg64 };
        let mut dr2 = unsafe { out[2].0.Reg64 };
        let mut dr3 = unsafe { out[3].0.Reg64 };
        let mut dr7 = unsafe { out[5].0.Reg64 };

        // Check if breakpoint already exists
        if [dr0, dr1, dr2, dr3].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| dr7 & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        *[&mut dr0, &mut dr1, &mut dr2, &mut dr3][i] = addr;

        // Enable LOCAL bit
        dr7 |= 1 << (i * 2);

        // Set the debug registers
        let registers = vec![
            (
                WHvX64RegisterDr0,
                Align16(WHV_REGISTER_VALUE { Reg64: dr0 }),
            ),
            (
                WHvX64RegisterDr1,
                Align16(WHV_REGISTER_VALUE { Reg64: dr1 }),
            ),
            (
                WHvX64RegisterDr2,
                Align16(WHV_REGISTER_VALUE { Reg64: dr2 }),
            ),
            (
                WHvX64RegisterDr3,
                Align16(WHV_REGISTER_VALUE { Reg64: dr3 }),
            ),
            (
                WHvX64RegisterDr7,
                Align16(WHV_REGISTER_VALUE { Reg64: dr7 }),
            ),
        ];
        self.set_registers(&registers)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
        // Get current debug registers
        const LEN: usize = 6;
        let names: [WHV_REGISTER_NAME; LEN] = [
            WHvX64RegisterDr0,
            WHvX64RegisterDr1,
            WHvX64RegisterDr2,
            WHvX64RegisterDr3,
            WHvX64RegisterDr6,
            WHvX64RegisterDr7,
        ];

        let mut out: [Align16<WHV_REGISTER_VALUE>; LEN] = unsafe { std::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                LEN as u32,
                out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        let mut dr0 = unsafe { out[0].0.Reg64 };
        let mut dr1 = unsafe { out[1].0.Reg64 };
        let mut dr2 = unsafe { out[2].0.Reg64 };
        let mut dr3 = unsafe { out[3].0.Reg64 };
        let mut dr7 = unsafe { out[5].0.Reg64 };

        let regs = [&mut dr0, &mut dr1, &mut dr2, &mut dr3];

        if let Some(i) = regs.iter().position(|&&mut reg| reg == addr) {
            // Clear the address
            *regs[i] = 0;
            // Disable LOCAL bit
            dr7 &= !(1 << (i * 2));

            // Set the debug registers
            let registers = vec![
                (
                    WHvX64RegisterDr0,
                    Align16(WHV_REGISTER_VALUE { Reg64: dr0 }),
                ),
                (
                    WHvX64RegisterDr1,
                    Align16(WHV_REGISTER_VALUE { Reg64: dr1 }),
                ),
                (
                    WHvX64RegisterDr2,
                    Align16(WHV_REGISTER_VALUE { Reg64: dr2 }),
                ),
                (
                    WHvX64RegisterDr3,
                    Align16(WHV_REGISTER_VALUE { Reg64: dr3 }),
                ),
                (
                    WHvX64RegisterDr7,
                    Align16(WHV_REGISTER_VALUE { Reg64: dr7 }),
                ),
            ];
            self.set_registers(&registers)?;
            Ok(())
        } else {
            Err(new_error!("Tried to remove non-existing hw-breakpoint"))
        }
    }
}

impl Drop for HypervWindowsDriver {
    fn drop(&mut self) {
        self.interrupt_handle.set_dropped();
    }
}
