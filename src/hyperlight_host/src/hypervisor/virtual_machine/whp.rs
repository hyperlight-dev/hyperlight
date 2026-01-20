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

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows::core::s;
use windows_result::HRESULT;

#[cfg(gdb)]
use crate::hypervisor::gdb::DebuggableVm;
use crate::hypervisor::regs::{
    Align16, CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
    WHP_DEBUG_REGS_NAMES, WHP_DEBUG_REGS_NAMES_LEN, WHP_FPU_NAMES, WHP_FPU_NAMES_LEN,
    WHP_REGS_NAMES, WHP_REGS_NAMES_LEN, WHP_SREGS_NAMES, WHP_SREGS_NAMES_LEN,
};
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::get_surrogate_process_manager;
use crate::hypervisor::virtual_machine::{VirtualMachine, VmExit};
use crate::hypervisor::wrappers::HandleWrapper;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{Result, log_then_return, new_error};

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
            log::info!("Windows Hypervisor Platform is not available on this system");
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
    // Offset between surrogate process and host process addresses (accounting for guard page)
    // Calculated lazily on first map_memory call
    surrogate_offset: Option<isize>,
    // Track if initial memory setup is complete.
    // Used to reject later memory mapping since it's not supported  on windows.
    // TODO remove this flag once memory mapping is supported on windows.
    initial_memory_setup_done: bool,
}

// Safety: `WhpVm` is !Send because it holds `SurrogateProcess` which contains a raw pointer
// `allocated_address` (*mut c_void). This pointer represents a memory mapped view address
// in the surrogate process. It is never dereferenced, only used for address arithmetic and
// resource management (unmapping). This is a system resource that is not bound to the creating
// thread and can be safely transferred between threads.
unsafe impl Send for WhpVm {}

impl WhpVm {
    pub(crate) fn new(mmap_file_handle: HandleWrapper, raw_size: usize) -> Result<Self> {
        const NUM_CPU: u32 = 1;
        let partition = unsafe {
            let partition = WHvCreatePartition()?;
            WHvSetPartitionProperty(
                partition,
                WHvPartitionPropertyCodeProcessorCount,
                &NUM_CPU as *const _ as *const _,
                std::mem::size_of_val(&NUM_CPU) as _,
            )?;
            WHvSetupPartition(partition)?;
            WHvCreateVirtualProcessor(partition, 0, 0)?;
            partition
        };

        // Create the surrogate process with the total memory size
        let mgr = get_surrogate_process_manager()?;
        let surrogate_process = mgr.get_surrogate_process(raw_size, mmap_file_handle)?;

        Ok(WhpVm {
            partition,
            surrogate_process,
            surrogate_offset: None,
            initial_memory_setup_done: false,
        })
    }

    /// Helper for setting arbitrary registers. Makes sure the same number
    /// of names and values are passed (at the expense of some performance).
    fn set_registers(
        &self,
        registers: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> Result<()> {
        let (names, values): (Vec<_>, Vec<_>) = registers.iter().copied().unzip();

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                names.as_ptr(),
                names.len() as u32,
                values.as_ptr() as *const WHV_REGISTER_VALUE, // Casting Align16 away
            )?;
        }

        Ok(())
    }
}

impl VirtualMachine for WhpVm {
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
    fn run_vcpu(&mut self) -> Result<VmExit> {
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
                VmExit::IoOut(
                    exit_context.Anonymous.IoPortAccess.PortNumber,
                    exit_context
                        .Anonymous
                        .IoPortAccess
                        .Rax
                        .to_le_bytes()
                        .to_vec(),
                )
            },
            WHvRunVpExitReasonX64Halt => VmExit::Halt(),
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
                    MemoryRegionFlags::READ => VmExit::MmioRead(gpa),
                    MemoryRegionFlags::WRITE => VmExit::MmioWrite(gpa),
                    _ => VmExit::Unknown("Unknown memory access type".to_string()),
                }
            }
            // Execution was cancelled by the host.
            WHvRunVpExitReasonCanceled => VmExit::Cancelled(),
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

                VmExit::Debug {
                    dr6,
                    exception: exception.ExceptionType as u32,
                }
            }
            WHV_RUN_VP_EXIT_REASON(_) => VmExit::Unknown(format!(
                "Unknown exit reason '{}'",
                exit_context.ExitReason.0
            )),
        };
        Ok(result)
    }

    fn regs(&self) -> Result<CommonRegisters> {
        let mut whv_regs_values: [Align16<WHV_REGISTER_VALUE>; WHP_REGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_REGS_NAMES.as_ptr(),
                whv_regs_values.len() as u32,
                whv_regs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        WHP_REGS_NAMES
            .into_iter()
            .zip(whv_regs_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                new_error!(
                    "Failed to convert WHP registers to CommonRegisters: {:?}",
                    e
                )
            })
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            regs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    fn fpu(&self) -> Result<CommonFpu> {
        let mut whp_fpu_values: [Align16<WHV_REGISTER_VALUE>; WHP_FPU_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_FPU_NAMES.as_ptr(),
                whp_fpu_values.len() as u32,
                whp_fpu_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        WHP_FPU_NAMES
            .into_iter()
            .zip(whp_fpu_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| new_error!("Failed to convert WHP registers to CommonFpu: {:?}", e))
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        let whp_fpu: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_FPU_NAMES_LEN] =
            fpu.into();
        self.set_registers(&whp_fpu)?;
        Ok(())
    }

    fn sregs(&self) -> Result<CommonSpecialRegisters> {
        let mut whp_sregs_values: [Align16<WHV_REGISTER_VALUE>; WHP_SREGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_SREGS_NAMES.as_ptr(),
                whp_sregs_values.len() as u32,
                whp_sregs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        WHP_SREGS_NAMES
            .into_iter()
            .zip(whp_sregs_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                new_error!(
                    "Failed to convert WHP registers to CommonSpecialRegisters: {:?}",
                    e
                )
            })
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            sregs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    fn debug_regs(&self) -> Result<CommonDebugRegs> {
        let mut whp_debug_regs_values: [Align16<WHV_REGISTER_VALUE>; WHP_DEBUG_REGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.partition,
                0,
                WHP_DEBUG_REGS_NAMES.as_ptr(),
                whp_debug_regs_values.len() as u32,
                whp_debug_regs_values.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
        }

        WHP_DEBUG_REGS_NAMES
            .into_iter()
            .zip(whp_debug_regs_values)
            .collect::<Vec<(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)>>()
            .as_slice()
            .try_into()
            .map_err(|e| {
                new_error!(
                    "Failed to convert WHP registers to CommonDebugRegs: {:?}",
                    e
                )
            })
    }

    fn set_debug_regs(&self, drs: &CommonDebugRegs) -> Result<()> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_DEBUG_REGS_NAMES_LEN] =
            drs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    #[cfg(crashdump)]
    fn xsave(&self) -> Result<Vec<u8>> {
        use crate::HyperlightError;

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
            return Err(HyperlightError::WindowsAPIError(e));
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
        }?;

        // Verify the number of written bytes matches the expected size
        if written_bytes != buffer_size_needed {
            return Err(new_error!(
                "Failed to get Xsave state: expected {} bytes, got {}",
                buffer_size_needed,
                written_bytes
            ));
        }

        Ok(xsave_buffer)
    }

    /// Mark that initial memory setup is complete. After this, map_memory will fail.
    fn complete_initial_memory_setup(&mut self) {
        self.initial_memory_setup_done = true;
    }

    /// Get the partition handle for this VM
    fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.partition
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
        let mut regs = self.debug_regs()?;

        // Check if breakpoint already exists
        if [regs.dr0, regs.dr1, regs.dr2, regs.dr3].contains(&addr) {
            return Ok(());
        }

        // Find the first available LOCAL (L0–L3) slot
        let i = (0..MAX_NO_OF_HW_BP)
            .position(|i| regs.dr7 & (1 << (i * 2)) == 0)
            .ok_or_else(|| new_error!("Tried to add more than 4 hardware breakpoints"))?;

        // Assign to corresponding debug register
        *[&mut regs.dr0, &mut regs.dr1, &mut regs.dr2, &mut regs.dr3][i] = addr;

        // Enable LOCAL bit
        regs.dr7 |= 1 << (i * 2);

        self.set_debug_regs(&regs)?;
        Ok(())
    }

    fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<()> {
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
            Err(new_error!("Tried to remove non-existing hw-breakpoint"))
        }
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        // HyperlightVm::drop() calls set_dropped() before this runs.
        // set_dropped() ensures no WHvCancelRunVirtualProcessor calls are in progress
        // or will be made in the future, so it's safe to delete the partition.
        // (HyperlightVm::drop() runs before its fields are dropped, so
        // set_dropped() completes before this Drop impl runs.)
        if let Err(e) = unsafe { WHvDeletePartition(self.partition) } {
            log::error!("Failed to delete partition: {}", e);
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

unsafe fn try_load_whv_map_gpa_range2() -> Result<WHvMapGpaRange2Func> {
    let library = unsafe {
        LoadLibraryExA(
            s!("winhvplatform.dll"),
            None,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };

    if let Err(e) = library {
        return Err(new_error!("{}", e));
    }

    #[allow(clippy::unwrap_used)]
    // We know this will succeed because we just checked for an error above
    let library = library.unwrap();

    let address = unsafe { GetProcAddress(library, s!("WHvMapGpaRange2")) };

    if address.is_none() {
        unsafe { FreeLibrary(library)? };
        return Err(new_error!(
            "Failed to find WHvMapGpaRange2 in winhvplatform.dll"
        ));
    }

    unsafe { Ok(std::mem::transmute_copy(&address)) }
}
