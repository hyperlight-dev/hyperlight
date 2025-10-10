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

use core::ffi::c_void;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use tracing::{Span, instrument};
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows::core::s;
use windows_result::HRESULT;

use super::regs::{
    Align16, CommonFpu, CommonRegisters, CommonSpecialRegisters, WHP_FPU_NAMES_LEN, WHP_REGS_NAMES,
    WHP_REGS_NAMES_LEN, WHP_SREGS_NAMES, WHP_SREGS_NAMES_LEN,
};
use super::surrogate_process::SurrogateProcess;
#[cfg(crashdump)]
use crate::HyperlightError;
use crate::hypervisor::regs::WHP_FPU_NAMES;
#[cfg(gdb)]
use crate::hypervisor::wrappers::WHvDebugRegisters;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{Result, new_error};

/// Interop calls for Windows Hypervisor Platform APIs
///
/// Documentation can be found at:
/// - https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform
/// - https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Hypervisor/index.html
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
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

#[derive(Debug)]
pub(super) struct VMPartition(WHV_PARTITION_HANDLE);

impl VMPartition {
    /// This is the position of the extended vm exit in partition property
    #[cfg(gdb)]
    const EXTENDED_VM_EXIT_POS: u32 = 2;

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(proc_count: u32) -> Result<Self> {
        let hdl = unsafe { WHvCreatePartition() }?;
        Self::set_processor_count(&hdl, proc_count)?;
        #[cfg(gdb)]
        Self::set_extended_vm_exits(&hdl)?;
        unsafe { WHvSetupPartition(hdl) }?;
        Ok(Self(hdl))
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn set_processor_count(
        partition_handle: &WHV_PARTITION_HANDLE,
        processor_count: u32,
    ) -> Result<()> {
        unsafe {
            WHvSetPartitionProperty(
                *partition_handle,
                WHvPartitionPropertyCodeProcessorCount,
                &processor_count as *const u32 as *const c_void,
                std::mem::size_of_val(&processor_count) as u32,
            )?;
        }

        Ok(())
    }

    /// Sets up the debugging exception interception for the partition
    /// This is needed for a HyperV partition to be able to intercept debug traps and breakpoints
    /// Steps:
    /// - set the extended VM exits property to enable extended VM exits
    /// - set the exception exit bitmap to include debug trap and breakpoint trap
    #[cfg(gdb)]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_extended_vm_exits(partition_handle: &WHV_PARTITION_HANDLE) -> Result<()> {
        let mut property: WHV_PARTITION_PROPERTY = Default::default();

        // Set the extended VM exits property
        property.ExtendedVmExits.AsUINT64 = 1 << Self::EXTENDED_VM_EXIT_POS;
        Self::set_property(
            partition_handle,
            WHvPartitionPropertyCodeExtendedVmExits,
            &property,
        )?;

        // Set the exception exit bitmap to include debug trap and breakpoint trap
        property = Default::default();
        property.ExceptionExitBitmap = (1 << WHvX64ExceptionTypeDebugTrapOrFault.0)
            | (1 << WHvX64ExceptionTypeBreakpointTrap.0);
        Self::set_property(
            partition_handle,
            WHvPartitionPropertyCodeExceptionExitBitmap,
            &property,
        )?;

        Ok(())
    }

    /// Helper function to set partition properties
    #[cfg(gdb)]
    fn set_property(
        partition_handle: &WHV_PARTITION_HANDLE,
        property_code: WHV_PARTITION_PROPERTY_CODE,
        property: &WHV_PARTITION_PROPERTY,
    ) -> Result<()> {
        unsafe {
            WHvSetPartitionProperty(
                *partition_handle,
                property_code,
                property as *const _ as *const c_void,
                std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )?;
        }

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn map_gpa_range(
        &mut self,
        regions: &[MemoryRegion],
        surrogate_process: &SurrogateProcess,
    ) -> Result<()> {
        let process_handle: HANDLE = surrogate_process.process_handle.into();
        // this is the address in the surrogate process where shared memory starts.
        // We add page-size because we don't care about the first guard page
        let surrogate_address = surrogate_process.allocated_address as usize + PAGE_SIZE_USIZE;
        if regions.is_empty() {
            return Err(new_error!("No memory regions to map"));
        }
        // this is the address in the main process where the shared memory starts
        let host_address = regions[0].host_region.start;

        // offset between the surrogate process and the host process address of start of shared memory
        let offset = isize::try_from(surrogate_address)? - isize::try_from(host_address)?;

        // The function pointer to WHvMapGpaRange2 is resolved dynamically to allow us to detect
        // when we are running on older versions of windows that do not support this API and
        // return a more informative error message, rather than failing with an error about a missing entrypoint
        let whvmapgparange2_func = unsafe {
            match try_load_whv_map_gpa_range2() {
                Ok(func) => func,
                Err(e) => return Err(new_error!("Can't find API: {}", e)),
            }
        };

        regions.iter().try_for_each(|region| unsafe {
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
                .fold(WHvMapGpaRangeFlagNone, |acc, flag| acc | *flag); // collect using bitwise OR

            let res = whvmapgparange2_func(
                self.0,
                process_handle,
                (isize::try_from(region.host_region.start)? + offset) as *const c_void,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            );
            if res.is_err() {
                return Err(new_error!("Call to WHvMapGpaRange2 failed"));
            }
            Ok(())
        })?;
        Ok(())
    }
}

// This function dynamically loads the WHvMapGpaRange2 function from the winhvplatform.dll
// WHvMapGpaRange2 only available on Windows 11 or Windows Server 2022 and later
// we do things this way to allow a user trying to load hyperlight on an older version of windows to
// get an error message saying that hyperlight requires a newer version of windows, rather than just failing
// with an error about a missing entrypoint
// This function should always succeed since before we get here we have already checked that the hypervisor is present and
// that we are on a supported version of windows.
type WHvMapGpaRange2Func = unsafe extern "system" fn(
    WHV_PARTITION_HANDLE,
    HANDLE,
    *const c_void,
    u64,
    u64,
    WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT;

pub unsafe fn try_load_whv_map_gpa_range2() -> Result<WHvMapGpaRange2Func> {
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

impl Drop for VMPartition {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        if let Err(e) = unsafe { WHvDeletePartition(self.0) } {
            tracing::error!(
                "Failed to delete partition (WHvDeletePartition failed): {:?}",
                e
            );
        }
    }
}

#[derive(Debug)]
pub(crate) struct VMProcessor(VMPartition);
impl VMProcessor {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(part: VMPartition) -> Result<Self> {
        unsafe { WHvCreateVirtualProcessor(part.0, 0, 0) }?;
        Ok(Self(part))
    }

    /// This function is used to translate a guest virtual address to a guest physical address
    #[cfg(gdb)]
    pub(super) fn translate_gva(&self, gva: u64) -> Result<u64> {
        let partition_handle = self.get_partition_hdl();
        let mut gpa = 0;
        let mut result = WHV_TRANSLATE_GVA_RESULT::default();

        // Only validate read access because the write access is handled through the
        // host memory mapping
        let translateflags = WHvTranslateGvaFlagValidateRead;

        unsafe {
            WHvTranslateGva(
                partition_handle,
                0,
                gva,
                translateflags,
                &mut result,
                &mut gpa,
            )?;
        }

        Ok(gpa)
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_partition_hdl(&self) -> WHV_PARTITION_HANDLE {
        let part = &self.0;
        part.0
    }

    /// Helper for setting arbitrary registers.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn set_registers(
        &self,
        registers: &[(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>)],
    ) -> Result<()> {
        let register_count = registers.len();

        let mut register_names = Vec::with_capacity(register_count);
        let mut register_values = Vec::with_capacity(register_count);

        for (key, value) in registers.iter() {
            register_names.push(*key);
            register_values.push(*value);
        }

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.get_partition_hdl(),
                0,
                register_names.as_ptr(),
                register_count as u32,
                register_values.as_ptr() as *const WHV_REGISTER_VALUE,
            )?;
        }

        Ok(())
    }

    pub(super) fn regs(&self) -> Result<CommonRegisters> {
        let mut whv_regs_values: [Align16<WHV_REGISTER_VALUE>; WHP_REGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.get_partition_hdl(),
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

    pub(super) fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_REGS_NAMES_LEN] =
            regs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    pub(super) fn sregs(&self) -> Result<CommonSpecialRegisters> {
        let mut whp_sregs_values: [Align16<WHV_REGISTER_VALUE>; WHP_SREGS_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.get_partition_hdl(),
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

    pub(super) fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        let whp_regs: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_SREGS_NAMES_LEN] =
            sregs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    pub(super) fn fpu(&self) -> Result<CommonFpu> {
        let mut whp_fpu_values: [Align16<WHV_REGISTER_VALUE>; WHP_FPU_NAMES_LEN] =
            unsafe { std::mem::zeroed() };

        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.get_partition_hdl(),
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

    pub(super) fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        let whp_fpu: [(WHV_REGISTER_NAME, Align16<WHV_REGISTER_VALUE>); WHP_FPU_NAMES_LEN] =
            fpu.into();
        self.set_registers(&whp_fpu)?;
        Ok(())
    }

    #[cfg(crashdump)]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_xsave(&self) -> Result<Vec<u8>> {
        // Get the required buffer size by calling with NULL buffer
        let mut buffer_size_needed: u32 = 0;

        unsafe {
            // First call with NULL buffer to get required size
            // If the buffer is not large enough, the return value is WHV_E_INSUFFICIENT_BUFFER.
            // In this case, BytesWritten receives the required buffer size.
            let result = WHvGetVirtualProcessorXsaveState(
                self.get_partition_hdl(),
                0,
                std::ptr::null_mut(),
                0,
                &mut buffer_size_needed,
            );

            // If it failed for reasons other than insufficient buffer, return error
            if let Err(e) = result
                && e.code() != windows::Win32::Foundation::WHV_E_INSUFFICIENT_BUFFER
            {
                return Err(HyperlightError::WindowsAPIError(e));
            }
        }

        // Create a buffer with the appropriate size
        let mut xsave_buffer = vec![0; buffer_size_needed as usize];

        // Get the Xsave state
        let mut written_bytes = 0;
        unsafe {
            WHvGetVirtualProcessorXsaveState(
                self.get_partition_hdl(),
                0,
                xsave_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size_needed,
                &mut written_bytes,
            )
        }?;

        // Check if the number of written bytes matches the expected size
        if written_bytes != buffer_size_needed {
            return Err(new_error!(
                "Failed to get Xsave state: expected {} bytes, got {}",
                buffer_size_needed,
                written_bytes
            ));
        }

        Ok(xsave_buffer)
    }

    #[cfg(gdb)]
    pub(super) fn set_debug_regs(&self, regs: &WHvDebugRegisters) -> Result<()> {
        let registers = vec![
            (
                WHvX64RegisterDr0,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr0 }),
            ),
            (
                WHvX64RegisterDr1,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr1 }),
            ),
            (
                WHvX64RegisterDr2,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr2 }),
            ),
            (
                WHvX64RegisterDr3,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr3 }),
            ),
            (
                WHvX64RegisterDr6,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr6 }),
            ),
            (
                WHvX64RegisterDr7,
                Align16(WHV_REGISTER_VALUE { Reg64: regs.dr7 }),
            ),
        ];

        self.set_registers(&registers)
    }

    #[cfg(gdb)]
    pub(super) fn get_debug_regs(&self) -> Result<WHvDebugRegisters> {
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
                self.get_partition_hdl(),
                0,
                names.as_ptr(),
                LEN as u32,
                out.as_mut_ptr() as *mut WHV_REGISTER_VALUE,
            )?;
            Ok(WHvDebugRegisters {
                dr0: out[0].0.Reg64,
                dr1: out[1].0.Reg64,
                dr2: out[2].0.Reg64,
                dr3: out[3].0.Reg64,
                dr6: out[4].0.Reg64,
                dr7: out[5].0.Reg64,
            })
        }
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn run(&mut self) -> Result<WHV_RUN_VP_EXIT_CONTEXT> {
        let partition_handle = self.get_partition_hdl();
        let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT = Default::default();

        unsafe {
            WHvRunVirtualProcessor(
                partition_handle,
                0,
                &mut exit_context as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )?;
        }

        Ok(exit_context)
    }
}

impl Drop for VMProcessor {
    #[instrument(parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        let part_hdl = self.get_partition_hdl();
        if let Err(e) = unsafe { WHvDeleteVirtualProcessor(part_hdl, 0) } {
            tracing::error!(
                "Failed to delete virtual processor (WHvDeleteVirtualProcessor failed): {:?}",
                e
            );
        }
    }
}
