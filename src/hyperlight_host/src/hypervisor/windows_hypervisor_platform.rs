/*
Copyright 2024 The Hyperlight Authors.

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

use tracing::{instrument, Span};
use windows::core::s;
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows_result::HRESULT;

use super::regs::{CommonFpu, CommonRegisters};
use super::wrappers::HandleWrapper;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{new_error, Result};

// We need to pass in a primitive array of register names/values
// to WHvSetVirtualProcessorRegisters and rust needs to know array size
// at compile time. There is an assert in set_virtual_process_registers
// to ensure we never try and set more registers than this constant
const REGISTER_COUNT: usize = 16;

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
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(proc_count: u32) -> Result<Self> {
        let hdl = unsafe { WHvCreatePartition() }?;
        Self::set_processor_count(&hdl, proc_count)?;
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

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn map_gpa_range(
        &mut self,
        regions: &[MemoryRegion],
        process_handle: HandleWrapper,
    ) -> Result<()> {
        let process_handle: HANDLE = process_handle.into();
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
                region.host_region.start as *const c_void,
                region.guest_region.start as u64,
                (region.guest_region.end - region.guest_region.start) as u64,
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
type WHvMapGpaRange2Func = unsafe extern "cdecl" fn(
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
pub(super) struct VMProcessor(pub(super) VMPartition);
impl VMProcessor {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn new(part: VMPartition) -> Result<Self> {
        unsafe { WHvCreateVirtualProcessor(part.0, 0, 0) }?;
        Ok(Self(part))
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_partition_hdl(&self) -> WHV_PARTITION_HANDLE {
        let part = &self.0;
        part.0
    }

    pub(super) fn get_regs(&self) -> Result<CommonRegisters> {
        const LEN: usize = 18;

        let names: [WHV_REGISTER_NAME; LEN] = [
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
            WHvX64RegisterRsi,
            WHvX64RegisterRdi,
            WHvX64RegisterRsp,
            WHvX64RegisterRbp,
            WHvX64RegisterR8,
            WHvX64RegisterR9,
            WHvX64RegisterR10,
            WHvX64RegisterR11,
            WHvX64RegisterR12,
            WHvX64RegisterR13,
            WHvX64RegisterR14,
            WHvX64RegisterR15,
            WHvX64RegisterRip,
            WHvX64RegisterRflags,
        ];

        let mut out: [WHV_REGISTER_VALUE; LEN] = unsafe { std::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.get_partition_hdl(),
                0,
                names.as_ptr(),
                LEN as u32,
                out.as_mut_ptr(),
            )?;
            Ok(CommonRegisters {
                rax: out[0].Reg64,
                rbx: out[1].Reg64,
                rcx: out[2].Reg64,
                rdx: out[3].Reg64,
                rsi: out[4].Reg64,
                rdi: out[5].Reg64,
                rsp: out[6].Reg64,
                rbp: out[7].Reg64,
                r8: out[8].Reg64,
                r9: out[9].Reg64,
                r10: out[10].Reg64,
                r11: out[11].Reg64,
                r12: out[12].Reg64,
                r13: out[13].Reg64,
                r14: out[14].Reg64,
                r15: out[15].Reg64,
                rip: out[16].Reg64,
                rflags: out[17].Reg64,
            })
        }
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        const LEN: usize = 17;

        let names: [WHV_REGISTER_NAME; LEN] = [
            WHvX64RegisterCs,
            WHvX64RegisterDs,
            WHvX64RegisterEs,
            WHvX64RegisterFs,
            WHvX64RegisterGs,
            WHvX64RegisterSs,
            WHvX64RegisterTr,
            WHvX64RegisterLdtr,
            WHvX64RegisterGdtr,
            WHvX64RegisterIdtr,
            WHvX64RegisterCr0,
            WHvX64RegisterCr2,
            WHvX64RegisterCr3,
            WHvX64RegisterCr4,
            WHvX64RegisterCr8,
            WHvX64RegisterEfer,
            WHvX64RegisterApicBase,
        ];

        let mut out: [WHV_REGISTER_VALUE; LEN] = unsafe { std::mem::zeroed() };
        unsafe {
            WHvGetVirtualProcessorRegisters(
                self.get_partition_hdl(),
                0,
                names.as_ptr(),
                out.len() as u32,
                out.as_mut_ptr(),
            )?;
        }

        let result = unsafe {
            CommonSpecialRegisters {
                cs: out[0].into(),
                ds: out[1].into(),
                es: out[2].into(),
                fs: out[3].into(),
                gs: out[4].into(),
                ss: out[5].into(),
                tr: out[6].into(),
                ldt: out[7].into(),
                gdt: out[8].into(),
                idt: out[9].into(),
                cr0: out[10].Reg64,
                cr2: out[11].Reg64,
                cr3: out[12].Reg64,
                cr4: out[13].Reg64,
                cr8: out[14].Reg64,
                efer: out[15].Reg64,
                apic_base: out[16].Reg64,
                interrupt_bitmap: Default::default(), // TODO: I'm not sure how to get this at the moment
            }
        };

        Ok(result)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub(super) fn set_registers(
        &self,
        registers: &[(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)],
    ) -> Result<()> {
        let partition_handle = self.get_partition_hdl();
        let register_count = registers.len();
        let mut register_names: Vec<WHV_REGISTER_NAME> = vec![];
        let mut register_values: Vec<WHV_REGISTER_VALUE> = vec![];

        for (key, value) in registers.iter() {
            register_names.push(*key);
            register_values.push(*value);
        }

        unsafe {
            WHvSetVirtualProcessorRegisters(
                partition_handle,
                0,
                register_names.as_ptr(),
                register_count as u32,
                register_values.as_ptr(),
            )?;
        }

        Ok(())
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
