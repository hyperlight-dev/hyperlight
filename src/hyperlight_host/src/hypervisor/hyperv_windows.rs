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

use std::os::raw::c_void;

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use windows::core::s;
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows_result::HRESULT;

#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::wrappers::HandleWrapper;
use super::{
    HyperlightExit, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR,
    CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::regs::{CommonFpu, CommonRegisters, CommonSpecialRegisters};
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::get_surrogate_process_manager;
use crate::hypervisor::vm::Vm;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::{new_error, Result};

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

/// A Hypervisor driver for HyperV-on-Windows.
#[derive(Debug)]
pub(crate) struct WhpVm {
    partition: WHV_PARTITION_HANDLE,
    // Lazily create the surrogate process when we need to map memory
    surrogate_process: Option<SurrogateProcess>,
    mmap_file_handle: HandleWrapper,
}

unsafe impl Send for WhpVm {}
unsafe impl Sync for WhpVm {}

impl WhpVm {
    pub(crate) fn new(mmap_file_handle: HandleWrapper) -> Result<Self> {
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

        Ok(WhpVm {
            partition,
            surrogate_process: None,
            mmap_file_handle,
        })
    }

    /// Helper for setting arbitrary registers
    fn set_registers(&self, registers: &[(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)]) -> Result<()> {
        let register_count = registers.len();
        let mut register_names: Vec<WHV_REGISTER_NAME> = vec![];
        let mut register_values: Vec<WHV_REGISTER_VALUE> = vec![];

        for (key, value) in registers.iter() {
            register_names.push(*key);
            register_values.push(*value);
        }

        unsafe {
            WHvSetVirtualProcessorRegisters(
                self.partition,
                0,
                register_names.as_ptr(),
                register_count as u32,
                register_values.as_ptr(),
            )
            .unwrap();
        }

        Ok(())
    }
}

impl Vm for WhpVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
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
                self.partition,
                0,
                names.as_ptr(),
                LEN as u32,
                out.as_mut_ptr(),
            )
            .unwrap();
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

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let whp_regs: Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)> = regs.into();
        self.set_registers(&whp_regs)?;
        Ok(())
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
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
                self.partition,
                0,
                names.as_ptr(),
                out.len() as u32,
                out.as_mut_ptr(),
            )
            .unwrap();
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

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        // self.processor.set_sregs(sregs).unwrap();
        self.set_registers(&[
            (WHvX64RegisterCr3, WHV_REGISTER_VALUE { Reg64: sregs.cr3 }),
            (
                WHvX64RegisterCr4,
                WHV_REGISTER_VALUE {
                    Reg64: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
                },
            ),
            (
                WHvX64RegisterCr0,
                WHV_REGISTER_VALUE {
                    Reg64: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
                },
            ),
            (
                WHvX64RegisterEfer,
                WHV_REGISTER_VALUE {
                    Reg64: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
                },
            ),
            (
                WHvX64RegisterCs,
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER {
                        Anonymous: WHV_X64_SEGMENT_REGISTER_0 {
                            Attributes: 0b1011 | 1 << 4 | 1 << 7 | 1 << 13, // Type (11: Execute/Read, accessed) | L (64-bit mode) | P (present) | S (code segment)
                        },
                        ..Default::default() // zero out the rest
                    },
                },
            ),
        ])?;
        Ok(())
    }

    fn get_fpu(&self) -> Result<CommonFpu> {
        todo!()
    }

    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()> {
        let whp_fpu: Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)> = fpu.into();
        self.set_registers(&whp_fpu)?;
        Ok(())
    }

    unsafe fn map_memory(&mut self, regions: &[MemoryRegion]) -> Result<()> {
        if regions.is_empty() {
            return Err(new_error!("No memory regions to map"));
        }
        if self.surrogate_process.is_some() {
            return Err(new_error!("Memory has already been mapped"));
        }

        let size: usize = regions.iter().map(|r| r.host_region.len()).sum();
        let raw_size = size + 2 * PAGE_SIZE_USIZE;
        let raw_source_address = regions[0].host_region.start - PAGE_SIZE_USIZE;

        // get a surrogate process with preallocated memory of size SharedMemory::raw_mem_size()
        // with guard pages setup
        let surrogate_process = {
            let mgr = get_surrogate_process_manager()?;
            mgr.get_surrogate_process(
                raw_size,
                raw_source_address as *const c_void,
                self.mmap_file_handle,
            )
        }?;

        let process_handle: HANDLE = surrogate_process.process_handle.into();
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
                self.partition,
                process_handle,
                region.host_region.start as *const c_void,
                region.guest_region.start as u64,
                region.guest_region.len() as u64,
                flags,
            );
            if res.is_err() {
                return Err(new_error!("Call to WHvMapGpaRange2 failed"));
            }
            Ok(())
        })?;

        self.surrogate_process = Some(surrogate_process);

        Ok(())
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
                self.set_registers(&[(WHvX64RegisterRip, WHV_REGISTER_VALUE { Reg64: rip })])?;
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
                let rip = exit_context.VpContext.Rip;
                println!("MemoryAccess: gpa: {:#x}", gpa);
                println!("MemoryAccess: rip: {:#x}", rip);
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
            //  Execution was cancelled by the host.
            //  This will happen when guest code runs for too long
            WHvRunVpExitReasonCanceled => HyperlightExit::Cancelled(),
            WHV_RUN_VP_EXIT_REASON(_) => HyperlightExit::Unknown(format!(
                "Unknown exit reason '{}'",
                exit_context.ExitReason.0
            )),
        };
        Ok(result)
    }

    fn get_partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.partition
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        if let Err(e) = unsafe { WHvDeletePartition(self.partition) } {
            log::error!("Failed to delete partition: {}", e);
        }
    }
}

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
