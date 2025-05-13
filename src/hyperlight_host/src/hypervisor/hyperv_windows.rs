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

use crate::hypervisor::regs::CommonFpu;
use crate::hypervisor::surrogate_process::SurrogateProcess;
use crate::hypervisor::surrogate_process_manager::get_surrogate_process_manager;
use crate::hypervisor::vm::Vm;
use crate::mem::memory_region::MemoryRegionFlags;
use crate::new_error;

use super::{
    HyperlightExit, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR,
    CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};

#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::windows_hypervisor_platform::VMPartition;
use super::windows_hypervisor_platform::VMProcessor;
use super::wrappers::HandleWrapper;
use crate::hypervisor::regs::CommonRegisters;
use crate::hypervisor::regs::CommonSpecialRegisters;
use crate::hypervisor::regs::{FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
use crate::mem::memory_region::MemoryRegion;
use crate::Result;
use hyperlight_common::mem::PAGE_SIZE_USIZE;
use windows::core::s;
use windows::Win32::Foundation::{FreeLibrary, HANDLE};
use windows::Win32::System::Hypervisor::*;
use windows::Win32::System::LibraryLoader::*;
use windows_result::HRESULT;

/// A Hypervisor driver for HyperV-on-Windows.
#[derive(Debug)]
pub(crate) struct WhpVm {
    processor: VMProcessor,
    surrogate_process: Option<SurrogateProcess>,
    mmap_file_handle: HandleWrapper,
}

unsafe impl Send for WhpVm {}
unsafe impl Sync for WhpVm {}

impl WhpVm {
    pub(crate) fn new(mmap_file_handle: HandleWrapper) -> Result<Self> {
        let partition = VMPartition::new(1)?;
        let processor = VMProcessor::new(partition)?;

        Ok(WhpVm {
            processor,
            surrogate_process: None,
            mmap_file_handle,
        })
    }
}

impl Vm for WhpVm {
    fn get_regs(&self) -> Result<CommonRegisters> {
        self.processor.get_regs()
    }

    fn set_regs(&self, regs: &CommonRegisters) -> Result<()> {
        let regs_array: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); 18] = [
            (WHvX64RegisterRax, WHV_REGISTER_VALUE { Reg64: regs.rax }),
            (WHvX64RegisterRbx, WHV_REGISTER_VALUE { Reg64: regs.rbx }),
            (WHvX64RegisterRcx, WHV_REGISTER_VALUE { Reg64: regs.rcx }),
            (WHvX64RegisterRdx, WHV_REGISTER_VALUE { Reg64: regs.rdx }),
            (WHvX64RegisterRsi, WHV_REGISTER_VALUE { Reg64: regs.rsi }),
            (WHvX64RegisterRdi, WHV_REGISTER_VALUE { Reg64: regs.rdi }),
            (WHvX64RegisterRsp, WHV_REGISTER_VALUE { Reg64: regs.rsp }),
            (WHvX64RegisterRbp, WHV_REGISTER_VALUE { Reg64: regs.rbp }),
            (WHvX64RegisterR8, WHV_REGISTER_VALUE { Reg64: regs.r8 }),
            (WHvX64RegisterR9, WHV_REGISTER_VALUE { Reg64: regs.r9 }),
            (WHvX64RegisterR10, WHV_REGISTER_VALUE { Reg64: regs.r10 }),
            (WHvX64RegisterR11, WHV_REGISTER_VALUE { Reg64: regs.r11 }),
            (WHvX64RegisterR12, WHV_REGISTER_VALUE { Reg64: regs.r12 }),
            (WHvX64RegisterR13, WHV_REGISTER_VALUE { Reg64: regs.r13 }),
            (WHvX64RegisterR14, WHV_REGISTER_VALUE { Reg64: regs.r14 }),
            (WHvX64RegisterR15, WHV_REGISTER_VALUE { Reg64: regs.r15 }),
            (WHvX64RegisterRip, WHV_REGISTER_VALUE { Reg64: regs.rip }),
            (
                WHvX64RegisterRflags,
                WHV_REGISTER_VALUE { Reg64: regs.rflags },
            ),
        ];

        self.processor.set_registers(&regs_array)?;
        Ok(())
    }

    fn get_sregs(&self) -> Result<CommonSpecialRegisters> {
        self.processor.get_sregs()
    }

    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()> {
        // self.processor.set_sregs(sregs).unwrap();
        self.processor.set_registers(&[
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
        self.processor.set_registers(&whp_fpu)?;
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

        self.processor
            .0
            .map_gpa_range(regions, surrogate_process.process_handle)?;
        self.surrogate_process = Some(surrogate_process);
        Ok(())
    }

    fn run_vcpu(&mut self) -> Result<HyperlightExit> {
        let exit_context: WHV_RUN_VP_EXIT_CONTEXT = self.processor.run()?;

        let result = match exit_context.ExitReason {
            // WHvRunVpExitReasonX64IoPortAccess
            WHV_RUN_VP_EXIT_REASON(2i32) => unsafe {
                let instruction_length = exit_context.VpContext._bitfield & 0xF;
                let rip = exit_context.VpContext.Rip + instruction_length as u64;
                self.processor
                    .set_registers(&[(WHvX64RegisterRip, WHV_REGISTER_VALUE { Reg64: rip })])?;
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
            // HvRunVpExitReasonX64Halt
            WHV_RUN_VP_EXIT_REASON(8i32) => HyperlightExit::Halt(),
            // WHvRunVpExitReasonMemoryAccess
            WHV_RUN_VP_EXIT_REASON(1i32) => {
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
            //  WHvRunVpExitReasonCanceled
            //  Execution was cancelled by the host.
            //  This will happen when guest code runs for too long
            WHV_RUN_VP_EXIT_REASON(8193i32) => HyperlightExit::Cancelled(),
            WHV_RUN_VP_EXIT_REASON(_) => HyperlightExit::Unknown(format!(
                "Unknown exit reason '{}'",
                exit_context.ExitReason.0
            )),
        };
        Ok(result)
    }

    fn get_partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.processor.get_partition_hdl()
    }
}
