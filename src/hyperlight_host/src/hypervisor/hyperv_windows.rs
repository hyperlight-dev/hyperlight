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
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::string::String;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use log::LevelFilter;
use tracing::{Span, instrument};
use windows::Win32::System::Hypervisor::{
    WHV_MEMORY_ACCESS_TYPE, WHV_PARTITION_HANDLE, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_RUN_VP_EXIT_REASON, WHV_X64_SEGMENT_REGISTER, WHV_X64_SEGMENT_REGISTER_0,
    WHvCancelRunVirtualProcessor, WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4,
    WHvX64RegisterCs, WHvX64RegisterEfer,
};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

use super::fpu::{FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::surrogate_process::SurrogateProcess;
use super::surrogate_process_manager::*;
use super::windows_hypervisor_platform::{VMPartition, VMProcessor};
use super::wrappers::{HandleWrapper, WHvFPURegisters};
use super::{
    CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE,
    EFER_LMA, EFER_LME, EFER_NX, EFER_SCE, HyperlightExit, Hypervisor, InterruptHandle, VirtualCPU,
};
use crate::hypervisor::fpu::FP_CONTROL_WORD_DEFAULT;
use crate::hypervisor::wrappers::WHvGeneralRegisters;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{Result, debug, new_error};

/// A Hypervisor driver for HyperV-on-Windows.
pub(crate) struct HypervWindowsDriver {
    size: usize, // this is the size of the memory region, excluding the 2 surrounding guard pages
    processor: VMProcessor,
    _surrogate_process: SurrogateProcess, // we need to keep a reference to the SurrogateProcess for the duration of the driver since otherwise it will dropped and the memory mapping will be unmapped and the surrogate process will be returned to the pool
    source_address: *mut c_void,          // this points into the first guard page
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,
    interrupt_handle: Arc<WindowsInterruptHandle>,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
}
/* This does not automatically impl Send/Sync because the host
 * address of the shared memory region is a raw pointer, which are
 * marked as !Send and !Sync. However, the access patterns used
 * here are safe.
 */
unsafe impl Send for HypervWindowsDriver {}
unsafe impl Sync for HypervWindowsDriver {}

impl HypervWindowsDriver {
    #[allow(clippy::too_many_arguments)]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn new(
        mem_regions: Vec<MemoryRegion>,
        raw_size: usize,
        raw_source_address: *mut c_void,
        pml4_address: u64,
        entrypoint: u64,
        rsp: u64,
        mmap_file_handle: HandleWrapper,
        #[cfg(crashdump)] rt_cfg: SandboxRuntimeConfig,
    ) -> Result<Self> {
        // create and setup hypervisor partition
        let mut partition = VMPartition::new(1)?;

        // get a surrogate process with preallocated memory of size SharedMemory::raw_mem_size()
        // with guard pages setup
        let surrogate_process = {
            let mgr = get_surrogate_process_manager()?;
            mgr.get_surrogate_process(raw_size, raw_source_address, mmap_file_handle)
        }?;

        partition.map_gpa_range(&mem_regions, surrogate_process.process_handle)?;

        let mut proc = VMProcessor::new(partition)?;
        Self::setup_initial_sregs(&mut proc, pml4_address)?;
        let partition_handle = proc.get_partition_hdl();

        // subtract 2 pages for the guard pages, since when we copy memory to and from surrogate process,
        // we don't want to copy the guard pages themselves (that would cause access violation)
        let mem_size = raw_size - 2 * PAGE_SIZE_USIZE;
        Ok(Self {
            size: mem_size,
            processor: proc,
            _surrogate_process: surrogate_process,
            source_address: raw_source_address,
            entrypoint,
            orig_rsp: GuestPtr::try_from(RawPtr::from(rsp))?,
            mem_regions,
            interrupt_handle: Arc::new(WindowsInterruptHandle {
                running: AtomicBool::new(false),
                cancel_requested: AtomicBool::new(false),
                partition_handle,
                dropped: AtomicBool::new(false),
            }),
            #[cfg(crashdump)]
            rt_cfg,
        })
    }

    fn setup_initial_sregs(proc: &mut VMProcessor, pml4_addr: u64) -> Result<()> {
        proc.set_registers(&[
            (WHvX64RegisterCr3, WHV_REGISTER_VALUE { Reg64: pml4_addr }),
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
                            Attributes: 0b1011 | (1 << 4) | (1 << 7) | (1 << 13), // Type (11: Execute/Read, accessed) | L (64-bit mode) | P (present) | S (code segment)
                        },
                        ..Default::default() // zero out the rest
                    },
                },
            ),
        ])?;
        Ok(())
    }

    #[inline]
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn get_exit_details(&self, exit_reason: WHV_RUN_VP_EXIT_REASON) -> Result<String> {
        let mut error = String::new();
        error.push_str(&format!(
            "Did not receive a halt from Hypervisor as expected - Received {exit_reason:?}!\n"
        ));
        error.push_str(&format!("Registers: \n{:#?}", self.processor.get_regs()?));
        Ok(error)
    }
}

impl Debug for HypervWindowsDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut fs = f.debug_struct("HyperV Driver");

        fs.field("Size", &self.size)
            .field("Source Address", &self.source_address)
            .field("Entrypoint", &self.entrypoint)
            .field("Original RSP", &self.orig_rsp);

        for region in &self.mem_regions {
            fs.field("Memory Region", &region);
        }

        // Get the registers

        let regs = self.processor.get_regs();

        if let Ok(regs) = regs {
            {
                fs.field("Registers", &regs);
            }
        }

        // Get the special registers

        let special_regs = self.processor.get_sregs();
        if let Ok(special_regs) = special_regs {
            fs.field("CR0", unsafe { &special_regs.cr0.Reg64 });
            fs.field("CR2", unsafe { &special_regs.cr2.Reg64 });
            fs.field("CR3", unsafe { &special_regs.cr3.Reg64 });
            fs.field("CR4", unsafe { &special_regs.cr4.Reg64 });
            fs.field("CR8", unsafe { &special_regs.cr8.Reg64 });
            fs.field("EFER", unsafe { &special_regs.efer.Reg64 });
            fs.field("APIC_BASE", unsafe { &special_regs.apic_base.Reg64 });

            // Segment registers
            fs.field(
                "CS",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.cs.Segment.Base },
                    unsafe { &special_regs.cs.Segment.Limit },
                    unsafe { &special_regs.cs.Segment.Selector },
                    unsafe { &special_regs.cs.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "DS",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.ds.Segment.Base },
                    unsafe { &special_regs.ds.Segment.Limit },
                    unsafe { &special_regs.ds.Segment.Selector },
                    unsafe { &special_regs.ds.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "ES",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.es.Segment.Base },
                    unsafe { &special_regs.es.Segment.Limit },
                    unsafe { &special_regs.es.Segment.Selector },
                    unsafe { &special_regs.es.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "FS",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.fs.Segment.Base },
                    unsafe { &special_regs.fs.Segment.Limit },
                    unsafe { &special_regs.fs.Segment.Selector },
                    unsafe { &special_regs.fs.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "GS",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.gs.Segment.Base },
                    unsafe { &special_regs.gs.Segment.Limit },
                    unsafe { &special_regs.gs.Segment.Selector },
                    unsafe { &special_regs.gs.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "SS",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.ss.Segment.Base },
                    unsafe { &special_regs.ss.Segment.Limit },
                    unsafe { &special_regs.ss.Segment.Selector },
                    unsafe { &special_regs.ss.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "TR",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.tr.Segment.Base },
                    unsafe { &special_regs.tr.Segment.Limit },
                    unsafe { &special_regs.tr.Segment.Selector },
                    unsafe { &special_regs.tr.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "LDTR",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Selector: {:?}, Attributes: {:?} }}",
                    unsafe { &special_regs.ldtr.Segment.Base },
                    unsafe { &special_regs.ldtr.Segment.Limit },
                    unsafe { &special_regs.ldtr.Segment.Selector },
                    unsafe { &special_regs.ldtr.Segment.Anonymous.Attributes }
                ),
            );
            fs.field(
                "GDTR",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Pad: {:?} }}",
                    unsafe { &special_regs.gdtr.Table.Base },
                    unsafe { &special_regs.gdtr.Table.Limit },
                    unsafe { &special_regs.gdtr.Table.Pad }
                ),
            );
            fs.field(
                "IDTR",
                &format_args!(
                    "{{ Base: {:?}, Limit: {:?}, Pad: {:?} }}",
                    unsafe { &special_regs.idtr.Table.Base },
                    unsafe { &special_regs.idtr.Table.Limit },
                    unsafe { &special_regs.idtr.Table.Pad }
                ),
            );
        };

        fs.finish()
    }
}

impl Hypervisor for HypervWindowsDriver {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_address: RawPtr,
        seed: u64,
        page_size: u32,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_hdl: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = WHvGeneralRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rdi: peb_address.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,
            rflags: 1 << 1, // eflags bit index 1 is reserved and always needs to be 1

            ..Default::default()
        };
        self.processor.set_general_purpose_registers(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            outb_hdl,
            mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_hdl,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        #[cfg(gdb)] dbg_mem_access_hdl: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = WHvGeneralRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            rflags: 1 << 1, // eflags bit index 1 is reserved and always needs to be 1
            ..Default::default()
        };
        self.processor.set_general_purpose_registers(&regs)?;

        // reset fpu state
        self.processor.set_fpu(&WHvFPURegisters {
            fp_control_word: FP_CONTROL_WORD_DEFAULT,
            fp_tag_word: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        })?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            outb_hdl,
            mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_hdl,
        )?;

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        rip: u64,
        instruction_length: u64,
        outb_handle_fn: OutBHandlerWrapper,
    ) -> Result<()> {
        let mut padded = [0u8; 4];
        let copy_len = data.len().min(4);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);
        let val = u32::from_le_bytes(padded);

        outb_handle_fn
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .call(port, val)?;

        let mut regs = self.processor.get_regs()?;
        regs.rip = rip + instruction_length;
        self.processor.set_general_purpose_registers(&regs)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<super::HyperlightExit> {
        self.interrupt_handle.running.store(true, Ordering::Relaxed);

        // Don't run the vcpu if `cancel_requested` is true
        let exit_context = if self
            .interrupt_handle
            .cancel_requested
            .load(Ordering::Relaxed)
        {
            WHV_RUN_VP_EXIT_CONTEXT {
                ExitReason: WHV_RUN_VP_EXIT_REASON(8193i32), // WHvRunVpExitReasonCanceled
                VpContext: Default::default(),
                Anonymous: Default::default(),
                Reserved: Default::default(),
            }
        } else {
            self.processor.run()?
        };
        self.interrupt_handle
            .cancel_requested
            .store(false, Ordering::Relaxed);
        self.interrupt_handle
            .running
            .store(false, Ordering::Relaxed);

        let result = match exit_context.ExitReason {
            // WHvRunVpExitReasonX64IoPortAccess
            WHV_RUN_VP_EXIT_REASON(2i32) => {
                // size of current instruction is in lower byte of _bitfield
                // see https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvexitcontextdatatypes)
                let instruction_length = exit_context.VpContext._bitfield & 0xF;
                unsafe {
                    debug!(
                        "HyperV IO Details :\n Port: {:#x} \n {:#?}",
                        exit_context.Anonymous.IoPortAccess.PortNumber, &self
                    );
                    HyperlightExit::IoOut(
                        exit_context.Anonymous.IoPortAccess.PortNumber,
                        exit_context
                            .Anonymous
                            .IoPortAccess
                            .Rax
                            .to_le_bytes()
                            .to_vec(),
                        exit_context.VpContext.Rip,
                        instruction_length as u64,
                    )
                }
            }
            // HvRunVpExitReasonX64Halt
            WHV_RUN_VP_EXIT_REASON(8i32) => {
                debug!("HyperV Halt Details :\n {:#?}", &self);
                HyperlightExit::Halt()
            }
            // WHvRunVpExitReasonMemoryAccess
            WHV_RUN_VP_EXIT_REASON(1i32) => {
                let gpa = unsafe { exit_context.Anonymous.MemoryAccess.Gpa };
                let access_info = unsafe {
                    WHV_MEMORY_ACCESS_TYPE(
                        // 2 first bits are the access type, see https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/memoryaccess#syntax
                        (exit_context.Anonymous.MemoryAccess.AccessInfo.AsUINT32 & 0b11) as i32,
                    )
                };
                let access_info = MemoryRegionFlags::try_from(access_info)?;
                debug!(
                    "HyperV Memory Access Details :\n GPA: {:#?}\n Access Info :{:#?}\n {:#?} ",
                    gpa, access_info, &self
                );

                match self.get_memory_access_violation(gpa as usize, &self.mem_regions, access_info)
                {
                    Some(access_info) => access_info,
                    None => HyperlightExit::Mmio(gpa),
                }
            }
            //  WHvRunVpExitReasonCanceled
            //  Execution was cancelled by the host.
            //  This will happen when guest code runs for too long
            WHV_RUN_VP_EXIT_REASON(8193i32) => {
                debug!("HyperV Cancelled Details :\n {:#?}", &self);
                HyperlightExit::Cancelled()
            }
            WHV_RUN_VP_EXIT_REASON(_) => {
                debug!(
                    "HyperV Unexpected Exit Details :#nReason {:#?}\n {:#?}",
                    exit_context.ExitReason, &self
                );
                match self.get_exit_details(exit_context.ExitReason) {
                    Ok(error) => HyperlightExit::Unknown(error),
                    Err(e) => HyperlightExit::Unknown(format!("Error getting exit details: {}", e)),
                }
            }
        };

        Ok(result)
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<crashdump::CrashDumpContext>> {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.processor.get_regs()?;
            let sregs = self.processor.get_sregs()?;
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
            regs[17] = unsafe { sregs.cs.Segment.Selector } as u64; // cs
            regs[18] = vcpu_regs.rflags; // eflags
            regs[19] = vcpu_regs.rsp; // rsp
            regs[20] = unsafe { sregs.ss.Segment.Selector } as u64; // ss
            regs[21] = unsafe { sregs.fs.Segment.Base }; // fs_base
            regs[22] = unsafe { sregs.gs.Segment.Base }; // gs_base
            regs[23] = unsafe { sregs.ds.Segment.Selector } as u64; // ds
            regs[24] = unsafe { sregs.es.Segment.Selector } as u64; // es
            regs[25] = unsafe { sregs.fs.Segment.Selector } as u64; // fs
            regs[26] = unsafe { sregs.gs.Segment.Selector } as u64; // gs

            // Get the filename from the config
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            Ok(Some(crashdump::CrashDumpContext::new(
                &self.mem_regions,
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
}

impl Drop for HypervWindowsDriver {
    fn drop(&mut self) {
        self.interrupt_handle.dropped.store(true, Ordering::Relaxed);
    }
}

pub struct WindowsInterruptHandle {
    // `WHvCancelRunVirtualProcessor()` will return Ok even if the vcpu is not running, which is the reason we need this flag.
    running: AtomicBool,
    cancel_requested: AtomicBool,
    partition_handle: WHV_PARTITION_HANDLE,
    dropped: AtomicBool,
}

impl InterruptHandle for WindowsInterruptHandle {
    fn kill(&self) -> bool {
        self.cancel_requested.store(true, Ordering::Relaxed);
        self.running.load(Ordering::Relaxed)
            && unsafe { WHvCancelRunVirtualProcessor(self.partition_handle, 0, 0).is_ok() }
    }

    fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }
}
