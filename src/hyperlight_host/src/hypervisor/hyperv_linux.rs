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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use log::{LevelFilter, error};
#[cfg(mshv2)]
use mshv_bindings::hv_message;
use mshv_bindings::{
    FloatingPointUnit, SegmentRegister, SpecialRegisters, StandardRegisters, hv_message_type,
    hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_user_mem_region,
};
#[cfg(gdb)]
use mshv_bindings::{
    HV_INTERCEPT_ACCESS_MASK_EXECUTE, hv_intercept_parameters,
    hv_intercept_type_HV_INTERCEPT_TYPE_EXCEPTION, hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT,
    mshv_install_intercept,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
#[cfg(feature = "trace_guest")]
use mshv_bindings::{
    hv_register_name, hv_register_name_HV_X64_REGISTER_RAX, hv_register_name_HV_X64_REGISTER_RBP,
    hv_register_name_HV_X64_REGISTER_RCX, hv_register_name_HV_X64_REGISTER_RSP,
};
use mshv_ioctls::{Mshv, MshvError, VcpuFd, VmFd};
use tracing::{Span, instrument};
#[cfg(crashdump)]
use {super::crashdump, std::path::Path};

#[cfg(feature = "trace_guest")]
use super::TraceRegister;
use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{
    DebugCommChannel, DebugMsg, DebugResponse, GuestDebug, MshvDebug, VcpuStopReason,
};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
#[cfg(feature = "init-paging")]
use super::{
    CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE,
    EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use super::{HyperlightExit, Hypervisor, InterruptHandle, LinuxInterruptHandle, VirtualCPU};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::hypervisor::get_memory_access_violation;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::mem::shared_mem::HostSharedMemory;
use crate::sandbox::SandboxConfiguration;
#[cfg(feature = "trace_guest")]
use crate::sandbox::TraceInfo;
use crate::sandbox::host_funcs::FunctionRegistry;
use crate::sandbox::mem_mgr::MemMgrWrapper;
use crate::sandbox::outb::handle_outb;
#[cfg(crashdump)]
use crate::sandbox::uninitialized::SandboxRuntimeConfig;
use crate::{Result, log_then_return, new_error};

#[cfg(gdb)]
mod debug {
    use std::sync::{Arc, Mutex};

    use super::mshv_bindings::hv_x64_exception_intercept_message;
    use super::{HypervLinuxDriver, *};
    use crate::hypervisor::gdb::{DebugMsg, DebugResponse, VcpuStopReason, X86_64Regs};
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::{Result, new_error};

    impl HypervLinuxDriver {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            let mut debug = MshvDebug::default();

            debug.set_single_step(&self.vcpu_fd, false)?;

            self.debug = Some(debug);

            Ok(())
        }

        /// Get the reason the vCPU has stopped
        pub(crate) fn get_stop_reason(
            &mut self,
            ex_info: hv_x64_exception_intercept_message,
        ) -> Result<VcpuStopReason> {
            let debug = self
                .debug
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            debug.get_stop_reason(&self.vcpu_fd, ex_info.exception_vector, self.entrypoint)
        }

        pub(crate) fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<DebugResponse> {
            if let Some(debug) = self.debug.as_mut() {
                match req {
                    DebugMsg::AddHwBreakpoint(addr) => Ok(DebugResponse::AddHwBreakpoint(
                        debug
                            .add_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to add hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::AddSwBreakpoint(addr) => Ok(DebugResponse::AddSwBreakpoint(
                        debug
                            .add_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to add sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Continue => {
                        debug.set_single_step(&self.vcpu_fd, false).map_err(|e| {
                            log::error!("Failed to continue execution: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Continue)
                    }
                    DebugMsg::DisableDebug => {
                        self.disable_debug().map_err(|e| {
                            log::error!("Failed to disable debugging: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::DisableDebug)
                    }
                    DebugMsg::GetCodeSectionOffset => {
                        let offset = dbg_mem_access_fn
                            .try_lock()
                            .map_err(|e| {
                                new_error!("Error locking at {}:{}: {}", file!(), line!(), e)
                            })?
                            .get_code_offset()
                            .map_err(|e| {
                                log::error!("Failed to get code offset: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                    }
                    DebugMsg::ReadAddr(addr, len) => {
                        let mut data = vec![0u8; len];

                        debug
                            .read_addrs(&self.vcpu_fd, addr, &mut data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to read from address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::ReadAddr(data))
                    }
                    DebugMsg::ReadRegisters => {
                        let mut regs = X86_64Regs::default();

                        debug
                            .read_regs(&self.vcpu_fd, &mut regs)
                            .map_err(|e| {
                                log::error!("Failed to read registers: {:?}", e);

                                e
                            })
                            .map(|_| DebugResponse::ReadRegisters(regs))
                    }
                    DebugMsg::RemoveHwBreakpoint(addr) => Ok(DebugResponse::RemoveHwBreakpoint(
                        debug
                            .remove_hw_breakpoint(&self.vcpu_fd, addr)
                            .map_err(|e| {
                                log::error!("Failed to remove hw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::RemoveSwBreakpoint(addr) => Ok(DebugResponse::RemoveSwBreakpoint(
                        debug
                            .remove_sw_breakpoint(&self.vcpu_fd, addr, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to remove sw breakpoint: {:?}", e);

                                e
                            })
                            .is_ok(),
                    )),
                    DebugMsg::Step => {
                        debug.set_single_step(&self.vcpu_fd, true).map_err(|e| {
                            log::error!("Failed to enable step instruction: {:?}", e);

                            e
                        })?;

                        Ok(DebugResponse::Step)
                    }
                    DebugMsg::WriteAddr(addr, data) => {
                        debug
                            .write_addrs(&self.vcpu_fd, addr, &data, dbg_mem_access_fn)
                            .map_err(|e| {
                                log::error!("Failed to write to address: {:?}", e);

                                e
                            })?;

                        Ok(DebugResponse::WriteAddr)
                    }
                    DebugMsg::WriteRegisters(regs) => debug
                        .write_regs(&self.vcpu_fd, &regs)
                        .map_err(|e| {
                            log::error!("Failed to write registers: {:?}", e);

                            e
                        })
                        .map(|_| DebugResponse::WriteRegisters),
                }
            } else {
                Err(new_error!("Debugging is not enabled"))
            }
        }

        pub(crate) fn recv_dbg_msg(&mut self) -> Result<DebugMsg> {
            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.recv().map_err(|e| {
                new_error!(
                    "Got an error while waiting to receive a
                    message: {:?}",
                    e
                )
            })
        }

        pub(crate) fn send_dbg_msg(&mut self, cmd: DebugResponse) -> Result<()> {
            log::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn
                .send(cmd)
                .map_err(|e| new_error!("Got an error while sending a response message {:?}", e))
        }
    }
}

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

/// A Hypervisor driver for HyperV-on-Linux. This hypervisor is often
/// called the Microsoft Hypervisor (MSHV)
pub(crate) struct HypervLinuxDriver {
    _mshv: Mshv,
    page_size: usize,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    orig_rsp: GuestPtr,
    entrypoint: u64,
    interrupt_handle: Arc<LinuxInterruptHandle>,
    mem_mgr: Option<MemMgrWrapper<HostSharedMemory>>,
    host_funcs: Option<Arc<Mutex<FunctionRegistry>>>,

    sandbox_regions: Vec<MemoryRegion>, // Initially mapped regions when sandbox is created
    mmap_regions: Vec<MemoryRegion>,    // Later mapped regions

    #[cfg(gdb)]
    debug: Option<MshvDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    #[cfg(crashdump)]
    rt_cfg: SandboxRuntimeConfig,
    #[cfg(feature = "trace_guest")]
    #[allow(dead_code)]
    trace_info: TraceInfo,
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
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
    ) -> Result<Self> {
        let mshv = Mshv::new()?;
        let pr = Default::default();
        #[cfg(mshv2)]
        let vm_fd = mshv.create_vm_with_config(&pr)?;
        #[cfg(mshv3)]
        let vm_fd = {
            // It's important to avoid create_vm() and explicitly use
            // create_vm_with_args() with an empty arguments structure
            // here, because otherwise the partition is set up with a SynIC.

            let vm_fd = mshv.create_vm_with_args(&pr)?;
            let features: hv_partition_synthetic_processor_features = Default::default();
            vm_fd.hvcall_set_partition_property(
                hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
                unsafe { features.as_uint64[0] },
            )?;
            vm_fd.initialize()?;
            vm_fd
        };

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;

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

        Self::setup_initial_sregs(&mut vcpu_fd, pml4_ptr.absolute()?)?;

        let interrupt_handle = Arc::new(LinuxInterruptHandle {
            running: AtomicU64::new(0),
            cancel_requested: AtomicBool::new(false),
            #[cfg(gdb)]
            debug_interrupt: AtomicBool::new(false),
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

        #[allow(unused_mut)]
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
            mem_mgr: None,
            host_funcs: None,
            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
            #[cfg(crashdump)]
            rt_cfg,
            #[cfg(feature = "trace_guest")]
            trace_info,
        };

        // Send the interrupt handle to the GDB thread if debugging is enabled
        // This is used to allow the GDB thread to stop the vCPU
        #[cfg(gdb)]
        if hv.debug.is_some() {
            hv.send_dbg_msg(DebugResponse::InterruptHandle(interrupt_handle))?;
        }

        Ok(hv)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu: &mut VcpuFd, _pml4_addr: u64) -> Result<()> {
        #[cfg(feature = "init-paging")]
        let sregs = SpecialRegisters {
            cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
            cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
            cr3: _pml4_addr,
            efer: EFER_LME | EFER_LMA | EFER_SCE | EFER_NX,
            cs: SegmentRegister {
                type_: 11,
                present: 1,
                s: 1,
                l: 1,
                ..Default::default()
            },
            tr: SegmentRegister {
                limit: 65535,
                type_: 11,
                present: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        #[cfg(not(feature = "init-paging"))]
        let sregs = SpecialRegisters {
            cs: SegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 1,
                ..Default::default()
            },
            ds: SegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 3,
                present: 1,
                s: 1,
                ..Default::default()
            },
            tr: SegmentRegister {
                base: 0,
                selector: 0,
                limit: 0xFFFF,
                type_: 11,
                present: 1,
                s: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        vcpu.set_sregs(&sregs)?;
        Ok(())
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

#[cfg(feature = "trace_guest")]
impl From<TraceRegister> for hv_register_name {
    fn from(r: TraceRegister) -> Self {
        match r {
            TraceRegister::RAX => hv_register_name_HV_X64_REGISTER_RAX,
            TraceRegister::RCX => hv_register_name_HV_X64_REGISTER_RCX,
            TraceRegister::RIP => hv_register_name_HV_X64_REGISTER_RIP,
            TraceRegister::RSP => hv_register_name_HV_X64_REGISTER_RSP,
            TraceRegister::RBP => hv_register_name_HV_X64_REGISTER_RBP,
        }
    }
}

impl Hypervisor for HypervLinuxDriver {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        mem_mgr: MemMgrWrapper<HostSharedMemory>,
        host_funcs: Arc<Mutex<FunctionRegistry>>,
        max_guest_log_level: Option<LevelFilter>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        self.mem_mgr = Some(mem_mgr);
        self.host_funcs = Some(host_funcs);
        self.page_size = page_size as usize;

        let max_guest_log_level: u64 = match max_guest_log_level {
            Some(level) => level as u64,
            None => self.get_max_log_level().into(),
        };

        let regs = StandardRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,
            rflags: 2, //bit 1 of rlags is required to be set

            // function args
            rdi: peb_addr.into(),
            rsi: seed,
            rdx: page_size.into(),
            rcx: max_guest_log_level,

            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn map_region(&mut self, rgn: &MemoryRegion) -> Result<()> {
        if [
            rgn.guest_region.start,
            rgn.guest_region.end,
            rgn.host_region.start,
            rgn.host_region.end,
        ]
        .iter()
        .any(|x| x % self.page_size != 0)
        {
            log_then_return!("region is not page-aligned");
        }
        let mshv_region: mshv_user_mem_region = rgn.to_owned().into();
        self.vm_fd.map_user_memory(mshv_region)?;
        self.mmap_regions.push(rgn.to_owned());
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    unsafe fn unmap_region(&mut self, region: &MemoryRegion) -> Result<()> {
        if let Some(pos) = self.mmap_regions.iter().position(|r| r == region) {
            let removed_region = self.mmap_regions.remove(pos);
            let mshv_region: mshv_user_mem_region = removed_region.into();
            self.vm_fd.unmap_user_memory(mshv_region)?;
            Ok(())
        } else {
            Err(new_error!("Tried to unmap region that is not mapped"))
        }
    }

    fn get_mapped_regions(&self) -> Box<dyn ExactSizeIterator<Item = &MemoryRegion> + '_> {
        Box::new(self.mmap_regions.iter())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        // Reset general purpose registers, then set RIP and RSP
        let regs = StandardRegisters {
            rip: dispatch_func_addr.into(),
            rsp: self.orig_rsp.absolute()?,
            rflags: 2, //bit 1 of rlags is required to be set
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        // reset fpu state
        let fpu = FloatingPointUnit {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vcpu_fd.set_fpu(&fpu)?;

        // run
        VirtualCPU::run(
            self.as_mut_hypervisor(),
            #[cfg(gdb)]
            dbg_mem_access_fn,
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
    ) -> Result<()> {
        let mut padded = [0u8; 4];
        let copy_len = data.len().min(4);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);
        let val = u32::from_le_bytes(padded);

        #[cfg(feature = "trace_guest")]
        {
            // We need to handle the borrow checker issue where we need both:
            // - &mut MemMgrWrapper (from self.mem_mgr.as_mut())
            // - &mut dyn Hypervisor (from self)
            // We'll use a temporary approach to extract the mem_mgr temporarily
            let mem_mgr_option = self.mem_mgr.take();
            let mut mem_mgr = mem_mgr_option
                .ok_or_else(|| new_error!("mem_mgr should be initialized before handling IO"))?;
            let host_funcs = self
                .host_funcs
                .as_ref()
                .ok_or_else(|| new_error!("host_funcs should be initialized before handling IO"))?
                .clone();

            handle_outb(&mut mem_mgr, host_funcs, self, port, val)?;

            // Put the mem_mgr back
            self.mem_mgr = Some(mem_mgr);
        }

        #[cfg(not(feature = "trace_guest"))]
        {
            let mem_mgr = self
                .mem_mgr
                .as_mut()
                .ok_or_else(|| new_error!("mem_mgr should be initialized before handling IO"))?;
            let host_funcs = self
                .host_funcs
                .as_ref()
                .ok_or_else(|| new_error!("host_funcs should be initialized before handling IO"))?
                .clone();

            handle_outb(mem_mgr, host_funcs, port, val)?;
        }

        // update rip
        self.vcpu_fd.set_reg(&[hv_register_assoc {
            name: hv_register_name_HV_X64_REGISTER_RIP,
            value: hv_register_value {
                reg64: rip + instruction_length,
            },
            ..Default::default()
        }])?;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<super::HyperlightExit> {
        const HALT_MESSAGE: hv_message_type = hv_message_type_HVMSG_X64_HALT;
        const IO_PORT_INTERCEPT_MESSAGE: hv_message_type =
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT;
        const UNMAPPED_GPA_MESSAGE: hv_message_type = hv_message_type_HVMSG_UNMAPPED_GPA;
        const INVALID_GPA_ACCESS_MESSAGE: hv_message_type = hv_message_type_HVMSG_GPA_INTERCEPT;
        #[cfg(gdb)]
        const EXCEPTION_INTERCEPT: hv_message_type = hv_message_type_HVMSG_X64_EXCEPTION_INTERCEPT;

        self.interrupt_handle
            .tid
            .store(unsafe { libc::pthread_self() as u64 }, Ordering::Relaxed);
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
        self.interrupt_handle
            .set_running_and_increment_generation()
            .map_err(|e| {
                new_error!(
                    "Error setting running state and incrementing generation: {}",
                    e
                )
            })?;
        #[cfg(not(gdb))]
        let debug_interrupt = false;
        #[cfg(gdb)]
        let debug_interrupt = self
            .interrupt_handle
            .debug_interrupt
            .load(Ordering::Relaxed);

        // Don't run the vcpu if `cancel_requested` is true
        //
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then this is fine since `cancel_requested` is set to true, so we will skip the `VcpuFd::run()` call
        let exit_reason = if self
            .interrupt_handle
            .cancel_requested
            .load(Ordering::Relaxed)
            || debug_interrupt
        {
            Err(MshvError::Errno(vmm_sys_util::errno::Error::new(
                libc::EINTR,
            )))
        } else {
            #[cfg(feature = "trace_guest")]
            if self.trace_info.guest_start_epoch.is_none() {
                // Store the guest start epoch and cycles to trace the guest execution time
                crate::debug!("MSHV - Guest Start Epoch set");
                self.trace_info.guest_start_tsc =
                    Some(hyperlight_guest_tracing::invariant_tsc::read_tsc());
                self.trace_info.guest_start_epoch = Some(std::time::Instant::now());
            }
            // Note: if a `InterruptHandle::kill()` called while this thread is **here**
            // Then the vcpu will run, but we will keep sending signals to this thread
            // to interrupt it until `running` is set to false. The `vcpu_fd::run()` call will
            // return either normally with an exit reason, or from being "kicked" by out signal handler, with an EINTR error,
            // both of which are fine.
            #[cfg(mshv2)]
            {
                let hv_message: hv_message = Default::default();
                self.vcpu_fd.run(hv_message)
            }
            #[cfg(mshv3)]
            self.vcpu_fd.run()
        };
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then signals will be sent to this thread until `running` is set to false.
        // This is fine since the signal handler is a no-op.
        let cancel_requested = self
            .interrupt_handle
            .cancel_requested
            .load(Ordering::Relaxed);
        #[cfg(gdb)]
        let debug_interrupt = self
            .interrupt_handle
            .debug_interrupt
            .load(Ordering::Relaxed);
        // Note: if a `InterruptHandle::kill()` called while this thread is **here**
        // Then `cancel_requested` will be set to true again, which will cancel the **next vcpu run**.
        // Additionally signals will be sent to this thread until `running` is set to false.
        // This is fine since the signal handler is a no-op.
        self.interrupt_handle.clear_running_bit();
        // At this point, `running` is false so no more signals will be sent to this thread,
        // but we may still receive async signals that were sent before this point.
        // To prevent those signals from interrupting subsequent calls to `run()`,
        // we make sure to check `cancel_requested` before cancelling (see `libc::EINTR` match-arm below).
        let result = match exit_reason {
            Ok(m) => match m.header.message_type {
                HALT_MESSAGE => {
                    crate::debug!("mshv - Halt Details : {:#?}", &self);
                    HyperlightExit::Halt()
                }
                IO_PORT_INTERCEPT_MESSAGE => {
                    let io_message = m.to_ioport_info()?;
                    let port_number = io_message.port_number;
                    let rip = io_message.header.rip;
                    let rax = io_message.rax;
                    let instruction_length = io_message.header.instruction_length() as u64;
                    crate::debug!("mshv IO Details : \nPort : {}\n{:#?}", port_number, &self);
                    HyperlightExit::IoOut(
                        port_number,
                        rax.to_le_bytes().to_vec(),
                        rip,
                        instruction_length,
                    )
                }
                UNMAPPED_GPA_MESSAGE => {
                    let mimo_message = m.to_memory_info()?;
                    let addr = mimo_message.guest_physical_address;
                    crate::debug!(
                        "mshv MMIO unmapped GPA -Details: Address: {} \n {:#?}",
                        addr,
                        &self
                    );
                    HyperlightExit::Mmio(addr)
                }
                INVALID_GPA_ACCESS_MESSAGE => {
                    let mimo_message = m.to_memory_info()?;
                    let gpa = mimo_message.guest_physical_address;
                    let access_info = MemoryRegionFlags::try_from(mimo_message)?;
                    crate::debug!(
                        "mshv MMIO invalid GPA access -Details: Address: {} \n {:#?}",
                        gpa,
                        &self
                    );
                    match get_memory_access_violation(
                        gpa as usize,
                        self.sandbox_regions.iter().chain(self.mmap_regions.iter()),
                        access_info,
                    ) {
                        Some(access_info_violation) => access_info_violation,
                        None => HyperlightExit::Mmio(gpa),
                    }
                }
                // The only case an intercept exit is expected is when debugging is enabled
                // and the intercepts are installed.
                // Provide the extra information about the exception to accurately determine
                // the stop reason
                #[cfg(gdb)]
                EXCEPTION_INTERCEPT => {
                    // Extract exception info from the message so we can figure out
                    // more information about the vCPU state
                    let ex_info = match m.to_exception_info() {
                        Ok(info) => info,
                        Err(e) => {
                            log_then_return!("Error converting to exception info: {:?}", e);
                        }
                    };

                    match self.get_stop_reason(ex_info) {
                        Ok(reason) => HyperlightExit::Debug(reason),
                        Err(e) => {
                            log_then_return!("Error getting stop reason: {:?}", e);
                        }
                    }
                }
                other => {
                    crate::debug!("mshv Other Exit: Exit: {:#?} \n {:#?}", other, &self);
                    #[cfg(crashdump)]
                    let _ = crashdump::generate_crashdump(self);
                    log_then_return!("unknown Hyper-V run message type {:?}", other);
                }
            },
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                libc::EINTR => {
                    // If cancellation was not requested for this specific vm, the vcpu was interrupted because of debug interrupt or
                    // a stale signal that meant to be delivered to a previous/other vcpu on this same thread, so let's ignore it
                    if cancel_requested {
                        self.interrupt_handle
                            .cancel_requested
                            .store(false, Ordering::Relaxed);
                        HyperlightExit::Cancelled()
                    } else {
                        #[cfg(gdb)]
                        if debug_interrupt {
                            self.interrupt_handle
                                .debug_interrupt
                                .store(false, Ordering::Relaxed);

                            // If the vCPU was stopped because of an interrupt, we need to
                            // return a special exit reason so that the gdb thread can handle it
                            // and resume execution
                            HyperlightExit::Debug(VcpuStopReason::Interrupt)
                        } else {
                            HyperlightExit::Retry()
                        }

                        #[cfg(not(gdb))]
                        HyperlightExit::Retry()
                    }
                }
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("mshv Error - Details: Error: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
        };
        Ok(result)
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt_handle.clone()
    }

    #[cfg(crashdump)]
    fn crashdump_context(&self) -> Result<Option<super::crashdump::CrashDumpContext>> {
        if self.rt_cfg.guest_core_dump {
            let mut regs = [0; 27];

            let vcpu_regs = self.vcpu_fd.get_regs()?;
            let sregs = self.vcpu_fd.get_sregs()?;
            let xsave = self.vcpu_fd.get_xsave()?;

            // Set up the registers for the crash dump
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

            // Get the filename from the binary path
            let filename = self.rt_cfg.binary_path.clone().and_then(|path| {
                Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_os_string().into_string().ok())
            });

            Ok(Some(crashdump::CrashDumpContext::new(
                &self.sandbox_regions,
                regs,
                xsave.buffer.to_vec(),
                self.entrypoint,
                self.rt_cfg.binary_path.clone(),
                filename,
            )))
        } else {
            Ok(None)
        }
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: std::sync::Arc<
            std::sync::Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>,
        >,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
        if self.debug.is_none() {
            return Err(new_error!("Debugging is not enabled"));
        }

        match stop_reason {
            // If the vCPU stopped because of a crash, we need to handle it differently
            // We do not want to allow resuming execution or placing breakpoints
            // because the guest has crashed.
            // We only allow reading registers and memory
            VcpuStopReason::Crash => {
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    // Flag to store if we should deny continue or step requests
                    let mut deny_continue = false;
                    // Flag to store if we should detach from the gdb session
                    let mut detach = false;

                    let response = match req {
                        // Allow the detach request to disable debugging by continuing resuming
                        // hypervisor crash error reporting
                        DebugMsg::DisableDebug => {
                            detach = true;
                            DebugResponse::DisableDebug
                        }
                        // Do not allow continue or step requests
                        DebugMsg::Continue | DebugMsg::Step => {
                            deny_continue = true;
                            DebugResponse::NotAllowed
                        }
                        // Do not allow adding/removing breakpoints and writing to memory or registers
                        DebugMsg::AddHwBreakpoint(_)
                        | DebugMsg::AddSwBreakpoint(_)
                        | DebugMsg::RemoveHwBreakpoint(_)
                        | DebugMsg::RemoveSwBreakpoint(_)
                        | DebugMsg::WriteAddr(_, _)
                        | DebugMsg::WriteRegisters(_) => DebugResponse::NotAllowed,

                        // For all other requests, we will process them normally
                        _ => {
                            let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());
                            match result {
                                Ok(response) => response,
                                Err(HyperlightError::TranslateGuestAddress(_)) => {
                                    // Treat non fatal errors separately so the guest doesn't fail
                                    DebugResponse::ErrorOccurred
                                }
                                Err(e) => {
                                    log::error!("Error processing debug request: {:?}", e);
                                    return Err(e);
                                }
                            }
                        }
                    };

                    // Send the response to the request back to gdb
                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // If we are denying continue or step requests, the debugger assumes the
                    // execution started so we need to report a stop reason as a crash and let
                    // it request to read registers/memory to figure out what happened
                    if deny_continue {
                        self.send_dbg_msg(DebugResponse::VcpuStopped(VcpuStopReason::Crash))
                            .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;
                    }

                    // If we are detaching, we will break the loop and the Hypervisor will continue
                    // to handle the Crash reason
                    if detach {
                        break;
                    }
                }
            }
            // If the vCPU stopped because of any other reason except a crash, we can handle it
            // normally
            _ => {
                // Send the stop reason to the gdb thread
                self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
                    .map_err(|e| {
                        new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e)
                    })?;

                loop {
                    log::debug!("Debug wait for event to resume vCPU");
                    // Wait for a message from gdb
                    let req = self.recv_dbg_msg()?;

                    let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());

                    let response = match result {
                        Ok(response) => response,
                        // Treat non fatal errors separately so the guest doesn't fail
                        Err(HyperlightError::TranslateGuestAddress(_)) => {
                            DebugResponse::ErrorOccurred
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    };

                    let cont = matches!(
                        response,
                        DebugResponse::Continue | DebugResponse::Step | DebugResponse::DisableDebug
                    );

                    self.send_dbg_msg(response)
                        .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

                    // Check if we should continue execution
                    // We continue if the response is one of the following: Step, Continue, or DisableDebug
                    if cont {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn check_stack_guard(&self) -> Result<bool> {
        if let Some(mgr) = self.mem_mgr.as_ref() {
            mgr.check_stack_guard()
        } else {
            Err(new_error!("Memory manager is not initialized"))
        }
    }

    #[cfg(feature = "trace_guest")]
    fn read_trace_reg(&self, reg: TraceRegister) -> Result<u64> {
        let mut assoc = [hv_register_assoc {
            name: reg.into(),
            ..Default::default()
        }];
        self.vcpu_fd.get_reg(&mut assoc)?;
        // safety: all registers that we currently support are 64-bit
        unsafe { Ok(assoc[0].value.reg64) }
    }

    #[cfg(feature = "trace_guest")]
    fn trace_info_as_ref(&self) -> &TraceInfo {
        &self.trace_info
    }
    #[cfg(feature = "trace_guest")]
    fn trace_info_as_mut(&mut self) -> &mut TraceInfo {
        &mut self.trace_info
    }
}

impl Drop for HypervLinuxDriver {
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn drop(&mut self) {
        self.interrupt_handle.dropped.store(true, Ordering::Relaxed);
        for region in self.sandbox_regions.iter().chain(self.mmap_regions.iter()) {
            let mshv_region: mshv_user_mem_region = region.to_owned().into();
            match self.vm_fd.unmap_user_memory(mshv_region) {
                Ok(_) => (),
                Err(e) => error!("Failed to unmap user memory in HyperVOnLinux ({:?})", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "unwind_guest")]
    use crate::mem::exe::DummyUnwindInfo;
    use crate::mem::memory_region::MemoryRegionVecBuilder;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};

    #[rustfmt::skip]
    const CODE: [u8; 12] = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, (%dx) */
        /* send a 0 to indicate we're done */
        0xb0, b'\0', /* mov $'\0', %al */
        0xee, /* out %al, (%dx) */
        0xf4, /* HLT */
    ];

    fn shared_mem_with_code(
        code: &[u8],
        mem_size: usize,
        load_offset: usize,
    ) -> Result<Box<ExclusiveSharedMemory>> {
        if load_offset > mem_size {
            log_then_return!(
                "code load offset ({}) > memory size ({})",
                load_offset,
                mem_size
            );
        }
        let mut shared_mem = ExclusiveSharedMemory::new(mem_size)?;
        shared_mem.copy_from_slice(code, load_offset)?;
        Ok(Box::new(shared_mem))
    }

    #[test]
    fn create_driver() {
        if !super::is_hypervisor_present() {
            return;
        }
        const MEM_SIZE: usize = 0x3000;
        let gm = shared_mem_with_code(CODE.as_slice(), MEM_SIZE, 0).unwrap();
        let rsp_ptr = GuestPtr::try_from(0).unwrap();
        let pml4_ptr = GuestPtr::try_from(0).unwrap();
        let entrypoint_ptr = GuestPtr::try_from(0).unwrap();
        let mut regions = MemoryRegionVecBuilder::new(0, gm.base_addr());
        regions.push_page_aligned(
            MEM_SIZE,
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE,
            crate::mem::memory_region::MemoryRegionType::Code,
        );
        let config: SandboxConfiguration = Default::default();

        super::HypervLinuxDriver::new(
            regions.build(),
            entrypoint_ptr,
            rsp_ptr,
            pml4_ptr,
            &config,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            SandboxRuntimeConfig {
                #[cfg(crashdump)]
                binary_path: None,
                #[cfg(gdb)]
                debug_info: None,
                #[cfg(crashdump)]
                guest_core_dump: true,
            },
            #[cfg(feature = "trace_guest")]
            TraceInfo::new(
                #[cfg(feature = "unwind_guest")]
                Arc::new(DummyUnwindInfo {}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}
