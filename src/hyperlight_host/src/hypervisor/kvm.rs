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

use std::convert::TryFrom;
use std::fmt::Debug;
#[cfg(gdb)]
use std::sync::{Arc, Mutex};

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
#[cfg(gdb)]
use super::gdb::{DebugCommChannel, DebugMsg, DebugResponse, VcpuStopReason};
#[cfg(gdb)]
use super::handlers::DbgMemAccessHandlerWrapper;
use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::{
    HyperlightExit, Hypervisor, VirtualCPU, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
#[cfg(gdb)]
use crate::HyperlightError;
use crate::{log_then_return, new_error, Result};

/// Return `true` if the KVM API is available, version 12, and has UserMemory capability, or `false` otherwise
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    if let Ok(kvm) = Kvm::new() {
        let api_version = kvm.get_api_version();
        match api_version {
            version if version == 12 && kvm.check_extension(UserMemory) => true,
            12 => {
                log::info!("KVM does not have KVM_CAP_USER_MEMORY capability");
                false
            }
            version => {
                log::info!("KVM GET_API_VERSION returned {}, expected 12", version);
                false
            }
        }
    } else {
        log::info!("Error creating KVM object");
        false
    }
}

#[cfg(gdb)]
mod debug {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use hyperlight_common::mem::PAGE_SIZE;
    use kvm_bindings::{
        kvm_guest_debug, kvm_regs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
        KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
    };
    use kvm_ioctls::VcpuFd;

    use super::KVMDriver;
    use crate::hypervisor::gdb::{DebugMsg, DebugResponse, VcpuStopReason, X86_64Regs};
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::mem::layout::SandboxMemoryLayout;
    use crate::{new_error, HyperlightError, Result};

    /// Software Breakpoint size in memory
    pub const SW_BP_SIZE: usize = 1;
    /// Software Breakpoint opcode
    const SW_BP_OP: u8 = 0xCC;
    /// Software Breakpoint written to memory
    pub const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];

    /// KVM Debug struct
    /// This struct is used to abstract the internal details of the kvm
    /// guest debugging settings
    #[derive(Default)]
    pub struct KvmDebug {
        /// vCPU stepping state
        single_step: bool,

        /// Array of addresses for HW breakpoints
        hw_breakpoints: Vec<u64>,
        /// Saves the bytes modified to enable SW breakpoints
        sw_breakpoints: HashMap<u64, [u8; SW_BP_SIZE]>,

        /// Sent to KVM for enabling guest debug
        pub dbg_cfg: kvm_guest_debug,
    }

    impl KvmDebug {
        const MAX_NO_OF_HW_BP: usize = 4;

        pub fn new() -> Self {
            let dbg = kvm_guest_debug {
                control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
                ..Default::default()
            };

            Self {
                single_step: false,
                hw_breakpoints: vec![],
                sw_breakpoints: HashMap::new(),
                dbg_cfg: dbg,
            }
        }

        /// This method sets the kvm debugreg fields to enable breakpoints at
        /// specific addresses
        ///
        /// The first 4 debug registers are used to set the addresses
        /// The 4th and 5th debug registers are obsolete and not used
        /// The 7th debug register is used to enable the breakpoints
        /// For more information see: DEBUG REGISTERS chapter in the architecture
        /// manual
        fn set_debug_config(&mut self, vcpu_fd: &VcpuFd, step: bool) -> Result<()> {
            let addrs = &self.hw_breakpoints;

            self.dbg_cfg.arch.debugreg = [0; 8];
            for (k, addr) in addrs.iter().enumerate() {
                self.dbg_cfg.arch.debugreg[k] = *addr;
                self.dbg_cfg.arch.debugreg[7] |= 1 << (k * 2);
            }

            if !addrs.is_empty() {
                self.dbg_cfg.control |= KVM_GUESTDBG_USE_HW_BP;
            } else {
                self.dbg_cfg.control &= !KVM_GUESTDBG_USE_HW_BP;
            }

            if step {
                self.dbg_cfg.control |= KVM_GUESTDBG_SINGLESTEP;
            } else {
                self.dbg_cfg.control &= !KVM_GUESTDBG_SINGLESTEP;
            }

            log::debug!("Setting bp: {:?} cfg: {:?}", addrs, self.dbg_cfg);
            vcpu_fd
                .set_guest_debug(&self.dbg_cfg)
                .map_err(|e| new_error!("Could not set guest debug: {:?}", e))?;

            self.single_step = step;

            Ok(())
        }

        /// Method that adds a breakpoint
        fn add_breakpoint(&mut self, vcpu_fd: &VcpuFd, addr: u64) -> Result<bool> {
            if self.hw_breakpoints.len() >= Self::MAX_NO_OF_HW_BP {
                Ok(false)
            } else if self.hw_breakpoints.contains(&addr) {
                Ok(true)
            } else {
                self.hw_breakpoints.push(addr);
                self.set_debug_config(vcpu_fd, self.single_step)?;

                Ok(true)
            }
        }

        /// Method that removes a breakpoint
        fn remove_breakpoint(&mut self, vcpu_fd: &VcpuFd, addr: u64) -> Result<bool> {
            if self.hw_breakpoints.contains(&addr) {
                self.hw_breakpoints.retain(|&a| a != addr);
                self.set_debug_config(vcpu_fd, self.single_step)?;

                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    impl KVMDriver {
        /// Resets the debug information to disable debugging
        fn disable_debug(&mut self) -> Result<()> {
            self.debug = Some(KvmDebug::default());

            self.set_single_step(false)
        }

        /// Returns the instruction pointer from the stopped vCPU
        fn get_instruction_pointer(&self) -> Result<u64> {
            let regs = self
                .vcpu_fd
                .get_regs()
                .map_err(|e| new_error!("Could not retrieve registers from vCPU: {:?}", e))?;

            Ok(regs.rip)
        }

        /// Sets or clears stepping for vCPU
        fn set_single_step(&mut self, enable: bool) -> Result<()> {
            let debug = self
                .debug
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            debug.set_debug_config(&self.vcpu_fd, enable)
        }

        /// Translates the guest address to physical address
        fn translate_gva(&self, gva: u64) -> Result<u64> {
            let tr = self
                .vcpu_fd
                .translate_gva(gva)
                .map_err(|_| HyperlightError::TranslateGuestAddress(gva))?;

            if tr.valid == 0 {
                Err(HyperlightError::TranslateGuestAddress(gva))
            } else {
                Ok(tr.physical_address)
            }
        }

        fn read_addrs(
            &mut self,
            mut gva: u64,
            mut data: &mut [u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<()> {
            let data_len = data.len();
            log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.translate_gva(gva)?;

                let read_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

                dbg_mem_access_fn
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .read(offset, &mut data[..read_len])?;

                data = &mut data[read_len..];
                gva += read_len as u64;
            }

            Ok(())
        }

        fn write_addrs(
            &mut self,
            mut gva: u64,
            mut data: &[u8],
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<()> {
            let data_len = data.len();
            log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

            while !data.is_empty() {
                let gpa = self.translate_gva(gva)?;

                let write_len = std::cmp::min(
                    data.len(),
                    (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
                );
                let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

                dbg_mem_access_fn
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .write(offset, data)?;

                data = &data[write_len..];
                gva += write_len as u64;
            }

            Ok(())
        }

        fn read_regs(&self, regs: &mut X86_64Regs) -> Result<()> {
            log::debug!("Read registers");
            let vcpu_regs = self
                .vcpu_fd
                .get_regs()
                .map_err(|e| new_error!("Could not read guest registers: {:?}", e))?;

            regs.rax = vcpu_regs.rax;
            regs.rbx = vcpu_regs.rbx;
            regs.rcx = vcpu_regs.rcx;
            regs.rdx = vcpu_regs.rdx;
            regs.rsi = vcpu_regs.rsi;
            regs.rdi = vcpu_regs.rdi;
            regs.rbp = vcpu_regs.rbp;
            regs.rsp = vcpu_regs.rsp;
            regs.r8 = vcpu_regs.r8;
            regs.r9 = vcpu_regs.r9;
            regs.r10 = vcpu_regs.r10;
            regs.r11 = vcpu_regs.r11;
            regs.r12 = vcpu_regs.r12;
            regs.r13 = vcpu_regs.r13;
            regs.r14 = vcpu_regs.r14;
            regs.r15 = vcpu_regs.r15;

            regs.rip = vcpu_regs.rip;
            regs.rflags = vcpu_regs.rflags;

            Ok(())
        }

        fn write_regs(&self, regs: &X86_64Regs) -> Result<()> {
            log::debug!("Write registers");
            let new_regs = kvm_regs {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rbp: regs.rbp,
                rsp: regs.rsp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,

                rip: regs.rip,
                rflags: regs.rflags,
            };

            self.vcpu_fd
                .set_regs(&new_regs)
                .map_err(|e| new_error!("Could not write guest registers: {:?}", e))
        }

        fn add_hw_breakpoint(&mut self, addr: u64) -> Result<bool> {
            let addr = self.translate_gva(addr)?;

            if let Some(debug) = self.debug.as_mut() {
                debug.add_breakpoint(&self.vcpu_fd, addr)
            } else {
                Ok(false)
            }
        }

        fn remove_hw_breakpoint(&mut self, addr: u64) -> Result<bool> {
            let addr = self.translate_gva(addr)?;

            if let Some(debug) = self.debug.as_mut() {
                debug.remove_breakpoint(&self.vcpu_fd, addr)
            } else {
                Ok(false)
            }
        }

        fn add_sw_breakpoint(
            &mut self,
            addr: u64,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<bool> {
            let addr = {
                let debug = self
                    .debug
                    .as_ref()
                    .ok_or_else(|| new_error!("Debug is not enabled"))?;
                let addr = self.translate_gva(addr)?;
                if debug.sw_breakpoints.contains_key(&addr) {
                    return Ok(true);
                }

                addr
            };

            let mut save_data = [0; SW_BP_SIZE];
            self.read_addrs(addr, &mut save_data[..], dbg_mem_access_fn.clone())?;
            self.write_addrs(addr, &SW_BP, dbg_mem_access_fn)?;

            {
                let debug = self
                    .debug
                    .as_mut()
                    .ok_or_else(|| new_error!("Debug is not enabled"))?;
                debug.sw_breakpoints.insert(addr, save_data);
            }

            Ok(true)
        }

        fn remove_sw_breakpoint(
            &mut self,
            addr: u64,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<bool> {
            let (ret, data) = {
                let addr = self.translate_gva(addr)?;
                let debug = self
                    .debug
                    .as_mut()
                    .ok_or_else(|| new_error!("Debug is not enabled"))?;

                if debug.sw_breakpoints.contains_key(&addr) {
                    let save_data = debug
                        .sw_breakpoints
                        .remove(&addr)
                        .ok_or_else(|| new_error!("Expected the hashmap to contain the address"))?;

                    (true, Some(save_data))
                } else {
                    (false, None)
                }
            };

            if ret {
                self.write_addrs(addr, &data.unwrap(), dbg_mem_access_fn)?;
            }

            Ok(ret)
        }

        /// Gdb expects the target to be stopped when connected.
        /// This method provides a way to set a breakpoint at the entry point
        /// it does not keep this breakpoint set after the vCPU already stopped at the address
        pub fn set_entrypoint_bp(&self) -> Result<()> {
            if self.debug.is_some() {
                log::debug!("Setting entrypoint bp {:X}", self.entrypoint);
                let mut entrypoint_debug = KvmDebug::new();
                entrypoint_debug.add_breakpoint(&self.vcpu_fd, self.entrypoint)?;

                Ok(())
            } else {
                Ok(())
            }
        }

        /// Get the reason the vCPU has stopped
        pub fn get_stop_reason(&self) -> Result<VcpuStopReason> {
            let debug = self
                .debug
                .as_ref()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            if debug.single_step {
                return Ok(VcpuStopReason::DoneStep);
            }

            let ip = self.get_instruction_pointer()?;
            let gpa = self.translate_gva(ip)?;
            if debug.sw_breakpoints.contains_key(&gpa) {
                return Ok(VcpuStopReason::SwBp);
            }

            if debug.hw_breakpoints.contains(&gpa) {
                return Ok(VcpuStopReason::HwBp);
            }

            if ip == self.entrypoint {
                return Ok(VcpuStopReason::HwBp);
            }

            Ok(VcpuStopReason::Unknown)
        }

        pub fn process_dbg_request(
            &mut self,
            req: DebugMsg,
            dbg_mem_access_fn: Arc<Mutex<dyn DbgMemAccessHandlerCaller>>,
        ) -> Result<DebugResponse> {
            match req {
                DebugMsg::AddHwBreakpoint(addr) => self
                    .add_hw_breakpoint(addr)
                    .map(DebugResponse::AddHwBreakpoint),
                DebugMsg::AddSwBreakpoint(addr) => self
                    .add_sw_breakpoint(addr, dbg_mem_access_fn)
                    .map(DebugResponse::AddSwBreakpoint),
                DebugMsg::Continue => {
                    self.set_single_step(false)?;
                    Ok(DebugResponse::Continue)
                }
                DebugMsg::DisableDebug => {
                    self.disable_debug()?;

                    Ok(DebugResponse::DisableDebug)
                }
                DebugMsg::GetCodeSectionOffset => {
                    let offset = dbg_mem_access_fn
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                        .get_code_offset()?;

                    Ok(DebugResponse::GetCodeSectionOffset(offset as u64))
                }
                DebugMsg::ReadAddr(addr, len) => {
                    let mut data = vec![0u8; len];

                    self.read_addrs(addr, &mut data, dbg_mem_access_fn)?;

                    Ok(DebugResponse::ReadAddr(data))
                }
                DebugMsg::ReadRegisters => {
                    let mut regs = X86_64Regs::default();

                    self.read_regs(&mut regs)
                        .map(|_| DebugResponse::ReadRegisters(regs))
                }
                DebugMsg::RemoveHwBreakpoint(addr) => self
                    .remove_hw_breakpoint(addr)
                    .map(DebugResponse::RemoveHwBreakpoint),
                DebugMsg::RemoveSwBreakpoint(addr) => self
                    .remove_sw_breakpoint(addr, dbg_mem_access_fn)
                    .map(DebugResponse::RemoveSwBreakpoint),
                DebugMsg::Step => {
                    self.set_single_step(true)?;
                    Ok(DebugResponse::Step)
                }
                DebugMsg::WriteAddr(addr, data) => {
                    self.write_addrs(addr, &data, dbg_mem_access_fn)?;

                    Ok(DebugResponse::WriteAddr)
                }
                DebugMsg::WriteRegisters(regs) => self
                    .write_regs(&regs)
                    .map(|_| DebugResponse::WriteRegisters),
            }
        }

        pub fn recv_dbg_msg(&mut self) -> Result<DebugMsg> {
            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.recv().map_err(|e| {
                new_error!(
                    "Got an error while waiting to receive a message from the gdb thread: {:?}",
                    e
                )
            })
        }

        pub fn send_dbg_msg(&mut self, cmd: DebugResponse) -> Result<()> {
            log::debug!("Sending {:?}", cmd);

            let gdb_conn = self
                .gdb_conn
                .as_mut()
                .ok_or_else(|| new_error!("Debug is not enabled"))?;

            gdb_conn.send(cmd).map_err(|e| {
                new_error!(
                    "Got an error while sending a response message to the gdb thread: {:?}",
                    e
                )
            })
        }
    }
}

/// A Hypervisor driver for KVM on Linux
pub(super) struct KVMDriver {
    _kvm: Kvm,
    _vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,

    #[cfg(gdb)]
    debug: Option<debug::KvmDebug>,
    #[cfg(gdb)]
    gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
}

impl KVMDriver {
    /// Create a new instance of a `KVMDriver`, with only control registers
    /// set. Standard registers will not be set, and `initialise` must
    /// be called to do so.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new(
        mem_regions: Vec<MemoryRegion>,
        pml4_addr: u64,
        entrypoint: u64,
        rsp: u64,
        #[cfg(gdb)] gdb_conn: Option<DebugCommChannel<DebugResponse, DebugMsg>>,
    ) -> Result<Self> {
        let kvm = Kvm::new()?;

        let vm_fd = kvm.create_vm_with_type(0)?;

        let perm_flags =
            MemoryRegionFlags::READ | MemoryRegionFlags::WRITE | MemoryRegionFlags::EXECUTE;

        mem_regions.iter().enumerate().try_for_each(|(i, region)| {
            let perm_flags = perm_flags.intersection(region.flags);
            let kvm_region = kvm_userspace_memory_region {
                slot: i as u32,
                guest_phys_addr: region.guest_region.start as u64,
                memory_size: (region.guest_region.end - region.guest_region.start) as u64,
                userspace_addr: region.host_region.start as u64,
                flags: match perm_flags {
                    MemoryRegionFlags::READ => KVM_MEM_READONLY,
                    _ => 0, // normal, RWX
                },
            };
            unsafe { vm_fd.set_user_memory_region(kvm_region) }
        })?;

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;
        Self::setup_initial_sregs(&mut vcpu_fd, pml4_addr)?;

        #[cfg(gdb)]
        let (debug, gdb_conn) = if let Some(gdb_conn) = gdb_conn {
            (Some(debug::KvmDebug::new()), Some(gdb_conn))
        } else {
            (None, None)
        };

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;

        let ret = Self {
            _kvm: kvm,
            _vm_fd: vm_fd,
            vcpu_fd,
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions,

            #[cfg(gdb)]
            debug,
            #[cfg(gdb)]
            gdb_conn,
        };

        #[cfg(gdb)]
        ret.set_entrypoint_bp()?;

        Ok(ret)
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu_fd: &mut VcpuFd, pml4_addr: u64) -> Result<()> {
        // setup paging and IA-32e (64-bit) mode
        let mut sregs = vcpu_fd.get_sregs()?;
        sregs.cr3 = pml4_addr;
        sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
        sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
        sregs.efer = EFER_LME | EFER_LMA | EFER_SCE | EFER_NX;
        sregs.cs.l = 1; // required for 64-bit mode
        vcpu_fd.set_sregs(&sregs)?;
        Ok(())
    }
}

impl Debug for KVMDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("KVM Driver");
        // Output each memory region

        for region in &self.mem_regions {
            f.field("Memory Region", &region);
        }
        let regs = self.vcpu_fd.get_regs();
        // check that regs is OK and then set field in debug struct

        if let Ok(regs) = regs {
            f.field("Registers", &regs);
        }

        let sregs = self.vcpu_fd.get_sregs();

        // check that sregs is OK and then set field in debug struct

        if let Ok(sregs) = sregs {
            f.field("Special Registers", &sregs);
        }

        f.finish()
    }
}

impl Hypervisor for KVMDriver {
    /// Implementation of initialise for Hypervisor trait.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        let regs = kvm_regs {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,

            // function args
            rcx: peb_addr.into(),
            rdx: seed,
            r8: page_size.into(),
            r9: self.get_max_log_level().into(),

            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        VirtualCPU::run(
            self.as_mut_hypervisor(),
            hv_handler,
            outb_hdl,
            mem_access_hdl,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        // reset RSP to what it was before initialise
        self.vcpu_fd.set_regs(&kvm_regs {
            rsp: self.orig_rsp.absolute()?,
            ..Default::default()
        })?;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn dispatch_call_from_host(
        &mut self,
        dispatch_func_addr: RawPtr,
        outb_handle_fn: OutBHandlerWrapper,
        mem_access_fn: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
        #[cfg(gdb)] dbg_mem_access_fn: DbgMemAccessHandlerWrapper,
    ) -> Result<()> {
        // Reset general purpose registers except RSP, then set RIP
        let rsp_before = self.vcpu_fd.get_regs()?.rsp;
        let regs = kvm_regs {
            rip: dispatch_func_addr.into(),
            rsp: rsp_before,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs)?;

        // reset fpu state
        let fpu = kvm_fpu {
            fcw: FP_CONTROL_WORD_DEFAULT,
            ftwx: FP_TAG_WORD_DEFAULT,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default() // zero out the rest
        };
        self.vcpu_fd.set_fpu(&fpu)?;

        // run
        VirtualCPU::run(
            self.as_mut_hypervisor(),
            hv_handler,
            outb_handle_fn,
            mem_access_fn,
            #[cfg(gdb)]
            dbg_mem_access_fn,
        )?;

        // reset RSP to what it was before function call
        self.vcpu_fd.set_regs(&kvm_regs {
            rsp: rsp_before,
            ..Default::default()
        })?;
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn handle_io(
        &mut self,
        port: u16,
        data: Vec<u8>,
        _rip: u64,
        _instruction_length: u64,
        outb_handle_fn: OutBHandlerWrapper,
    ) -> Result<()> {
        // KVM does not need RIP or instruction length, as it automatically sets the RIP

        // The payload param for the outb_handle_fn is the first byte
        // of the data array cast to an u64. Thus, we need to make sure
        // the data array has at least one u8, then convert that to an u64
        if data.is_empty() {
            log_then_return!("no data was given in IO interrupt");
        } else {
            let payload_u64 = u64::from(data[0]);
            outb_handle_fn
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .call(port, payload_u64)?;
        }

        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn run(&mut self) -> Result<HyperlightExit> {
        let exit_reason = self.vcpu_fd.run();
        let result = match exit_reason {
            Ok(VcpuExit::Hlt) => {
                crate::debug!("KVM - Halt Details : {:#?}", &self);
                HyperlightExit::Halt()
            }
            Ok(VcpuExit::IoOut(port, data)) => {
                // because vcpufd.run() mutably borrows self we cannot pass self to crate::debug! macro here
                crate::debug!("KVM IO Details : \nPort : {}\nData : {:?}", port, data);
                // KVM does not need to set RIP or instruction length so these are set to 0
                HyperlightExit::IoOut(port, data.to_vec(), 0, 0)
            }
            Ok(VcpuExit::MmioRead(addr, _)) => {
                crate::debug!("KVM MMIO Read -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::READ,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            Ok(VcpuExit::MmioWrite(addr, _)) => {
                crate::debug!("KVM MMIO Write -Details: Address: {} \n {:#?}", addr, &self);

                match self.get_memory_access_violation(
                    addr as usize,
                    &self.mem_regions,
                    MemoryRegionFlags::WRITE,
                ) {
                    Some(access_violation_exit) => access_violation_exit,
                    None => HyperlightExit::Mmio(addr),
                }
            }
            #[cfg(gdb)]
            Ok(VcpuExit::Debug(_)) => match self.get_stop_reason() {
                Ok(reason) => HyperlightExit::Debug(reason),
                Err(e) => {
                    log_then_return!("Error getting stop reason: {:?}", e);
                }
            },
            Err(e) => match e.errno() {
                // In case of the gdb feature, the timeout is not enabled, this
                // exit is because of a signal sent from the gdb thread to the
                // hypervisor thread to cancel execution
                #[cfg(gdb)]
                libc::EINTR => HyperlightExit::Debug(VcpuStopReason::Interrupt),
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                #[cfg(not(gdb))]
                libc::EINTR => HyperlightExit::Cancelled(),
                libc::EAGAIN => HyperlightExit::Retry(),
                _ => {
                    crate::debug!("KVM Error -Details: Address: {} \n {:#?}", e, &self);
                    log_then_return!("Error running VCPU {:?}", e);
                }
            },
            Ok(other) => {
                crate::debug!("KVM Other Exit {:?}", other);
                HyperlightExit::Unknown(format!("Unexpected KVM Exit {:?}", other))
            }
        };
        Ok(result)
    }

    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn as_mut_hypervisor(&mut self) -> &mut dyn Hypervisor {
        self as &mut dyn Hypervisor
    }

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion] {
        &self.mem_regions
    }

    #[cfg(gdb)]
    fn handle_debug(
        &mut self,
        dbg_mem_access_fn: Arc<Mutex<dyn super::handlers::DbgMemAccessHandlerCaller>>,
        stop_reason: VcpuStopReason,
    ) -> Result<()> {
        self.send_dbg_msg(DebugResponse::VcpuStopped(stop_reason))
            .map_err(|e| new_error!("Couldn't signal vCPU stopped event to GDB thread: {:?}", e))?;

        loop {
            log::debug!("Debug wait for event to resume vCPU");
            // Wait for a message from gdb
            let req = self.recv_dbg_msg()?;

            let result = self.process_dbg_request(req, dbg_mem_access_fn.clone());

            let response = match result {
                Ok(response) => response,
                // Treat non fatal errors separately so the guest doesn't fail
                Err(HyperlightError::TranslateGuestAddress(_)) => DebugResponse::ErrorOccurred,
                Err(e) => {
                    return Err(e);
                }
            };

            // If the command was either step or continue, we need to run the vcpu
            let cont = matches!(
                response,
                DebugResponse::Step | DebugResponse::Continue | DebugResponse::DisableDebug
            );

            self.send_dbg_msg(response)
                .map_err(|e| new_error!("Couldn't send response to gdb: {:?}", e))?;

            if cont {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    #[cfg(gdb)]
    use crate::hypervisor::handlers::DbgMemAccessHandlerCaller;
    use crate::hypervisor::handlers::{MemAccessHandler, OutBHandler};
    use crate::hypervisor::tests::test_initialise;
    use crate::Result;

    #[cfg(gdb)]
    struct DbgMemAccessHandler {}

    #[cfg(gdb)]
    impl DbgMemAccessHandlerCaller for DbgMemAccessHandler {
        fn read(&mut self, _offset: usize, _data: &mut [u8]) -> Result<()> {
            Ok(())
        }

        fn write(&mut self, _offset: usize, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        fn get_code_offset(&mut self) -> Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn test_init() {
        if !super::is_hypervisor_present() {
            return;
        }

        let outb_handler: Arc<Mutex<OutBHandler>> = {
            let func: Box<dyn FnMut(u16, u64) -> Result<()> + Send> =
                Box::new(|_, _| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(OutBHandler::from(func)))
        };
        let mem_access_handler = {
            let func: Box<dyn FnMut() -> Result<()> + Send> = Box::new(|| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(MemAccessHandler::from(func)))
        };
        #[cfg(gdb)]
        let dbg_mem_access_handler = Arc::new(Mutex::new(DbgMemAccessHandler {}));

        test_initialise(
            outb_handler,
            mem_access_handler,
            #[cfg(gdb)]
            dbg_mem_access_handler,
        )
        .unwrap();
    }
}
