use std::sync::{Arc, Mutex};

use crossbeam_channel::TryRecvError;
use gdbstub::arch::Arch;
use gdbstub::stub::{BaseStopReason, SingleThreadStopReason};
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets};
use gdbstub::target::{Target, TargetError, TargetResult};
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;
use hyperlight_common::mem::PAGE_SIZE;
use kvm_bindings::{
    kvm_guest_debug, kvm_regs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
};
use kvm_ioctls::VcpuFd;

use super::GdbConnection;
use super::GdbTargetError;
use crate::hypervisor::gdb::{DebugMessage, GdbDebug};
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::{GuestSharedMemory, SharedMemory};

/// KVM Debug struct
/// This struct is used to abstract the internal details of the kvm
/// guest debugging settings
struct KvmDebug {
    /// Sent to KVM for enabling guest debug
    pub debug: kvm_guest_debug,
}

impl KvmDebug {
    const MAX_NO_OF_HW_BP: usize = 4;

    pub fn new() -> Self {
        let dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE,
            ..Default::default()
        };

        Self { debug: dbg }
    }

    /// Method to set the kvm debugreg fields for breakpoints
    /// The maximum number of supported breakpoints is `Self::MAX_NO_OF_HW_BP`
    pub fn set_breakpoints(
        &mut self,
        vcpu_fd: &VcpuFd,
        addrs: &[u64],
        step: bool,
    ) -> Result<bool, GdbTargetError> {
        if addrs.len() >= Self::MAX_NO_OF_HW_BP {
            return Ok(false);
        }

        self.debug.arch.debugreg = [0; 8];
        for (k, addr) in addrs.iter().enumerate() {
            self.debug.arch.debugreg[k] = *addr;
            self.debug.arch.debugreg[7] |= 1 << (k * 2);
        }

        if !addrs.is_empty() {
            self.debug.control |= KVM_GUESTDBG_USE_HW_BP;
        } else {
            self.debug.control &= !KVM_GUESTDBG_USE_HW_BP;
        }

        if step {
            self.debug.control |= KVM_GUESTDBG_SINGLESTEP;
        } else {
            self.debug.control &= !KVM_GUESTDBG_SINGLESTEP;
        }

        vcpu_fd
            .set_guest_debug(&self.debug)
            .map_err(|_| GdbTargetError::SetGuestDebugError)?;

        Ok(true)
    }
}

#[allow(dead_code)]
/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightKvmSandboxTarget {
    /// Memory manager that grants access to guest's memory
    mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
    /// VcpuFd for access to vCPU state
    vcpu_fd: Arc<Mutex<VcpuFd>>,
    /// Guest entrypoint
    entrypoint: u64,

    /// KVM guest debug information
    debug: KvmDebug,

    /// vCPU paused state
    paused: bool,

    /// Hypervisor communication channels
    hyp_conn: GdbConnection,
}

impl HyperlightKvmSandboxTarget {
    pub fn new(
        mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
        vcpu_fd: Arc<Mutex<VcpuFd>>,
        entrypoint: u64,
        hyp_conn: GdbConnection,
    ) -> Self {
        let kvm_debug = KvmDebug::new();

        HyperlightKvmSandboxTarget {
            mgr,
            vcpu_fd,
            debug: kvm_debug,
            entrypoint,

            paused: false,
            hyp_conn,
        }
    }

    /// Returns the instruction pointer from the stopped vCPU
    fn get_instruction_pointer(&self) -> Result<u64, GdbTargetError> {
        let regs = self
            .vcpu_fd
            .lock()
            .unwrap()
            .get_regs()
            .map_err(|_| GdbTargetError::InstructionPointerError)?;

        Ok(regs.rip)
    }

    /// Get the reason the vCPU has stopped
    pub fn get_stop_reason(&self) -> Result<Option<BaseStopReason<(), u64>>, GdbTargetError> {
        let ip = self.get_instruction_pointer()?;

        if ip == self.entrypoint {
            return Ok(Some(SingleThreadStopReason::HwBreak(())));
        }

        Ok(None)
    }

    /// This method provides a way to set a breakpoint at the entrypoint
    /// it does not keep this breakpoint set after the vcpu already stopped at the address
    pub fn set_entrypoint_bp(&mut self) -> Result<bool, GdbTargetError> {
        let mut entrypoint_debug = KvmDebug::new();
        entrypoint_debug.set_breakpoints(&self.vcpu_fd.lock().unwrap(), &[self.entrypoint], false)
    }

    /// Translates the guest address to physical address
    fn translate_gva(&self, gva: u64) -> Result<u64, GdbTargetError> {
        // TODO: Properly handle errors
        let tr = self
            .vcpu_fd
            .lock()
            .unwrap()
            .translate_gva(gva)
            .map_err(|_| GdbTargetError::InvalidGva)?;

        if tr.valid == 0 {
            Err(GdbTargetError::InvalidGva)
        } else {
            Ok(tr.physical_address)
        }
    }

    pub fn pause_vcpu(&mut self) {
        self.paused = true;
    }

    fn read_regs(&self, regs: &mut X86_64CoreRegs) -> Result<(), GdbTargetError> {
        log::debug!("Read registers");
        let vcpu_regs = self
            .vcpu_fd
            .lock()
            .unwrap()
            .get_regs()
            .map_err(|_| GdbTargetError::ReadRegistersError)?;

        regs.regs[0] = vcpu_regs.rax;
        regs.regs[1] = vcpu_regs.rbx;
        regs.regs[2] = vcpu_regs.rcx;
        regs.regs[3] = vcpu_regs.rdx;
        regs.regs[4] = vcpu_regs.rsi;
        regs.regs[5] = vcpu_regs.rdi;
        regs.regs[6] = vcpu_regs.rbp;
        regs.regs[7] = vcpu_regs.rsp;
        regs.regs[8] = vcpu_regs.r8;
        regs.regs[9] = vcpu_regs.r9;
        regs.regs[10] = vcpu_regs.r10;
        regs.regs[11] = vcpu_regs.r11;
        regs.regs[12] = vcpu_regs.r12;
        regs.regs[13] = vcpu_regs.r13;
        regs.regs[14] = vcpu_regs.r14;
        regs.regs[15] = vcpu_regs.r15;

        regs.rip = vcpu_regs.rip;

        regs.eflags =
            u32::try_from(vcpu_regs.rflags).map_err(|_| GdbTargetError::ReadRegistersError)?;

        Ok(())
    }

    fn write_regs(&self, regs: &X86_64CoreRegs) -> Result<(), GdbTargetError> {
        log::debug!("Write registers");
        let new_regs = kvm_regs {
            rax: regs.regs[0],
            rbx: regs.regs[1],
            rcx: regs.regs[2],
            rdx: regs.regs[3],
            rsi: regs.regs[4],
            rdi: regs.regs[5],
            rbp: regs.regs[6],
            rsp: regs.regs[7],
            r8: regs.regs[8],
            r9: regs.regs[9],
            r10: regs.regs[10],
            r11: regs.regs[11],
            r12: regs.regs[12],
            r13: regs.regs[13],
            r14: regs.regs[14],
            r15: regs.regs[15],

            rip: regs.rip,
            rflags: regs.eflags as u64,
        };

        self.vcpu_fd
            .lock()
            .unwrap()
            .set_regs(&new_regs)
            .map_err(|_| GdbTargetError::WriteRegistersError)
    }
}

impl GdbDebug for HyperlightKvmSandboxTarget {
    fn send(&self, ev: DebugMessage) -> Result<(), GdbTargetError> {
        self.hyp_conn.send(ev)
    }

    fn recv(&self) -> Result<DebugMessage, GdbTargetError> {
        self.hyp_conn.recv()
    }

    fn try_recv(&self) -> Result<DebugMessage, TryRecvError> {
        self.hyp_conn.try_recv()
    }
}

impl Target for HyperlightKvmSandboxTarget {
    type Arch = GdbTargetArch;
    type Error = GdbTargetError;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn support_section_offsets(
        &mut self,
    ) -> Option<gdbstub::target::ext::section_offsets::SectionOffsetsOps<Self>> {
        Some(self)
    }
}

impl SingleThreadBase for HyperlightKvmSandboxTarget {
    fn read_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let data_len = data.len();
        log::debug!("Read addr: {:X} len: {:X}", gva, data_len);

        let mut mgr = self.mgr.lock().unwrap();
        while !data.is_empty() {
            let gpa = self.translate_gva(gva).expect("");
            let read_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            let _ = mgr.shared_mem.with_exclusivity(|ex| {
                data[..read_len].copy_from_slice(&ex.as_slice()[offset..offset + read_len]);
            });

            data = &mut data[read_len..];
            gva += read_len as u64;
        }

        Ok(data_len)
    }

    fn write_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &[u8],
    ) -> TargetResult<(), Self> {
        let data_len = data.len();
        log::debug!("Write addr: {:X} len: {:X}", gva, data_len);

        let mut mgr = self.mgr.lock().unwrap();
        while !data.is_empty() {
            let gpa = self.translate_gva(gva).expect("");

            let write_len = std::cmp::min(
                data.len(),
                (PAGE_SIZE - (gpa & (PAGE_SIZE - 1))).try_into().unwrap(),
            );
            let offset = gpa as usize - SandboxMemoryLayout::BASE_ADDRESS;

            let _ = mgr
                .shared_mem
                .with_exclusivity(|ex| ex.copy_from_slice(data, offset));

            data = &data[write_len..];
            gva += write_len as u64;
        }

        Ok(())
    }

    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.read_regs(regs).map_err(TargetError::Fatal)
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.write_regs(regs).map_err(TargetError::Fatal)
    }
}

impl SectionOffsets for HyperlightKvmSandboxTarget {
    fn get_section_offsets(&mut self) -> Result<Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        let mgr = self.mgr.lock().unwrap();
        let text = mgr.layout.get_guest_code_address();

        log::debug!("Get section offsets text: {:X}", text);
        Ok(Offsets::Segments {
            text_seg: text as u64,
            data_seg: None,
        })
    }
}