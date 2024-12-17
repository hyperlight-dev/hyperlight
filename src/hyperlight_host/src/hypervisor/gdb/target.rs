use std::sync::{Arc, Mutex};

use crossbeam_channel::TryRecvError;
use gdbstub::arch::Arch;
use gdbstub::stub::{BaseStopReason, SingleThreadStopReason};
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;
use kvm_bindings::{
    kvm_guest_debug, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
};
use kvm_ioctls::VcpuFd;

use super::GdbConnection;
use super::GdbTargetError;
use crate::hypervisor::gdb::{DebugMessage, GdbDebug};
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::GuestSharedMemory;

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

    pub fn pause_vcpu(&mut self) {
        self.paused = true;
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
}

impl SingleThreadBase for HyperlightKvmSandboxTarget {
    fn read_addrs(
        &mut self,
        _gva: <Self::Arch as Arch>::Usize,
        _data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        todo!()
    }

    fn write_addrs(
        &mut self,
        _gva: <Self::Arch as Arch>::Usize,
        _data: &[u8],
    ) -> TargetResult<(), Self> {
        todo!()
    }

    fn read_registers(
        &mut self,
        _regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        todo!()
    }

    fn write_registers(
        &mut self,
        _regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        todo!()
    }
}
