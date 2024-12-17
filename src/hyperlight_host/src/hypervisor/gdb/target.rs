use std::sync::{Arc, Mutex};

use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase,
};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::{Target, TargetResult};
use gdbstub_arch::x86::X86_64_SSE as GdbTargetArch;
use kvm_ioctls::VcpuFd;
use super::GdbTargetError;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::GuestSharedMemory;


#[allow(dead_code)]
/// Gdbstub target used by the gdbstub crate to provide GDB protocol implementation
pub struct HyperlightKvmSandboxTarget {
    /// Memory manager that grants access to guest's memory
    mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
    /// VcpuFd for access to vCPU state
    vcpu_fd: Arc<Mutex<VcpuFd>>,
    /// Guest entrypoint
    entrypoint: u64,
}

impl HyperlightKvmSandboxTarget {
    pub fn new(
        mgr: Arc<Mutex<SandboxMemoryManager<GuestSharedMemory>>>,
        vcpu_fd: Arc<Mutex<VcpuFd>>,
        entrypoint: u64,
    ) -> Self {
        HyperlightKvmSandboxTarget {
            mgr,
            vcpu_fd,
            entrypoint,
        }
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
