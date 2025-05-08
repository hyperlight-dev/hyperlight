#[cfg(feature = "kvm")]
use libc::SIGUSR1;

use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use crate::fpuregs::CommonFpu;
use crate::hypervisor::HyperlightExit;
use crate::mem::memory_region::MemoryRegion;
use crate::regs::CommonRegisters;
use crate::sregs::CommonSpecialRegisters;
use crate::Result;

pub(crate) trait Vm: Send + Sync + Debug {
    fn get_regs(&self) -> Result<CommonRegisters>;
    fn set_regs(&self, regs: &CommonRegisters) -> Result<()>;

    fn get_sregs(&self) -> Result<CommonSpecialRegisters>;
    fn set_sregs(&self, sregs: &CommonSpecialRegisters) -> Result<()>;

    fn get_fpu(&self) -> Result<CommonFpu>;
    fn set_fpu(&self, fpu: &CommonFpu) -> Result<()>;

    unsafe fn map_memory(&self, region: &[MemoryRegion]) -> Result<()>;

    fn run_vcpu(&mut self) -> Result<HyperlightExit>;

    fn interrupt_handle(&self) -> InterruptHandle;
}

pub(crate) struct InterruptHandle {
    #[cfg(target_os = "linux")]
    pub(crate) tid: Arc<AtomicU64>,
    #[cfg(target_os = "windows")]
    pub(crate) partition_handle: Arc<windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE>,
    pub(crate) is_running: Arc<AtomicBool>,
}

unsafe impl Send for InterruptHandle {}
unsafe impl Sync for InterruptHandle {}

impl InterruptHandle {
    pub(crate) fn interrupt_vm_if_running(&self) {
        println!("Interrupting VM...");
        if self.is_running.load(Ordering::Relaxed) {
            println!("Sending SIGUSR1 to thread on which VM is running...");
            // will cause blocking run call to exit with EINTR
            #[cfg(target_os = "linux")]
            unsafe {
                libc::pthread_kill(self.tid.load(Ordering::Relaxed), SIGUSR1)
            };
            #[cfg(target_os = "windows")]
            unsafe {
                WHvCancelRunVirtualProcessor(*self.partition_handle, 0, 0).unwrap()
            }
        } else {
            println!("VM was not running, not interrupting..");
        }
    }
}
