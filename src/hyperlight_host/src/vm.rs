use kvm_bindings::kvm_fpu;
#[cfg(feature = "kvm")]
use kvm_bindings::{kvm_sregs, kvm_userspace_memory_region};
use libc::SIGUSR1;

use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use crate::hypervisor::HyperlightExit;
use crate::regs::Registers;
use crate::Result;

pub(crate) trait Vm: Send + Sync + Debug {
    fn regs(&self) -> Result<Registers>;
    fn set_regs(&self, regs: &Registers) -> Result<()>;

    fn sregs_kvm(&self) -> Result<kvm_sregs>;
    fn set_sregs_kvm(&self, sregs: &kvm_sregs) -> Result<()>;

    fn fpu_regs(&self) -> Result<kvm_fpu>;
    fn set_fpu_regs(&self, fpu: &kvm_fpu) -> Result<()>;

    unsafe fn map_memory_kvm(&self, region: kvm_userspace_memory_region) -> Result<()>;

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
