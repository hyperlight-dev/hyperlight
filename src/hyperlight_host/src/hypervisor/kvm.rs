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

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::Cap::UserMemory;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::{
    HyperlightExit, Hypervisor, VirtualCPU, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP,
    CR4_OSFXSR, CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
#[cfg(feature = "trace_guest")]
use crate::sandbox::TraceInfo;
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

/// A Hypervisor driver for KVM on Linux
pub(super) struct KVMDriver {
    _kvm: Kvm,
    _vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    orig_rsp: GuestPtr,
    mem_regions: Vec<MemoryRegion>,
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
    ) -> Result<Self> {
        if !is_hypervisor_present() {
            log_then_return!("KVM is not present");
        };
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

        let rsp_gp = GuestPtr::try_from(RawPtr::from(rsp))?;
        Ok(Self {
            _kvm: kvm,
            _vm_fd: vm_fd,
            vcpu_fd,
            entrypoint,
            orig_rsp: rsp_gp,
            mem_regions,
        })
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
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
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
            #[cfg(feature = "trace_guest")]
            trace_info,
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
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
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
            #[cfg(feature = "trace_guest")]
            trace_info,
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
        #[cfg(feature = "trace_guest")] trace_info: TraceInfo,
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
                .call(
                    #[cfg(feature = "trace_guest")]
                    self,
                    #[cfg(feature = "trace_guest")]
                    trace_info,
                    port,
                    payload_u64,
                )?;
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
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
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
}

#[cfg(test)]
pub(crate) mod test_cfg {
    use once_cell::sync::Lazy;
    use serde::Deserialize;

    pub(crate) static TEST_CONFIG: Lazy<TestConfig> =
        Lazy::new(|| match envy::from_env::<TestConfig>() {
            Ok(config) => config,
            Err(err) => panic!("error parsing config from env: {}", err),
        });
    pub(crate) static SHOULD_RUN_TEST: Lazy<bool> = Lazy::new(is_kvm_present);

    fn is_kvm_present() -> bool {
        println!(
            "KVM_SHOULD_BE_PRESENT is {}",
            TEST_CONFIG.kvm_should_be_present
        );
        let is_present = super::is_hypervisor_present();
        if (is_present && !TEST_CONFIG.kvm_should_be_present)
            || (!is_present && TEST_CONFIG.kvm_should_be_present)
        {
            println!(
                "WARNING: KVM is-present returned {}, should be present is: {}",
                is_present, TEST_CONFIG.kvm_should_be_present
            );
        }
        is_present
    }

    fn kvm_should_be_present_default() -> bool {
        false
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct TestConfig {
        #[serde(default = "kvm_should_be_present_default")]
        // Set env var KVM_SHOULD_BE_PRESENT to require kvm to be present for the tests.
        pub(crate) kvm_should_be_present: bool,
    }

    #[macro_export]
    macro_rules! should_run_kvm_linux_test {
        () => {{
            if !(*$crate::hypervisor::kvm::test_cfg::SHOULD_RUN_TEST) {
                println! {"Not Running KVM Test - SHOULD_RUN_TEST is false"}
                return;
            }
            println! {"Running Test - SHOULD_RUN_TEST is true"}
        }};
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::hypervisor::handlers::{MemAccessHandler, OutBHandler, OutBHandlerFunction};
    use crate::hypervisor::tests::test_initialise;
    use crate::{should_run_kvm_linux_test, Result};

    #[test]
    fn test_init() {
        should_run_kvm_linux_test!();
        let outb_handler = {
            let func: OutBHandlerFunction = Box::new(
                |#[cfg(feature = "trace_guest")] _,
                 #[cfg(feature = "trace_guest")] _,
                 _,
                 _|
                 -> Result<()> { Ok(()) },
            );
            Arc::new(Mutex::new(OutBHandler::from(func)))
        };
        let mem_access_handler = {
            let func: Box<dyn FnMut() -> Result<()> + Send> = Box::new(|| -> Result<()> { Ok(()) });
            Arc::new(Mutex::new(MemAccessHandler::from(func)))
        };
        test_initialise(outb_handler, mem_access_handler).unwrap();
    }
}
