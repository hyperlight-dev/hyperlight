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

#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

use std::fmt::{Debug, Formatter};

use log::error;
#[cfg(mshv2)]
use mshv_bindings::hv_message;
use mshv_bindings::{
    hv_message_type, hv_message_type_HVMSG_GPA_INTERCEPT, hv_message_type_HVMSG_UNMAPPED_GPA,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT, hv_register_assoc,
    hv_register_name_HV_X64_REGISTER_RIP, hv_register_value, mshv_user_mem_region,
    FloatingPointUnit, SegmentRegister, SpecialRegisters, StandardRegisters,
};
#[cfg(mshv3)]
use mshv_bindings::{
    hv_partition_property_code_HV_PARTITION_PROPERTY_SYNTHETIC_PROC_FEATURES,
    hv_partition_synthetic_processor_features,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use tracing::{instrument, Span};

use super::fpu::{FP_CONTROL_WORD_DEFAULT, FP_TAG_WORD_DEFAULT, MXCSR_DEFAULT};
use super::handlers::{MemAccessHandlerWrapper, OutBHandlerWrapper};
use super::{
    Hypervisor, VirtualCPU, CR0_AM, CR0_ET, CR0_MP, CR0_NE, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR,
    CR4_OSXMMEXCPT, CR4_PAE, EFER_LMA, EFER_LME, EFER_NX, EFER_SCE,
};
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
use crate::hypervisor::HyperlightExit;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::mem::ptr::{GuestPtr, RawPtr};
use crate::{log_then_return, new_error, Result};

/// Determine whether the HyperV for Linux hypervisor API is present
/// and functional.
#[instrument(skip_all, parent = Span::current(), level = "Trace")]
pub(crate) fn is_hypervisor_present() -> bool {
    match Mshv::open_with_cloexec(true) {
        Ok(fd) => {
            unsafe {
                libc::close(fd);
            } // must explicitly close fd to avoid a leak
            true
        }
        Err(e) => {
            log::info!("Error creating MSHV object: {:?}", e);
            false
        }
    }
}

/// A Hypervisor driver for HyperV-on-Linux. This hypervisor is often
/// called the Microsoft Hypervisor (MSHV)
pub(super) struct HypervLinuxDriver {
    _mshv: Mshv,
    vm_fd: VmFd,
    vcpu_fd: VcpuFd,
    entrypoint: u64,
    mem_regions: Vec<MemoryRegion>,
    orig_rsp: GuestPtr,
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
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn new(
        mem_regions: Vec<MemoryRegion>,
        entrypoint_ptr: GuestPtr,
        rsp_ptr: GuestPtr,
        pml4_ptr: GuestPtr,
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
            vm_fd
        };

        let mut vcpu_fd = vm_fd.create_vcpu(0)?;

        mem_regions.iter().try_for_each(|region| {
            let mshv_region = region.to_owned().into();
            vm_fd.map_user_memory(mshv_region)
        })?;

        Self::setup_initial_sregs(&mut vcpu_fd, pml4_ptr.absolute()?)?;

        Ok(Self {
            _mshv: mshv,
            vm_fd,
            vcpu_fd,
            mem_regions,
            entrypoint: entrypoint_ptr.absolute()?,
            orig_rsp: rsp_ptr,
        })
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn setup_initial_sregs(vcpu: &mut VcpuFd, pml4_addr: u64) -> Result<()> {
        let sregs = SpecialRegisters {
            cr0: CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP,
            cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
            cr3: pml4_addr,
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
        vcpu.set_sregs(&sregs)?;
        Ok(())
    }
}

impl Debug for HypervLinuxDriver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Hyperv Linux Driver");

        f.field("Entrypoint", &self.entrypoint)
            .field("Original RSP", &self.orig_rsp);

        for region in &self.mem_regions {
            f.field("Memory Region", &region);
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

impl Hypervisor for HypervLinuxDriver {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn initialise(
        &mut self,
        peb_addr: RawPtr,
        seed: u64,
        page_size: u32,
        outb_hdl: OutBHandlerWrapper,
        mem_access_hdl: MemAccessHandlerWrapper,
        hv_handler: Option<HypervisorHandler>,
    ) -> Result<()> {
        let regs = StandardRegisters {
            rip: self.entrypoint,
            rsp: self.orig_rsp.absolute()?,
            rflags: 2, //bit 1 of rlags is required to be set

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
        )?;

        // reset RSP to what it was before initialise
        self.vcpu_fd.set_regs(&StandardRegisters {
            rsp: self.orig_rsp.absolute()?,
            rflags: 2, //bit 1 of rlags is required to be set
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
    ) -> Result<()> {
        // Reset general purpose registers except RSP, then set RIP
        let rsp_before = self.vcpu_fd.get_regs()?.rsp;
        let regs = StandardRegisters {
            rip: dispatch_func_addr.into(),
            rsp: rsp_before,
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
            hv_handler,
            outb_handle_fn,
            mem_access_fn,
        )?;

        // reset RSP to what it was before function call
        self.vcpu_fd.set_regs(&StandardRegisters {
            rsp: rsp_before,
            rflags: 2, //bit 1 of rlags is required to be set
            ..Default::default()
        })?;
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
        let payload = data[..8].try_into()?;
        outb_handle_fn
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .call(port, u64::from_le_bytes(payload))?;

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

        #[cfg(mshv2)]
        let run_result = {
            let hv_message: hv_message = Default::default();
            &self.vcpu_fd.run(hv_message)
        };
        #[cfg(mshv3)]
        let run_result = &self.vcpu_fd.run();

        let result = match run_result {
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
                    match self.get_memory_access_violation(
                        gpa as usize,
                        &self.mem_regions,
                        access_info,
                    ) {
                        Some(access_info_violation) => access_info_violation,
                        None => HyperlightExit::Mmio(gpa),
                    }
                }
                other => {
                    crate::debug!("mshv Other Exit: Exit: {:#?} \n {:#?}", other, &self);
                    log_then_return!("unknown Hyper-V run message type {:?}", other);
                }
            },
            Err(e) => match e.errno() {
                // we send a signal to the thread to cancel execution this results in EINTR being returned by KVM so we return Cancelled
                libc::EINTR => HyperlightExit::Cancelled(),
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

    #[cfg(crashdump)]
    fn get_memory_regions(&self) -> &[MemoryRegion] {
        &self.mem_regions
    }
}

impl Drop for HypervLinuxDriver {
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    fn drop(&mut self) {
        for region in &self.mem_regions {
            let mshv_region: mshv_user_mem_region = region.to_owned().into();
            match self.vm_fd.unmap_user_memory(mshv_region) {
                Ok(_) => (),
                Err(e) => error!("Failed to unmap user memory in HyperVOnLinux ({:?})", e),
            }
        }
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
    pub(crate) static SHOULD_RUN_TEST: Lazy<bool> = Lazy::new(is_hyperv_present);

    fn is_hyperv_present() -> bool {
        println!(
            "HYPERV_SHOULD_BE_PRESENT is {}",
            TEST_CONFIG.hyperv_should_be_present
        );
        let is_present = super::is_hypervisor_present();
        if (is_present && !TEST_CONFIG.hyperv_should_be_present)
            || (!is_present && TEST_CONFIG.hyperv_should_be_present)
        {
            panic!(
                "WARNING Hyper-V is present returned  {}, should be present is: {}",
                is_present, TEST_CONFIG.hyperv_should_be_present
            );
        }
        is_present
    }

    fn hyperv_should_be_present_default() -> bool {
        false
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct TestConfig {
        #[serde(default = "hyperv_should_be_present_default")]
        // Set env var HYPERV_SHOULD_BE_PRESENT to require hyperv to be present for the tests.
        pub(crate) hyperv_should_be_present: bool,
    }

    #[macro_export]
    macro_rules! should_run_hyperv_linux_test {
        () => {{
            if !(*SHOULD_RUN_TEST) {
                println! {"Not Running Test SHOULD_RUN_TEST is false"}
                return;
            }
            println! {"Running Test SHOULD_RUN_TEST is true"}
        }};
    }
}

#[cfg(test)]
mod tests {
    use super::test_cfg::{SHOULD_RUN_TEST, TEST_CONFIG};
    use super::*;
    use crate::mem::memory_region::MemoryRegionVecBuilder;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, SharedMemory};
    use crate::should_run_hyperv_linux_test;

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
    fn is_hypervisor_present() {
        let result = super::is_hypervisor_present();
        assert_eq!(result, TEST_CONFIG.hyperv_should_be_present);
    }

    #[test]
    fn create_driver() {
        should_run_hyperv_linux_test!();
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
        super::HypervLinuxDriver::new(regions.build(), entrypoint_ptr, rsp_ptr, pml4_ptr).unwrap();
    }
}
