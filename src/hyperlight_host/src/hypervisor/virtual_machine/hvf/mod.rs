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

//! # Bridging Hyperlight's assumptions with Hypervisor.framework
//!
//! Hypervisor.framework has some constraints that run counter to the
//! flexibility provided by the usual Hyperlight API. In particular,
//! hvf assumes that there is only <= 1 VM per process, and <= 1 VCPU
//! per thread.
//!
//! ## Supporting more than one Sandbox per process
//!
//! This is not yet implemented, but we plan to support >1 sandbox per
//! process by using nested virtualisation on platforms where it is
//! available, making each sandbox a nested guest VM. This does,
//! unfortunately, of course have some performance implications.
//!
//! ## Supporting [`core::marker::Send`] on Sandboxes
//!
//! The Hyperlight public API constraints sandboxes (and, by
//! extension, hypervisor API implementations) to implement
//! [`core::marker::Send`]. Other hypervisors have one vCPU but allow
//! the vCPU handle to be mgirated across threads, although this comes
//! with severe performance impact in some cases (e.g. KVM).
//!
//! Unfortunately, this does not work on hvf, since cross-thread
//! access is prohibited (most `hv_vcpu_` functions note that "This
//! function must be called by the owning thread") rather than merely
//! unperformant.
//!
//! There are, largely, two approaches that we could use to work
//! around this. We could either:
//!
//! 1. Create a dedicated vcpu thread, and implement sandbox
//!    operations as RPCs to that thread
//! 2. Create one vcpu per thread-from-which-a-Sandbox-is-used, and
//!    reset that vcpu's state to match the correct sandbox whenever a
//!    sandbox operation is called.
//!
//! A long time ago, Hyperlight briefly unconditionally used approach
//! (1) on all hypervisors, but it had unacceptable performance impact
//! on most of them.
//!
//! Although an implementation of (1) scoped just to hvf could make
//! sense, this module presently implements (2), on the rationale that
//! it ought to be /possible/ for a host application to get decent
//! performance out of (2) (if the host application exercises some
//! discipline and uses a 1:1 mapping between sandboxes and threads;
//! although there is some unavoidable overhead due to needing to sync
//! registers on every VM exit, unfortunately), but an implementation
//! based on (1) would have to create the thread up-front (not knowing
//! if the sandbox would in fact be Sent to another thread) and so
//! would impose unavoidable overhead on all consumers.
//!
//! Applications which wish to use multiple sandboxes per thread, or
//! multiple threads per sandbox, and to have decent performance on
//! Hypervisor.framework, should consider (and benchmark!) the
//! alternative architecture of keeping the sandbox itself on a single
//! thread and pass data/make RPCs to/from that thread.

use core::cell::RefCell;
use core::ffi;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hyperlight_common::outb::VmAction;
use parking_lot::{Mutex, MutexGuard};

use super::{
    CreateVmError, HvfSyncError, HypervisorError, MapMemoryError, RegisterError, ResetVcpuError,
    RunVcpuError, UnmapMemoryError, VirtualMachine, VmExit,
};
use crate::hypervisor::InterruptHandleImpl;
use crate::hypervisor::regs::{
    CommonDebugRegs, CommonFpu, CommonRegisters, CommonSpecialRegisters,
};
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};

#[allow(
    dead_code,
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types
)] // bindgen
pub(crate) mod bindings {
    include!(concat!(env!("OUT_DIR"), "/hvf_bindings.rs"));
    impl hv_return_t {
        pub(super) fn is_success(&self) -> Result<(), super::HypervisorError> {
            if self.0.0.0 == HV_SUCCESS {
                Ok(())
            } else {
                Err(super::HypervisorError::HvfError(*self))
            }
        }
        pub(super) fn unless_success<T>(
            &self,
            f: impl Fn(super::HypervisorError) -> T,
        ) -> Result<(), T> {
            self.is_success().map_err(f)
        }
    }
    impl core::fmt::Display for hv_return_t {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
            write!(f, "0x{:x}", self.0.0.0)
        }
    }
    // the default base-10 signed printout is totally useless
    impl core::fmt::Debug for hv_return_t {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
            write!(f, "0x{:x}", self.0.0.0)
        }
    }
}

pub(super) fn is_hypervisor_present() -> bool {
    let mut val: ffi::c_int = 0;
    let mut len: usize = core::mem::size_of::<ffi::c_int>();
    let ret = unsafe {
        libc::sysctlbyname(
            c"kern.hv_support".as_ptr(),
            &raw mut val as *mut ffi::c_void,
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    ret == 0 && val == 1
}

// Used to figure out when registers have been updated since the last
// time that the sandbox ran on this vcpu & need to be sync'd back.
#[derive(Clone, Copy, Default, Debug)]
struct EpochStamped<T> {
    value: T,
    epoch: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
struct SandboxId(u64);

struct HvfCpu {
    id: bindings::hv_vcpu_t,
    exit: *mut bindings::hv_vcpu_exit_t,
    current_loaded: Option<EpochStamped<SandboxId>>,

    // reset_vcpu() needs to destroy the current vcpu before it can
    // create the new one, but when it creates the new one and assigns
    // it to the thread-local, the HvfCpu for the old one will be
    // dropped. This lets the Drop implementation know that that has
    // happened and avoid destroying the cpu a second time.
    destroyed_in_reset_vcpu: bool,
}

impl HvfCpu {
    /// Must be called only once per thread.
    fn new() -> Result<Self, HypervisorError> {
        use core::mem::MaybeUninit;
        let mut vcpu: MaybeUninit<bindings::hv_vcpu_t> = MaybeUninit::zeroed();
        let mut exit: *mut bindings::hv_vcpu_exit_t = core::ptr::null_mut();
        unsafe {
            let config = bindings::hv_vcpu_config_create();
            bindings::hv_vcpu_create(vcpu.as_mut_ptr(), &raw mut exit, config)
        }
        .is_success()?;
        Ok(Self {
            id: unsafe { vcpu.assume_init() },
            exit,
            current_loaded: None,
            destroyed_in_reset_vcpu: false,
        })
    }

    fn reset_vcpu(&mut self) -> Result<(), HypervisorError> {
        // TODO: figure out if there is a more efficient way to clear
        // all the state
        unsafe { bindings::hv_vcpu_destroy(self.id) }.is_success()?;
        self.destroyed_in_reset_vcpu = true;
        *self = HvfCpu::new()?;
        Ok(())
    }

    fn hv_vcpu_get_reg(&self, reg: bindings::hv_reg_t) -> Result<u64, HypervisorError> {
        let mut value: u64 = 0;
        unsafe { bindings::hv_vcpu_get_reg(self.id, reg, &raw mut value) }.is_success()?;
        Ok(value)
    }

    fn hv_vcpu_set_reg(
        &mut self,
        reg: bindings::hv_reg_t,
        value: u64,
    ) -> Result<(), HypervisorError> {
        unsafe { bindings::hv_vcpu_set_reg(self.id, reg, value) }.is_success()
    }

    fn hv_vcpu_get_simd_fp_reg(
        &self,
        reg: bindings::hv_simd_fp_reg_t,
    ) -> Result<u128, HypervisorError> {
        let mut value: [u8; 16] = [0; 16];
        unsafe {
            bindings::hv_vcpu_get_simd_fp_reg_rsabi(self.id, reg, value.as_mut_ptr() as *mut i8)
        }
        .is_success()?;
        Ok(u128::from_ne_bytes(value))
    }

    fn hv_vcpu_set_simd_fp_reg(
        &mut self,
        reg: bindings::hv_simd_fp_reg_t,
        value: u128,
    ) -> Result<(), HypervisorError> {
        let bytes: [u8; 16] = value.to_ne_bytes();
        unsafe {
            bindings::hv_vcpu_set_simd_fp_reg_rsabi(self.id, reg, bytes.as_ptr() as *const i8)
        }
        .is_success()
    }

    fn hv_vcpu_get_sys_reg(&self, reg: bindings::hv_sys_reg_t) -> Result<u64, HypervisorError> {
        let mut value: u64 = 0;
        unsafe { bindings::hv_vcpu_get_sys_reg(self.id, reg, &raw mut value) }.is_success()?;
        Ok(value)
    }

    fn hv_vcpu_set_sys_reg(
        &mut self,
        reg: bindings::hv_sys_reg_t,
        value: u64,
    ) -> Result<(), HypervisorError> {
        unsafe { bindings::hv_vcpu_set_sys_reg(self.id, reg, value) }.is_success()
    }

    fn set_vcpu_regs(&mut self, regs: &CommonRegisters) -> Result<(), HypervisorError> {
        use bindings::{hv_reg_t, hv_sys_reg_t};
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X0, regs.x[0])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X1, regs.x[1])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X2, regs.x[2])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X3, regs.x[3])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X4, regs.x[4])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X5, regs.x[5])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X6, regs.x[6])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X7, regs.x[7])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X8, regs.x[8])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X9, regs.x[9])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X10, regs.x[10])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X11, regs.x[11])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X12, regs.x[12])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X13, regs.x[13])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X14, regs.x[14])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X15, regs.x[15])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X16, regs.x[16])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X17, regs.x[17])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X18, regs.x[18])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X19, regs.x[19])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X20, regs.x[20])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X21, regs.x[21])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X22, regs.x[22])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X23, regs.x[23])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X24, regs.x[24])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X25, regs.x[25])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X26, regs.x[26])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X27, regs.x[27])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X28, regs.x[28])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X29, regs.x[29])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_X30, regs.x[30])?;
        // set SP_EL0 or SP_EL1 depending on SPSel
        if regs.pstate & 0x1 == 0x1 {
            self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL1, regs.sp)?;
        } else {
            self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL0, regs.sp)?;
        }
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_PC, regs.pc)?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_CPSR, regs.pstate)?;
        Ok(())
    }

    fn get_vcpu_regs(&self) -> Result<CommonRegisters, HypervisorError> {
        use bindings::{hv_reg_t, hv_sys_reg_t};
        let pstate = self.hv_vcpu_get_reg(hv_reg_t::HV_REG_CPSR)?;
        Ok(CommonRegisters {
            x: [
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X0)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X1)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X2)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X3)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X4)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X5)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X6)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X7)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X8)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X9)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X10)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X11)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X12)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X13)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X14)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X15)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X16)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X17)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X18)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X19)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X20)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X21)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X22)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X23)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X24)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X25)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X26)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X27)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X28)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X29)?,
                self.hv_vcpu_get_reg(hv_reg_t::HV_REG_X30)?,
            ],
            sp: if pstate & 0x1 == 0x1 {
                self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL1)?
            } else {
                self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL0)?
            },
            pc: self.hv_vcpu_get_reg(hv_reg_t::HV_REG_PC)?,
            pstate,
        })
    }

    fn set_vcpu_fpregs(&mut self, regs: &CommonFpu) -> Result<(), HypervisorError> {
        use bindings::{hv_reg_t, hv_simd_fp_reg_t};
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q0, regs.v[0])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q1, regs.v[1])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q2, regs.v[2])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q3, regs.v[3])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q4, regs.v[4])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q5, regs.v[5])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q6, regs.v[6])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q7, regs.v[7])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q8, regs.v[8])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q9, regs.v[9])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q10, regs.v[10])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q11, regs.v[11])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q12, regs.v[12])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q13, regs.v[13])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q14, regs.v[14])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q15, regs.v[15])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q16, regs.v[16])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q17, regs.v[17])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q18, regs.v[18])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q19, regs.v[19])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q20, regs.v[20])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q21, regs.v[21])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q22, regs.v[22])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q23, regs.v[23])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q24, regs.v[24])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q25, regs.v[25])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q26, regs.v[26])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q27, regs.v[27])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q28, regs.v[28])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q29, regs.v[29])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q30, regs.v[30])?;
        self.hv_vcpu_set_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q31, regs.v[31])?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_FPSR, regs.fpsr as u64)?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_FPCR, regs.fpcr as u64)?;
        Ok(())
    }

    fn get_vcpu_fpregs(&mut self) -> Result<CommonFpu, HypervisorError> {
        use bindings::{hv_reg_t, hv_simd_fp_reg_t};
        Ok(CommonFpu {
            v: [
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q0)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q1)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q2)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q3)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q4)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q5)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q6)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q7)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q8)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q9)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q10)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q11)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q12)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q13)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q14)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q15)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q16)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q17)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q18)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q19)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q20)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q21)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q22)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q23)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q24)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q25)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q26)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q27)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q28)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q29)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q30)?,
                self.hv_vcpu_get_simd_fp_reg(hv_simd_fp_reg_t::HV_SIMD_FP_REG_Q31)?,
            ],
            fpsr: self.hv_vcpu_get_reg(hv_reg_t::HV_REG_FPSR)? as u32,
            fpcr: self.hv_vcpu_get_reg(hv_reg_t::HV_REG_FPCR)? as u32,
        })
    }

    fn set_vcpu_sregs(&mut self, regs: &CommonSpecialRegisters) -> Result<(), HypervisorError> {
        use bindings::hv_sys_reg_t;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_TTBR0_EL1, regs.ttbr0_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_TCR_EL1, regs.tcr_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_MAIR_EL1, regs.mair_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_SCTLR_EL1, regs.sctlr_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_CPACR_EL1, regs.cpacr_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_VBAR_EL1, regs.vbar_el1)?;
        self.hv_vcpu_set_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL1, regs.sp_el1)?;
        Ok(())
    }

    fn get_vcpu_sregs(&self) -> Result<CommonSpecialRegisters, HypervisorError> {
        use bindings::hv_sys_reg_t;
        Ok(CommonSpecialRegisters {
            ttbr0_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_TTBR0_EL1)?,
            tcr_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_TCR_EL1)?,
            mair_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_MAIR_EL1)?,
            sctlr_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_SCTLR_EL1)?,
            cpacr_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_CPACR_EL1)?,
            vbar_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_VBAR_EL1)?,
            sp_el1: self.hv_vcpu_get_sys_reg(hv_sys_reg_t::HV_SYS_REG_SP_EL1)?,
        })
    }

    fn sync_state_from(
        &mut self,
        sandbox_id: EpochStamped<SandboxId>,
        regs: &EpochStamped<CommonRegisters>,
        sregs: &EpochStamped<CommonSpecialRegisters>,
        fpregs: &EpochStamped<CommonFpu>,
    ) -> Result<u64, HvfSyncError> {
        let (regs_dirty, fpregs_dirty, sregs_dirty) = match self.current_loaded {
            None => (true, true, true),
            Some(s) => {
                if sandbox_id.value != s.value || sandbox_id.epoch > s.epoch {
                    self.reset_vcpu().map_err(HvfSyncError::ResetVcpu)?;
                    (true, true, true)
                } else {
                    (
                        regs.epoch > s.epoch,
                        fpregs.epoch > s.epoch,
                        sregs.epoch > s.epoch,
                    )
                }
            }
        };
        if regs_dirty {
            self.set_vcpu_regs(&regs.value)
                .map_err(RegisterError::SetRegs)?;
        }
        if fpregs_dirty {
            self.set_vcpu_fpregs(&fpregs.value)
                .map_err(RegisterError::SetFpu)?;
        }
        if sregs_dirty {
            self.set_vcpu_sregs(&sregs.value)
                .map_err(RegisterError::SetSregs)?;
        }
        let sync_epoch = core::cmp::max(sandbox_id.epoch, core::cmp::max(regs.epoch, sregs.epoch));
        self.current_loaded = Some(EpochStamped {
            value: sandbox_id.value,
            epoch: sync_epoch,
        });
        Ok(sync_epoch)
    }

    fn sync_state_from_vm(&mut self, vm: &mut HvfVm) -> Result<(), HvfSyncError> {
        let epoch = self.sync_state_from(vm.id, &vm.regs, &vm.sregs, &vm.fpu)?;
        // update epoch eagerly, since at this point the vcpu
        // epoch has been updated to the max, so if we returned early (e.g. due
        // to an error in the next call(s)) it would be possible
        // to miss updates
        vm.id.epoch = epoch;
        vm.regs.epoch = epoch;
        vm.fpu.epoch = epoch;
        vm.sregs.epoch = epoch;
        Ok(())
    }

    fn sync_state_to_vm(&mut self, vm: &mut HvfVm) -> Result<(), HvfSyncError> {
        let Some(EpochStamped {
            value: sandbox_id,
            epoch,
        }) = self.current_loaded
        else {
            // sync_state_to_vm is always used just after
            // sync_state_from_vm, so this should be impossible
            debug_assert!(false);
            return Err(HvfSyncError::SyncInvariant(
                "Missing loaded sandbox".to_string(),
            ));
        };
        if sandbox_id != vm.id.value {
            // sync_state_to_vm is always used just after
            // sync_state_from_vm, so this should be impossible
            debug_assert!(false);
            return Err(HvfSyncError::SyncInvariant(
                "Wrong loaded sandbox".to_string(),
            ));
        }
        vm.id.epoch = epoch;
        vm.regs = EpochStamped {
            value: self.get_vcpu_regs().map_err(RegisterError::GetRegs)?,
            epoch,
        };
        vm.fpu = EpochStamped {
            value: self.get_vcpu_fpregs().map_err(RegisterError::GetFpu)?,
            epoch,
        };
        vm.sregs = EpochStamped {
            value: self.get_vcpu_sregs().map_err(RegisterError::GetSregs)?,
            epoch,
        };
        Ok(())
    }

    fn advance_pc(&mut self) -> Result<(), HypervisorError> {
        use bindings::hv_reg_t;
        let old_pc = self.hv_vcpu_get_reg(hv_reg_t::HV_REG_PC)?;
        self.hv_vcpu_set_reg(hv_reg_t::HV_REG_PC, old_pc + 4)?;
        Ok(())
    }

    fn run(&mut self) -> Result<VmExit, HypervisorError> {
        let ret = unsafe { bindings::hv_vcpu_run(self.id) };
        if let Some(EpochStamped { ref mut epoch, .. }) = self.current_loaded {
            *epoch += 1;
        }
        ret.is_success()?;
        let exit = unsafe { self.exit.read() };

        use bindings::hv_exit_reason_t;
        let hl_exit = match exit.reason {
            hv_exit_reason_t::HV_EXIT_REASON_CANCELED => VmExit::Cancelled(),
            hv_exit_reason_t::HV_EXIT_REASON_EXCEPTION => {
                #[inline(always)]
                fn bits<const HIGH_BIT: u8, const LOW_BIT: u8>(x: u64) -> u64 {
                    (x & ((1 << (HIGH_BIT + 1)) - 1)) >> LOW_BIT
                }

                let esr = exit.exception.syndrome.0;
                let ipa = exit.exception.physical_address.0;

                let unknown_exit = VmExit::Unknown(format!(
                    "Unknown HVF vcpu exit ESR_EL2: {:16x} IPA {:16x}",
                    esr, ipa,
                ));

                const ESR_EL2_EC_DATA_ABORT_LOWER_EL: u64 = 0b100100;
                let ec = bits::<31, 26>(esr);
                let isv = bits::<24, 24>(esr);
                if ec == ESR_EL2_EC_DATA_ABORT_LOWER_EL && isv == 0b1 {
                    let is_translation_fault =
                        bits::<5, 2>(esr) == 0b0001 || bits::<5, 0>(esr) == 0b101011;
                    let is_permission_fault = bits::<5, 2>(esr) == 0b0011;
                    if is_translation_fault || is_permission_fault {
                        // For MMIO exits, always resume after the
                        // faulting instruction to match kvm behaviour
                        self.advance_pc()?;

                        let wnr = bits::<6, 6>(esr);
                        if wnr == 1 {
                            let io_page_gpa =
                                const { hyperlight_common::layout::io_page().unwrap().0 };
                            if ipa >= io_page_gpa
                                && let off = (ipa - io_page_gpa) as usize
                                && off < hyperlight_common::vmem::PAGE_SIZE
                            {
                                let port = off / core::mem::size_of::<u64>();
                                if port == VmAction::Halt as usize {
                                    VmExit::Halt()
                                } else {
                                    let srt = bits::<20, 16>(esr);
                                    let data = self.get_vcpu_regs()?.x[srt as usize];
                                    VmExit::IoOut(port as u16, data.to_ne_bytes().to_vec())
                                }
                            } else {
                                VmExit::MmioWrite(ipa)
                            }
                        } else {
                            VmExit::MmioRead(ipa)
                        }
                    } else {
                        unknown_exit
                    }
                } else {
                    unknown_exit
                }
            }
            reason => VmExit::Unknown(format!("Unknown HVF vcpu exit reason: {}", reason.0)),
        };
        Ok(hl_exit)
    }
}

impl Drop for HvfCpu {
    fn drop(&mut self) {
        unsafe {
            if !self.destroyed_in_reset_vcpu {
                bindings::hv_vcpu_destroy(self.id);
            };
        }
    }
}

std::thread_local! {
    static HVF_VCPU: RefCell<Option<HvfCpu>> = const { RefCell::new(None) };
}

#[derive(Debug)]
pub(crate) struct HvfVm {
    id: EpochStamped<SandboxId>,
    regs: EpochStamped<CommonRegisters>,
    fpu: EpochStamped<CommonFpu>,
    sregs: EpochStamped<CommonSpecialRegisters>,
    memory_space: MemorySpace,
    interrupt_handle: Arc<dyn InterruptHandleImpl>,
}

static HV_VM_CREATED: AtomicBool = AtomicBool::new(false);

impl HvfVm {
    pub(crate) fn new(
        interrupt_handle: Arc<dyn InterruptHandleImpl>,
    ) -> Result<Self, CreateVmError> {
        static NEXT_AVAILABLE_ID: AtomicU64 = AtomicU64::new(0);
        // If the vm for this process has not yet been created, create it
        if !HV_VM_CREATED.swap(true, Ordering::Relaxed) {
            let cfg = unsafe { bindings::hv_vm_config_create() };
            unsafe { bindings::hv_vm_create(cfg) }.unless_success(|e| {
                HV_VM_CREATED.store(false, Ordering::Relaxed);
                CreateVmError::CreateVmFd(e)
            })?
        }
        Ok(Self {
            id: EpochStamped {
                value: SandboxId(NEXT_AVAILABLE_ID.fetch_add(1, Ordering::Relaxed)),
                epoch: 0,
            },
            regs: Default::default(),
            fpu: Default::default(),
            sregs: Default::default(),
            memory_space: MemorySpace::new(),
            interrupt_handle,
        })
    }
}

impl From<MemoryRegionFlags> for bindings::hv_memory_flags_t {
    fn from(mrf: MemoryRegionFlags) -> bindings::hv_memory_flags_t {
        let mut flags: bindings::hv_memory_flags_t = 0;
        if mrf.contains(MemoryRegionFlags::READ) {
            flags |= bindings::HV_MEMORY_READ as bindings::hv_memory_flags_t;
        }
        if mrf.contains(MemoryRegionFlags::WRITE) {
            flags |= bindings::HV_MEMORY_WRITE as bindings::hv_memory_flags_t;
        }
        if mrf.contains(MemoryRegionFlags::EXECUTE) {
            flags |= bindings::HV_MEMORY_EXEC as bindings::hv_memory_flags_t;
        }
        flags
    }
}

struct LoadedMemorySpace {
    space_id: Option<u64>,
    mappings: Vec<Option<MemoryRegion>>,
}
impl LoadedMemorySpace {
    const fn new() -> Self {
        Self {
            space_id: None,
            mappings: Vec::new(),
        }
    }
    fn do_map(region: &MemoryRegion) -> Result<(), HypervisorError> {
        unsafe {
            bindings::hv_vm_map(
                region.host_region.start as *mut core::ffi::c_void,
                bindings::hv_ipa_t(region.guest_region.start as u64),
                region.guest_region.end - region.guest_region.start,
                region.flags.into(),
            )
        }
        .is_success()
    }
    fn do_unmap(region: &MemoryRegion) -> Result<(), HypervisorError> {
        unsafe {
            bindings::hv_vm_unmap(
                bindings::hv_ipa_t(region.guest_region.start as u64),
                region.guest_region.end - region.guest_region.start,
            )
        }
        .is_success()
    }
    fn update_mapping(
        &mut self,
        slot: usize,
        region: Option<MemoryRegion>,
    ) -> Result<(), HypervisorError> {
        if self.mappings.len() <= slot {
            self.mappings.resize(slot + 1, None);
        }
        if let Some(ref old_region) = self.mappings[slot] {
            Self::do_unmap(old_region)?;
        }
        if let Some(ref new_region) = region {
            Self::do_map(new_region)?;
        }
        self.mappings[slot] = region;
        Ok(())
    }
    #[allow(clippy::collapsible_if, clippy::manual_flatten)]
    fn sync_space(&mut self, space: &MemorySpace) -> Result<(), HypervisorError> {
        if self.space_id == Some(space.id) {
            return Ok(());
        }
        self.space_id = Some(space.id);
        for mapping in &self.mappings {
            if let Some(region) = mapping {
                Self::do_unmap(region)?
            }
        }
        self.mappings = space.mappings.clone();
        for mapping in &self.mappings {
            if let Some(region) = mapping {
                Self::do_map(region)?
            }
        }
        Ok(())
    }
}
static CURRENT_LOADED_MEMORY_SPACE: Mutex<LoadedMemorySpace> = Mutex::new(LoadedMemorySpace::new());
#[derive(Debug)]
struct MemorySpace {
    id: u64,
    mappings: Vec<Option<MemoryRegion>>,
}
struct MemorySpaceInstalledGuard<'a> {
    _loaded_mutex_guard: MutexGuard<'a, LoadedMemorySpace>,
}
enum MemorySpaceInstallError {
    Sync(HypervisorError),
    Timeout,
}
impl MemorySpace {
    fn new() -> Self {
        static NEXT_AVAILABLE_ID: AtomicU64 = AtomicU64::new(0);
        Self {
            id: NEXT_AVAILABLE_ID.fetch_add(1, Ordering::Relaxed),
            mappings: Vec::new(),
        }
    }

    /// This function is used both as a performance optimisation e(when
    /// this space is not being swapped out) and in order to allow
    /// [`unmap_memory`] to guarantee that the region is no longer in
    /// use in the kernel when it returns.
    fn opportunistically_sync_slot(&mut self, slot: usize) -> Result<(), HypervisorError> {
        // It suffices to use try_lock() here: if try_lock fails,
        // then the lock is currently being held, but it must be held
        // by a different memory space (since we have an &mut self
        // reference)
        if let Some(mut current) = CURRENT_LOADED_MEMORY_SPACE.try_lock()
            && current.space_id == Some(self.id)
        {
            current.update_mapping(slot, self.mappings[slot].clone())?;
        }
        Ok(())
    }

    fn map_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<(), HypervisorError> {
        let slot = region.0 as usize;
        if self.mappings.len() <= slot {
            self.mappings.resize(slot + 1, None);
        }
        self.mappings[slot] = Some(region.1.clone());
        self.opportunistically_sync_slot(slot)
    }

    fn unmap_memory(&mut self, region: (u32, &MemoryRegion)) -> Result<(), HypervisorError> {
        let slot = region.0 as usize;
        if self.mappings.len() <= slot {
            self.mappings.resize(slot + 1, None);
        }
        self.mappings[slot] = None;
        self.opportunistically_sync_slot(slot)
    }

    fn install_in_cpu(
        &mut self,
        _cpu: &mut HvfCpu,
    ) -> Result<MemorySpaceInstalledGuard<'_>, MemorySpaceInstallError> {
        let mut guard = CURRENT_LOADED_MEMORY_SPACE
            .try_lock_for(Duration::from_millis(50))
            .ok_or(MemorySpaceInstallError::Timeout)?;
        guard
            .sync_space(self)
            .map_err(MemorySpaceInstallError::Sync)?;
        Ok(MemorySpaceInstalledGuard {
            _loaded_mutex_guard: guard,
        })
    }
}

impl VirtualMachine for HvfVm {
    unsafe fn map_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), MapMemoryError> {
        self.memory_space
            .map_memory(region)
            .map_err(MapMemoryError::Hypervisor)
    }

    fn unmap_memory(
        &mut self,
        region: (u32, &MemoryRegion),
    ) -> std::result::Result<(), UnmapMemoryError> {
        self.memory_space
            .unmap_memory(region)
            .map_err(UnmapMemoryError::Hypervisor)
    }

    fn run_vcpu(
        &mut self,
        #[cfg(feature = "trace_guest")] tc: &mut SandboxTraceContext,
    ) -> std::result::Result<VmExit, RunVcpuError> {
        HVF_VCPU.with_borrow_mut(|vcpu| {
            // Sadly, Option::get_or_try_insert_with() is not yet stable :(
            let vcpu = match vcpu {
                None => vcpu.insert(
                    HvfCpu::new()
                        .map_err(HvfSyncError::CreateVcpu)
                        .map_err(RunVcpuError::HvfSync)?,
                ),
                Some(v) => v,
            };
            self.interrupt_handle.set_vcpu(vcpu.id);
            vcpu.sync_state_from_vm(self)
                .map_err(RunVcpuError::HvfSync)?;
            // TODO: replace unwrap()
            let space_installed_guard = loop {
                match self.memory_space.install_in_cpu(vcpu) {
                    Ok(guard) => break guard,
                    Err(MemorySpaceInstallError::Sync(e)) => {
                        return Err(RunVcpuError::HvfSync(HvfSyncError::MemorySpace(e)));
                    }
                    Err(MemorySpaceInstallError::Timeout) => {
                        let (_, cancel, debug) =
                            self.interrupt_handle.state().get_running_cancel_debug();
                        if cancel || debug {
                            return Ok(VmExit::Cancelled());
                        } else {
                            continue;
                        }
                    }
                }
            };
            let exit = vcpu.run().map_err(RunVcpuError::Unknown)?;
            drop(space_installed_guard);
            vcpu.sync_state_to_vm(self).map_err(RunVcpuError::HvfSync)?;
            Ok(exit)
        })
    }

    fn regs(&self) -> std::result::Result<CommonRegisters, RegisterError> {
        Ok(self.regs.value)
    }

    fn set_regs(&mut self, regs: &CommonRegisters) -> std::result::Result<(), RegisterError> {
        self.regs.value = *regs;
        self.regs.epoch += 1;
        Ok(())
    }

    fn fpu(&self) -> std::result::Result<CommonFpu, RegisterError> {
        Ok(self.fpu.value)
    }

    fn set_fpu(&mut self, fpu: &CommonFpu) -> std::result::Result<(), RegisterError> {
        self.fpu.value = *fpu;
        self.fpu.epoch += 1;
        Ok(())
    }

    fn sregs(&self) -> std::result::Result<CommonSpecialRegisters, RegisterError> {
        Ok(self.sregs.value)
    }

    fn set_sregs(
        &mut self,
        sregs: &CommonSpecialRegisters,
    ) -> std::result::Result<(), RegisterError> {
        self.sregs.value = *sregs;
        self.sregs.epoch += 1;
        Ok(())
    }

    fn debug_regs(&self) -> std::result::Result<CommonDebugRegs, RegisterError> {
        todo!()
    }

    fn set_debug_regs(&self, _drs: &CommonDebugRegs) -> std::result::Result<(), RegisterError> {
        todo!()
    }

    #[cfg(target_arch = "aarch64")]
    fn can_reset_vcpu(&self) -> bool {
        true
    }

    #[cfg(target_arch = "aarch64")]
    fn reset_vcpu(&mut self) -> std::result::Result<(), ResetVcpuError> {
        self.id.epoch += 1;
        Ok(())
    }
}
