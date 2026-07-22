/*
Copyright 2026 The Hyperlight Authors.

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

//! Thin wrapper over the Hypervisor.framework C API.
//!
//! Threading: HVF requires that a vCPU is created, run, and accessed
//! (register reads/writes) from a single thread. The only exception is
//! cancellation: `hv_vcpus_exit` may be called from any thread.

use std::collections::HashMap;
use std::ffi::c_void;

use applevisor_sys::{
    HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_error_t, hv_exit_reason_t,
    hv_ipa_granule_t, hv_reg_t, hv_simd_fp_reg_t, hv_sys_reg_t, hv_vcpu_create, hv_vcpu_destroy,
    hv_vcpu_exit_t, hv_vcpu_get_reg, hv_vcpu_get_simd_fp_reg, hv_vcpu_get_sys_reg, hv_vcpu_run,
    hv_vcpu_set_reg, hv_vcpu_set_simd_fp_reg, hv_vcpu_set_sys_reg, hv_vcpu_t, hv_vcpus_exit,
    hv_vm_config_create, hv_vm_config_set_ipa_granule, hv_vm_create, hv_vm_destroy, hv_vm_map,
    hv_vm_unmap, os_release,
};
use hyperlight_common::outb::VmAction;
use serde::{Deserialize, Serialize};

/// ESR_EL2 exception classes (EC field, bits [31:26]) relevant to this backend.
const EC_WFI_WFE: u64 = 0x01;
const EC_INST_ABORT: u64 = 0x20; // instruction abort from a lower EL
const EC_DATA_ABORT: u64 = 0x24; // data abort from a lower EL

/// ESR_EL2 ISS fields for aborts.
const ESR_ISV: u64 = 1 << 24; // instruction syndrome valid
const ESR_SAS_SHIFT: u64 = 22; // syndrome access size (log2 bytes)
const ESR_SRT_SHIFT: u64 = 16; // syndrome register transfer (X register index)
const ESR_WNR: u64 = 1 << 6; // write not read

/// Error returned by HVF operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum HvfError {
    /// A Hypervisor.framework call failed; payload is the `hv_return_t`.
    #[error("HVF error: {0:#x}")]
    Hv(u32),
    /// A data abort to the IO page arrived without a valid instruction
    /// syndrome, so the access details (register, size) cannot be decoded.
    #[error("HVF data abort without valid instruction syndrome")]
    NoInstructionSyndrome,
    /// The 4 KiB IPA granule could not be configured. Hyperlight requires
    /// it (the default 16 KiB granule is incompatible with 4 KiB-aligned
    /// guest regions); the granule API is available since macOS 26.
    #[error("HVF 4 KiB IPA granule is not supported (requires macOS 26 or later)")]
    IpaGranuleUnsupported,
}

/// Convert an `hv_return_t` into a `Result`.
fn check_hv(ret: i32) -> Result<(), HvfError> {
    if ret == hv_error_t::HV_SUCCESS as i32 {
        Ok(())
    } else {
        Err(HvfError::Hv(ret as u32))
    }
}

/// General-purpose register selectors indexed by X-register number (X0..X30).
const X_REGS: [hv_reg_t; 31] = [
    hv_reg_t::X0,
    hv_reg_t::X1,
    hv_reg_t::X2,
    hv_reg_t::X3,
    hv_reg_t::X4,
    hv_reg_t::X5,
    hv_reg_t::X6,
    hv_reg_t::X7,
    hv_reg_t::X8,
    hv_reg_t::X9,
    hv_reg_t::X10,
    hv_reg_t::X11,
    hv_reg_t::X12,
    hv_reg_t::X13,
    hv_reg_t::X14,
    hv_reg_t::X15,
    hv_reg_t::X16,
    hv_reg_t::X17,
    hv_reg_t::X18,
    hv_reg_t::X19,
    hv_reg_t::X20,
    hv_reg_t::X21,
    hv_reg_t::X22,
    hv_reg_t::X23,
    hv_reg_t::X24,
    hv_reg_t::X25,
    hv_reg_t::X26,
    hv_reg_t::X27,
    hv_reg_t::X28,
    hv_reg_t::X29,
    hv_reg_t::X30,
];

/// SIMD/FP register selectors indexed by Q-register number (Q0..Q31).
const Q_REGS: [hv_simd_fp_reg_t; 32] = [
    hv_simd_fp_reg_t::Q0,
    hv_simd_fp_reg_t::Q1,
    hv_simd_fp_reg_t::Q2,
    hv_simd_fp_reg_t::Q3,
    hv_simd_fp_reg_t::Q4,
    hv_simd_fp_reg_t::Q5,
    hv_simd_fp_reg_t::Q6,
    hv_simd_fp_reg_t::Q7,
    hv_simd_fp_reg_t::Q8,
    hv_simd_fp_reg_t::Q9,
    hv_simd_fp_reg_t::Q10,
    hv_simd_fp_reg_t::Q11,
    hv_simd_fp_reg_t::Q12,
    hv_simd_fp_reg_t::Q13,
    hv_simd_fp_reg_t::Q14,
    hv_simd_fp_reg_t::Q15,
    hv_simd_fp_reg_t::Q16,
    hv_simd_fp_reg_t::Q17,
    hv_simd_fp_reg_t::Q18,
    hv_simd_fp_reg_t::Q19,
    hv_simd_fp_reg_t::Q20,
    hv_simd_fp_reg_t::Q21,
    hv_simd_fp_reg_t::Q22,
    hv_simd_fp_reg_t::Q23,
    hv_simd_fp_reg_t::Q24,
    hv_simd_fp_reg_t::Q25,
    hv_simd_fp_reg_t::Q26,
    hv_simd_fp_reg_t::Q27,
    hv_simd_fp_reg_t::Q28,
    hv_simd_fp_reg_t::Q29,
    hv_simd_fp_reg_t::Q30,
    hv_simd_fp_reg_t::Q31,
];

/// General-purpose register state (EL1t guest: `sp` is SP_EL0).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Regs {
    /// X0..X30 (X29=FP, X30=LR)
    pub x: [u64; 31],
    /// SP_EL0 (the active stack pointer at EL1t)
    pub sp: u64,
    /// Program counter
    pub pc: u64,
    /// CPSR
    pub pstate: u64,
}

/// SIMD/FP register state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpuState {
    /// Q0..Q31
    pub v: [u128; 32],
    /// FPSR
    pub fpsr: u32,
    /// FPCR
    pub fpcr: u32,
}

/// System register state needed by Hyperlight guests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sregs {
    /// TTBR0_EL1
    pub ttbr0_el1: u64,
    /// TCR_EL1
    pub tcr_el1: u64,
    /// MAIR_EL1
    pub mair_el1: u64,
    /// SCTLR_EL1
    pub sctlr_el1: u64,
    /// CPACR_EL1
    pub cpacr_el1: u64,
    /// VBAR_EL1
    pub vbar_el1: u64,
    /// SP_EL1
    pub sp_el1: u64,
}

/// Memory permissions for a guest mapping.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Perms {
    /// Guest may read
    pub read: bool,
    /// Guest may write
    pub write: bool,
    /// Guest may execute
    pub exec: bool,
}

impl Perms {
    fn to_hv_flags(self) -> u64 {
        let mut flags = 0;
        if self.read {
            flags |= HV_MEMORY_READ;
        }
        if self.write {
            flags |= HV_MEMORY_WRITE;
        }
        if self.exec {
            flags |= HV_MEMORY_EXEC;
        }
        flags
    }
}

/// The reasons a vCPU run can exit, decoded from HVF exit info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmExit {
    /// The guest wrote to the halt "port" of the IO page
    Halt,
    /// The guest wrote `data` to the given IO-page port
    IoOut(u16, Vec<u8>),
    /// The guest read from the given unmapped GPA
    MmioRead(u64),
    /// The guest wrote to the given unmapped GPA
    MmioWrite(u64),
    /// The run was cancelled via [`cancel`]
    Cancelled,
    /// Any other exit
    Unknown(String),
}

/// Create the process-wide VM, requesting the 4 KiB IPA granule so that
/// 4 KiB-aligned guest regions can be mapped (the granule API requires
/// macOS 26; the default granule is 16 KiB, which Hyperlight's 4 KiB
/// guest page granule is incompatible with). Falls back to the default
/// configuration if the config object itself cannot be created.
fn create_vm() -> Result<(), HvfError> {
    // SAFETY: `hv_vm_config_create` returns a retained config object (or
    // null), which is released below.
    let config = unsafe { hv_vm_config_create() };
    if !config.is_null() {
        // SAFETY: `config` is a live VM config object.
        let ret = unsafe {
            let ret = hv_vm_config_set_ipa_granule(config, hv_ipa_granule_t::HV_IPA_GRANULE_4KB);
            if ret == hv_error_t::HV_SUCCESS as i32 {
                hv_vm_create(config)
            } else {
                ret
            }
        };
        // SAFETY: `config` is no longer needed.
        unsafe { os_release(config) };
        return check_hv(ret).map_err(|e| match e {
            // Most likely a pre-macOS 26 system without the granule API.
            HvfError::Hv(_) => HvfError::IpaGranuleUnsupported,
            e => e,
        });
    }
    // SAFETY: a null config creates a VM with the default configuration.
    check_hv(unsafe { hv_vm_create(std::ptr::null_mut()) })
}

/// Return `true` if Hypervisor.framework is available in this process.
///
/// Requires the calling binary to hold the `com.apple.security.hypervisor`
/// entitlement. Note that HVF allows only one live VM per process.
pub fn is_hypervisor_present() -> bool {
    if create_vm().is_err() {
        return false;
    }
    // SAFETY: the VM was just created above.
    unsafe { hv_vm_destroy() == hv_error_t::HV_SUCCESS as i32 }
}

/// Force the given vCPU out of `hv_vcpu_run`.
///
/// Safe to call from any thread; a stale cancel of a destroyed vCPU fails
/// harmlessly since vCPU IDs are kernel-validated.
pub fn cancel(vcpu: hv_vcpu_t) -> Result<(), HvfError> {
    // SAFETY: `hv_vcpus_exit` may be called from any thread.
    check_hv(unsafe { hv_vcpus_exit(&vcpu, 1) })
}

/// A single-vCPU HVF virtual machine.
///
/// HVF has no slot concept for guest memory; `mappings` tracks the
/// `(gpa, size)` of each slot given to [`Vm::map_memory`] so that slots can
/// be unmapped and replaced.
pub struct Vm {
    vcpu: hv_vcpu_t,
    /// Exit info written by `hv_vcpu_run` on the vCPU thread.
    exit: *const hv_vcpu_exit_t,
    /// Slot -> (guest physical address, size) of active mappings.
    mappings: HashMap<u32, (u64, usize)>,
}

// SAFETY: `Vm` is `Send` so it can be moved as part of a sandbox, but all
// vCPU operations (register access and `hv_vcpu_run`) must happen on the
// thread that created the vCPU, and `*const hv_vcpu_exit_t` is only
// dereferenced there.
unsafe impl Send for Vm {}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("vcpu", &self.vcpu)
            .field("mappings", &self.mappings)
            .finish()
    }
}

impl Vm {
    /// Create the process-wide VM and one vCPU on the current thread.
    ///
    /// Fails with `HV_BUSY` if a VM already exists in this process (HVF
    /// allows only one).
    pub fn new() -> Result<Self, HvfError> {
        create_vm()?;

        let mut vcpu: hv_vcpu_t = 0;
        let mut exit: *const hv_vcpu_exit_t = std::ptr::null();
        // SAFETY: `vcpu` and `exit` are valid out-pointers; a null config
        // creates a vCPU with the default configuration on the current thread.
        if let Err(e) =
            check_hv(unsafe { hv_vcpu_create(&mut vcpu, &mut exit, std::ptr::null_mut()) })
        {
            // Don't leak the process-wide VM on failure.
            // SAFETY: the VM was just created above and has no vCPUs.
            unsafe {
                let _ = hv_vm_destroy();
            }
            return Err(e);
        }

        Ok(Self {
            vcpu,
            exit,
            mappings: HashMap::new(),
        })
    }

    /// The raw HVF vCPU ID (usable with [`cancel`] from any thread).
    pub fn vcpu_id(&self) -> u64 {
        self.vcpu
    }

    /// Map `size` bytes of host memory at `va` into the guest at `gpa`,
    /// replacing any existing mapping for `slot`.
    ///
    /// # Safety
    /// The caller must ensure `[va, va + size)` is valid memory that outlives
    /// the mapping.
    pub unsafe fn map_memory(
        &mut self,
        slot: u32,
        gpa: u64,
        va: usize,
        size: usize,
        perms: Perms,
    ) -> Result<(), HvfError> {
        if let Some((old_gpa, old_size)) = self.mappings.remove(&slot) {
            // SAFETY: the range was mapped by this VM.
            check_hv(unsafe { hv_vm_unmap(old_gpa, old_size) })?;
        }
        // SAFETY: upheld by the caller (see above).
        check_hv(unsafe { hv_vm_map(va as *const c_void, gpa, size, perms.to_hv_flags()) })?;
        self.mappings.insert(slot, (gpa, size));
        Ok(())
    }

    /// Unmap the mapping previously created for `slot`. `gpa`/`size` are used
    /// as a fallback when the slot is unknown.
    pub fn unmap_memory(&mut self, slot: u32, gpa: u64, size: usize) -> Result<(), HvfError> {
        let (gpa, size) = self.mappings.remove(&slot).unwrap_or((gpa, size));
        // SAFETY: the range was mapped by this VM.
        check_hv(unsafe { hv_vm_unmap(gpa, size) })
    }

    /// Read a general-purpose register by X-register index (0..=30).
    fn get_x_reg(&self, index: u8) -> Result<u64, HvfError> {
        let mut value = 0;
        // SAFETY: called on the vCPU thread with a valid out-pointer.
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, X_REGS[index as usize], &mut value) })?;
        Ok(value)
    }

    /// Advance the guest program counter past an instruction of `len` bytes.
    fn advance_pc(&self, len: u64) -> Result<(), HvfError> {
        let mut pc = 0;
        // SAFETY: called on the vCPU thread with a valid out-pointer.
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, hv_reg_t::PC, &mut pc) })?;
        // SAFETY: called on the vCPU thread.
        check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::PC, pc + len) })
    }

    /// Run the vCPU until it exits, decoding HVF exit info into [`VmExit`].
    pub fn run_vcpu(&mut self) -> Result<VmExit, HvfError> {
        loop {
            // SAFETY: called on the vCPU thread; `self.exit` is written by
            // the hypervisor before `hv_vcpu_run` returns.
            check_hv(unsafe { hv_vcpu_run(self.vcpu) })?;
            let exit = unsafe { &*self.exit };

            match exit.reason {
                hv_exit_reason_t::CANCELED => return Ok(VmExit::Cancelled),
                hv_exit_reason_t::VTIMER_ACTIVATED => {
                    // The vtimer is masked automatically on this exit and
                    // Hyperlight guests do not use interrupts; keep running.
                    continue;
                }
                hv_exit_reason_t::UNKNOWN => {
                    return Ok(VmExit::Unknown("HVF exit reason UNKNOWN".to_string()));
                }
                hv_exit_reason_t::EXCEPTION => {
                    let esr = exit.exception.syndrome;
                    let ipa = exit.exception.physical_address;
                    match (esr >> 26) & 0x3f {
                        EC_WFI_WFE => {
                            // No interrupts are configured; treat WFI/WFE as a
                            // no-op and keep running.
                            self.advance_pc(4)?;
                            continue;
                        }
                        EC_INST_ABORT => return Ok(VmExit::MmioRead(ipa)),
                        EC_DATA_ABORT => {
                            let io_page_gpa =
                                const { hyperlight_common::layout::io_page().unwrap().0 };
                            let off = ipa.wrapping_sub(io_page_gpa);
                            let is_io_page = (off as usize) < hyperlight_common::vmem::PAGE_SIZE;
                            let is_write = esr & ESR_WNR != 0;

                            if is_io_page && is_write {
                                if esr & ESR_ISV == 0 {
                                    // No instruction syndrome: we cannot tell
                                    // which register holds the written data.
                                    return Err(HvfError::NoInstructionSyndrome);
                                }
                                let len = 1usize << ((esr >> ESR_SAS_SHIFT) & 0x3);
                                let srt = ((esr >> ESR_SRT_SHIFT) & 0x1f) as u8;
                                let value = if srt == 31 {
                                    // XZR as the source register
                                    0
                                } else {
                                    let mask = u64::MAX >> (64 - (len as u64 * 8));
                                    self.get_x_reg(srt)? & mask
                                };
                                // HVF traps before the access completes;
                                // skip the store instruction ourselves.
                                self.advance_pc(4)?;

                                let port = (off as usize) / core::mem::size_of::<u64>();
                                if port == VmAction::Halt as usize {
                                    return Ok(VmExit::Halt);
                                }
                                return Ok(VmExit::IoOut(
                                    port as u16,
                                    value.to_le_bytes()[..len].to_vec(),
                                ));
                            }

                            if is_write {
                                return Ok(VmExit::MmioWrite(ipa));
                            }
                            return Ok(VmExit::MmioRead(ipa));
                        }
                        _ => {
                            return Ok(VmExit::Unknown(format!(
                                "HVF exception exit: syndrome={:#x} va={:#x} ipa={:#x}",
                                esr, exit.exception.virtual_address, ipa
                            )));
                        }
                    }
                }
            }
        }
    }

    /// Read the general-purpose registers.
    pub fn regs(&self) -> Result<Regs, HvfError> {
        let mut x: [u64; 31] = [0; 31];
        for (i, xi) in x.iter_mut().enumerate() {
            *xi = self.get_x_reg(i as u8)?;
        }
        // SAFETY: called on the vCPU thread with valid out-pointers.
        let mut sp = 0;
        check_hv(unsafe { hv_vcpu_get_sys_reg(self.vcpu, hv_sys_reg_t::SP_EL0, &mut sp) })?;
        let mut pc = 0;
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, hv_reg_t::PC, &mut pc) })?;
        let mut pstate = 0;
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, hv_reg_t::CPSR, &mut pstate) })?;
        Ok(Regs { x, sp, pc, pstate })
    }

    /// Write the general-purpose registers.
    pub fn set_regs(&self, regs: &Regs) -> Result<(), HvfError> {
        for (i, &value) in regs.x.iter().enumerate() {
            // SAFETY: called on the vCPU thread.
            check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, X_REGS[i], value) })?;
        }
        // SAFETY: called on the vCPU thread.
        check_hv(unsafe { hv_vcpu_set_sys_reg(self.vcpu, hv_sys_reg_t::SP_EL0, regs.sp) })?;
        check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::PC, regs.pc) })?;
        check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::CPSR, regs.pstate) })?;
        Ok(())
    }

    /// Read the SIMD/FP registers.
    pub fn fpu(&self) -> Result<FpuState, HvfError> {
        let mut v: [u128; 32] = [0; 32];
        for (i, vi) in v.iter_mut().enumerate() {
            // SAFETY: called on the vCPU thread with a valid out-pointer.
            check_hv(unsafe { hv_vcpu_get_simd_fp_reg(self.vcpu, Q_REGS[i], vi) })?;
        }
        let mut fpsr = 0;
        // SAFETY: called on the vCPU thread with valid out-pointers.
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, hv_reg_t::FPSR, &mut fpsr) })?;
        let mut fpcr = 0;
        check_hv(unsafe { hv_vcpu_get_reg(self.vcpu, hv_reg_t::FPCR, &mut fpcr) })?;
        Ok(FpuState {
            v,
            fpsr: fpsr as u32,
            fpcr: fpcr as u32,
        })
    }

    /// Write the SIMD/FP registers.
    pub fn set_fpu(&self, fpu: &FpuState) -> Result<(), HvfError> {
        for (i, &value) in fpu.v.iter().enumerate() {
            // SAFETY: called on the vCPU thread.
            check_hv(unsafe { hv_vcpu_set_simd_fp_reg(self.vcpu, Q_REGS[i], value) })?;
        }
        // SAFETY: called on the vCPU thread.
        check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::FPSR, fpu.fpsr as u64) })?;
        check_hv(unsafe { hv_vcpu_set_reg(self.vcpu, hv_reg_t::FPCR, fpu.fpcr as u64) })?;
        Ok(())
    }

    /// Read the system registers.
    pub fn sregs(&self) -> Result<Sregs, HvfError> {
        // SAFETY: called on the vCPU thread with a valid out-pointer.
        let get = |reg: hv_sys_reg_t| {
            let mut value = 0;
            check_hv(unsafe { hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value) })?;
            Ok(value)
        };
        Ok(Sregs {
            ttbr0_el1: get(hv_sys_reg_t::TTBR0_EL1)?,
            tcr_el1: get(hv_sys_reg_t::TCR_EL1)?,
            mair_el1: get(hv_sys_reg_t::MAIR_EL1)?,
            sctlr_el1: get(hv_sys_reg_t::SCTLR_EL1)?,
            cpacr_el1: get(hv_sys_reg_t::CPACR_EL1)?,
            vbar_el1: get(hv_sys_reg_t::VBAR_EL1)?,
            sp_el1: get(hv_sys_reg_t::SP_EL1)?,
        })
    }

    /// Write the system registers.
    pub fn set_sregs(&self, sregs: &Sregs) -> Result<(), HvfError> {
        // SAFETY: called on the vCPU thread.
        let set = |reg: hv_sys_reg_t, value: u64| {
            check_hv(unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, value) })
        };
        set(hv_sys_reg_t::TTBR0_EL1, sregs.ttbr0_el1)?;
        set(hv_sys_reg_t::TCR_EL1, sregs.tcr_el1)?;
        set(hv_sys_reg_t::MAIR_EL1, sregs.mair_el1)?;
        set(hv_sys_reg_t::SCTLR_EL1, sregs.sctlr_el1)?;
        set(hv_sys_reg_t::CPACR_EL1, sregs.cpacr_el1)?;
        set(hv_sys_reg_t::VBAR_EL1, sregs.vbar_el1)?;
        set(hv_sys_reg_t::SP_EL1, sregs.sp_el1)?;
        Ok(())
    }

    /// Reset the vCPU to a clean state, emulating KVM's `KVM_ARM_VCPU_INIT`
    /// (HVF has no equivalent operation): GP and FP registers are zeroed,
    /// and the debug breakpoint/watchpoint pair 0 is cleared so no stale
    /// breakpoints survive a snapshot restore. Only pair 0 is cleared —
    /// Hyperlight guests use no other debug registers. Translation system
    /// registers (TCR/TTBR/…) are NOT touched; the caller applies them
    /// from the snapshot after the reset.
    pub fn reset_vcpu(&self) -> Result<(), HvfError> {
        self.set_regs(&Regs::default())?;
        self.set_fpu(&FpuState::default())?;
        // SAFETY: called on the vCPU thread.
        unsafe {
            check_hv(hv_vcpu_set_sys_reg(self.vcpu, hv_sys_reg_t::DBGBVR0_EL1, 0))?;
            check_hv(hv_vcpu_set_sys_reg(self.vcpu, hv_sys_reg_t::DBGBCR0_EL1, 0))?;
            check_hv(hv_vcpu_set_sys_reg(self.vcpu, hv_sys_reg_t::DBGWVR0_EL1, 0))?;
            check_hv(hv_vcpu_set_sys_reg(self.vcpu, hv_sys_reg_t::DBGWCR0_EL1, 0))?;
        }
        Ok(())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // SAFETY: `hv_vcpu_destroy` must be called on the thread that created
        // the vCPU (see module-level threading note). Errors are ignored: the
        // VM and vCPU are per-process resources reclaimed at process exit.
        unsafe {
            let _ = hv_vcpu_destroy(self.vcpu);
            let _ = hv_vm_destroy();
        }
    }
}
