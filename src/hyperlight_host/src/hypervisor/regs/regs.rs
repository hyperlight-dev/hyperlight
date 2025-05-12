#[cfg(mshv2)]
extern crate mshv_bindings2 as mshv_bindings;
#[cfg(mshv2)]
extern crate mshv_ioctls2 as mshv_ioctls;

#[cfg(mshv3)]
extern crate mshv_bindings3 as mshv_bindings;
#[cfg(mshv3)]
extern crate mshv_ioctls3 as mshv_ioctls;

#[cfg(kvm)]
use kvm_bindings::kvm_regs;
#[cfg(mshv)]
use mshv_bindings::StandardRegisters;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

// --- KVM ---
#[cfg(kvm)]
impl From<kvm_regs> for CommonRegisters {
    fn from(kvm_regs: kvm_regs) -> Self {
        CommonRegisters {
            rax: kvm_regs.rax,
            rbx: kvm_regs.rbx,
            rcx: kvm_regs.rcx,
            rdx: kvm_regs.rdx,
            rsi: kvm_regs.rsi,
            rdi: kvm_regs.rdi,
            rsp: kvm_regs.rsp,
            rbp: kvm_regs.rbp,
            r8: kvm_regs.r8,
            r9: kvm_regs.r9,
            r10: kvm_regs.r10,
            r11: kvm_regs.r11,
            r12: kvm_regs.r12,
            r13: kvm_regs.r13,
            r14: kvm_regs.r14,
            r15: kvm_regs.r15,
            rip: kvm_regs.rip,
            rflags: kvm_regs.rflags,
        }
    }
}

#[cfg(kvm)]
impl From<CommonRegisters> for kvm_regs {
    fn from(regs: CommonRegisters) -> Self {
        kvm_regs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
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
        }
    }
}

// --- MSHV ---

#[cfg(mshv)]
impl From<StandardRegisters> for CommonRegisters {
    fn from(mshv_regs: StandardRegisters) -> Self {
        CommonRegisters {
            rax: mshv_regs.rax,
            rbx: mshv_regs.rbx,
            rcx: mshv_regs.rcx,
            rdx: mshv_regs.rdx,
            rsi: mshv_regs.rsi,
            rdi: mshv_regs.rdi,
            rsp: mshv_regs.rsp,
            rbp: mshv_regs.rbp,
            r8: mshv_regs.r8,
            r9: mshv_regs.r9,
            r10: mshv_regs.r10,
            r11: mshv_regs.r11,
            r12: mshv_regs.r12,
            r13: mshv_regs.r13,
            r14: mshv_regs.r14,
            r15: mshv_regs.r15,
            rip: mshv_regs.rip,
            rflags: mshv_regs.rflags,
        }
    }
}

#[cfg(mshv)]
impl From<CommonRegisters> for StandardRegisters {
    fn from(regs: CommonRegisters) -> Self {
        StandardRegisters {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
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
        }
    }
}
