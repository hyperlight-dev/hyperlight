use kvm_bindings::{kvm_regs, kvm_sregs};

#[derive(Debug, Default)]
pub(crate) struct Registers {
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

impl From<kvm_regs> for Registers {
    fn from(kvm_regs: kvm_regs) -> Self {
        Registers {
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

impl From<&Registers> for kvm_regs {
    fn from(regs: &Registers) -> Self {
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

#[derive(Debug)]
pub(crate) struct SpecialRegisters {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
}

impl From<&SpecialRegisters> for kvm_sregs {
    fn from(sregs: &SpecialRegisters) -> Self {
        kvm_sregs {
            cr0: sregs.cr0,
            cr3: sregs.cr3,
            cr4: sregs.cr4,
            efer: sregs.efer,
            ..Default::default()
        }
    }
}

impl From<kvm_sregs> for SpecialRegisters {
    fn from(kvm_sregs: kvm_sregs) -> Self {
        SpecialRegisters {
            cr0: kvm_sregs.cr0,
            cr3: kvm_sregs.cr3,
            cr4: kvm_sregs.cr4,
            efer: kvm_sregs.efer,
        }
    }
}
