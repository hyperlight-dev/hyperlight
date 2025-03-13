use core::ptr::addr_of;

use crate::idt::{IDT, IdtEntry, init_idt};

#[repr(C, packed)]
pub struct Idtr {
    pub limit: u16,
    pub base: u64,
}

static mut IDTR: Idtr = Idtr { limit: 0, base: 0 };

impl Idtr {
    unsafe fn init(&mut self, base: u64, size: u16) {
        self.limit = size - 1;
        self.base = base;
    }

    unsafe fn load(&self) {
        unsafe {
            core::arch::asm!("lidt [{}]", in(reg) self, options(readonly, nostack, preserves_flags));
        }
    }
}

pub(crate) unsafe fn load_idt() {
    init_idt();

    let idt_size = 256 * size_of::<IdtEntry>();
    let expected_base = addr_of!(IDT) as *const _ as u64;

    #[allow(static_mut_refs)]
    unsafe {
        IDTR.init(expected_base, idt_size as u16);
        IDTR.load();
    }
}
