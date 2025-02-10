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

use core::arch::global_asm;
use core::ptr::addr_of;
use crate::idt::{IdtEntry, IDT};

global_asm!(
    "
    .global lidt
    lidt:
        # SysV64 calling convention: first argument (IDTR) is in RDI
        lidt [rdi]  # Load IDT from memory address in RDI
        ret
    "
);

extern "sysv64" {
    fn lidt(idt_ptr: *const Idtr);
}


// The location of the IDT is stored in the IDTR.
#[repr(C)]
struct Idtr {
    limit: u16,
    base: u64,
}

pub(crate) unsafe fn load_idt() {
    let idt_ptr = Idtr {
        limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: addr_of!(IDT) as *const _ as u64,
    };

    lidt(&idt_ptr);
}
