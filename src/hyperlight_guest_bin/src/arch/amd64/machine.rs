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

use core::mem;

use hyperlight_common::vmem::{BasicMapping, MappingKind, PAGE_SIZE};

use super::layout::PROC_CONTROL_GVA;

/// Entry in the Global Descriptor Table (GDT)
/// For reference, see page 3-10 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual, figure 3-8
/// (https://i.imgur.com/1i9xUmx.png).
/// From the bottom, we have:
/// - segment limit 15..0 = limit_low
/// - base address 31..16 = base_low
/// - base 23..16 = base_middle
/// - p dpl s type 15..8 = access
/// - p d/b l avl seg. limit 23..16 = flags_limit
/// - base 31..24 = base_high
#[derive(Copy, Clone)]
#[repr(C, align(8))]
pub(super) struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    flags_limit: u8,
    base_high: u8,
}
const _: () = assert!(mem::size_of::<GdtEntry>() == 0x8);

impl GdtEntry {
    /// Creates a new GDT entry.
    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            base_low: (base & 0xffff) as u16,
            base_middle: ((base >> 16) & 0xff) as u8,
            base_high: ((base >> 24) & 0xff) as u8,
            limit_low: (limit & 0xffff) as u16,
            flags_limit: (((limit >> 16) & 0x0f) as u8) | ((flags & 0x0f) << 4),
            access,
        }
    }

    /// Create a new entry that describes the Task State Segment
    /// (TSS).
    ///
    /// The segment descriptor for the TSS needs to be wider than
    /// other segments, because its base address is actually used &
    /// must therefore be able to encode an entire 64-bit VA.  Because
    /// of this, it uses two adjacent descriptor entries.
    ///
    /// See AMD64 Architecture Programmer's Manual, Volume 2: System Programming
    ///     Section 4: Segmented Virtual Memory
    ///         §4.8: Long-Mod Segment Descriptors
    ///             §4.8.3: System Descriptors
    /// for details of the layout
    pub const fn tss(base: u64, limit: u32) -> [Self; 2] {
        [
            Self {
                limit_low: (limit & 0xffff) as u16,
                base_low: (base & 0xffff) as u16,
                base_middle: ((base >> 16) & 0xff) as u8,
                access: 0x89,
                flags_limit: ((limit >> 16) & 0x0f) as u8,
                base_high: ((base >> 24) & 0xff) as u8,
            },
            Self {
                limit_low: ((base >> 32) & 0xffff) as u16,
                base_low: ((base >> 48) & 0xffff) as u16,
                base_middle: 0,
                access: 0,
                flags_limit: 0,
                base_high: 0,
            },
        ]
    }
}

/// GDTR (GDT pointer)
///
/// This contains the virtual address of the GDT. The GDT that it
/// points to needs to remain mapped in memory at that address, but
/// this structure itself does not.
#[repr(C, packed)]
pub(super) struct GdtPointer {
    pub(super) limit: u16,
    pub(super) base: u64,
}

/// Task State Segment
///
/// See AMD64 Architecture Programmer's Manual, Volume 2: System Programming
///     Section 12: Task Management
///         §12.2: Task-Management Resources
///             §12.2.5: 64-bit Task State Segment
#[allow(clippy::upper_case_acronyms)]
#[repr(C, packed)]
pub(super) struct TSS {
    _rsvd0: [u8; 4],
    _rsp0: u64,
    _rsp1: u64,
    _rsp2: u64,
    _rsvd1: [u8; 8],
    pub(super) ist1: u64,
    _ist2: u64,
    _ist3: u64,
    _ist4: u64,
    _ist5: u64,
    _ist6: u64,
    _ist7: u64,
    _rsvd2: [u8; 8],
}
const _: () = assert!(mem::size_of::<TSS>() == 0x64);
const _: () = assert!(mem::offset_of!(TSS, ist1) == 0x24);

/// An entry in the Interrupt Descriptor Table (IDT)
/// For reference, see page 7-20 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual, figure 7-8
/// (i.e., https://i.imgur.com/N4rEjHj.png).
/// From the bottom, we have:
/// - offset 15..0 = offset_low
/// - segment selector 31..16 = selector
/// - 000 0 0 Interrupt Stack Table 7..0 = interrupt_stack_table_offset
/// - p dpl 0 type 15..8 = type_attr
/// - offset 31..16 = offset_mid
/// - offset 63..32 = offset_high
/// - reserved 31..0 = zero
#[repr(C, align(16))]
pub(crate) struct IdtEntry {
    offset_low: u16,                  // Lower 16 bits of handler address
    selector: u16,                    // code segment selector in GDT
    interrupt_stack_table_offset: u8, // Interrupt Stack Table offset
    type_attr: u8,                    // Gate type and flags
    offset_mid: u16,                  // Middle 16 bits of handler address
    offset_high: u32,                 // High 32 bits of handler address
    _rsvd: u32,                       // Reserved, ignored
}
const _: () = assert!(mem::size_of::<IdtEntry>() == 0x10);

impl IdtEntry {
    pub(super) fn new(handler: u64) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: 0x08, // Kernel Code Segment
            interrupt_stack_table_offset: 1,
            type_attr: 0x8E,
            // 0x8E = 10001110b
            // 1 00 0 1101
            // 1 = Present
            // 00 = Descriptor Privilege Level (0)
            // 0 = Storage Segment (0)
            // 1110 = Gate Type (0b1110 = 14 = 0xE)
            // 0xE means it's an interrupt gate
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFFFFFF) as u32,
            _rsvd: 0,
        }
    }
}

#[repr(C, packed)]
pub(super) struct IdtPointer {
    pub limit: u16,
    pub base: u64,
}
const _: () = assert!(mem::size_of::<IdtPointer>() == 10);

#[allow(clippy::upper_case_acronyms)]
pub(super) type GDT = [GdtEntry; 5];
#[allow(clippy::upper_case_acronyms)]
#[repr(align(0x1000))]
pub(super) struct IDT {
    pub(super) entries: [IdtEntry; 256],
}
const _: () = assert!(mem::size_of::<IDT>() == 0x1000);

const PADDING_BEFORE_TSS: usize = 64 - mem::size_of::<GDT>();
/// A single structure containing all of the processor control
/// structures that we use during early initialization, making it easy
/// to keep them in an early-allocated physical page.  Field alignment
/// is chosen partly to lineup nicely with likely cache line
/// boundaries (gdt, tss) and to keep the idt (which is 4k in size) on
/// its own page.
#[repr(C, align(0x1000))]
pub(super) struct ProcCtrl {
    pub(super) gdt: GDT,
    _pad: mem::MaybeUninit<[u8; PADDING_BEFORE_TSS]>,
    pub(super) tss: TSS,
    pub(super) idt: IDT,
}
const _: () = assert!(mem::size_of::<ProcCtrl>() == 0x2000);
const _: () = assert!(mem::size_of::<ProcCtrl>() <= PAGE_SIZE * 2);
const _: () = assert!(mem::offset_of!(ProcCtrl, gdt) == 0);
const _: () = assert!(mem::offset_of!(ProcCtrl, tss) == 64);
const _: () = assert!(mem::offset_of!(ProcCtrl, idt) == 0x1000);

impl ProcCtrl {
    /// Create a copy of the ProcCtrl structure at its known
    /// mapping.
    ///
    /// # Safety
    /// This should only be called once, and before any of the
    /// gdtr/tr/idtr pointing at its address have been loaded.
    pub(super) unsafe fn init() -> *mut Self {
        unsafe {
            let ptr = PROC_CONTROL_GVA as *mut u8;
            crate::paging::map_region(
                hyperlight_guest::prim_alloc::alloc_phys_pages(2),
                ptr,
                PAGE_SIZE as u64 * 2,
                MappingKind::Basic(BasicMapping {
                    readable: true,
                    writable: true,
                    executable: false,
                }),
            );
            crate::paging::barrier::first_valid_same_ctx();
            let ptr = ptr as *mut Self;
            (&raw mut (*ptr).gdt).write_bytes(0u8, 1);
            (&raw mut (*ptr).tss).write_bytes(0u8, 1);
            (&raw mut (*ptr).idt).write_bytes(0u8, 1);
            ptr
        }
    }
}

/// See AMD64 Architecture Programmer's Manual, Volume 2
///     §8.9.3 Interrupt Stack Frame, pp. 283--284
///       Figure 8-14: Long-Mode Stack After Interrupt---Same Privilege,
///       Figure 8-15: Long-Mode Stack After Interrupt---Higher Privilege
/// Subject to the proviso that we push a dummy error code of 0 for exceptions
/// for which the processor does not provide one
#[repr(C)]
pub struct ExceptionInfo {
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}
const _: () = assert!(size_of::<ExceptionInfo>() == 8 * 6);
const _: () = assert!(mem::offset_of!(ExceptionInfo, rip) == 8);
const _: () = assert!(mem::offset_of!(ExceptionInfo, rsp) == 32);
