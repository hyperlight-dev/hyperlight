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

#[cfg_attr(target_arch = "x86_64", path = "arch/amd64/layout.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{MAX_GPA, MAX_GVA, SNAPSHOT_PT_GVA_MAX, SNAPSHOT_PT_GVA_MIN};

// The topmost page of scratch serves as a host→guest bookkeeping /
// configuration page. The host writes these fields before the first vCPU
// run and on snapshot restore; the guest reads them at startup and on
// each clock query. All fields are u64, little-endian, naturally aligned.
pub const SCRATCH_TOP_SIZE_OFFSET: u64 = 0x08;
pub const SCRATCH_TOP_ALLOCATOR_OFFSET: u64 = 0x10;
pub const SCRATCH_TOP_SNAPSHOT_PT_GPA_BASE_OFFSET: u64 = 0x18;
pub const SCRATCH_TOP_SNAPSHOT_GENERATION_OFFSET: u64 = 0x20;

/// Offset from the top of scratch for the `clock_type` field (u64).
///
/// Identifies which paravirtualized clock the host configured
/// ([`crate::time::ClockType`]). Lives in the bookkeeping page at the
/// top of scratch — NOT in the clock page itself — so the hypervisor
/// cannot clobber it if it extends the TLFS-reserved region.
pub const SCRATCH_TOP_CLOCK_TYPE_OFFSET: u64 = 0x28;

/// Offset from the top of scratch for the `boot_time_ns` field (u64).
///
/// The Unix-epoch origin of the monotonic clock, computed by the host
/// as `SystemTime::now() - current_monotonic_ns()` and written in
/// `arm_clock`. The guest recovers wall time as
/// `boot_time_ns + monotonic_time_ns()`.
///
/// Hyper-V has no equivalent to KVM's `MSR_KVM_WALL_CLOCK_NEW`, so
/// we use this uniform host-computed approach on all backends.
pub const SCRATCH_TOP_BOOT_TIME_NS_OFFSET: u64 = 0x30;

// ---- Next free offset in the bookkeeping page: 0x38 ----
// When adding new host→guest shared fields, use the next multiple of
// 8 after the last offset above. All fields in this page are u64,
// little-endian, host-written and guest-read, and are excluded from
// snapshots because they live in scratch memory.

/// Offset from the top of scratch memory to the clock page's **high edge**
/// (its top, exclusive).
///
/// The reserved region at the very top of scratch is, from the top down:
///
/// ```text
///   [MAX_GPA + 1 - 0x1000, MAX_GPA + 1)            metadata / bookkeeping page
///   [MAX_GPA + 1 - 0x2000, MAX_GPA + 1 - 0x1000)   clock page
///   [MAX_GPA + 1 - 0x4000, MAX_GPA + 1 - 0x2000)   exception (IST1) stack (2 pages)
/// ```
///
/// The clock page is therefore the **second page from the top**, one 4 KiB
/// page below the metadata page, so this offset to its high edge is exactly
/// one page. The clock page *base* is one page lower again — see
/// [`SCRATCH_TOP_EXN_STACK_OFFSET`] and [`clock_page_gpa`].
///
/// Keeping the clock page on its own page — separate from the bookkeeping
/// fields above it — guarantees the hypervisor, which owns the whole page
/// (KVM pvclock or Hyper-V Reference TSC), cannot clobber Hyperlight's
/// `clock_type` / `boot_time_ns` metadata even if a future TLFS extension
/// grows the reserved region.
///
/// The page is always reserved regardless of the `enable_guest_clock`
/// feature so that the memory layout (and therefore stack positions)
/// is stable across feature-flag builds. The host only populates it
/// when the feature is enabled; otherwise it stays zero-filled and
/// the guest sees `ClockType::None`.
pub const SCRATCH_TOP_CLOCK_PAGE_OFFSET: u64 = crate::mem::PAGE_SIZE;

/// Offset from the top of scratch to the top of the exception (IST1) stack,
/// which is also the **base** of the clock page (the boundary between the
/// clock page and the exception stack below it).
///
/// Derived as one page below [`SCRATCH_TOP_CLOCK_PAGE_OFFSET`] so it can
/// never drift from the clock page above it. The exception stack grows
/// *downward* from here for `EXN_STACK_PAGES` pages; placing its top here
/// means neither it nor any page-fault / COW handler running on it can
/// clobber the clock page or the metadata page above.
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = SCRATCH_TOP_CLOCK_PAGE_OFFSET + crate::mem::PAGE_SIZE;

/// Number of 4 KiB pages reserved for the IST1 exception stack at the top
/// of scratch.
const EXN_STACK_PAGES: u64 = 2;

/// Total size of the reserved region at the very top of scratch: the
/// metadata page, the clock page, and the `EXN_STACK_PAGES`-page exception
/// stack. Everything below this is general scratch (heap, I/O buffers, …).
///
/// Both the guest physical allocator and the host minimum-size check use
/// this single value, so the reservation and the size requirement can never
/// disagree.
pub const SCRATCH_TOP_RESERVED_SIZE: u64 =
    SCRATCH_TOP_EXN_STACK_OFFSET + EXN_STACK_PAGES * crate::mem::PAGE_SIZE;

pub fn scratch_base_gpa(size: usize) -> u64 {
    (MAX_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (MAX_GVA - size + 1) as u64
}

/// Guest physical address of the base of the paravirtualized clock page.
///
/// The clock page sits at a fixed offset from the top of the guest physical
/// address space, independent of `scratch_size`: its base is always
/// `MAX_GPA + 1 - SCRATCH_TOP_EXN_STACK_OFFSET` (the clock page is the second
/// page from the top, and its base is the boundary with the exception stack
/// below it).
///
/// Only meaningful when the host is built with the `enable_guest_clock`
/// feature; otherwise the page is not populated.
pub const fn clock_page_gpa() -> u64 {
    (MAX_GPA as u64) + 1 - SCRATCH_TOP_EXN_STACK_OFFSET
}

/// Guest virtual address of the base of the paravirtualized clock page.
///
/// See [`clock_page_gpa`]. Scratch is mapped identity-style from
/// `scratch_base_gva` to `scratch_base_gpa`, so the clock page sits at the
/// equivalent offset in the guest virtual address space.
pub const fn clock_page_gva() -> u64 {
    (MAX_GVA as u64) + 1 - SCRATCH_TOP_EXN_STACK_OFFSET
}

/// Compute the minimum scratch region size needed for a sandbox.
pub use arch::min_scratch_size;
