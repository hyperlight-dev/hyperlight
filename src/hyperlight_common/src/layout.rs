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

#[cfg_attr(target_arch = "x86", path = "arch/i686/layout.rs")]
#[cfg_attr(
    all(target_arch = "x86_64", not(feature = "i686-guest")),
    path = "arch/amd64/layout.rs"
)]
#[cfg_attr(
    all(target_arch = "x86_64", feature = "i686-guest"),
    path = "arch/i686/layout.rs"
)]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64/layout.rs")]
mod arch;

pub use arch::{MAX_GPA, MAX_GVA};
#[cfg(any(
    all(target_arch = "x86_64", not(feature = "i686-guest")),
    target_arch = "aarch64"
))]
pub use arch::{SNAPSHOT_PT_GVA_MAX, SNAPSHOT_PT_GVA_MIN};

// offsets down from the top of scratch memory for various things
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

/// Offset from the top of scratch memory for a shared host-guest u64 counter.
///
/// This is placed at 0x1008 (rather than the next sequential 0x28) so that the
/// counter falls in scratch page 0xffffe000 instead of the very last page
/// 0xfffff000, which on i686 guests would require frame 0xfffff — exceeding the
/// maximum representable frame number.
#[cfg(feature = "guest-counter")]
pub const SCRATCH_TOP_GUEST_COUNTER_OFFSET: u64 = 0x1008;

/// Offset from the top of scratch memory for the start of the paravirtualized
/// clock page.
///
/// The clock page is a single 4 KiB page occupying the scratch offsets
/// `[0x3000, 0x2000)` from the top — i.e. one page lower than the
/// guest-counter page, to avoid the i686 frame-number issue that forces the
/// counter off the very last page (see [`SCRATCH_TOP_GUEST_COUNTER_OFFSET`]).
///
/// The constant is the *high* (exclusive) offset; the page base is one page
/// below, at `top - SCRATCH_TOP_CLOCK_PAGE_OFFSET` + 1 byte — in other words,
/// subtract this value from `MAX_GPA`/`MAX_GVA` + 1 to get the page base.
///
/// The page is always reserved regardless of the `enable_guest_clock`
/// feature so that the memory layout (and therefore stack positions)
/// is stable across feature-flag builds. The host only populates it
/// when the feature is enabled; otherwise it stays zero-filled and
/// the guest sees `ClockType::None`.
pub const SCRATCH_TOP_CLOCK_PAGE_OFFSET: u64 = 0x3000;

/// Size of the paravirtualized clock page in bytes (one 4 KiB page).
/// The entire page is owned by the hypervisor (KVM pvclock or Hyper-V
/// Reference TSC). Hyperlight's own metadata (`clock_type`,
/// `boot_time_ns`) lives in the bookkeeping page at offsets
/// `SCRATCH_TOP_CLOCK_TYPE_OFFSET` / `SCRATCH_TOP_BOOT_TIME_NS_OFFSET`,
/// NOT in the clock page, so a future TLFS extension cannot clobber it.
pub const CLOCK_PAGE_SIZE: u64 = 0x1000;

pub fn scratch_base_gpa(size: usize) -> u64 {
    (MAX_GPA - size + 1) as u64
}
pub fn scratch_base_gva(size: usize) -> u64 {
    (MAX_GVA - size + 1) as u64
}

/// Guest physical address of the base of the paravirtualized clock page.
///
/// The clock page sits at a fixed offset from the top of the guest physical
/// address space, independent of `scratch_size`: it is always
/// `MAX_GPA + 1 - SCRATCH_TOP_CLOCK_PAGE_OFFSET`.
///
/// Only meaningful when the host is built with the `enable_guest_clock`
/// feature; otherwise the page is not populated.
pub const fn clock_page_gpa() -> u64 {
    (MAX_GPA as u64) + 1 - SCRATCH_TOP_CLOCK_PAGE_OFFSET
}

/// Guest virtual address of the base of the paravirtualized clock page.
///
/// See [`clock_page_gpa`]. Scratch is mapped identity-style from
/// `scratch_base_gva` to `scratch_base_gpa`, so the clock page sits at the
/// equivalent offset in the guest virtual address space.
pub const fn clock_page_gva() -> u64 {
    (MAX_GVA as u64) + 1 - SCRATCH_TOP_CLOCK_PAGE_OFFSET
}

/// Compute the minimum scratch region size needed for a sandbox.
pub use arch::min_scratch_size;
