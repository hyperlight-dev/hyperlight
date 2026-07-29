// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// TODO: consider using the upper half, like we do on x86;
// this would require enabling ttbr1
pub const SCRATCH_TOP_GVA: usize = 0x0000_ffff_ffff_dfff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0x0000_8000_0000_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0x0000_80ff_ffff_ffff;
pub const SCRATCH_TOP_GPA: usize = 0x0000_000f_ffff_bfff;

pub const IO_PAGE_GVA: u64 = 0x0000_ffff_ffff_e000;
pub const IO_PAGE_GPA: u64 = 0x0000_000f_ffff_f000;

pub const fn io_page() -> Option<(crate::vmem::PhysAddr, crate::vmem::VirtAddr)> {
    Some((IO_PAGE_GPA, IO_PAGE_GVA))
}

pub(super) fn min_scratch_size(input_data_size: usize, output_data_size: usize) -> Option<usize> {
    input_data_size
        .checked_add(output_data_size)?
        .checked_next_multiple_of(crate::vmem::PAGE_SIZE)?
        .checked_add(12 * crate::vmem::PAGE_SIZE)
}
