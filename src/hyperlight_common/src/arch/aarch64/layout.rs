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

// TODO: consider using the upper half, like we do on x86;
// this would require enabling ttbr1
pub const SCRATCH_TOP_GVA: usize = 0x0000_ffff_ffff_dfff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0x0000_8000_0000_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0x0000_80ff_ffff_ffff;
pub const SCRATCH_TOP_GPA: usize = 0x0000_000f_ffff_efff;

pub const IO_PAGE_GVA: u64 = 0x0000_ffff_ffff_e000;
pub const IO_PAGE_GPA: u64 = 0x0000_000f_ffff_f000;

pub const fn io_page() -> Option<(crate::vmem::PhysAddr, crate::vmem::VirtAddr)> {
    Some((IO_PAGE_GPA, IO_PAGE_GVA))
}

pub fn min_scratch_size(input_data_size: usize, output_data_size: usize) -> usize {
    (input_data_size + output_data_size).next_multiple_of(crate::vmem::PAGE_SIZE)
        + 12 * crate::vmem::PAGE_SIZE
}
