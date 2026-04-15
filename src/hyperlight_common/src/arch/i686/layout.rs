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

// i686 layout constants for 32-bit protected mode with paging.

pub const MAX_GVA: usize = 0xffff_ffff;
pub const MAX_GPA: usize = 0xffff_ffff;

/// Minimum scratch region size: IO buffers (page-aligned) plus 12 pages
/// for bookkeeping and the exception stack. Page table space is validated
/// separately by `set_pt_size()`.
pub fn min_scratch_size(input_data_size: usize, output_data_size: usize) -> usize {
    (input_data_size + output_data_size).next_multiple_of(crate::vmem::PAGE_SIZE)
        + 12 * crate::vmem::PAGE_SIZE
}
