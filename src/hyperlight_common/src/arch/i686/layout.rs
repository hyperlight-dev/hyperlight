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
/// Set below the KVM APIC access page at 0xFEE00000 to avoid EEXIST when scratch
/// regions are large enough to reach that address.
pub const MAX_GPA: usize = 0xFEDF_FFFF;

pub fn min_scratch_size(
    _input_data_size: usize,
    _output_data_size: usize,
    _g2h_num_descs: usize,
    _h2g_num_descs: usize,
) -> usize {
    crate::vmem::PAGE_SIZE
}
