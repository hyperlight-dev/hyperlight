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

// This file is just dummy definitions at the moment, in order to
// allow compiling the guest for real mode boot scenarios.

pub const MAX_GVA: usize = 0xffff_efff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0xef00_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0xefff_efff;
pub const MAX_GPA: usize = 0xffff_ffff;

pub fn min_scratch_size() -> usize {
    1 * crate::vmem::PAGE_SIZE
}
