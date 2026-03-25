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

// TODO(aarch64): change these, they are only provided in order to compile
pub const MAX_GVA: usize = 0xffff_ffff_ffff_efff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0xffff_8000_0000_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0xffff_80ff_ffff_ffff;
pub const MAX_GPA: usize = 0x0000_000f_ffff_ffff;

pub fn min_scratch_size(
    _input_data_size: usize,
    _output_data_size: usize,
    _g2h_num_descs: usize,
    _h2g_num_descs: usize,
) -> usize {
    unimplemented!("min_scratch_size")
}
