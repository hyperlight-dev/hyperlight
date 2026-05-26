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

// TODO(aarch64): these values are placeholders copied from amd64
pub const MAIN_STACK_TOP_GVA: u64 = 0x0000_ff00_0000_0000;
pub const MAIN_STACK_LIMIT_GVA: u64 = 0x0000_fe00_0000_0000;

pub fn scratch_size() -> u64 {
    let addr = crate::layout::scratch_size_gva();
    unsafe { (addr as *mut u64).read_volatile() }
}

pub fn scratch_base_gpa() -> u64 {
    hyperlight_common::layout::scratch_base_gpa(scratch_size() as usize)
}

pub fn scratch_base_gva() -> u64 {
    hyperlight_common::layout::scratch_base_gva(scratch_size() as usize)
}
