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

pub const MAX_GVA: usize = 0xffff_ffff_ffff_ffff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0xffff_8000_0000_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0xffff_80ff_ffff_ffff;

// Let's assume 40-bit IPAs for now
pub const MAX_GPA: usize = 0x0000_03ff_ffff_ffff;

/// Note that the x86-64 ELF psABI requires that the stack be 16-byte
/// aligned before a call instruction, and the architecture requires
/// the same alignment when jumping to an IST offset; we use the
/// aligned version here, although when we jump to the entrypoint,
/// there is no return address pushed on the stack & so we must adjust
/// the alignment.
pub const SCRATCH_TOP_EXN_STACK_OFFSET: u64 = 0x20;

/// Compute the minimum scratch region size needed for give requested
/// input and output data sizes. This is:
/// - A page-aligned amount of memory for the buffers
/// - A page for the smallest possible non-exception stack
/// - (up to) 3 pages for PTEs for mapping that
/// - A page for the TSS and IDT
/// - (up to) 3 pages for PTEs for mapping that
/// - A page for the exception stack and metadata
pub fn min_scratch_size(input_data_size: usize, output_data_size: usize) -> usize {
    crate::util::round_up_to(
        input_data_size + output_data_size,
        crate::vm::PAGE_SIZE,
    ) + 9 * crate::vm::PAGE_SIZE
}
