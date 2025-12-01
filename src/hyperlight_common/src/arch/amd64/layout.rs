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
