/*
Copyright 2024 The Hyperlight Authors.

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

//! This file contains architecture specific code for the x86_64

/// Software Breakpoint size in memory
pub(crate) const SW_BP_SIZE: usize = 1;
/// Software Breakpoint opcode - INT3
/// Check page 7-28 Vol. 3A of Intel 64 and IA-32
/// Architectures Software Developer's Manual
pub(crate) const SW_BP_OP: u8 = 0xCC;
/// Software Breakpoint written to memory
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = [SW_BP_OP];
/// Maximum number of supported hardware breakpoints
pub(crate) const MAX_NO_OF_HW_BP: usize = 4;

/// Check page 19-4 Vol. 3B of Intel 64 and IA-32
/// Architectures Software Developer's Manual
/// Bit position of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_POS: usize = 14;
/// Bit mask of BS flag in DR6 debug register
pub(crate) const DR6_BS_FLAG_MASK: u64 = 1 << DR6_BS_FLAG_POS;
/// Bit position of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_POS: usize = 0;
/// Bit mask of HW breakpoints status in DR6 debug register
pub(crate) const DR6_HW_BP_FLAGS_MASK: u64 = 0x0F << DR6_HW_BP_FLAGS_POS;
