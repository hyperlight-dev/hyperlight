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

// The addresses in this file should be coordinated with
// src/hyperlight_guest/src/arch/amd64/layout.rs and
// src/hyperlight_guest_bin/src/arch/amd64/layout.rs

/// We have this the top of the page below the top of memory in order
/// to make working with start/end ptrs in a few places more
/// convenient (not needing to worry about overflow)
pub const MAX_GVA: usize = 0xffff_ffff_ffff_efff;
pub const SNAPSHOT_PT_GVA_MIN: usize = 0xffff_8000_0000_0000;
pub const SNAPSHOT_PT_GVA_MAX: usize = 0xffff_80ff_ffff_ffff;

/// We assume 36-bit IPAs for now, since every amd64 processor
/// supports at least 36 bits.  Almost all of them support at least 40
/// bits, so we could consider bumping this in the future if we were
/// ever memory-constrained.
pub const MAX_GPA: usize = 0x0000_000f_ffff_ffff;
