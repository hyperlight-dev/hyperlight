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

// AArch64 uses a different virtual address space layout than x86_64.
// The kernel (upper) address space typically starts at 0xFFFF_0000_0000_0000
// with a 48-bit VA (4-level, 4KB granule).
pub const SNAPSHOT_PT_GVA: usize = 0xFFFF_FF00_0000_0000;
