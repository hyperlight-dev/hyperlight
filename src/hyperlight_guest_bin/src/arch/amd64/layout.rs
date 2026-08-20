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
// src/hyperlight_common/src/arch/amd64/layout.rs and
// src/hyperlight_guest/src/arch/amd64/layout.rs

/// On amd64, since the processor is told the VAs of control
/// structures like the GDT/IDT/TSS, we need to map them somewhere to
/// a VA that will survive the snapshot process. Since we don't have a
/// useful virtual allocator yet, we just put them here...
pub const PROC_CONTROL_GVA: u64 = 0xffff_fd00_0000_0000;
