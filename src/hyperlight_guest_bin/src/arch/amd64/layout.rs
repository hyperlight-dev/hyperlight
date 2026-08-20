// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// The addresses in this file should be coordinated with
// src/hyperlight_common/src/arch/amd64/layout.rs and
// src/hyperlight_guest/src/arch/amd64/layout.rs

/// On amd64, since the processor is told the VAs of control
/// structures like the GDT/IDT/TSS, we need to map them somewhere to
/// a VA that will survive the snapshot process. Since we don't have a
/// useful virtual allocator yet, we just put them here...
pub const PROC_CONTROL_GVA: u64 = 0xffff_fd00_0000_0000;
