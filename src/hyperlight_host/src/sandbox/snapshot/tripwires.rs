/*
Copyright 2025 The Hyperlight Authors.

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

//! Compile-time tripwires for the snapshot ABI.
//!
//! Each assertion pins one piece of the contract that snapshots
//! depend on: the manifest media types, the OCI Image Layout version,
//! the `HyperlightPEB` size, the `OutBAction` and `VmAction`
//! port numbers, and `BASE_ADDRESS`. A change to any of these breaks
//! loading of older snapshots.
//!
//! When an assertion fires, see `docs/snapshot-versioning.md`.

use super::file::{
    MT_CONFIG_CURRENT, MT_SNAPSHOT_CURRENT, OCI_LAYOUT_VERSION, SNAPSHOT_ABI_VERSION,
};

const EXPECTED_ABI_VERSION: u32 = 1;
const EXPECTED_MT_CONFIG: &str = "application/vnd.hyperlight.snapshot.config.v1+json";
const EXPECTED_MT_SNAPSHOT: &str = "application/vnd.hyperlight.snapshot.memory.v1";
const EXPECTED_OCI_LAYOUT_VERSION: &str = "1.0.0";

/// `assert!` with the shared tripwire failure message. The message must
/// be a string literal for const eval, so the macro carries it.
macro_rules! abi_assert {
    ($cond:expr) => {
        assert!(
            $cond,
            "snapshot ABI changed: this breaks loading of existing snapshots. \
             Do not just update the expected value to make this compile. \
             See docs/snapshot-versioning.md."
        );
    };
}

const _: () = {
    abi_assert!(SNAPSHOT_ABI_VERSION == EXPECTED_ABI_VERSION);
    abi_assert!(str_eq(MT_CONFIG_CURRENT, EXPECTED_MT_CONFIG));
    abi_assert!(str_eq(MT_SNAPSHOT_CURRENT, EXPECTED_MT_SNAPSHOT));
    abi_assert!(str_eq(OCI_LAYOUT_VERSION, EXPECTED_OCI_LAYOUT_VERSION));
};

const _: () = {
    use hyperlight_common::mem::{HyperlightPEB, PAGE_SIZE_USIZE};
    // The loading host derives `guest_heap_buffer_offset`, and every
    // offset after it, from the PEB's page-rounded size. Existing
    // snapshots place the PEB in a single page, so the only thing that
    // must hold is that the PEB keeps fitting in one page. Field layout
    // is not pinned: only the captured guest reads the fields, and it
    // travels inside the snapshot, so it stays self-consistent.
    abi_assert!(std::mem::size_of::<HyperlightPEB>() <= PAGE_SIZE_USIZE);
};

const _: () = {
    use hyperlight_common::outb::OutBAction;
    abi_assert!(OutBAction::Log as u16 == 99);
    abi_assert!(OutBAction::CallFunction as u16 == 101);
    abi_assert!(OutBAction::Abort as u16 == 102);
    abi_assert!(OutBAction::DebugPrint as u16 == 103);
    #[cfg(feature = "trace_guest")]
    abi_assert!(OutBAction::TraceBatch as u16 == 104);
    #[cfg(feature = "mem_profile")]
    abi_assert!(OutBAction::TraceMemoryAlloc as u16 == 105);
    #[cfg(feature = "mem_profile")]
    abi_assert!(OutBAction::TraceMemoryFree as u16 == 106);
};

const _: () = {
    use hyperlight_common::outb::VmAction;
    abi_assert!(VmAction::PvTimerConfig as u16 == 107);
    abi_assert!(VmAction::Halt as u16 == 108);
};

const _: () = {
    use crate::mem::layout::SandboxMemoryLayout;
    abi_assert!(SandboxMemoryLayout::BASE_ADDRESS == 0x1000);
};

const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
