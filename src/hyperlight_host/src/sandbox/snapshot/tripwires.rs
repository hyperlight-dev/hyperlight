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
//! Each assertion below pins one piece of the on-disk or in-memory
//! contract that snapshots depend on: the manifest media types, the
//! OCI Image Layout version, the `HyperlightPEB` field offsets, and
//! the `OutBAction` port numbers. A change to any of these means
//! snapshots produced by older builds can no longer be loaded
//! correctly by this build.
//!
//! When one of these assertions fires, the change is breaking the
//! snapshot ABI. The fix is one of:
//!
//! * Avoid the break entirely. Reshape the change so the on-disk
//!   contract does not move.
//! * Make the change backwards compatible (add a versioned variant,
//!   add a compatibility path in the loader) and leave the pinned
//!   values here alone.
//! * Accept the break: bump [`super::file::SNAPSHOT_ABI_VERSION`]
//!   together with `EXPECTED_ABI_VERSION` below, and update any
//!   other `EXPECTED_*` constants here to match whatever the source
//!   values now are. Snapshots produced by older builds will be
//!   rejected at load time by the version check, so they must be
//!   regenerated. Call this out in the release notes.

use super::file::{
    MT_CONFIG_CURRENT, MT_SNAPSHOT_CURRENT, OCI_LAYOUT_VERSION, SNAPSHOT_ABI_VERSION,
};

const EXPECTED_ABI_VERSION: u32 = 1;
const EXPECTED_MT_CONFIG: &str = "application/vnd.hyperlight.snapshot.config.v1+json";
const EXPECTED_MT_SNAPSHOT: &str = "application/vnd.hyperlight.snapshot.memory.v1";
const EXPECTED_OCI_LAYOUT_VERSION: &str = "1.0.0";

const _: () = {
    assert!(SNAPSHOT_ABI_VERSION == EXPECTED_ABI_VERSION);
    assert!(str_eq(MT_CONFIG_CURRENT, EXPECTED_MT_CONFIG));
    assert!(str_eq(MT_SNAPSHOT_CURRENT, EXPECTED_MT_SNAPSHOT));
    assert!(str_eq(OCI_LAYOUT_VERSION, EXPECTED_OCI_LAYOUT_VERSION));
};

#[cfg(not(feature = "nanvix-unstable"))]
const _: () = {
    use hyperlight_common::mem::{GuestMemoryRegion, HyperlightPEB};
    assert!(std::mem::size_of::<GuestMemoryRegion>() == 16);
    assert!(std::mem::size_of::<HyperlightPEB>() == 4 * 16);
    assert!(std::mem::offset_of!(HyperlightPEB, input_stack) == 0);
    assert!(std::mem::offset_of!(HyperlightPEB, output_stack) == 16);
    assert!(std::mem::offset_of!(HyperlightPEB, init_data) == 32);
    assert!(std::mem::offset_of!(HyperlightPEB, guest_heap) == 48);
};

#[cfg(feature = "nanvix-unstable")]
const _: () = {
    use hyperlight_common::mem::{GuestMemoryRegion, HyperlightPEB};
    assert!(std::mem::size_of::<GuestMemoryRegion>() == 16);
    assert!(std::mem::size_of::<HyperlightPEB>() == 5 * 16);
    assert!(std::mem::offset_of!(HyperlightPEB, input_stack) == 0);
    assert!(std::mem::offset_of!(HyperlightPEB, output_stack) == 16);
    assert!(std::mem::offset_of!(HyperlightPEB, init_data) == 32);
    assert!(std::mem::offset_of!(HyperlightPEB, guest_heap) == 48);
    assert!(std::mem::offset_of!(HyperlightPEB, file_mappings) == 64);
};

const _: () = {
    use hyperlight_common::outb::OutBAction;
    assert!(OutBAction::Log as u16 == 99);
    assert!(OutBAction::CallFunction as u16 == 101);
    assert!(OutBAction::Abort as u16 == 102);
    assert!(OutBAction::DebugPrint as u16 == 103);
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
