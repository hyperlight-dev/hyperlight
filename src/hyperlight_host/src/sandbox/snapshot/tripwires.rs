// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

//! Tripwires for the snapshot ABI.
//!
//! Each assertion pins one piece of the contract that snapshots
//! depend on: the manifest media types, the OCI Image Layout version,
//! the `OutBAction` and `VmAction` port numbers, `BASE_ADDRESS`, the
//! transport message kinds, the STATUS flags, and the stream limits.
//! A change to any of these breaks loading of older snapshots.
//!
//! The host-guest message encoding is pinned by tests in
//! `hyperlight_common/src/flatbuffer_wrappers/abi_tests.rs`.
//! Bootstrap ring bytes are pinned by the test below.
//!
//! When an assertion fires, see `docs/snapshot-versioning.md`.

use super::file::{
    MT_CONFIG_CURRENT, MT_SNAPSHOT_CURRENT, OCI_LAYOUT_VERSION, SNAPSHOT_ABI_VERSION,
};

const EXPECTED_ABI_VERSION: u32 = 12;
const EXPECTED_MT_CONFIG: &str = "application/vnd.hyperlight.snapshot.config.v6+json";
const EXPECTED_MT_SNAPSHOT: &str = "application/vnd.hyperlight.snapshot.memory.v2";
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
    use hyperlight_common::outb::OutBAction;
    abi_assert!(OutBAction::Abort as u16 == 102);
    abi_assert!(OutBAction::DebugPrint as u16 == 103);
    #[cfg(feature = "trace_guest")]
    abi_assert!(OutBAction::TraceBatch as u16 == 104);
    #[cfg(feature = "mem_profile")]
    abi_assert!(OutBAction::TraceMemoryAlloc as u16 == 105);
    #[cfg(feature = "mem_profile")]
    abi_assert!(OutBAction::TraceMemoryFree as u16 == 106);
    abi_assert!(OutBAction::VirtqNotify as u16 == 109);
};

const _: () = {
    use hyperlight_common::outb::VmAction;
    abi_assert!(VmAction::PvTimerConfig as u16 == 107);
    abi_assert!(VmAction::Halt as u16 == 108);
};

const _: () = {
    use crate::mem::layout::SandboxMemoryLayout;
    abi_assert!(SandboxMemoryLayout::BASE_ADDRESS == 0x4000);
};

const _: () = {
    use hyperlight_common::transport::MsgKind;

    abi_assert!(MsgKind::Request as u8 == 0x01);
    abi_assert!(MsgKind::Response as u8 == 0x02);
    abi_assert!(MsgKind::Stream as u8 == 0x03);
    abi_assert!(MsgKind::Log as u8 == 0x06);
};

const _: () = {
    use hyperlight_common::stream::{MAX_STREAMS, MAX_TRANSFERS, StatusFlags};

    abi_assert!(StatusFlags::READY.bits() == 0x01);
    abi_assert!(StatusFlags::ACTIVE.bits() == 0x02);
    abi_assert!(MAX_STREAMS == 16);
    abi_assert!(MAX_TRANSFERS == 16);
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

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::mem::layout::SandboxMemoryLayout;
    use crate::mem::shared_mem::ExclusiveSharedMemory;
    use crate::mem::virtq::VirtqSnapshot;
    use crate::sandbox::SandboxConfiguration;

    #[test]
    fn bootstrap_ring_images_match_snapshot_abi() {
        let mut config = SandboxConfiguration::default();
        config.set_scratch_size(512 * 1024);
        config.set_g2h_queue_size(16);
        config.set_h2g_queue_size(8);
        config.set_g2h_buffer_size(4096);
        config.set_h2g_buffer_size(3000);
        config.set_g2h_pool_pages(3);
        config.set_h2g_pool_pages(3);

        let layout = SandboxMemoryLayout::new(config, 16 * 1024).unwrap();
        let scratch = ExclusiveSharedMemory::new(layout.get_scratch_size())
            .unwrap()
            .build()
            .0;
        VirtqSnapshot::bootstrap(&layout)
            .unwrap()
            .restore(&layout, &scratch)
            .unwrap();

        let arena = layout.get_transport_arena();
        let g2h_offset = layout.arena_scratch_offset();
        let h2g_offset = g2h_offset + (arena.h2g_ring_addr() - arena.base_addr()) as usize;
        let mut digest = Sha256::new();

        for (offset, len) in [
            (g2h_offset, layout.get_g2h_queue_dims().ring_len()),
            (h2g_offset, layout.get_h2g_queue_dims().ring_len()),
        ] {
            let mut bytes = vec![0; len];
            scratch.copy_to_slice(&mut bytes, offset).unwrap();
            digest.update(bytes);
        }

        // Descriptor addresses use the architecture's fixed scratch mapping.
        #[cfg(target_arch = "x86_64")]
        let expected = "190ad84e314d01a8423901f96297e9bbcc3b49c531929b6170b8e77a4ae5622c";
        #[cfg(target_arch = "aarch64")]
        let expected = "385ef94cb91007d372092c81c91bcd5547bde04366b4c839a0a417b6d8b02d8b";

        assert_eq!(
            hex::encode(digest.finalize()),
            expected,
            "snapshot bootstrap ABI changed. See docs/snapshot-versioning.md."
        );
    }
}
