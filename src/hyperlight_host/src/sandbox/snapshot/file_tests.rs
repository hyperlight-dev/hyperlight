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

//! Tests for the snapshot file format (`super::file`).

#![cfg(test)]

use std::sync::Arc;

use hyperlight_testing::simple_guest_as_string;

use super::file::{FIXED_PREFIX_SIZE, HypervisorTag, RawHashes, RawHeaderV1, RawPreamble};
use crate::sandbox::snapshot::Snapshot;
use crate::{GuestBinary, HostFunctions, MultiUseSandbox, UninitializedSandbox};

/// Absolute file offset of a `RawHeaderV1` field. Computed from
/// the struct definition so it stays correct if the field order
/// changes.
macro_rules! v1_offset {
    ($field:ident) => {
        std::mem::size_of::<RawPreamble>() + std::mem::offset_of!(RawHeaderV1, $field)
    };
}

fn create_test_sandbox() -> MultiUseSandbox {
    let path = simple_guest_as_string().unwrap();
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

fn create_snapshot_from_binary() -> Snapshot {
    let path = simple_guest_as_string().unwrap();
    Snapshot::from_env(
        GuestBinary::FilePath(path),
        crate::sandbox::SandboxConfiguration::default(),
    )
    .unwrap()
}

#[test]
fn from_snapshot_already_initialized_in_memory() {
    // Test from_snapshot with a snapshot taken from an already-initialized
    // sandbox (NextAction::Call), directly from memory without file I/O
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let new_snap = Snapshot {
        sandbox_id: super::SANDBOX_CONFIGURATION_COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        layout: *snapshot.layout(),
        memory: snapshot.memory().clone(),
        regions: snapshot.regions().to_vec(),
        load_info: snapshot.load_info(),
        hash: snapshot.hash,
        stack_top_gva: snapshot.stack_top_gva(),
        sregs: snapshot.sregs().cloned(),
        entrypoint: snapshot.entrypoint(),
        snapshot_generation: snapshot.snapshot_generation(),
        host_functions: snapshot.host_functions.clone(),
    };

    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(new_snap), HostFunctions::default(), None).unwrap();
    let result: i32 = sbox2.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn from_snapshot_in_memory() {
    // Test from_snapshot pathway using the existing Snapshot::from_env
    let path = simple_guest_as_string().unwrap();
    let snap = Snapshot::from_env(
        GuestBinary::FilePath(path),
        crate::sandbox::SandboxConfiguration::default(),
    )
    .unwrap();

    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(snap), HostFunctions::default(), None).unwrap();

    // from_env creates a snapshot with NextAction::Initialise,
    // so from_snapshot will run the init code via vm.initialise()
    let result: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn round_trip_save_load_call() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("test.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    let result: String = sbox2.call("Echo", "hello\n".to_string()).unwrap();
    assert_eq!(result, "hello\n");
}

#[test]
fn snapshot_and_pt_size_round_trip() {
    // Running-sandbox snapshot.
    let mut sbox = create_test_sandbox();
    let snap = sbox.snapshot().unwrap();
    let original_snapshot_size = snap.layout().snapshot_size;
    let original_pt_size = snap.layout().pt_size;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("running.hls");
    snap.to_file(&path).unwrap();

    let loaded = Snapshot::from_file(&path).unwrap();
    assert_eq!(loaded.layout().snapshot_size, original_snapshot_size);
    assert_eq!(loaded.layout().pt_size, original_pt_size);

    // Pre-init snapshot.
    let preinit = create_snapshot_from_binary();
    let preinit_snapshot_size = preinit.layout().snapshot_size;
    let preinit_pt_size = preinit.layout().pt_size;

    let path = dir.path().join("preinit.hls");
    preinit.to_file(&path).unwrap();

    let loaded = Snapshot::from_file(&path).unwrap();
    assert_eq!(loaded.layout().snapshot_size, preinit_snapshot_size);
    assert_eq!(loaded.layout().pt_size, preinit_pt_size);
}

#[test]
fn hash_verification_detects_corruption() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("corrupted.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Corrupt a byte in the memory blob (after the 4096-byte header)
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(4096 + 100)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(4096 + 100)).unwrap();
        file.write_all(&byte).unwrap();
    }

    let result = Snapshot::from_file(&snap_path);
    let err_msg = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("expected load to fail with hash mismatch"),
    };
    assert!(
        err_msg.contains("hash mismatch"),
        "expected hash mismatch error, got: {}",
        err_msg
    );
}

#[test]
fn arch_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("wrong_arch.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite the architecture tag
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(arch) as u64)).unwrap();
        file.write_all(&99u32.to_le_bytes()).unwrap();
    }

    let result = Snapshot::from_file(&snap_path);
    let err_msg = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("expected load to fail with arch mismatch"),
    };
    assert!(
        err_msg.contains("architecture"),
        "expected arch-related error, got: {}",
        err_msg
    );
}

#[test]
fn format_version_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("wrong_version.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite the format version
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(
            std::mem::offset_of!(RawPreamble, format_version) as u64,
        ))
        .unwrap();
        file.write_all(&999u32.to_le_bytes()).unwrap();
    }

    let result = Snapshot::from_file(&snap_path);
    let err_msg = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("expected load to fail with version mismatch"),
    };
    assert!(
        err_msg.contains("format version"),
        "expected version mismatch error, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("convertible"),
        "expected hint about convertibility, got: {}",
        err_msg
    );
}

#[test]
fn abi_version_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("wrong_abi.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite the ABI version
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(abi_version) as u64))
            .unwrap();
        file.write_all(&999u32.to_le_bytes()).unwrap();
    }

    let result = Snapshot::from_file(&snap_path);
    let err_msg = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("expected load to fail with ABI version mismatch"),
    };
    assert!(
        err_msg.contains("ABI version mismatch"),
        "expected ABI version mismatch error, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("regenerated"),
        "expected hint about regeneration, got: {}",
        err_msg
    );
}

#[test]
fn hypervisor_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("wrong_hv.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite the hypervisor tag with a valid but wrong tag.
    let current = HypervisorTag::current().unwrap();
    let wrong_tag = match current {
        HypervisorTag::Whp => HypervisorTag::Kvm,
        _ => HypervisorTag::Whp,
    };
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(hypervisor) as u64))
            .unwrap();
        file.write_all(&(wrong_tag as u64).to_le_bytes()).unwrap();
    }

    let result = Snapshot::from_file(&snap_path);
    let err_msg = match result {
        Err(e) => format!("{}", e),
        Ok(_) => panic!("expected load to fail with hypervisor mismatch"),
    };
    assert!(
        err_msg.contains("hypervisor mismatch"),
        "expected hypervisor mismatch error, got: {}",
        err_msg
    );
}

#[test]
fn restore_from_loaded_snapshot() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("restore.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    // Mutate state
    sbox.call::<i32>("AddToStatic", 42i32).unwrap();
    let val: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(val, 42);

    // Take a new snapshot and restore to it
    let snap2 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 10i32).unwrap();
    let val: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(val, 52);

    sbox.restore(snap2).unwrap();
    let val: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(val, 42);
}

#[test]
fn restore_to_original_file_snapshot() {
    let mut sbox = create_test_sandbox();
    sbox.call::<i32>("AddToStatic", 10i32).unwrap();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("original.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());
    let mut sbox =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    sbox.call::<i32>("AddToStatic", 42i32).unwrap();
    let val: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(val, 52);

    sbox.restore(loaded).unwrap();
    let val: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(val, 10);
}

/// Sandboxes built from clones of the same `Arc<Snapshot>` must
/// be mutually `restore`-compatible (they share the same
/// `sandbox_id`). Conversely, two `Snapshot::from_file` calls of
/// the same path return distinct snapshots; that property is
/// exercised by `restore_to_different_file_loaded_snapshot_rejected`.
#[test]
fn sandboxes_from_shared_arc_snapshot_can_restore_to_each_other() {
    let mut producer = create_test_sandbox();
    let snapshot = producer.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("shared_id.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());
    let mut sbox1 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    // Take an in-process snapshot from one sibling. That snapshot
    // inherits its sandbox's id, which must match every other sandbox
    // built from the same `Arc<Snapshot>`.
    sbox1.call::<i32>("AddToStatic", 7i32).unwrap();
    let mid_snap = sbox1.snapshot().unwrap();

    let mut sbox2 = MultiUseSandbox::from_snapshot(loaded, HostFunctions::default(), None).unwrap();
    // Restoring `sbox2` to a snapshot taken from `sbox1` must
    // succeed because they share the same id.
    sbox2.restore(mid_snap).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 7);
}

/// A single `Arc<Snapshot>` loaded from disk must be safely shared
/// across many `from_snapshot` calls. Each resulting sandbox gets
/// its own CoW view and must be independent of the others.
#[test]
fn many_sandboxes_share_single_arc_snapshot() {
    const N: usize = 8;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("shared_arc.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());

    let mut sandboxes: Vec<MultiUseSandbox> = (0..N)
        .map(|_| {
            MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap()
        })
        .collect();

    // Each sandbox writes a unique value and must observe its own write.
    for (i, sbox) in sandboxes.iter_mut().enumerate() {
        sbox.call::<i32>("AddToStatic", (i as i32 + 1) * 10)
            .unwrap();
    }
    for (i, sbox) in sandboxes.iter_mut().enumerate() {
        let val: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(
            val,
            (i as i32 + 1) * 10,
            "sandbox {i} must observe its own write",
        );
    }

    // Dropping the original Arc<Snapshot> while sandboxes are still
    // alive must not invalidate their CoW mappings.
    drop(loaded);
    for (i, sbox) in sandboxes.iter_mut().enumerate() {
        let val: i32 = sbox.call("GetStatic", ()).unwrap();
        assert_eq!(
            val,
            (i as i32 + 1) * 10,
            "sandbox {i} must still work after the source Arc is dropped",
        );
    }
}

/// Multiple sandboxes built from the same on-disk snapshot must
/// behave correctly under concurrent use from multiple threads.
#[test]
fn concurrent_sandboxes_from_same_file() {
    use std::thread;

    const N: usize = 8;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("concurrent.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());

    let handles: Vec<_> = (0..N)
        .map(|i| {
            let loaded = loaded.clone();
            thread::spawn(move || {
                let mut sbox =
                    MultiUseSandbox::from_snapshot(loaded, HostFunctions::default(), None).unwrap();
                let increment = (i as i32 + 1) * 7;
                for _ in 0..5 {
                    sbox.call::<i32>("AddToStatic", increment).unwrap();
                }
                let final_val: i32 = sbox.call("GetStatic", ()).unwrap();
                assert_eq!(
                    final_val,
                    increment * 5,
                    "thread {i} must see its own writes"
                );
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Snapshots loaded from the same file must be restorable
/// independently from each other after concurrent mutations.
#[test]
fn restore_works_per_sandbox_with_shared_file() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("restore_shared.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());

    let mut sbox1 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    sbox1.call::<i32>("AddToStatic", 100i32).unwrap();
    sbox2.call::<i32>("AddToStatic", 200i32).unwrap();

    sbox1.restore(loaded.clone()).unwrap();
    assert_eq!(sbox1.call::<i32>("GetStatic", ()).unwrap(), 0);
    // sbox2 must be unaffected by sbox1's restore.
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 200);

    sbox2.restore(loaded).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

/// Pre-init snapshots (NextAction::Initialise) round-tripped through
/// a file must be usable concurrently by multiple sandboxes. This is
/// distinct from already-initialised (`Call`) snapshots because each
/// sandbox runs the guest init code under `vm.initialise()`.
#[test]
fn multiple_sandboxes_from_pre_init_file() {
    let snapshot = create_snapshot_from_binary();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("preinit_shared.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&snap_path).unwrap());

    let mut sbox1 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();
    let mut sbox2 = MultiUseSandbox::from_snapshot(loaded, HostFunctions::default(), None).unwrap();

    sbox1.call::<i32>("AddToStatic", 11i32).unwrap();
    assert_eq!(sbox1.call::<i32>("GetStatic", ()).unwrap(), 11);
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);

    sbox2.call::<i32>("AddToStatic", 22i32).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 22);
    assert_eq!(sbox1.call::<i32>("GetStatic", ()).unwrap(), 11);
}

#[test]
fn snapshot_then_save_round_trip() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path1 = dir.path().join("first.hls");
    snapshot.to_file(&snap_path1).unwrap();

    // Load, create sandbox, mutate, take snapshot, save again
    let loaded = Snapshot::from_file(&snap_path1).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    sbox2.call::<i32>("AddToStatic", 77i32).unwrap();
    let snap2 = sbox2.snapshot().unwrap();

    let snap_path2 = dir.path().join("second.hls");
    snap2.to_file(&snap_path2).unwrap();

    // Load the second snapshot and verify mutated state
    let loaded2 = Snapshot::from_file(&snap_path2).unwrap();
    let mut sbox3 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded2), HostFunctions::default(), None).unwrap();

    let val: i32 = sbox3.call("GetStatic", ()).unwrap();
    assert_eq!(val, 77);
}

/// `MultiUseSandbox::from_snapshot` should register the default
/// `HostPrint` host function, just like the regular codepath.
#[test]
fn from_snapshot_has_default_host_print() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("test.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    let result = sbox2.call::<i32>("PrintOutput", "hello from snapshot".to_string());
    assert!(
        result.is_ok(),
        "PrintOutput should succeed because HostPrint is registered by from_snapshot: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn from_file_unchecked_skips_hash_verification() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("unchecked.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Corrupt a byte in the memory blob (past the header)
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        // Write garbage into the memory blob region
        file.seek(SeekFrom::Start(4096 + 64)).unwrap();
        file.write_all(&[0xFF; 16]).unwrap();
    }

    // from_file (with hash check) should fail
    let result = Snapshot::from_file(&snap_path);
    assert!(result.is_err(), "from_file should detect corruption");

    // from_file_unchecked should succeed despite corruption
    let loaded = Snapshot::from_file_unchecked(&snap_path);
    assert!(loaded.is_ok(), "from_file_unchecked should skip hash check");
}

/// Sandbox built with a custom host function — a snapshot taken
/// from it must persist the function's signature, and loading
/// requires the same function to be registered.
fn create_sandbox_with_custom_host_funcs() -> MultiUseSandbox {
    use crate::func::Registerable;
    let path = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    u.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    u.evolve().unwrap()
}

#[test]
fn from_snapshot_accepts_matching_host_functions() {
    use crate::func::Registerable;

    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("with_funcs.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut funcs = HostFunctions::default();
    funcs
        .register_host_function("Add", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    let result = MultiUseSandbox::from_snapshot(Arc::new(loaded), funcs, None);
    assert!(
        result.is_ok(),
        "from_snapshot should accept matching host fns: {:?}",
        result.err()
    );
}

#[test]
fn from_snapshot_rejects_missing_host_function() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("missing_fn.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    // Don't register "Add" — only the default HostPrint.
    let result = MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None);
    let err = result.expect_err("expected missing-fn rejection");
    let msg = format!("{}", err);
    assert!(
        msg.contains("missing") && msg.contains("Add"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn from_snapshot_rejects_signature_mismatch() {
    use crate::func::Registerable;

    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("sig_mismatch.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut funcs = HostFunctions::default();
    // Wrong signature: snapshot has (i32, i32) -> i32, register (String) -> i32.
    funcs
        .register_host_function("Add", |_s: String| Ok(0i32))
        .unwrap();
    let result = MultiUseSandbox::from_snapshot(Arc::new(loaded), funcs, None);
    let err = result.expect_err("expected signature mismatch");
    let msg = format!("{}", err);
    assert!(
        msg.contains("signature_mismatches") && msg.contains("Add"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn from_snapshot_allows_extra_host_functions() {
    use crate::func::Registerable;

    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("extra_funcs.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut funcs = HostFunctions::default();
    funcs
        .register_host_function("Add", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    // Extra functions not in the snapshot — superset is allowed.
    funcs
        .register_host_function("Extra", |x: i64| Ok(x * 2))
        .unwrap();
    let result = MultiUseSandbox::from_snapshot(Arc::new(loaded), funcs, None);
    assert!(
        result.is_ok(),
        "extras should be allowed (superset semantics): {:?}",
        result.err()
    );
}

/// Register enough host functions on the sandbox that the
/// serialized `HostFunctionDetails` flatbuffer exceeds a single
/// page, exercising the variable-`memory_offset` path. Verifies
/// that the saved file round-trips cleanly and that
/// `from_snapshot` correctly accepts a matching set.
#[test]
fn from_snapshot_with_many_host_functions_round_trip() {
    use hyperlight_common::vmem::PAGE_SIZE;

    use crate::func::Registerable;

    let path = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    // Register many host functions with long names so the
    // serialized flatbuffer comfortably exceeds PAGE_SIZE.
    const N: usize = 200;
    for i in 0..N {
        let name = format!("HostFunc_with_a_reasonably_long_name_{:04}", i);
        u.register_host_function(&name, |a: i32, b: i32| Ok(a + b))
            .unwrap();
    }
    let mut sbox = u.evolve().unwrap();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("many_funcs.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Sanity-check that the file's recorded memory_offset is
    // larger than a single page (the host-function blob spilled
    // beyond the fixed header).
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&snap_path).unwrap();
        f.seek(SeekFrom::Start(v1_offset!(memory_offset) as u64))
            .unwrap();
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).unwrap();
        let memory_offset = u64::from_le_bytes(buf) as usize;
        assert!(
            memory_offset > PAGE_SIZE,
            "expected memory_offset > PAGE_SIZE for large host_funcs (got {})",
            memory_offset
        );
    }

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut funcs = HostFunctions::default();
    for i in 0..N {
        let name = format!("HostFunc_with_a_reasonably_long_name_{:04}", i);
        funcs
            .register_host_function(&name, |a: i32, b: i32| Ok(a + b))
            .unwrap();
    }
    let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), funcs, None).unwrap();
    let result: String = sbox2.call("Echo", "hello\n".to_string()).unwrap();
    assert_eq!(result, "hello\n");
}

/// A file with the wrong magic bytes should be rejected with a
/// descriptive error.
#[test]
fn bad_magic_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("bad_magic.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite the 4-byte magic at offset 0.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"XXXX").unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected magic mismatch"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("magic"),
        "expected magic-related error, got: {}",
        msg
    );
}

/// A file truncated to less than the fixed header should be
/// rejected at header read time, not panic.
#[test]
fn truncated_file_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("truncated.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Truncate to 100 bytes (well below the fixed header).
    std::fs::OpenOptions::new()
        .write(true)
        .open(&snap_path)
        .unwrap()
        .set_len(100)
        .unwrap();

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected truncation error"),
    };
    let msg = format!("{}", err);
    // Either "truncated" (read_bytes) or "snapshot read error" (read_u64) —
    // both are acceptable; just assert no panic and an error came back.
    assert!(
        msg.contains("truncated") || msg.contains("read error"),
        "expected truncation/read error, got: {}",
        msg
    );
}

/// A file whose `host_funcs_size` claims more bytes than the
/// host-funcs region actually contains should be rejected
/// without panic.
#[test]
fn corrupt_host_funcs_size_rejected() {
    // Use a sandbox with at least one custom host function so the
    // host-funcs region exists in the file.
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("bad_hf_size.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Overwrite host_funcs_size with a huge value that exceeds
    // the file.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(host_funcs_size) as u64))
            .unwrap();
        file.write_all(&u64::MAX.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected host_funcs_size error"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("host_funcs_size"),
        "expected host_funcs_size error, got: {}",
        msg
    );
}

/// A `host_funcs_size` that fits within the file but exceeds the
/// fixed cap must be rejected before the loader tries to allocate
/// a buffer of that size.
#[test]
fn oversized_host_funcs_size_rejected() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("oversized_hf.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Pad the file so a value that's well above the cap still
    // fits within `file_len` (otherwise the existing
    // "exceeds remaining file bytes" check would catch it first).
    let bloated = 64 * 1024 * 1024_u64;
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        let cur_len = file.metadata().unwrap().len();
        file.seek(SeekFrom::Start(cur_len)).unwrap();
        file.write_all(&vec![0u8; bloated as usize]).unwrap();
        file.seek(SeekFrom::Start(v1_offset!(host_funcs_size) as u64))
            .unwrap();
        file.write_all(&bloated.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected oversized host_funcs_size error"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("exceeds maximum"),
        "expected cap error, got: {}",
        msg
    );
}

/// `memory_offset` of 0 is structurally invalid because the memory
/// blob would overlap the fixed prefix.
#[test]
fn memory_offset_zero_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("memory_offset_zero.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(memory_offset) as u64))
            .unwrap();
        file.write_all(&0u64.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected memory_offset=0 to be rejected"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("memory_offset"),
        "expected memory_offset error, got: {}",
        msg
    );
}

/// `memory_offset` must be a multiple of `PAGE_SIZE` so the memory
/// blob can be mmapped directly. A non-aligned offset must be
/// rejected.
#[test]
fn memory_offset_unaligned_rejected() {
    use hyperlight_common::vmem::PAGE_SIZE;

    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("memory_offset_unaligned.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(memory_offset) as u64))
            .unwrap();
        let bad = (PAGE_SIZE as u64) + 1;
        file.write_all(&bad.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected unaligned memory_offset to be rejected"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("memory_offset") && msg.contains("PAGE_SIZE"),
        "expected page-alignment error, got: {}",
        msg
    );
}

/// `memory_size` that would push the memory blob past the end of
/// the file must be rejected.
#[test]
fn memory_blob_extends_past_eof_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("memory_size_overflow.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        let file_len = file.metadata().unwrap().len();
        file.seek(SeekFrom::Start(v1_offset!(memory_size) as u64))
            .unwrap();
        // A value that fits in u64 but is much larger than the
        // file, so the blob bound check trips before any add
        // overflows.
        file.write_all(&(file_len * 2).to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected oversized memory blob to be rejected"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("memory blob") && msg.contains("end of the file"),
        "expected blob-end error, got: {}",
        msg
    );
}

/// `entrypoint_tag` is a u64 discriminant for `NextAction`. Only
/// values 0 (Initialise) and 1 (Call) are defined. Anything else
/// must be rejected when parsing the raw header.
#[test]
fn invalid_entrypoint_tag_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("bad_entrypoint_tag.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(entrypoint_tag) as u64))
            .unwrap();
        file.write_all(&0xDEADu64.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected invalid entrypoint tag to be rejected"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("entrypoint tag"),
        "expected entrypoint-tag error, got: {}",
        msg
    );
}

/// `init_data_permissions` is stored as `u64` on disk but the in
/// memory flag set is `u32`. Any value with bits beyond the u32
/// range must be rejected before narrowing so that high bits do not
/// silently disappear.
#[test]
fn init_data_permissions_oversized_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("oversized_perms.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(init_data_permissions) as u64))
            .unwrap();
        // High 32 bits set so `u32::try_from` fails.
        file.write_all(&(1u64 << 33).to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected oversized init_data_permissions to be rejected"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("init_data_permissions") && msg.contains("u32"),
        "expected u32-range error, got: {}",
        msg
    );
}

/// `has_sregs` is serialized as `u64` for on-disk uniformity but is
/// semantically a boolean. Any value other than 0 or 1 must be
/// rejected at parse time.
#[test]
fn invalid_has_sregs_value_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("bad_has_sregs.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(has_sregs) as u64))
            .unwrap();
        file.write_all(&2u64.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected has_sregs validation error"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("has_sregs"),
        "expected has_sregs error, got: {}",
        msg
    );
}

/// A `Call` snapshot is mid-execution and must carry sregs.
/// Flipping `has_sregs` to 0 on such a snapshot must be rejected.
#[test]
fn call_snapshot_without_sregs_rejected() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("call_no_sregs.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(has_sregs) as u64))
            .unwrap();
        file.write_all(&0u64.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected entrypoint/has_sregs mismatch"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("has_sregs"),
        "expected has_sregs error, got: {}",
        msg
    );
}

/// An `Initialise` snapshot has not yet run on the vCPU and must
/// not carry sregs. Flipping `has_sregs` to 1 must be rejected.
#[test]
fn initialise_snapshot_with_sregs_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("init_with_sregs.hls");
    snapshot.to_file(&snap_path).unwrap();

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(has_sregs) as u64))
            .unwrap();
        file.write_all(&1u64.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected entrypoint/has_sregs mismatch"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("has_sregs"),
        "expected has_sregs error, got: {}",
        msg
    );
}

/// `header_hash` covers the preamble, header, sregs, and host_funcs
/// blob. Any mutation of those regions must trip verification, even
/// via `from_file_unchecked`.
#[test]
fn header_mutation_caught_by_hash() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("hdr_mut.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Flip a byte in `stack_top_gva` to mutate the header in place.
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(stack_top_gva) as u64))
            .unwrap();
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf).unwrap();
        buf[0] ^= 0xFF;
        file.seek(SeekFrom::Start(v1_offset!(stack_top_gva) as u64))
            .unwrap();
        file.write_all(&buf).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("header mutation must be detected"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );

    // `from_file_unchecked` skips the blob hash but still verifies
    // the header hash, so it must also reject this.
    let err = match Snapshot::from_file_unchecked(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("header mutation must be detected even by from_file_unchecked"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );
}

/// Sregs sit between the header and the host_funcs blob. Mutating
/// any sregs byte must trip `header_hash` verification.
#[test]
fn sregs_mutation_caught_by_hash() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("sregs_mut.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Flip the first byte of the sregs region (just after the
    // RawHeaderV1 ends).
    let sregs_offset = std::mem::size_of::<RawPreamble>() + std::mem::size_of::<RawHeaderV1>();
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(sregs_offset as u64)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(sregs_offset as u64)).unwrap();
        file.write_all(&byte).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("sregs mutation must be detected"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );
}

/// The host-functions flatbuffer blob is part of `header_hash`.
/// Mutating its bytes must trip verification.
#[test]
fn host_funcs_mutation_caught_by_hash() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("hf_mut.hls");
    snapshot.to_file(&snap_path).unwrap();

    let hf_offset = FIXED_PREFIX_SIZE;
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(hf_offset as u64)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(hf_offset as u64)).unwrap();
        file.write_all(&byte).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("host_funcs mutation must be detected"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );
}

/// `blob_hash` itself is part of `header_hash`. Flipping a bit
/// inside the on-disk `blob_hash` field must be detected by the
/// always-checked header hash, in both `from_file` and
/// `from_file_unchecked`. Without this property an attacker who
/// rewrites a tampered blob could also rewrite `blob_hash` to
/// match and slip past `from_file_unchecked`.
#[test]
fn blob_hash_field_mutation_caught_by_header_hash() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("blob_hash_mut.hls");
    snapshot.to_file(&snap_path).unwrap();

    // `RawHashes` sits between sregs and the host_funcs blob, so
    // its end is at `FIXED_PREFIX_SIZE`. Compute the field offset
    // from the struct itself so this stays correct if the layout
    // ever changes.
    let blob_hash_offset = FIXED_PREFIX_SIZE - std::mem::size_of::<RawHashes>()
        + std::mem::offset_of!(RawHashes, blob_hash);
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(blob_hash_offset as u64)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(blob_hash_offset as u64)).unwrap();
        file.write_all(&byte).unwrap();
    }

    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("blob_hash mutation must be detected"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );

    // The unchecked loader skips the blob hash itself, but
    // `blob_hash` is folded into `header_hash`, so the unchecked
    // loader must still reject this.
    let err = match Snapshot::from_file_unchecked(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("blob_hash mutation must be detected even by from_file_unchecked"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );
}

/// Security regression: an attacker who rewrites the memory blob
/// AND updates `RawHashes.blob_hash` to match the new blob must
/// still be rejected, because `header_hash` covers `blob_hash`.
/// Without this property `from_file_unchecked` would silently
/// accept attacker-controlled guest memory.
#[test]
fn blob_and_blob_hash_mutation_caught_by_header_hash() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("blob_and_hash_mut.hls");
    snapshot.to_file(&snap_path).unwrap();

    use std::io::{Read, Seek, SeekFrom, Write};

    // Read `memory_offset` and `memory_size` out of the header.
    let (memory_offset, memory_size) = {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(&snap_path)
            .unwrap();
        let mut buf8 = [0u8; 8];

        file.seek(SeekFrom::Start(v1_offset!(memory_offset) as u64))
            .unwrap();
        file.read_exact(&mut buf8).unwrap();
        let mo = u64::from_le_bytes(buf8) as usize;

        file.seek(SeekFrom::Start(v1_offset!(memory_size) as u64))
            .unwrap();
        file.read_exact(&mut buf8).unwrap();
        let ms = u64::from_le_bytes(buf8) as usize;

        (mo, ms)
    };

    // Mutate one byte in the memory blob.
    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start((memory_offset + 100) as u64))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start((memory_offset + 100) as u64))
            .unwrap();
        file.write_all(&byte).unwrap();
    }

    // Recompute `blob_hash` over the modified blob and write it
    // back into the `RawHashes.blob_hash` field. This is exactly
    // the attacker model: edit the blob, recompute the cheap hash,
    // hope the loader trusts it.
    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&snap_path)
            .unwrap();
        let mut blob = vec![0u8; memory_size];
        file.seek(SeekFrom::Start(memory_offset as u64)).unwrap();
        file.read_exact(&mut blob).unwrap();
        let new_blob_hash: [u8; 32] = blake3::hash(&blob).into();

        let blob_hash_offset = FIXED_PREFIX_SIZE - std::mem::size_of::<RawHashes>()
            + std::mem::offset_of!(RawHashes, blob_hash);
        file.seek(SeekFrom::Start(blob_hash_offset as u64)).unwrap();
        file.write_all(&new_blob_hash).unwrap();
    }

    // `from_file` rejects: the blob hash now matches the modified
    // blob, but `header_hash` still covers the original `blob_hash`.
    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("tampered blob with matching blob_hash must be detected"),
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );

    // `from_file_unchecked` must also reject. This is the load-bearing
    // case: it skips the blob hash check itself, so the only thing
    // protecting it from a tampered blob is `header_hash` covering
    // `blob_hash`.
    let err = match Snapshot::from_file_unchecked(&snap_path) {
        Err(e) => e,
        Ok(_) => {
            panic!("tampered blob with matching blob_hash must be detected by from_file_unchecked")
        }
    };
    assert!(
        format!("{}", err).contains("header_hash"),
        "expected header_hash error, got: {}",
        err
    );
}

/// `MAP_PRIVATE` / `FILE_MAP_COPY` invariant: guest writes
/// through a file-backed snapshot must NOT modify the on-disk
/// file. Verifies this by hashing the raw bytes before and after
/// running guest functions that mutate state.
#[test]
fn cow_does_not_mutate_backing_file() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("cow.hls");
    snapshot.to_file(&snap_path).unwrap();

    let hash_before: [u8; 32] = blake3::hash(&std::fs::read(&snap_path).unwrap()).into();

    // Load the snapshot and have the guest write into mapped memory.
    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    sbox.call::<i32>("AddToStatic", 999i32).unwrap();

    // Drop the sandbox to ensure mappings are released before re-reading.
    drop(sbox);

    let hash_after: [u8; 32] = blake3::hash(&std::fs::read(&snap_path).unwrap()).into();
    assert_eq!(
        hash_before, hash_after,
        "guest writes must not propagate to the backing snapshot file"
    );
}

/// Pre-init snapshot (`from_env`) round-tripped through a file
/// must still complete guest initialisation on load.
#[test]
fn pre_init_snapshot_save_load() {
    use super::NextAction;

    let snapshot = create_snapshot_from_binary();
    // Guard: this constructor produces a `NextAction::Initialise`
    // snapshot. If that ever changes, this test loses its purpose.
    assert!(
        matches!(snapshot.entrypoint(), NextAction::Initialise(_)),
        "expected pre-init snapshot from from_env"
    );

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("preinit.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded = Snapshot::from_file(&snap_path).unwrap();
    assert!(
        matches!(loaded.entrypoint(), NextAction::Initialise(_)),
        "pre-init entrypoint should round-trip"
    );

    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    // Guest init must run via vm.initialise() before the call works.
    let result: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

/// `from_file_unchecked` skips the blake3 hash check but must
/// still validate the rest of the header (magic, format version,
/// architecture, ABI version, hypervisor tag).
#[test]
fn from_file_unchecked_still_validates_header() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("unchecked_bad_arch.hls");
    snapshot.to_file(&snap_path).unwrap();

    // Corrupt the architecture tag to a bogus value.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&snap_path)
            .unwrap();
        file.seek(SeekFrom::Start(v1_offset!(arch) as u64)).unwrap();
        file.write_all(&99u32.to_le_bytes()).unwrap();
    }

    let err = match Snapshot::from_file_unchecked(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected arch validation to fail even without hash check"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("architecture"),
        "expected arch error from from_file_unchecked, got: {}",
        msg
    );
}

// Tests for `MultiUseSandbox::from_snapshot` `SandboxConfiguration`
// plumbing. Layout fields must be silently overridden by the snapshot.
// Runtime fields (interrupt knobs, gdb, crashdump) must take effect.
// `interrupt_*` are covered by `interrupt_custom_signal_no_and_retry_delay`
// in `tests/integration_test.rs`. `guest_debug_info` (gdb) needs an
// in-test gdb stub and is not exercised here.

/// Layout fields supplied via `SandboxConfiguration` must be silently
/// overridden. The snapshot's own layout is authoritative because the
/// on-disk memory blob already encodes those sizes.
#[test]
fn from_snapshot_silently_ignores_layout_overrides() {
    use crate::sandbox::SandboxConfiguration;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let original_input = snapshot.layout().input_data_size;
    let original_output = snapshot.layout().output_data_size;
    let original_heap = snapshot.layout().heap_size;
    let original_scratch = snapshot.layout().scratch_size;

    // Build a config whose every layout field is different from the
    // snapshot's layout. `from_snapshot` must ignore all of them.
    let mut config = SandboxConfiguration::default();
    config.set_input_data_size(original_input * 2);
    config.set_output_data_size(original_output * 2);
    config.set_heap_size((original_heap as u64) * 2);
    config.set_scratch_size(original_scratch * 2);

    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot.clone(), HostFunctions::default(), Some(config))
            .unwrap();

    // The new sandbox must be fully usable.
    sbox2.call::<i32>("GetStatic", ()).unwrap();

    // The new sandbox's layout must match the snapshot's, not the
    // override config.
    let new_snap = sbox2.snapshot().unwrap();
    assert_eq!(new_snap.layout().input_data_size, original_input);
    assert_eq!(new_snap.layout().output_data_size, original_output);
    assert_eq!(new_snap.layout().heap_size, original_heap);
    assert_eq!(new_snap.layout().scratch_size, original_scratch);
}

/// `from_snapshot` must honor `guest_core_dump=true` from the supplied
/// config so that `generate_crashdump_to_dir` actually writes a file.
#[test]
#[cfg(crashdump)]
fn from_snapshot_honors_guest_core_dump_enabled() {
    use crate::sandbox::SandboxConfiguration;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let mut config = SandboxConfiguration::default();
    config.set_guest_core_dump(true);

    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), Some(config)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    sbox2
        .generate_crashdump_to_dir(dir.path().to_str().unwrap())
        .unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        !entries.is_empty(),
        "expected core dump file to be created when guest_core_dump=true"
    );
}

/// `from_snapshot` must honor `guest_core_dump=false` from the supplied
/// config so that `generate_crashdump_to_dir` produces no file.
#[test]
#[cfg(crashdump)]
fn from_snapshot_honors_guest_core_dump_disabled() {
    use crate::sandbox::SandboxConfiguration;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let mut config = SandboxConfiguration::default();
    config.set_guest_core_dump(false);

    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), Some(config)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    sbox2
        .generate_crashdump_to_dir(dir.path().to_str().unwrap())
        .unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "expected no core dump file when guest_core_dump=false, found {:?}",
        entries.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

/// `from_file` on a non-existent path must return an error rather
/// than panicking.
#[test]
fn from_file_nonexistent_path_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("does_not_exist.hls");
    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected I/O error for missing file"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("failed to open snapshot file"),
        "expected open-failure message, got: {}",
        msg
    );
}

/// `to_file` must succeed when overwriting an existing file, and
/// the resulting file must be loadable.
#[test]
fn to_file_overwrites_existing() {
    let mut sbox = create_test_sandbox();
    let snap1 = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("overwrite.hls");

    snap1.to_file(&snap_path).unwrap();
    let first_size = std::fs::metadata(&snap_path).unwrap().len();
    assert!(first_size > 0);

    // Mutate sandbox state and snapshot again, overwriting the same file.
    sbox.call::<i32>("AddToStatic", 314i32).unwrap();
    let snap2 = sbox.snapshot().unwrap();
    snap2.to_file(&snap_path).unwrap();

    // Load the overwritten file and verify it observes the second
    // snapshot's state.
    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 314);
}

/// `from_snapshot`-built sandbox must support `map_file_cow` of a
/// host file and the guest must read back the file contents.
#[test]
fn map_file_cow_after_from_snapshot() {
    use std::io::Write;

    // Build a snapshot from disk.
    let mut producer = create_test_sandbox();
    let snap = producer.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("for_map.hls");
    snap.to_file(&snap_path).unwrap();

    // Build a host file with known contents to map into the sandbox.
    let page_size = page_size::get();
    let payload = b"hello from map_file_cow after from_snapshot";
    let mut padded = vec![0u8; page_size];
    padded[..payload.len()].copy_from_slice(payload);
    let file_path = dir.path().join("mapped_payload.bin");
    std::fs::File::create(&file_path)
        .unwrap()
        .write_all(&padded)
        .unwrap();

    // Construct a sandbox from the on-disk snapshot and map the file.
    let loaded = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    let guest_base: u64 = 0x1_0000_0000;
    let mapped_size = sbox.map_file_cow(&file_path, guest_base, None).unwrap();
    assert!(mapped_size as usize >= payload.len());

    // Read back from the guest and verify byte-for-byte equality.
    let actual: Vec<u8> = sbox
        .call("ReadMappedBuffer", (guest_base, payload.len() as u64, true))
        .unwrap();
    assert_eq!(actual, payload);
}

/// A sandbox restored from a file-loaded snapshot must still be
/// snapshottable, and the new snapshot must save and reload
/// correctly.
#[test]
fn snapshot_after_restore_to_file_loaded_baseline() {
    let mut producer = create_test_sandbox();
    let baseline = producer.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let baseline_path = dir.path().join("baseline.hls");
    baseline.to_file(&baseline_path).unwrap();

    let loaded = Arc::new(Snapshot::from_file(&baseline_path).unwrap());
    let mut sbox =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    // Mutate, restore to the file baseline, mutate to a new value,
    // then snapshot the post-restore sandbox.
    sbox.call::<i32>("AddToStatic", 7i32).unwrap();
    sbox.restore(loaded).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    sbox.call::<i32>("AddToStatic", 99i32).unwrap();

    let new_snap = sbox.snapshot().unwrap();
    let new_path = dir.path().join("after_restore.hls");
    new_snap.to_file(&new_path).unwrap();

    // Load the new snapshot in a fresh sandbox and verify state.
    let reloaded = Snapshot::from_file(&new_path).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(reloaded), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 99);
}

/// `from_file` on an empty file must return an error rather than
/// panicking.
#[test]
fn from_file_empty_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("empty.hls");
    std::fs::File::create(&snap_path).unwrap();
    let err = match Snapshot::from_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected error from zero-byte file"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("snapshot read error") || msg.contains("truncated"),
        "expected truncation/read error, got: {}",
        msg
    );
}

/// `to_file` to a path inside a non-existent directory must return
/// an I/O error rather than panicking.
#[test]
fn to_file_nonexistent_directory_returns_error() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("does_not_exist").join("snap.hls");
    let err = match snapshot.to_file(&snap_path) {
        Err(e) => e,
        Ok(_) => panic!("expected error writing to nonexistent directory"),
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("failed to create snapshot file"),
        "expected create-failure message, got: {}",
        msg
    );
}

/// Restore is currently rejected when the target snapshot was
/// loaded from a different file than the sandbox was built from.
/// `Snapshot::sandbox_id` is a process-local atomic counter assigned
/// fresh on every `from_file`, so the ids never match. Documented as
/// a known limitation in `MultiUseSandbox::from_snapshot` and tracked
/// by the `TODO` to replace ids with a `SandboxMemoryLayout`-equality
/// check.
#[test]
fn restore_to_different_file_loaded_snapshot_rejected() {
    let mut producer = create_test_sandbox();

    let dir = tempfile::tempdir().unwrap();

    // Snapshot A: zero state.
    let snap_a_path = dir.path().join("a.hls");
    producer.snapshot().unwrap().to_file(&snap_a_path).unwrap();

    // Snapshot B: state with AddToStatic(50).
    producer.call::<i32>("AddToStatic", 50i32).unwrap();
    let snap_b_path = dir.path().join("b.hls");
    producer.snapshot().unwrap().to_file(&snap_b_path).unwrap();

    let loaded_a = Arc::new(Snapshot::from_file(&snap_a_path).unwrap());
    let mut sbox =
        MultiUseSandbox::from_snapshot(loaded_a, HostFunctions::default(), None).unwrap();

    let loaded_b = Arc::new(Snapshot::from_file(&snap_b_path).unwrap());
    let err = match sbox.restore(loaded_b) {
        Err(e) => e,
        Ok(_) => panic!("expected SnapshotSandboxMismatch from cross-file restore"),
    };
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("SnapshotSandboxMismatch"),
        "expected SnapshotSandboxMismatch, got: {}",
        msg
    );
}

/// Two independent `Snapshot::from_file` calls of the same path
/// must each yield a usable snapshot. Sandboxes built from each
/// must work independently and produce isolated CoW state.
#[test]
fn multiple_from_file_calls_of_same_path() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("multi_load.hls");
    snapshot.to_file(&snap_path).unwrap();

    let loaded_a = Arc::new(Snapshot::from_file(&snap_path).unwrap());
    let loaded_b = Arc::new(Snapshot::from_file(&snap_path).unwrap());

    let mut sbox_a =
        MultiUseSandbox::from_snapshot(loaded_a, HostFunctions::default(), None).unwrap();
    let mut sbox_b =
        MultiUseSandbox::from_snapshot(loaded_b, HostFunctions::default(), None).unwrap();

    sbox_a.call::<i32>("AddToStatic", 11i32).unwrap();
    sbox_b.call::<i32>("AddToStatic", 22i32).unwrap();

    assert_eq!(sbox_a.call::<i32>("GetStatic", ()).unwrap(), 11);
    assert_eq!(sbox_b.call::<i32>("GetStatic", ()).unwrap(), 22);
}

/// Loading a file via `Snapshot::from_file` after the file has been
/// rewritten with a different snapshot must observe the new contents.
/// Documents the load-once / no-cache semantic.
#[test]
fn from_file_after_overwrite_observes_new_contents() {
    let mut sbox = create_test_sandbox();
    let dir = tempfile::tempdir().unwrap();
    let snap_path = dir.path().join("evolving.hls");

    // Write a snapshot at state X.
    sbox.snapshot().unwrap().to_file(&snap_path).unwrap();
    // Load and immediately drop. On Windows, an overwriting `to_file`
    // call on a path with an active mapped view fails with
    // `ERROR_USER_MAPPED_FILE` (1224), so the loaded snapshot must be
    // released before re-writing the same path.
    {
        let _loaded_x = Snapshot::from_file(&snap_path).unwrap();
    }

    // Mutate and overwrite with a snapshot at state Y.
    sbox.call::<i32>("AddToStatic", 55i32).unwrap();
    sbox.snapshot().unwrap().to_file(&snap_path).unwrap();

    // A subsequent `from_file` of the same path must reflect Y.
    let loaded_y = Snapshot::from_file(&snap_path).unwrap();
    let mut sbox_y =
        MultiUseSandbox::from_snapshot(Arc::new(loaded_y), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox_y.call::<i32>("GetStatic", ()).unwrap(), 55);
}
