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

//! Tests for the OCI Image Layout snapshot format (`super::file`).

#![cfg(test)]

use std::sync::Arc;

use hyperlight_testing::simple_guest_as_string;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::func::Registerable;
use crate::sandbox::snapshot::Snapshot;
use crate::{GuestBinary, HostFunctions, MultiUseSandbox, UninitializedSandbox};

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

/// `Result::unwrap_err` requires `T: Debug`, but `Snapshot` is not
/// `Debug`. This wrapper is the test-side equivalent.
#[track_caller]
fn unwrap_err_snapshot(r: crate::Result<Snapshot>) -> crate::HyperlightError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected Snapshot::from_oci to fail"),
    }
}

/// Locate the single config blob inside `oci_dir`. Returns its full
/// path. Used by tests that mutate the on-disk JSON.
fn find_config_blob(oci_dir: &std::path::Path) -> std::path::PathBuf {
    let manifest_bytes = std::fs::read(oci_dir.join("index.json")).unwrap();
    let index: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let manifest_path = oci_dir.join("blobs").join("sha256").join(manifest_digest);
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let cfg_digest = manifest["config"]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    oci_dir.join("blobs").join("sha256").join(cfg_digest)
}

// =============================================================================
// In-memory `from_snapshot` round-trips (no file I/O).
// =============================================================================

#[test]
fn from_snapshot_already_initialized_in_memory() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None).unwrap();
    let result: i32 = sbox2.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn from_snapshot_in_memory_pre_init() {
    let snap = create_snapshot_from_binary();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(snap), HostFunctions::default(), None).unwrap();
    let result: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

// =============================================================================
// Round-trip via OCI layout on disk.
// =============================================================================

#[test]
fn round_trip_save_load_call() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let oci = dir.path().join("snap");
    snapshot.to_oci(&oci, "latest").unwrap();

    let loaded = Snapshot::from_oci(&oci, "latest").unwrap();
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
    let path = dir.path().join("running");
    snap.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    assert_eq!(loaded.layout().snapshot_size, original_snapshot_size);
    assert_eq!(loaded.layout().pt_size, original_pt_size);

    // Pre-init snapshot.
    let preinit = create_snapshot_from_binary();
    let preinit_snapshot_size = preinit.layout().snapshot_size;
    let preinit_pt_size = preinit.layout().pt_size;

    let path = dir.path().join("preinit");
    preinit.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    assert_eq!(loaded.layout().snapshot_size, preinit_snapshot_size);
    assert_eq!(loaded.layout().pt_size, preinit_pt_size);
}

#[test]
fn snapshot_generation_round_trip() {
    let mut sbox = create_test_sandbox();
    sbox.call::<String>("Echo", "a".to_string()).unwrap();
    let snap1 = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "b".to_string()).unwrap();
    sbox.call::<String>("Echo", "c".to_string()).unwrap();
    let snap3 = sbox.snapshot().unwrap();
    let gen1 = snap1.snapshot_generation();
    let gen3 = snap3.snapshot_generation();
    assert_ne!(gen1, gen3);

    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("s1");
    let p3 = dir.path().join("s3");
    snap1.to_oci(&p1, "latest").unwrap();
    snap3.to_oci(&p3, "latest").unwrap();

    let loaded1 = Snapshot::from_oci(&p1, "latest").unwrap();
    let loaded3 = Snapshot::from_oci(&p3, "latest").unwrap();
    assert_eq!(loaded1.snapshot_generation(), gen1);
    assert_eq!(loaded3.snapshot_generation(), gen3);
}

#[test]
fn pre_init_snapshot_save_load() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preinit");
    snap.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
}

// =============================================================================
// Restore semantics (id/generation gating).
// =============================================================================

#[test]
fn restore_from_loaded_snapshot() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let loaded = Arc::new(Snapshot::from_oci(&path, "latest").unwrap());
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    sbox2.call::<i32>("AddToStatic", 5i32).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 5);

    sbox2.restore(loaded).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn restore_across_independent_oci_loads_succeeds() {
    // Compatibility between a sandbox and a snapshot is structural
    // (memory layout plus host-function set). Two independent
    // `from_oci` loads of the same image produce structurally
    // identical snapshots, so a sandbox built from one accepts a
    // restore from the other.
    let mut sbox = create_test_sandbox();
    let snap1 = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("snap1");
    snap1.to_oci(&p1, "latest").unwrap();
    let p2 = dir.path().join("snap2");
    snap1.to_oci(&p2, "latest").unwrap();

    let loaded1 = Arc::new(Snapshot::from_oci(&p1, "latest").unwrap());
    let loaded2 = Arc::new(Snapshot::from_oci(&p2, "latest").unwrap());

    let mut sbox = MultiUseSandbox::from_snapshot(loaded2, HostFunctions::default(), None).unwrap();
    sbox.restore(loaded1).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn many_sandboxes_share_single_arc_snapshot() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let loaded = Arc::new(Snapshot::from_oci(&path, "latest").unwrap());
    let mut sandboxes = Vec::new();
    for _ in 0..4 {
        sandboxes.push(
            MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap(),
        );
    }
    for sbox in sandboxes.iter_mut() {
        assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    }
}

#[test]
fn concurrent_sandboxes_from_same_oci() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let path = std::sync::Arc::new(path);
    let mut handles = Vec::new();
    for _ in 0..4 {
        let p = path.clone();
        handles.push(std::thread::spawn(move || {
            let loaded = Snapshot::from_oci(p.as_ref(), "latest").unwrap();
            let mut sbox =
                MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None)
                    .unwrap();
            assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn cow_does_not_mutate_backing_file() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Hash every blob file to verify nothing changes after a CoW write
    // through the loaded sandbox.
    let blobs_dir = path.join("blobs").join("sha256");
    let snapshot_before: std::collections::BTreeMap<_, _> = std::fs::read_dir(&blobs_dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let bytes = std::fs::read(e.path()).unwrap();
            (e.file_name(), bytes)
        })
        .collect();

    {
        let loaded = Snapshot::from_oci(&path, "latest").unwrap();
        let mut sbox =
            MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None)
                .unwrap();
        sbox.call::<i32>("AddToStatic", 99).unwrap();
    }

    let snapshot_after: std::collections::BTreeMap<_, _> = std::fs::read_dir(&blobs_dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let bytes = std::fs::read(e.path()).unwrap();
            (e.file_name(), bytes)
        })
        .collect();
    assert_eq!(
        snapshot_before, snapshot_after,
        "CoW writes must not mutate any blob in the OCI layout"
    );
}

// =============================================================================
// Architecture / hypervisor / ABI gating.
// =============================================================================

/// Compute sha256 of `bytes` and return the lowercase hex digest.
fn sha256_hex(bytes: &[u8]) -> String {
    let arr: [u8; 32] = Sha256::digest(bytes).into();
    hex::encode(arr)
}

fn rewrite_config<F: FnOnce(&mut Value)>(oci_dir: &std::path::Path, mutate: F) {
    // Mutate the config blob and rewrite the manifest + index so the
    // OCI layout stays self-consistent: blob filenames, descriptor
    // sizes, and descriptor sha256 digests all match the current
    // bytes on disk. The point of these helpers is to exercise
    // field-level validators (arch, abi_version, hypervisor, etc.),
    // not the digest layer; tests that want to probe the digest
    // layer write raw bytes directly.
    let cfg_path = find_config_blob(oci_dir);
    let mut cfg: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    mutate(&mut cfg);
    let new_cfg_bytes = serde_json::to_vec_pretty(&cfg).unwrap();
    let new_cfg_hex = sha256_hex(&new_cfg_bytes);
    let blobs_dir = oci_dir.join("blobs").join("sha256");
    let new_cfg_path = blobs_dir.join(&new_cfg_hex);
    std::fs::write(&new_cfg_path, &new_cfg_bytes).unwrap();
    if new_cfg_path != cfg_path {
        std::fs::remove_file(&cfg_path).ok();
    }

    let mp = manifest_path(oci_dir);
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
    manifest["config"]["digest"] = Value::from(format!("sha256:{}", new_cfg_hex));
    manifest["config"]["size"] = Value::from(new_cfg_bytes.len() as u64);
    let new_manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let new_manifest_hex = sha256_hex(&new_manifest_bytes);
    let new_manifest_path = blobs_dir.join(&new_manifest_hex);
    std::fs::write(&new_manifest_path, &new_manifest_bytes).unwrap();
    if new_manifest_path != mp {
        std::fs::remove_file(&mp).ok();
    }

    let index_path = oci_dir.join("index.json");
    let mut index: Value = serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    index["manifests"][0]["digest"] = Value::from(format!("sha256:{}", new_manifest_hex));
    index["manifests"][0]["size"] = Value::from(new_manifest_bytes.len() as u64);
    std::fs::write(index_path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
}

/// Locate the manifest blob path inside `oci_dir`.
fn manifest_path(oci_dir: &std::path::Path) -> std::path::PathBuf {
    let index: Value =
        serde_json::from_slice(&std::fs::read(oci_dir.join("index.json")).unwrap()).unwrap();
    let digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    oci_dir.join("blobs").join("sha256").join(digest)
}

/// Mutate the on-disk manifest JSON. Updates the index's manifest
/// descriptor `size` and `digest` to match the new manifest bytes
/// so the test exercises the field-level validator we care about,
/// not the digest layer.
fn rewrite_manifest<F: FnOnce(&mut Value)>(oci_dir: &std::path::Path, mutate: F) {
    let mp = manifest_path(oci_dir);
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
    mutate(&mut manifest);
    let new_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let new_hex = sha256_hex(&new_bytes);
    let blobs_dir = oci_dir.join("blobs").join("sha256");
    let new_path = blobs_dir.join(&new_hex);
    std::fs::write(&new_path, &new_bytes).unwrap();
    if new_path != mp {
        std::fs::remove_file(&mp).ok();
    }

    let index_path = oci_dir.join("index.json");
    let mut index: Value = serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    index["manifests"][0]["digest"] = Value::from(format!("sha256:{}", new_hex));
    index["manifests"][0]["size"] = Value::from(new_bytes.len() as u64);
    std::fs::write(index_path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
}

/// Mutate the on-disk index JSON in place. The index is the root of
/// the OCI layout and is not itself referenced by any digest, so
/// nothing further needs to be updated.
fn rewrite_index<F: FnOnce(&mut Value)>(oci_dir: &std::path::Path, mutate: F) {
    let path = oci_dir.join("index.json");
    let mut index: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    mutate(&mut index);
    std::fs::write(path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
}

#[test]
fn arch_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    rewrite_config(&path, |cfg| {
        cfg["arch"] = Value::from("aarch64");
    });

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("architecture") || msg.contains("arch"),
        "expected architecture mismatch, got: {}",
        msg
    );
}

#[test]
fn abi_version_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    rewrite_config(&path, |cfg| {
        cfg["abi_version"] = Value::from(9999u32);
    });

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("ABI") || msg.contains("abi"),
        "expected ABI version mismatch, got: {}",
        msg
    );
}

#[test]
fn hypervisor_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Pick a hypervisor that is not the current one.
    let current = cfg_current_hypervisor();
    let other = if current == "kvm" { "mshv" } else { "kvm" };

    rewrite_config(&path, |cfg| {
        cfg["hypervisor"] = Value::from(other);
    });

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("hypervisor"),
        "expected hypervisor mismatch, got: {}",
        msg
    );
}

fn cfg_current_hypervisor() -> &'static str {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe");
    create_snapshot_from_binary()
        .to_oci(&path, "latest")
        .unwrap();
    let cfg_path = find_config_blob(&path);
    let cfg: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    match cfg["hypervisor"].as_str().unwrap() {
        "kvm" => "kvm",
        "mshv" => "mshv",
        "whp" => "whp",
        other => panic!("unknown hypervisor tag {other}"),
    }
}

// =============================================================================
// Entrypoint vs sregs invariants enforced by serde shape.
// =============================================================================

#[test]
fn call_snapshot_without_sregs_rejected() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Strip sregs from the entrypoint variant. serde must reject the
    // missing field at parse time.
    rewrite_config(&path, |cfg| {
        let entry = cfg["entrypoint"].as_object_mut().unwrap();
        assert_eq!(entry["kind"].as_str().unwrap(), "call");
        entry.remove("sregs");
    });

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("sregs") || msg.contains("missing field") || msg.contains("config"),
        "expected serde error about missing sregs, got: {}",
        msg
    );
}

#[test]
fn initialise_snapshot_with_sregs_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Add a bogus sregs field to the Initialise variant. serde must
    // reject the unknown field (variant has deny_unknown_fields).
    rewrite_config(&path, |cfg| {
        let entry = cfg["entrypoint"].as_object_mut().unwrap();
        assert_eq!(entry["kind"].as_str().unwrap(), "initialise");
        entry.insert("sregs".to_string(), Value::from("{}"));
    });

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("sregs") || msg.contains("unknown field") || msg.contains("config"),
        "expected serde error about unknown field sregs, got: {}",
        msg
    );
}

// =============================================================================
// Host functions validation.
//
// `validate_host_functions` enforces a superset relation: every host
// function registered when the snapshot was taken must be present in
// the loaded sandbox's `HostFunctions` with a matching signature.
// Extras in the loaded set are allowed.
// =============================================================================

/// Build a `MultiUseSandbox` with the default host functions plus a
/// custom `Add(i32, i32) -> i32`. Used to seed the snapshot side of
/// the host-function validation tests so the snapshot has a
/// non-default required function.
fn create_sandbox_with_custom_host_funcs() -> MultiUseSandbox {
    let path = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    u.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    u.evolve().unwrap()
}

/// `HostFunctions::default()` plus a matching `Add(i32, i32) -> i32`.
fn host_funcs_with_matching_add() -> HostFunctions {
    let mut hf = HostFunctions::default();
    hf.register_host_function("Add", |a: i32, b: i32| Ok(a + b))
        .unwrap();
    hf
}

#[test]
fn from_snapshot_accepts_matching_host_functions() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), host_funcs_with_matching_add(), None)
            .unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn from_snapshot_rejects_missing_host_function() {
    // Snapshot was taken with `Add` registered. Loading with the
    // default `HostFunctions` (no `Add`) must be rejected.
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let err = MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None)
        .expect_err("from_snapshot must reject a HostFunctions set missing `Add`");
    let msg = format!("{}", err);
    assert!(
        msg.contains("missing") && msg.contains("Add"),
        "expected missing-host-function error mentioning Add, got: {}",
        msg
    );
}

#[test]
fn from_snapshot_rejects_signature_mismatch() {
    // Snapshot has `Add(i32, i32) -> i32`. Load registers an `Add`
    // with a different signature. validate_host_functions must
    // refuse the mismatch.
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();

    let mut hf = HostFunctions::default();
    hf.register_host_function("Add", |a: String, b: String| Ok(format!("{a}{b}")))
        .unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let err = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None)
        .expect_err("from_snapshot must reject a signature mismatch on Add");
    let msg = format!("{}", err);
    assert!(
        msg.contains("signature mismatches") && msg.contains("Add"),
        "expected signature-mismatch error mentioning Add, got: {}",
        msg
    );
}

#[test]
fn from_snapshot_accepts_extra_host_functions() {
    // Snapshot has `Add`. Load registers `Add` (matching) plus an
    // unrelated `Mul`. Extras are allowed.
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();

    let mut hf = host_funcs_with_matching_add();
    hf.register_host_function("Mul", |a: i32, b: i32| Ok(a * b))
        .unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn from_snapshot_accepts_zero_arg_host_function() {
    // A zero-arg host function must round-trip through OCI.
    let path = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    u.register_host_function("Zero", || Ok(7i64)).unwrap();
    let mut sbox = u.evolve().unwrap();

    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();

    let mut hf = HostFunctions::default();
    hf.register_host_function("Zero", || Ok(7i64)).unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let _sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None)
        .expect("zero-arg host function must round-trip through OCI");
}

#[test]
fn from_snapshot_has_default_host_print() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    let _ = sbox2.call::<i32>("PrintTwoArgs", ("hi".to_string(), 42i32));
}

// =============================================================================
// OCI-shape invariants.
// =============================================================================

#[test]
fn missing_oci_layout_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    std::fs::remove_file(path.join("oci-layout")).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("oci-layout"),
        "expected missing oci-layout error, got: {}",
        msg
    );
}

#[test]
fn wrong_image_layout_version_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    std::fs::write(
        path.join("oci-layout"),
        r#"{"imageLayoutVersion":"99.0.0"}"#,
    )
    .unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("image layout version") || msg.contains("imageLayoutVersion"),
        "expected layout version error, got: {}",
        msg
    );
}

#[test]
fn missing_index_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    std::fs::remove_file(path.join("index.json")).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("index.json"),
        "expected missing index.json error, got: {}",
        msg
    );
}

#[test]
fn snapshot_blob_size_mismatch_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Truncate the snapshot blob by one byte.
    let blobs_dir = path.join("blobs").join("sha256");
    let manifest_bytes = std::fs::read(path.join("index.json")).unwrap();
    let index: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let manifest_path = blobs_dir.join(manifest_digest);
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let snap_digest = manifest["layers"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let snap_path = blobs_dir.join(snap_digest);
    let bytes = std::fs::read(&snap_path).unwrap();
    std::fs::write(&snap_path, &bytes[..bytes.len() - 1]).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("size") || msg.contains("mismatch"),
        "expected size mismatch error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_zero_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();
    rewrite_config(&path, |cfg| {
        cfg["layout"]["snapshot_size"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("snapshot_size"),
        "expected snapshot_size error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_unaligned_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();
    rewrite_config(&path, |cfg| {
        let s = cfg["layout"]["snapshot_size"].as_u64().unwrap();
        cfg["layout"]["snapshot_size"] = Value::from(s + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("PAGE_SIZE") || msg.contains("multiple"),
        "expected page alignment error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_must_match_memory_size() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();
    let page = hyperlight_common::vmem::PAGE_SIZE as u64;
    rewrite_config(&path, |cfg| {
        let m = cfg["memory_size"].as_u64().unwrap();
        cfg["layout"]["snapshot_size"] = Value::from(m + page);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("does not equal memory_size"),
        "expected snapshot_size + pt_size != memory_size error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_pt_size_unaligned_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();
    rewrite_config(&path, |cfg| {
        if let Some(p) = cfg["layout"]["pt_size"].as_u64() {
            cfg["layout"]["pt_size"] = Value::from(p + 1);
        } else {
            cfg["layout"]["pt_size"] = Value::from(1u64);
        }
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("pt_size") || msg.contains("PAGE_SIZE") || msg.contains("multiple"),
        "expected pt_size validation error, got: {}",
        msg
    );
}

#[test]
fn missing_snapshot_blob_rejected() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let blobs_dir = path.join("blobs").join("sha256");
    let manifest_bytes = std::fs::read(path.join("index.json")).unwrap();
    let index: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let manifest_path = blobs_dir.join(manifest_digest);
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let snap_digest = manifest["layers"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    std::fs::remove_file(blobs_dir.join(snap_digest)).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("snapshot blob") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-blob error, got: {}",
        msg
    );
}

// =============================================================================
// Path semantics.
// =============================================================================

#[test]
fn from_oci_nonexistent_path_returns_error() {
    let err = unwrap_err_snapshot(Snapshot::from_oci("/nonexistent/path/to/oci", "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("stat") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-path error, got: {}",
        msg
    );
}

#[test]
fn from_oci_file_not_directory_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("not-a-dir");
    std::fs::write(&file_path, b"hello").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&file_path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("not a directory"),
        "expected not-a-directory error, got: {}",
        msg
    );
}

#[test]
fn to_oci_appends_into_existing_layout_with_new_tag() {
    // Two snapshots written to the same directory under different
    // tags coexist. Both load back independently. The shared
    // `oci-layout` marker and `blobs/sha256/` are reused.
    let snap_a = create_snapshot_from_binary();
    let snap_b = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap_a.to_oci(&path, "a").unwrap();
    snap_b.to_oci(&path, "b").unwrap();

    let _ = Snapshot::from_oci(&path, "a").unwrap();
    let _ = Snapshot::from_oci(&path, "b").unwrap();

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let tags: Vec<&str> = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            m["annotations"]["org.opencontainers.image.ref.name"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&"a"));
    assert!(tags.contains(&"b"));
}

#[test]
fn to_oci_replaces_descriptor_for_same_tag() {
    // Writing the same tag twice replaces the manifest descriptor
    // for that tag. The loader sees the second snapshot, not the
    // first. The index ends up with exactly one entry for the tag.
    let mut sbox = create_test_sandbox();
    sbox.call::<String>("Echo", "first".to_string()).unwrap();
    let snap_first = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "second".to_string()).unwrap();
    let snap_second = sbox.snapshot().unwrap();
    let gen_second = snap_second.snapshot_generation();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap_first.to_oci(&path, "latest").unwrap();
    snap_second.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    assert_eq!(loaded.snapshot_generation(), gen_second);

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let entries: Vec<&Value> = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| {
            m["annotations"]["org.opencontainers.image.ref.name"].as_str() == Some("latest")
        })
        .collect();
    assert_eq!(entries.len(), 1, "expected one descriptor for tag 'latest'");
}

#[test]
fn to_oci_requires_parent_dir_to_exist() {
    // The leaf directory at `path` is created, but the parent
    // chain must already exist. A missing ancestor errors and the
    // filesystem is left untouched.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let missing_parent = dir.path().join("a").join("b").join("c");
    let path = missing_parent.join("store");
    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("parent directory") || msg.contains("not accessible"),
        "expected missing-parent error, got: {msg}"
    );
    assert!(!missing_parent.exists(), "no parent dirs should be created");
}

#[test]
fn to_oci_creates_leaf_directory() {
    // The leaf at `path` is created when missing, as long as the
    // parent exists.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    snap.to_oci(&path, "latest").unwrap();
    let _ = Snapshot::from_oci(&path, "latest").unwrap();
}

#[test]
fn to_oci_rejects_regular_file_at_path() {
    // A regular file at `path` cannot be turned into a directory.
    // The call errors and the file is left intact.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-dir");
    std::fs::write(&path, b"i am a file").unwrap();
    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("is not a directory") || msg.contains("layout dir"),
        "expected non-directory error, got: {msg}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"i am a file");
}

#[test]
fn to_oci_rejects_unsupported_existing_layout_version() {
    // A pre-existing `oci-layout` with an unknown version is left
    // alone and the call errors. Defends against silently rewriting
    // a future layout we do not understand.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("oci-layout"),
        br#"{"imageLayoutVersion":"99.0.0"}"#,
    )
    .unwrap();
    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("imageLayoutVersion") || msg.contains("unsupported"),
        "expected unsupported-version error, got: {msg}"
    );
    assert!(
        !path.join("index.json").exists(),
        "to_oci must not have written index.json"
    );
}

#[test]
fn to_oci_invalid_tag_does_not_touch_filesystem() {
    // Tag grammar is checked before any filesystem mutation. An
    // empty tag is rejected without creating the layout directory.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    let _ = snap.to_oci(&path, "").unwrap_err();
    assert!(!path.exists(), "target path must not be created on error");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "unexpected leftover entries in parent: {:?}",
        leftovers
    );
}

#[test]
fn to_oci_into_empty_existing_directory() {
    // An empty pre-existing directory is treated as a fresh layout
    // location. The marker, index, and blobs are all written.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();

    snap.to_oci(&path, "latest").unwrap();
    let _ = Snapshot::from_oci(&path, "latest").unwrap();
    assert!(path.join("oci-layout").exists());
    assert!(path.join("index.json").exists());
}

#[test]
fn to_oci_preserves_unrelated_files_in_layout_dir() {
    // Files inside the layout dir that are not part of the OCI
    // structure are left alone. Mirrors the behaviour of every
    // merging tool surveyed (containers/image, crane, regclient).
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("README.md"), b"keep me").unwrap();

    snap.to_oci(&path, "latest").unwrap();
    assert_eq!(std::fs::read(path.join("README.md")).unwrap(), b"keep me");
}

#[test]
fn to_oci_same_tag_same_content_is_idempotent() {
    // Saving the same snapshot under the same tag twice ends up
    // with one descriptor for the tag and the same blob count as
    // after the first save. Blobs are content-addressed so the
    // second write reuses them.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap.to_oci(&path, "latest").unwrap();
    let blobs_after_first: Vec<_> = std::fs::read_dir(path.join("blobs").join("sha256"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    snap.to_oci(&path, "latest").unwrap();
    let blobs_after_second: Vec<_> = std::fs::read_dir(path.join("blobs").join("sha256"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert_eq!(blobs_after_first.len(), blobs_after_second.len());

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let manifests = index["manifests"].as_array().unwrap();
    assert_eq!(manifests.len(), 1);
    assert_eq!(
        manifests[0]["annotations"]["org.opencontainers.image.ref.name"],
        "latest"
    );
}

#[test]
fn to_oci_shares_blobs_across_tags_with_identical_content() {
    // Two tags written from the same in-memory snapshot share all
    // three blobs (manifest, config, snapshot). The blob directory
    // therefore holds exactly three files even with two tags.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap.to_oci(&path, "a").unwrap();
    snap.to_oci(&path, "b").unwrap();

    let blobs: Vec<_> = std::fs::read_dir(path.join("blobs").join("sha256"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert_eq!(blobs.len(), 3, "expected 3 deduped blobs, got {:?}", blobs);
}

#[test]
fn to_oci_replace_in_middle_preserves_other_tags() {
    // Replacing one tag in a layout with three tags keeps the
    // other two descriptors intact and produces a fresh descriptor
    // for the replaced tag.
    let mut sbox = create_test_sandbox();
    let snap_a = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "x".to_string()).unwrap();
    let snap_b = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "y".to_string()).unwrap();
    let snap_c = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "z".to_string()).unwrap();
    let snap_b2 = sbox.snapshot().unwrap();
    let gen_b2 = snap_b2.snapshot_generation();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    snap_a.to_oci(&path, "a").unwrap();
    snap_b.to_oci(&path, "b").unwrap();
    snap_c.to_oci(&path, "c").unwrap();
    snap_b2.to_oci(&path, "b").unwrap();

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let tags: Vec<&str> = index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            m["annotations"]["org.opencontainers.image.ref.name"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(tags.len(), 3);
    assert!(tags.contains(&"a"));
    assert!(tags.contains(&"b"));
    assert!(tags.contains(&"c"));

    let loaded_b = Snapshot::from_oci(&path, "b").unwrap();
    assert_eq!(loaded_b.snapshot_generation(), gen_b2);
}

#[test]
fn to_oci_rejects_malformed_existing_oci_layout_json() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("oci-layout"), b"not json").unwrap();

    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("oci-layout") && msg.contains("JSON"),
        "expected oci-layout JSON error, got: {msg}"
    );
    assert!(!path.join("index.json").exists());
}

#[test]
fn to_oci_rejects_existing_oci_layout_missing_version() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("oci-layout"), br#"{"other":"field"}"#).unwrap();

    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("imageLayoutVersion"),
        "expected missing-version error, got: {msg}"
    );
    assert!(!path.join("index.json").exists());
}

#[test]
fn to_oci_rejects_malformed_existing_index_json() {
    // An existing `oci-layout` with a supported version plus a
    // corrupt `index.json` is rejected. We do not silently discard
    // someone else's index.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(path.join("index.json"), b"{not valid json").unwrap();

    let err = snap.to_oci(&path, "latest").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("index.json"),
        "expected index.json error, got: {msg}"
    );
    assert_eq!(
        std::fs::read(path.join("index.json")).unwrap(),
        b"{not valid json",
        "to_oci must not overwrite a malformed existing index.json"
    );
}

/// Asserts the integrity contract: a snapshot blob whose bytes have
/// been replaced (without changing length, so descriptor sizes still
/// match) must be rejected on load via digest mismatch.
#[test]
fn from_oci_rejects_snapshot_blob_byte_mutation() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    // Locate the snapshot blob via the manifest, then flip one byte
    // somewhere in the middle. Length is preserved so all descriptor
    // size checks still pass. Only a digest re-hash can detect this.
    let blobs_dir = path.join("blobs").join("sha256");
    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(blobs_dir.join(&manifest_digest)).unwrap()).unwrap();
    let snap_digest = manifest["layers"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap()
        .to_string();
    let snap_path = blobs_dir.join(&snap_digest);
    let mut bytes = std::fs::read(&snap_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&snap_path, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("hash") || msg.contains("sha256"),
        "expected digest-mismatch error, got: {}",
        msg
    );
}

/// Same idea as `from_oci_rejects_snapshot_blob_byte_mutation`, but
/// targeting the config blob. A config-blob mutation that preserves
/// the descriptor size and the structural fields the loader
/// validates today (e.g. flipping a byte inside the host-function
/// flatbuffer payload) must be caught by digest verification.
#[test]
fn from_oci_rejects_config_blob_byte_mutation() {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let cfg_path = find_config_blob(&path);
    let mut bytes = std::fs::read(&cfg_path).unwrap();
    // Replace the first ASCII brace `{` with a different byte that
    // keeps the file the same length but yields a different sha256.
    // This will also break JSON parsing, but the point is to assert
    // the digest layer rejects it before the parser ever runs.
    bytes[0] = b' ';
    std::fs::write(&cfg_path, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("hash") || msg.contains("sha256"),
        "expected digest-mismatch error, got: {}",
        msg
    );
}

#[test]
fn from_oci_observes_per_path_contents() {
    // `to_oci` no longer permits overwriting, so verifying that two
    // independent saves have independent contents is done by writing
    // each snapshot to its own path and asserting the loaded
    // contents differ.
    let mut sbox = create_test_sandbox();
    sbox.call::<i32>("AddToStatic", 11i32).unwrap();
    let snap_x = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path_x = dir.path().join("snap_x");
    snap_x.to_oci(&path_x, "latest").unwrap();

    let loaded_x = Snapshot::from_oci(&path_x, "latest").unwrap();
    let mut sbox_x =
        MultiUseSandbox::from_snapshot(Arc::new(loaded_x), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox_x.call::<i32>("GetStatic", ()).unwrap(), 11);

    sbox.call::<i32>("AddToStatic", 44i32).unwrap();
    let snap_y = sbox.snapshot().unwrap();
    let path_y = dir.path().join("snap_y");
    snap_y.to_oci(&path_y, "latest").unwrap();

    let loaded_y = Snapshot::from_oci(&path_y, "latest").unwrap();
    let mut sbox_y =
        MultiUseSandbox::from_snapshot(Arc::new(loaded_y), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox_y.call::<i32>("GetStatic", ()).unwrap(), 55);
}

// =============================================================================
// Exhaustive input-validation tests for `from_oci`.
//
// Every load-side error path in `super::file::from_oci` should be
// exercised here.
// =============================================================================

fn save_for_mutation() -> (tempfile::TempDir, std::path::PathBuf) {
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();
    (dir, path)
}

fn assert_err_contains(err: crate::HyperlightError, needle: &str) {
    let msg = format!("{}", err);
    assert!(
        msg.contains(needle),
        "expected error to contain {:?}, got: {}",
        needle,
        msg
    );
}

#[test]
fn malformed_oci_layout_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::write(path.join("oci-layout"), b"not-valid-json{").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "oci-layout");
}

#[test]
fn oci_layout_missing_version_field_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::write(path.join("oci-layout"), r#"{"unrelated":"field"}"#).unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "imageLayoutVersion");
}

#[test]
fn malformed_index_json_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::write(path.join("index.json"), b"{not json").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "index.json");
}

#[test]
fn empty_index_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        idx["manifests"] = Value::Array(Vec::new());
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "no manifest tagged");
}

#[test]
fn from_oci_rejects_duplicate_tag_in_index() {
    // A valid OCI layout has unique tags. Two manifests sharing the
    // same `org.opencontainers.image.ref.name` annotation is
    // malformed and from_oci must refuse rather than silently
    // pick one.
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let first = idx["manifests"][0].clone();
        idx["manifests"].as_array_mut().unwrap().push(first);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "multiple manifests tagged");
}

#[test]
fn missing_manifest_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::remove_file(manifest_path(&path)).unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("open") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-manifest error, got: {}",
        msg
    );
}

#[test]
fn bad_digest_format_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        // Strip the algorithm prefix entirely. `oci-spec` validates
        // descriptor digests on parse, so the index parser rejects
        // this before our own digest helper sees it.
        idx["manifests"][0]["digest"] = Value::from("deadbeef");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("index.json"),
        "expected digest or parse error, got: {}",
        msg
    );
}

#[test]
fn malformed_manifest_json_rejected() {
    // Probes the manifest JSON parser. Under `from_oci`, the
    // digest-verification step would fire first and short-circuit
    // this; that path is covered by
    // `from_oci_rejects_manifest_blob_byte_mutation`. Use
    // `from_oci_unchecked` here to reach the parser.
    let (_dir, path) = save_for_mutation();
    let mp = manifest_path(&path);
    std::fs::write(&mp, b"{not json").unwrap();
    // Update index size to match so we hit the JSON parser, not the
    // size check.
    let new_len = std::fs::metadata(&mp).unwrap().len();
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["size"] = Value::from(new_len);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    assert_err_contains(err, "manifest");
}

#[test]
fn wrong_manifest_schema_version_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["schemaVersion"] = Value::from(99u32);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "schemaVersion");
}

#[test]
fn unknown_config_media_type_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["config"]["mediaType"] = Value::from("application/vnd.example.unknown.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "config media type");
}

#[test]
fn empty_layers_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["layers"] = Value::Array(Vec::new());
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "layer");
}

#[test]
fn extra_layers_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        let first = m["layers"][0].clone();
        m["layers"].as_array_mut().unwrap().push(first);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "layer");
}

#[test]
fn unknown_snapshot_layer_media_type_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["layers"][0]["mediaType"] = Value::from("application/vnd.example.unknown.v1");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "snapshot layer media type");
}

/// Manifest- and index-level annotations injected by third-party
/// tools (cosign, ORAS, build pipelines, etc.) must NOT break load.
/// `OciSnapshotConfig` is intentionally strict (`deny_unknown_fields`) but
/// the OCI envelope around it is parsed via `oci-spec`'s lenient
/// types.
#[test]
fn manifest_and_index_annotations_tolerated() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    rewrite_manifest(&path, |m| {
        let mut anns = serde_json::Map::new();
        anns.insert(
            "org.opencontainers.image.created".to_string(),
            Value::from("2024-01-01T00:00:00Z"),
        );
        anns.insert(
            "dev.sigstore.cosign/signature".to_string(),
            Value::from("MEUCIQDsignature"),
        );
        m["annotations"] = Value::Object(anns);
    });
    rewrite_index(&path, |idx| {
        let mut anns = serde_json::Map::new();
        anns.insert(
            "org.opencontainers.image.ref.name".to_string(),
            Value::from("v1.2.3"),
        );
        idx["annotations"] = Value::Object(anns);
    });

    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn config_blob_size_descriptor_mismatch_rejected() {
    let (_dir, path) = save_for_mutation();
    // Bump the config descriptor's claimed size by one without
    // touching the actual blob.
    rewrite_manifest(&path, |m| {
        let sz = m["config"]["size"].as_u64().unwrap();
        m["config"]["size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "config blob size mismatch");
}

#[test]
fn malformed_config_json_rejected() {
    // Probes the config JSON parser. Under `from_oci` the
    // digest-verification step would fire first; that path is
    // covered by `from_oci_rejects_config_blob_byte_mutation`.
    // Use `from_oci_unchecked` here to reach the parser.
    let (_dir, path) = save_for_mutation();
    let cfg_path = find_config_blob(&path);
    std::fs::write(&cfg_path, b"{not json").unwrap();
    // Update both the manifest's config descriptor size and the
    // index's manifest descriptor size to match so we reach the
    // JSON parser, not the size check.
    let new_cfg_len = std::fs::metadata(&cfg_path).unwrap().len();
    rewrite_manifest(&path, |m| {
        m["config"]["size"] = Value::from(new_cfg_len);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    assert_err_contains(err, "config JSON");
}

#[test]
fn memory_size_zero_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["memory_size"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "memory_size");
}

#[test]
fn memory_size_unaligned_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        let sz = cfg["memory_size"].as_u64().unwrap();
        cfg["memory_size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    // Either the page-alignment check or the file-size check trips.
    // Both are valid signals that the value was rejected.
    assert!(
        msg.contains("memory_size") || msg.contains("PAGE_SIZE") || msg.contains("size"),
        "expected memory_size rejection, got: {}",
        msg
    );
}

#[test]
fn bad_init_data_permissions_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // 1u32 << 31 is well outside the defined READ|WRITE|EXECUTE bits.
        cfg["layout"]["init_data_permissions"] = Value::from(0x8000_0000u32);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "init_data_permissions");
}

#[test]
fn entrypoint_addr_outside_snapshot_region_rejected() {
    // A crafted config can claim any u64 as the entry point. The
    // loader must refuse addresses that don't lie within
    // [BASE_ADDRESS, BASE_ADDRESS + snapshot_size) so a malicious
    // image can't direct execution into unmapped GPA space or into
    // the writable scratch region.
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        let entry = cfg["entrypoint"].as_object_mut().unwrap();
        // 0xDEAD_BEEF_0000 is far above any plausible snapshot
        // region (snapshot_size is bounded by MAX_MEMORY_SIZE,
        // ~16 GiB) and outside guest mapped memory.
        entry["addr"] = Value::from(0xDEAD_BEEF_0000u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "entrypoint addr");
}

#[test]
fn entrypoint_addr_below_base_address_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        let entry = cfg["entrypoint"].as_object_mut().unwrap();
        // 0 is below BASE_ADDRESS (0x1000); rejected as "outside the
        // snapshot region".
        entry["addr"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "entrypoint addr");
}

// =============================================================================
// `from_oci_unchecked`: skips blob digest verification but still runs
// every other validator (OCI structure, descriptor sizes, schema
// versions, arch / hypervisor / ABI tags, layout bounds, entrypoint
// bounds).
// =============================================================================

#[test]
fn from_oci_unchecked_round_trips() {
    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let loaded = Snapshot::from_oci_unchecked(&path, "latest").unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    let result: String = sbox2.call("Echo", "hi\n".to_string()).unwrap();
    assert_eq!(result, "hi\n");
}

#[test]
fn from_oci_unchecked_still_validates_config_fields() {
    // Field-level validators (arch, abi, hypervisor, layout bounds,
    // entrypoint bounds) must still fire under `from_oci_unchecked`.
    // Use `rewrite_config` so the layout stays self-consistent
    // (otherwise the checked path would also catch this via the
    // descriptor-size check before the field validator runs).
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["arch"] = Value::from("aarch64");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("architecture") || msg.contains("arch"),
        "expected architecture mismatch under from_oci_unchecked, got: {}",
        msg
    );
}

#[test]
fn from_oci_rejects_manifest_blob_byte_mutation() {
    // Mutate a manifest body byte (without updating the index's
    // descriptor digest) and confirm the loader catches it via
    // digest verification before any of the field-level manifest
    // validators (schema version, media type, etc.) run.
    let snapshot = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot.to_oci(&path, "latest").unwrap();

    let mp = manifest_path(&path);
    let mut bytes = std::fs::read(&mp).unwrap();
    // Flip the first byte. Length is preserved so the descriptor
    // size check still passes; only digest verification can detect
    // this. The byte will also break JSON parsing, but the digest
    // check fires first.
    bytes[0] ^= 0x20;
    std::fs::write(&mp, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "digest mismatch");
}

#[test]
fn from_oci_unknown_tag_lists_available_tags() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "alpha").unwrap();

    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "missing"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("no manifest tagged") && msg.contains("\"missing\""),
        "expected unknown-tag error mentioning the requested tag, got: {}",
        msg
    );
    assert!(
        msg.contains("alpha"),
        "expected available-tags listing to include the actual tag, got: {}",
        msg
    );
}

#[test]
fn manifest_descriptor_carries_ref_name_annotation() {
    // The OCI standard tag annotation must be set on the manifest
    // descriptor in `index.json` so external tools (`oras`,
    // `crane manifest`, `skopeo inspect`) see the tag.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "production-v3").unwrap();

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let manifest = &index["manifests"][0];
    assert_eq!(
        manifest["annotations"]["org.opencontainers.image.ref.name"]
            .as_str()
            .unwrap(),
        "production-v3"
    );
}

// =============================================================================
// Tag validation.
// =============================================================================

#[test]
fn empty_tag_rejected_on_save() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let err = snap.to_oci(dir.path().join("snap"), "").unwrap_err();
    assert!(format!("{err}").contains("tag"));
}

#[test]
fn empty_tag_rejected_on_load() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.to_oci(&path, "latest").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, ""));
    assert!(format!("{err}").contains("tag"));
}

#[test]
fn tag_with_illegal_leading_char_rejected() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let err = snap
        .to_oci(dir.path().join("snap"), ".dotleader")
        .unwrap_err();
    assert!(format!("{err}").contains("tag"));

    let err = snap
        .to_oci(dir.path().join("snap"), "-dashleader")
        .unwrap_err();
    assert!(format!("{err}").contains("tag"));
}

#[test]
fn tag_with_illegal_chars_rejected() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let err = snap
        .to_oci(dir.path().join("snap"), "with/slash")
        .unwrap_err();
    assert!(format!("{err}").contains("tag"));

    let err = snap
        .to_oci(dir.path().join("snap"), "with space")
        .unwrap_err();
    assert!(format!("{err}").contains("tag"));
}

#[test]
fn long_tag_within_limit_accepted() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let tag: String = "a".repeat(128);
    snap.to_oci(dir.path().join("snap"), &tag).unwrap();
    let _ = Snapshot::from_oci(dir.path().join("snap"), &tag).unwrap();
}

#[test]
fn over_long_tag_rejected() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let tag: String = "a".repeat(129);
    let err = snap.to_oci(dir.path().join("snap"), &tag).unwrap_err();
    assert!(format!("{err}").contains("tag"));
}

// =============================================================================
// Save-shape invariants. Verify the on-disk JSON we hand to standard
// OCI tools matches what the spec prescribes.
// =============================================================================

#[test]
fn manifest_descriptor_uses_image_manifest_media_type() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    assert_eq!(
        index["manifests"][0]["mediaType"].as_str().unwrap(),
        "application/vnd.oci.image.manifest.v1+json"
    );
}

#[test]
fn manifest_descriptor_non_image_manifest_rejected() {
    // The loader must refuse to follow a descriptor that does not
    // advertise an OCI image manifest, even if the blob it points
    // at would parse. This prevents misuse where an image index or
    // an unrelated artifact has been published under our tag.
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["mediaType"] = Value::from("application/vnd.oci.image.index.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{}", err);
    assert!(
        msg.contains("unexpected media type"),
        "expected manifest-descriptor media type error, got: {}",
        msg
    );
}

#[test]
fn manifest_uses_correct_config_and_layer_media_types() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(manifest_path(&path)).unwrap()).unwrap();
    assert_eq!(
        manifest["config"]["mediaType"].as_str().unwrap(),
        "application/vnd.hyperlight.snapshot.config.v1+json"
    );
    assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);
    assert_eq!(
        manifest["layers"][0]["mediaType"].as_str().unwrap(),
        "application/vnd.hyperlight.snapshot.memory.v1"
    );
    // `artifactType` mirrors `config.mediaType` so registries that surface
    // the distribution-spec referrers API report a useful type, and tooling
    // that predates `artifactType` and falls back to `config.mediaType`
    // sees the same value.
    assert_eq!(
        manifest["artifactType"].as_str().unwrap(),
        "application/vnd.hyperlight.snapshot.config.v1+json"
    );
}

#[test]
fn manifest_missing_artifact_type_rejected() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    rewrite_manifest(&path, |m| {
        m.as_object_mut().unwrap().remove("artifactType");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "missing required artifactType");
}

#[test]
fn manifest_mismatched_artifact_type_rejected() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    rewrite_manifest(&path, |m| {
        m["artifactType"] = Value::from("application/vnd.example.bogus.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "does not match config media type");
}

#[test]
fn save_writes_oci_layout_marker() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let marker: Value =
        serde_json::from_slice(&std::fs::read(path.join("oci-layout")).unwrap()).unwrap();
    assert_eq!(marker["imageLayoutVersion"].as_str().unwrap(), "1.0.0");
}

// =============================================================================
// Tag selection edge cases.
// =============================================================================

#[test]
fn tag_lookup_is_case_sensitive() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "MyTag").unwrap();

    // Different case must NOT match.
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "mytag"));
    assert_err_contains(err, "no manifest tagged");

    // Exact case loads.
    let _ = Snapshot::from_oci(&path, "MyTag").unwrap();
}

#[test]
fn ref_name_annotation_key_is_case_sensitive() {
    // If the index uses a misspelled annotation key (e.g.
    // `org.OpenContainers.image.ref.name`), the manifest is treated
    // as untagged and from_oci must not load it under any name.
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let anns = idx["manifests"][0]["annotations"].as_object_mut().unwrap();
        let value = anns.remove("org.opencontainers.image.ref.name").unwrap();
        anns.insert("org.OpenContainers.image.ref.name".to_string(), value);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "no manifest tagged");
}

#[test]
fn tag_with_all_valid_special_chars_accepted() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    let tag = "v1.2.3-rc.1_build";
    snap.to_oci(&path, tag).unwrap();
    let _ = Snapshot::from_oci(&path, tag).unwrap();
}

#[test]
fn other_descriptor_annotations_do_not_interfere() {
    // A manifest descriptor with the standard ref.name annotation
    // PLUS unrelated annotations (cosign signatures, build
    // pipelines, etc.) must still resolve by tag.
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let anns = idx["manifests"][0]["annotations"].as_object_mut().unwrap();
        anns.insert(
            "dev.sigstore.cosign/signature".to_string(),
            Value::from("MEUCIQDfake"),
        );
        anns.insert("io.example.build.id".to_string(), Value::from("12345"));
    });
    let _ = Snapshot::from_oci(&path, "latest").unwrap();
}

// =============================================================================
// Bad sha256 digest format on the inner descriptors (config and snapshot
// layer). The index-side equivalent is `bad_digest_format_rejected`.
// =============================================================================

#[test]
fn bad_config_descriptor_digest_format_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["config"]["digest"] = Value::from("md5:deadbeef");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{err}");
    assert!(
        msg.contains("digest"),
        "expected digest-format error, got: {msg}"
    );
}

#[test]
fn bad_snapshot_layer_descriptor_digest_format_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["layers"][0]["digest"] = Value::from("sha256:tooshort");
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{err}");
    assert!(
        msg.contains("digest"),
        "expected digest-format error, got: {msg}"
    );
}

// =============================================================================
// Missing inner blobs.
// =============================================================================

#[test]
fn missing_config_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    let cfg_path = find_config_blob(&path);
    std::fs::remove_file(&cfg_path).unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    let msg = format!("{err}");
    assert!(
        msg.contains("open") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-config-blob error, got: {msg}"
    );
}

// =============================================================================
// Size-bound enforcement.
// =============================================================================

#[test]
fn manifest_blob_too_large_rejected() {
    // The manifest reader bounds to 1 MiB. Replace the manifest
    // with junk longer than that and confirm the bound trips
    // before any parsing.
    let (_dir, path) = save_for_mutation();
    let mp = manifest_path(&path);
    let huge = vec![b'a'; (1024 * 1024 + 16) as usize];
    std::fs::write(&mp, &huge).unwrap();
    // Update descriptor size to match so we hit the bound check,
    // not the size mismatch check.
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["size"] = Value::from(huge.len() as u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    assert_err_contains(err, "exceeds maximum allowed");
}

#[test]
fn config_blob_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    let cfg_path = find_config_blob(&path);
    let huge = vec![b'a'; (1024 * 1024 + 16) as usize];
    std::fs::write(&cfg_path, &huge).unwrap();
    rewrite_manifest(&path, |m| {
        m["config"]["size"] = Value::from(huge.len() as u64);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    assert_err_contains(err, "exceeds maximum allowed");
}

#[test]
fn memory_size_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // 16 GiB exceeds MAX_MEMORY_SIZE.
        cfg["memory_size"] = Value::from(16u64 * 1024 * 1024 * 1024);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci(&path, "latest"));
    assert_err_contains(err, "memory_size");
}

#[test]
fn snapshot_descriptor_size_disagrees_with_file_rejected() {
    // Snapshot descriptor claims a different size than the actual
    // blob file. The loader must reject before mmap-ing.
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        let sz = m["layers"][0]["size"].as_u64().unwrap();
        m["layers"][0]["size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    let msg = format!("{err}");
    assert!(
        msg.contains("snapshot blob size"),
        "expected snapshot-blob descriptor disagreement error, got: {msg}"
    );
}

// =============================================================================
// `from_oci_unchecked` shares the same non-digest validators with
// `from_oci`. The key safety claim of the unchecked path is that it
// is faster, NOT that it is more permissive about anything other
// than digest checks. Pin that contract down here.
// =============================================================================

#[test]
fn from_oci_unchecked_validates_tag_format() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "bad/tag"));
    assert_err_contains(err, "tag");
}

#[test]
fn from_oci_unchecked_rejects_unknown_tag() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "nosuch"));
    assert_err_contains(err, "no manifest tagged");
}

#[test]
fn from_oci_unchecked_rejects_path_not_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("not-a-dir");
    std::fs::write(&file_path, b"hi").unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&file_path, "latest"));
    assert_err_contains(err, "not a directory");
}

#[test]
fn from_oci_unchecked_rejects_missing_oci_layout_marker() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    std::fs::remove_file(path.join("oci-layout")).unwrap();
    let err = unwrap_err_snapshot(Snapshot::from_oci_unchecked(&path, "latest"));
    assert_err_contains(err, "oci-layout");
}

// =============================================================================
// Round-trip data fidelity.
//
// The serde shape tests already prove individual fields parse, but
// they don't prove that all the values that came out of the producer
// reach the loaded snapshot. These tests pin down full round-trip
// fidelity for fields that are not exercised by the
// "load-then-call-the-guest" round-trip tests above.
// =============================================================================

#[test]
fn round_trip_preserves_stack_top_gva() {
    let mut sbox = create_test_sandbox();
    let snap = sbox.snapshot().unwrap();
    let original = snap.stack_top_gva();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    assert_eq!(loaded.stack_top_gva(), original);
}

#[test]
fn round_trip_preserves_non_default_scratch_size() {
    use crate::sandbox::SandboxConfiguration;
    let mut cfg = SandboxConfiguration::default();
    let custom_scratch: usize = 256 * 1024;
    cfg.set_scratch_size(custom_scratch);
    let snap = Snapshot::from_env(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        cfg,
    )
    .unwrap();
    let original = snap.layout().get_scratch_size();
    assert_eq!(original, custom_scratch);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    assert_eq!(loaded.layout().get_scratch_size(), custom_scratch);
}

#[test]
fn pre_init_snapshot_writes_initialise_entrypoint_kind() {
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    assert_eq!(cfg["entrypoint"]["kind"].as_str().unwrap(), "initialise");
    assert!(
        cfg["entrypoint"].get("sregs").is_none(),
        "Initialise snapshot must not carry sregs in the config"
    );
}

#[test]
fn already_initialised_snapshot_writes_call_entrypoint_kind() {
    let mut sbox = create_test_sandbox();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    assert_eq!(cfg["entrypoint"]["kind"].as_str().unwrap(), "call");
    assert!(
        cfg["entrypoint"]["sregs"].is_object(),
        "Call snapshot must carry sregs in the config"
    );
}

#[test]
fn round_trip_preserves_host_function_signatures() {
    // Save a snapshot with a custom host function signature, load
    // it, and confirm the recorded signatures survive.
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();

    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    let funcs = cfg["host_functions"].as_array().unwrap();
    let add = funcs
        .iter()
        .find(|f| f["function_name"].as_str().unwrap() == "Add")
        .expect("Add must be recorded");
    assert_eq!(
        add["parameter_types"].as_array().unwrap().len(),
        2,
        "Add signature must record two parameters"
    );
    // Loading and using the snapshot must accept the same signature.
    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let _ = MultiUseSandbox::from_snapshot(Arc::new(loaded), host_funcs_with_matching_add(), None)
        .unwrap();
}

#[test]
fn snapshot_with_no_host_functions_round_trips() {
    // A snapshot with `host_functions: []` must round-trip without
    // confusing the loader (which has special handling for the
    // empty-vs-None case).
    let snap = create_snapshot_from_binary();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "latest").unwrap();

    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    assert!(
        cfg["host_functions"].as_array().unwrap().is_empty(),
        "expected empty host_functions array for pre-init snapshot"
    );

    // The default HostFunctions set is sufficient because the
    // snapshot requires nothing.
    let loaded = Snapshot::from_oci(&path, "latest").unwrap();
    let _ =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
}

// =============================================================================
// Snapshot lineage and restore semantics.
//
// Hyperlight's snapshot model is NOT a tree. Each `MultiUseSandbox`
// has a process-local `sandbox_id`; `snapshot()` tags the snapshot
// with that id; `from_snapshot(snap)` adopts `snap.sandbox_id()` so
// the new sandbox can restore back to it; and `restore(snap)`
// requires `self.id == snap.sandbox_id()`. So sandboxes built from
// clones of the same `Arc<Snapshot>` form a flat id-equivalence
// class within which restore is freely interchangeable.
//
// These tests pin down all the combinations of build-from-snapshot,
// take-more-snapshots, restore-out-of-order, and reject-across-class
// that follow from that model.
// =============================================================================

#[test]
fn linear_chain_restore_in_order() {
    // Take three snapshots at different states in one sandbox, then
    // restore to each in chronological order. After each restore,
    // the static counter must read the value it had when that
    // snapshot was taken.
    let mut sbox = create_test_sandbox();
    let s0 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 10i32).unwrap();
    let s10 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 20i32).unwrap();
    let s30 = sbox.snapshot().unwrap();

    sbox.restore(s0.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    sbox.restore(s10.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 10);
    sbox.restore(s30.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 30);
}

#[test]
fn linear_chain_restore_out_of_order() {
    // Restore through the same chain but in a non-monotonic order
    // (forward, back, forward, back). Snapshots within one
    // id-equivalence class are NOT ordered by when they were
    // taken: any can be restored to from any other.
    let mut sbox = create_test_sandbox();
    let s0 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 7i32).unwrap();
    let s7 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 100i32).unwrap();
    let s107 = sbox.snapshot().unwrap();

    let order = [&s107, &s0, &s7, &s107, &s0];
    let expected = [107, 0, 7, 107, 0];
    for (snap, want) in order.iter().zip(expected.iter()) {
        sbox.restore((*snap).clone()).unwrap();
        assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), *want);
    }
}

#[test]
fn restore_then_call_then_snapshot_then_restore() {
    // Restore changes the live state, but it must NOT invalidate
    // the snapshot that was just used. After restoring to S1, the
    // sandbox can still take a new snapshot and restore back to
    // either S1 or the new one.
    let mut sbox = create_test_sandbox();
    let s_init = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 4i32).unwrap();

    // Restore back to init.
    sbox.restore(s_init.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);

    // Mutate again, snapshot, mutate further.
    sbox.call::<i32>("AddToStatic", 9i32).unwrap();
    let s_post_restore = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 100i32).unwrap();

    // Restore to either reachable snapshot.
    sbox.restore(s_post_restore.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 9);
    sbox.restore(s_init.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn restore_idempotent() {
    // Restoring to the same snapshot twice in a row must produce
    // the same observable state both times.
    let mut sbox = create_test_sandbox();
    sbox.call::<i32>("AddToStatic", 11i32).unwrap();
    let s = sbox.snapshot().unwrap();

    sbox.call::<i32>("AddToStatic", 22i32).unwrap();
    sbox.restore(s.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 11);

    // No mutation between restores.
    sbox.restore(s.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 11);

    // Mutation after the second restore must take effect.
    sbox.call::<i32>("AddToStatic", 1i32).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 12);
}

#[test]
fn from_snapshot_then_snapshot_then_restore_to_both() {
    // Build sandbox B from snapshot S0 (B inherits S0's id).
    // B takes its own snapshot S1 (also tagged with S0's id). Both
    // S0 and S1 must be reachable from B via `restore`.
    //
    // Note: only snapshots taken from a RUNNING sandbox (with
    // sregs) are valid restore targets. We therefore start from a
    // snapshot of a running sandbox, not a pre-init snapshot.
    let mut seed = create_test_sandbox();
    let s0 = seed.snapshot().unwrap();

    let mut b = MultiUseSandbox::from_snapshot(s0.clone(), HostFunctions::default(), None).unwrap();
    b.call::<i32>("AddToStatic", 5i32).unwrap();
    let s1 = b.snapshot().unwrap();
    b.call::<i32>("AddToStatic", 10i32).unwrap();

    // Restore back to S1.
    b.restore(s1.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 5);

    // Restore back further to the constructor snapshot S0.
    b.restore(s0.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn arc_clone_lineage_two_sandboxes_each_restores_to_either() {
    // Two sandboxes built from the SAME Arc<Snapshot> share the
    // sandbox_id. Each takes its own snapshot. Each must be
    // restorable to (a) its own derived snapshot, (b) the shared
    // root snapshot, and (c) the OTHER sandbox's derived snapshot
    // (because all four snapshots share one id).
    //
    // Note: the shared root must be a running-sandbox snapshot so
    // that restore() can use its sregs.
    let mut seed = create_test_sandbox();
    let snap_root = seed.snapshot().unwrap();

    let mut a =
        MultiUseSandbox::from_snapshot(snap_root.clone(), HostFunctions::default(), None).unwrap();
    let mut b =
        MultiUseSandbox::from_snapshot(snap_root.clone(), HostFunctions::default(), None).unwrap();

    a.call::<i32>("AddToStatic", 3i32).unwrap();
    let snap_a = a.snapshot().unwrap();

    b.call::<i32>("AddToStatic", 70i32).unwrap();
    let snap_b = b.snapshot().unwrap();

    // a: own snap then root then b's snap.
    a.restore(snap_a.clone()).unwrap();
    assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 3);
    a.restore(snap_root.clone()).unwrap();
    assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 0);
    a.restore(snap_b.clone()).unwrap();
    assert_eq!(a.call::<i32>("GetStatic", ()).unwrap(), 70);

    // b: cross-restore the other way.
    b.restore(snap_a.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 3);
    b.restore(snap_root.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 0);
    b.restore(snap_b.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 70);
}

#[test]
fn separate_from_snapshot_calls_share_id_class_through_lineage() {
    // Build sandbox A from a running-sandbox snapshot snap_root.
    // A takes snap_a. Then build sandbox B from snap_a (a different
    // Arc, but B adopts snap_a.sandbox_id == snap_root.sandbox_id).
    // B must be restorable to BOTH snap_a and snap_root because
    // they all share one id.
    let mut seed = create_test_sandbox();
    let snap_root = seed.snapshot().unwrap();

    let mut a =
        MultiUseSandbox::from_snapshot(snap_root.clone(), HostFunctions::default(), None).unwrap();
    a.call::<i32>("AddToStatic", 5i32).unwrap();
    let snap_a = a.snapshot().unwrap();

    let mut b =
        MultiUseSandbox::from_snapshot(snap_a.clone(), HostFunctions::default(), None).unwrap();
    b.restore(snap_a.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 5);
    b.restore(snap_root.clone()).unwrap();
    assert_eq!(b.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn separate_oci_loads_are_mutually_restore_compatible() {
    // Each `from_oci` call rehydrates a structurally identical
    // snapshot. Compatibility is determined by memory layout and
    // host-function set, so a sandbox built from one load accepts
    // a snapshot from any other load of the same image.
    let mut seed = create_test_sandbox();
    let snap = seed.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "v1").unwrap();

    let s_x = Arc::new(Snapshot::from_oci(&path, "v1").unwrap());
    let s_y = Arc::new(Snapshot::from_oci(&path, "v1").unwrap());

    let mut sbox_x =
        MultiUseSandbox::from_snapshot(s_x.clone(), HostFunctions::default(), None).unwrap();
    sbox_x.restore(s_y.clone()).unwrap();
    assert_eq!(sbox_x.call::<i32>("GetStatic", ()).unwrap(), 0);

    sbox_x.restore(s_x.clone()).unwrap();
    assert_eq!(sbox_x.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn oci_loaded_snapshot_supports_full_lifecycle() {
    // Full round-trip: save (from a running sandbox so the loaded
    // snapshot is a valid restore target), load, build sandbox,
    // mutate, snapshot, mutate, restore, mutate, snapshot, restore.
    // Both pre- and post-load snapshots in the loaded id class must
    // remain restore-compatible across an arbitrary number of
    // cycles.
    let mut seed = create_test_sandbox();
    let snap = seed.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.to_oci(&path, "v1").unwrap();

    let loaded = Arc::new(Snapshot::from_oci(&path, "v1").unwrap());
    let mut sbox =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    sbox.call::<i32>("AddToStatic", 1i32).unwrap();
    let s1 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 2i32).unwrap();
    let s3 = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 4i32).unwrap();

    sbox.restore(s1.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 1);
    sbox.restore(s3.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 3);
    sbox.restore(loaded.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);

    // Take a fresh snapshot post-restore. It is in the same id
    // class and remains interchangeable with the others.
    let s_post = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 50i32).unwrap();
    sbox.restore(s_post.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    sbox.restore(s3.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 3);
}

#[test]
fn restore_invariant_under_intermediate_mutations() {
    // Restoring to S followed by an arbitrary number of
    // mutate-then-restore cycles must always produce the same
    // post-restore observable state. This is the core "snapshot
    // and restore really mean what they say" property.
    let mut sbox = create_test_sandbox();
    sbox.call::<i32>("AddToStatic", 13i32).unwrap();
    let s = sbox.snapshot().unwrap();

    let mutations = [3, 5, 7, 11, 13, 17, 19];
    for m in mutations {
        sbox.call::<i32>("AddToStatic", m).unwrap();
        sbox.restore(s.clone()).unwrap();
        assert_eq!(
            sbox.call::<i32>("GetStatic", ()).unwrap(),
            13,
            "restore must reset to the snapshotted value regardless of intermediate mutation {m}"
        );
    }
}

#[test]
fn many_arc_clones_one_snapshot_share_id() {
    // Cloning Arc<Snapshot> N times yields N references with
    // identical sandbox_id. Each sandbox built from a clone shares
    // the id and is mutually restore-compatible. Verifies that the
    // id-equivalence-class semantics hold for arbitrary fan-out.
    //
    // The shared root must be a running-sandbox snapshot so the
    // sandboxes can restore to it.
    let mut seed = create_test_sandbox();
    let snap = seed.snapshot().unwrap();
    let mut sandboxes: Vec<MultiUseSandbox> = (0..4)
        .map(|_| {
            MultiUseSandbox::from_snapshot(snap.clone(), HostFunctions::default(), None).unwrap()
        })
        .collect();

    // Each sandbox takes its own derived snapshot tagged with a
    // unique value.
    let mut snaps: Vec<Arc<Snapshot>> = Vec::new();
    for (i, s) in sandboxes.iter_mut().enumerate() {
        s.call::<i32>("AddToStatic", (i as i32 + 1) * 10).unwrap();
        snaps.push(s.snapshot().unwrap());
    }

    // Every sandbox can restore to every snapshot in the class.
    for (i, sbox) in sandboxes.iter_mut().enumerate() {
        for (j, target) in snaps.iter().enumerate() {
            sbox.restore(target.clone()).unwrap();
            let want = (j as i32 + 1) * 10;
            assert_eq!(
                sbox.call::<i32>("GetStatic", ()).unwrap(),
                want,
                "sandbox {i} restored to snapshot {j} should observe value {want}"
            );
        }
        // And to the root snapshot.
        sbox.restore(snap.clone()).unwrap();
        assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    }
}
