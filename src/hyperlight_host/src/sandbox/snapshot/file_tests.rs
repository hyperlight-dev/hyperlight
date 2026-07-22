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
use crate::sandbox::snapshot::{OciDigest, OciReference, OciTag, Snapshot};
use crate::{GuestBinary, HostFunctions, MultiUseSandbox, UninitializedSandbox};

fn create_test_sandbox() -> MultiUseSandbox {
    let path = simple_guest_as_string().unwrap();
    UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap()
}

fn create_snapshot() -> Arc<Snapshot> {
    let mut sbox = create_test_sandbox();
    sbox.snapshot().unwrap()
}

/// `Result::unwrap_err` requires `T: Debug`, but `Snapshot` is not
/// `Debug`. This wrapper is the test-side equivalent.
#[track_caller]
fn unwrap_err_snapshot(r: crate::Result<Snapshot>) -> crate::HyperlightError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected snapshot load to fail"),
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

/// Locate the snapshot (layer 0) blob inside `oci_dir`.
fn find_snapshot_blob(oci_dir: &std::path::Path) -> std::path::PathBuf {
    let index: Value =
        serde_json::from_slice(&std::fs::read(oci_dir.join("index.json")).unwrap()).unwrap();
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    let manifest_path = oci_dir.join("blobs").join("sha256").join(manifest_digest);
    let manifest: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let snap_digest = manifest["layers"][0]["digest"]
        .as_str()
        .unwrap()
        .strip_prefix("sha256:")
        .unwrap();
    oci_dir.join("blobs").join("sha256").join(snap_digest)
}

// In-memory `from_snapshot` round-trips.

#[test]
fn from_snapshot_already_initialized_in_memory() {
    let snapshot = create_snapshot();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot, HostFunctions::default(), None).unwrap();
    let result: i32 = sbox2.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn from_snapshot_in_memory_pre_init() {
    let snap = Snapshot::from_env(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        crate::sandbox::SandboxConfiguration::default(),
    )
    .unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(snap), HostFunctions::default(), None).unwrap();
    let result: i32 = sbox.call("GetStatic", ()).unwrap();
    assert_eq!(result, 0);
}

// Round-trip via OCI layout on disk.

#[test]
fn round_trip_save_load_call() {
    let snapshot = create_snapshot();

    let dir = tempfile::tempdir().unwrap();
    let oci = dir.path().join("snap");
    snapshot
        .save(&oci, &OciTag::new("latest").unwrap())
        .unwrap();

    let loaded = Snapshot::checked_load(&oci, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();

    let result: String = sbox2.call("Echo", "hello\n".to_string()).unwrap();
    assert_eq!(result, "hello\n");
}

/// A pre-existing snapshot blob with the right length but wrong
/// bytes (corruption, partial copy, foreign tool) must be detected
/// and replaced by `save`, not silently trusted.
#[test]
fn save_self_heals_same_length_wrong_content_snapshot_blob() {
    let snapshot = create_snapshot();

    let dir = tempfile::tempdir().unwrap();
    let oci = dir.path().join("snap");
    snapshot
        .save(&oci, &OciTag::new("latest").unwrap())
        .unwrap();

    // Overwrite the snapshot blob with wrong bytes of the same
    // length, simulating on-disk corruption.
    let snap_path = find_snapshot_blob(&oci);
    let len = std::fs::metadata(&snap_path).unwrap().len() as usize;
    std::fs::write(&snap_path, vec![0xAAu8; len]).unwrap();

    // Re-save. `put_blob_if_absent` must notice the digest mismatch
    // and rewrite the blob.
    snapshot
        .save(&oci, &OciTag::new("latest").unwrap())
        .unwrap();

    // A checked load succeeds: the rewritten blob matches the
    // descriptor digest.
    let loaded = Snapshot::checked_load(&oci, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    let result: String = sbox2.call("Echo", "hello\n".to_string()).unwrap();
    assert_eq!(result, "hello\n");
}

#[test]
fn snapshot_and_pt_size_round_trip() {
    let snap = create_snapshot();
    let original_snapshot_size = snap.layout().snapshot_size();
    let original_pt_size = snap.layout().pt_size();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("running");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(loaded.layout().snapshot_size(), original_snapshot_size);
    assert_eq!(loaded.layout().pt_size(), original_pt_size);
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
    snap1.save(&p1, &OciTag::new("latest").unwrap()).unwrap();
    snap3.save(&p3, &OciTag::new("latest").unwrap()).unwrap();

    let loaded1 = Snapshot::checked_load(&p1, OciTag::new("latest").unwrap()).unwrap();
    let loaded3 = Snapshot::checked_load(&p3, OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(loaded1.snapshot_generation(), gen1);
    assert_eq!(loaded3.snapshot_generation(), gen3);
}

#[test]
fn pre_init_snapshot_cannot_be_persisted() {
    let snap = Snapshot::from_env(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        crate::sandbox::SandboxConfiguration::default(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preinit");
    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("pre-init snapshots cannot be persisted"),
        "expected pre-init rejection, got: {}",
        msg
    );
    assert!(
        !path.exists(),
        "a rejected save must not create the layout directory"
    );
}

// Restore semantics.

#[test]
fn restore_from_loaded_snapshot() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let loaded = Arc::new(Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap());
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(loaded.clone(), HostFunctions::default(), None).unwrap();

    sbox2.call::<i32>("AddToStatic", 5i32).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 5);

    sbox2.restore(loaded).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

/// Independent loads of the same image are structurally identical, so a
/// sandbox built from one accepts a restore from the other.
#[test]
fn restore_across_independent_oci_loads_succeeds() {
    let snap1 = create_snapshot();

    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("snap1");
    snap1.save(&p1, &OciTag::new("latest").unwrap()).unwrap();
    let p2 = dir.path().join("snap2");
    snap1.save(&p2, &OciTag::new("latest").unwrap()).unwrap();

    let loaded1 = Arc::new(Snapshot::checked_load(&p1, OciTag::new("latest").unwrap()).unwrap());
    let loaded2 = Arc::new(Snapshot::checked_load(&p2, OciTag::new("latest").unwrap()).unwrap());

    let mut sbox = MultiUseSandbox::from_snapshot(loaded2, HostFunctions::default(), None).unwrap();
    sbox.restore(loaded1).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn cow_does_not_mutate_backing_file() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

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
        let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
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

// Architecture, hypervisor, and ABI gating.

/// Compute sha256 of `bytes` and return the lowercase hex digest.
fn sha256_hex(bytes: &[u8]) -> String {
    let arr: [u8; 32] = Sha256::digest(bytes).into();
    hex::encode(arr)
}

fn rewrite_config<F: FnOnce(&mut Value)>(oci_dir: &std::path::Path, mutate: F) {
    // Mutate the config blob and rewrite the manifest and index so blob
    // filenames, descriptor sizes, and descriptor digests stay consistent.
    // For tests that target the digest layer directly, write raw bytes.
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

/// Mutate the on-disk manifest JSON and keep the index's manifest
/// descriptor `size` and `digest` in sync.
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
/// the OCI layout and is not referenced by any digest.
fn rewrite_index<F: FnOnce(&mut Value)>(oci_dir: &std::path::Path, mutate: F) {
    let path = oci_dir.join("index.json");
    let mut index: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    mutate(&mut index);
    std::fs::write(path, serde_json::to_vec_pretty(&index).unwrap()).unwrap();
}

#[test]
fn arch_mismatch_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    rewrite_config(&path, |cfg| {
        cfg["arch"] = Value::from(if cfg!(target_arch = "x86_64") {
            "aarch64"
        } else {
            "x86_64"
        });
    });

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("architecture") || msg.contains("arch"),
        "expected architecture mismatch, got: {}",
        msg
    );
}

#[test]
fn abi_version_mismatch_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    rewrite_config(&path, |cfg| {
        cfg["abi_version"] = Value::from(9999u32);
    });

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("ABI") || msg.contains("abi"),
        "expected ABI version mismatch, got: {}",
        msg
    );
}

#[test]
fn hypervisor_mismatch_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    // Pick a hypervisor that is not the current one.
    let current = cfg_current_hypervisor();
    let other = if current == "kvm" { "mshv" } else { "kvm" };

    rewrite_config(&path, |cfg| {
        cfg["hypervisor"] = Value::from(other);
    });

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
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
    create_snapshot()
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    let cfg_path = find_config_blob(&path);
    let cfg: Value = serde_json::from_slice(&std::fs::read(&cfg_path).unwrap()).unwrap();
    match cfg["hypervisor"].as_str().unwrap() {
        "kvm" => "kvm",
        "mshv" => "mshv",
        "whp" => "whp",
        "hvf" => "hvf",
        other => panic!("unknown hypervisor tag {other}"),
    }
}

#[test]
fn cpu_vendor_mismatch_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    rewrite_config(&path, |cfg| {
        cfg["cpu_vendor"] = Value::from("not-this-cpu-vendor");
    });

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("vendor"),
        "expected CPU vendor mismatch, got: {}",
        msg
    );
}

// A call snapshot must carry sregs. serde rejects a config that
// omits the field.

#[test]
fn call_snapshot_without_sregs_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    // Remove sregs from the config. serde rejects the missing
    // field at parse time.
    rewrite_config(&path, |cfg| {
        cfg.as_object_mut().unwrap().remove("sregs");
    });

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("sregs") || msg.contains("missing field") || msg.contains("config"),
        "expected serde error about missing sregs, got: {}",
        msg
    );
}

// Host-function validation. The loaded sandbox's `HostFunctions` must
// be a superset (by name and signature) of those recorded in the snapshot.

/// Build a `MultiUseSandbox` with the default host functions plus a
/// custom `Add(i32, i32) -> i32`.
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
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), host_funcs_with_matching_add(), None)
            .unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

/// A snapshot taken with `Add` registered is rejected when loaded
/// against a `HostFunctions` set that lacks `Add`.
#[test]
fn from_snapshot_rejects_missing_host_function() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let err = MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None)
        .expect_err("from_snapshot must reject a HostFunctions set missing `Add`");
    let msg = format!("{}", err);
    assert!(
        msg.contains("missing") && msg.contains("Add"),
        "expected missing-host-function error mentioning Add, got: {}",
        msg
    );
}

/// Loading registers `Add` with a signature different from the one the
/// snapshot recorded, which must be refused.
#[test]
fn from_snapshot_rejects_signature_mismatch() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let mut hf = HostFunctions::default();
    hf.register_host_function("Add", |a: String, b: String| Ok(format!("{a}{b}")))
        .unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let err = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None)
        .expect_err("from_snapshot must reject a signature mismatch on Add");
    let msg = format!("{}", err);
    assert!(
        msg.contains("signature mismatches") && msg.contains("Add"),
        "expected signature-mismatch error mentioning Add, got: {}",
        msg
    );
}

/// Registering host functions beyond those the snapshot recorded is
/// accepted.
#[test]
fn from_snapshot_accepts_extra_host_functions() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let mut hf = host_funcs_with_matching_add();
    hf.register_host_function("Mul", |a: i32, b: i32| Ok(a * b))
        .unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn from_snapshot_accepts_zero_arg_host_function() {
    let path = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
    u.register_host_function("Zero", || Ok(7i64)).unwrap();
    let mut sbox = u.evolve().unwrap();

    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let mut hf = HostFunctions::default();
    hf.register_host_function("Zero", || Ok(7i64)).unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let _sbox2 = MultiUseSandbox::from_snapshot(Arc::new(loaded), hf, None)
        .expect("zero-arg host function must round-trip through OCI");
}

// OCI-shape invariants.

#[test]
fn missing_oci_layout_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    std::fs::remove_file(path.join("oci-layout")).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("oci-layout"),
        "expected missing oci-layout error, got: {}",
        msg
    );
}

#[test]
fn wrong_image_layout_version_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    std::fs::write(
        path.join("oci-layout"),
        r#"{"imageLayoutVersion":"99.0.0"}"#,
    )
    .unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("image layout version") || msg.contains("imageLayoutVersion"),
        "expected layout version error, got: {}",
        msg
    );
}

#[test]
fn missing_index_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    std::fs::remove_file(path.join("index.json")).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("index.json"),
        "expected missing index.json error, got: {}",
        msg
    );
}

#[test]
fn snapshot_blob_size_mismatch_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

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

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("size") || msg.contains("mismatch"),
        "expected size mismatch error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_zero_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    rewrite_config(&path, |cfg| {
        cfg["layout"]["snapshot_size"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("snapshot_size"),
        "expected snapshot_size error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_unaligned_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    rewrite_config(&path, |cfg| {
        let s = cfg["layout"]["snapshot_size"].as_u64().unwrap();
        cfg["layout"]["snapshot_size"] = Value::from(s + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("PAGE_SIZE") || msg.contains("multiple"),
        "expected page alignment error, got: {}",
        msg
    );
}

#[test]
fn snapshot_layout_snapshot_size_must_match_memory_size() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    let page = hyperlight_common::vmem::PAGE_SIZE as u64;
    rewrite_config(&path, |cfg| {
        let m = cfg["memory_size"].as_u64().unwrap();
        cfg["layout"]["snapshot_size"] = Value::from(m + page);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("does not equal memory_size"),
        "expected snapshot_size + pt_size != memory_size error, got: {}",
        msg
    );
}

#[test]
fn snapshot_size_smaller_than_layout_rejected() {
    // Shrinking `snapshot_size` while growing `pt_size` by the same
    // amount preserves `snapshot_size + pt_size == memory_size` and the
    // blob length, yet leaves the guest mapping too short to back the
    // regions the layout describes. The loader must compare
    // `snapshot_size` against the size the layout fields imply.
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    let page = hyperlight_common::vmem::PAGE_SIZE as u64;
    // Size the layout fields imply. The guest-visible prefix must
    // cover at least this much.
    let required = snapshot.layout().get_memory_size().unwrap() as u64;
    rewrite_config(&path, |cfg| {
        let mem = cfg["memory_size"].as_u64().unwrap();
        // One page short of the required size, with the page-table
        // tail absorbing the rest so `memory_size` (and the blob
        // length) stay constant.
        let short = required - page;
        cfg["layout"]["snapshot_size"] = Value::from(short);
        cfg["layout"]["pt_size"] = Value::from(mem - short);
        // Grow scratch to cover the larger pt tail so the scratch
        // bound is not what trips.
        cfg["layout"]["scratch_size"] = Value::from(mem + page);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "is smaller than the layout size");
}

#[test]
fn snapshot_layout_pt_size_unaligned_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    rewrite_config(&path, |cfg| {
        if let Some(p) = cfg["layout"]["pt_size"].as_u64() {
            cfg["layout"]["pt_size"] = Value::from(p + 1);
        } else {
            cfg["layout"]["pt_size"] = Value::from(1u64);
        }
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("pt_size") || msg.contains("PAGE_SIZE") || msg.contains("multiple"),
        "expected pt_size validation error, got: {}",
        msg
    );
}

#[test]
fn missing_snapshot_blob_rejected() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

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

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("snapshot blob") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-blob error, got: {}",
        msg
    );
}

// Path semantics.

#[test]
fn checked_load_nonexistent_path_returns_error() {
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        "/nonexistent/path/to/oci",
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("stat") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-path error, got: {}",
        msg
    );
}

#[test]
fn checked_load_file_not_directory_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("not-a-dir");
    std::fs::write(&file_path, b"hello").unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &file_path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("not a directory"),
        "expected not-a-directory error, got: {}",
        msg
    );
}

/// Two snapshots written to one directory under different tags coexist
/// and load independently.
#[test]
fn save_appends_into_existing_layout_with_new_tag() {
    let snap_a = create_snapshot();
    let snap_b = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap_a.save(&path, &OciTag::new("a").unwrap()).unwrap();
    snap_b.save(&path, &OciTag::new("b").unwrap()).unwrap();

    let _ = Snapshot::checked_load(&path, OciTag::new("a").unwrap()).unwrap();
    let _ = Snapshot::checked_load(&path, OciTag::new("b").unwrap()).unwrap();

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let manifests = index["manifests"].as_array().unwrap();
    let tags: Vec<&str> = manifests
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

    // Every descriptor carries advisory arch and hypervisor
    // annotations so registry UIs and OCI tooling can show them.
    let expected_arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };
    for m in manifests {
        let anns = &m["annotations"];
        assert_eq!(
            anns["dev.hyperlight.snapshot.arch"].as_str().unwrap(),
            expected_arch
        );
        let hv = anns["dev.hyperlight.snapshot.hypervisor"].as_str().unwrap();
        assert!(
            ["kvm", "mshv", "whp", "hvf"].contains(&hv),
            "unexpected hypervisor annotation: {}",
            hv
        );
        let cpu = anns["dev.hyperlight.snapshot.cpu.vendor"].as_str().unwrap();
        assert!(!cpu.is_empty(), "missing cpu vendor annotation");
    }
}

#[test]
fn save_replaces_descriptor_for_same_tag() {
    let mut sbox = create_test_sandbox();
    sbox.call::<String>("Echo", "first".to_string()).unwrap();
    let snap_first = sbox.snapshot().unwrap();
    sbox.call::<String>("Echo", "second".to_string()).unwrap();
    let snap_second = sbox.snapshot().unwrap();
    let gen_second = snap_second.snapshot_generation();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap_first
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
    snap_second
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
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

/// `save` creates the leaf directory but requires its parent chain to
/// exist.
#[test]
fn save_requires_parent_dir_to_exist() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let missing_parent = dir.path().join("a").join("b").join("c");
    let path = missing_parent.join("store");
    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("parent directory") || msg.contains("not accessible"),
        "expected missing-parent error, got: {msg}"
    );
    assert!(!missing_parent.exists(), "no parent dirs should be created");
}

#[test]
fn save_rejects_regular_file_at_path() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-dir");
    std::fs::write(&path, b"i am a file").unwrap();
    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("is not a directory") || msg.contains("layout dir"),
        "expected non-directory error, got: {msg}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"i am a file");
}

/// A pre-existing `oci-layout` with an unknown version is left in place
/// and the call errors.
#[test]
fn save_rejects_unsupported_existing_layout_version() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("oci-layout"),
        br#"{"imageLayoutVersion":"99.0.0"}"#,
    )
    .unwrap();
    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("imageLayoutVersion") || msg.contains("unsupported"),
        "expected unsupported-version error, got: {msg}"
    );
    assert!(
        !path.join("index.json").exists(),
        "save must not have written index.json"
    );
}

#[test]
fn save_into_empty_existing_directory() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();

    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let _ = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    assert!(path.join("oci-layout").exists());
    assert!(path.join("index.json").exists());
}

/// Files in the layout dir that are not part of the OCI structure are
/// left alone, matching containers/image, crane, and regclient.
#[test]
fn save_preserves_unrelated_files_in_layout_dir() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("README.md"), b"keep me").unwrap();

    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(std::fs::read(path.join("README.md")).unwrap(), b"keep me");
}

/// Saving the same snapshot under the same tag twice keeps one
/// descriptor and reuses the content-addressed blobs.
#[test]
fn save_same_tag_same_content_is_idempotent() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let blobs_after_first: Vec<_> = std::fs::read_dir(path.join("blobs").join("sha256"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();

    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
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

/// Two tags written from one in-memory snapshot share all three blobs
/// (manifest, config, snapshot).
#[test]
fn save_shares_blobs_across_tags_with_identical_content() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");

    snap.save(&path, &OciTag::new("a").unwrap()).unwrap();
    snap.save(&path, &OciTag::new("b").unwrap()).unwrap();

    let blobs: Vec<_> = std::fs::read_dir(path.join("blobs").join("sha256"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .collect();
    assert_eq!(blobs.len(), 3, "expected 3 deduped blobs, got {:?}", blobs);
}

/// Replacing one tag in a three-tag layout keeps the other two
/// descriptors intact.
#[test]
fn save_replace_in_middle_preserves_other_tags() {
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
    snap_a.save(&path, &OciTag::new("a").unwrap()).unwrap();
    snap_b.save(&path, &OciTag::new("b").unwrap()).unwrap();
    snap_c.save(&path, &OciTag::new("c").unwrap()).unwrap();
    snap_b2.save(&path, &OciTag::new("b").unwrap()).unwrap();

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

    let loaded_b = Snapshot::checked_load(&path, OciTag::new("b").unwrap()).unwrap();
    assert_eq!(loaded_b.snapshot_generation(), gen_b2);
}

#[test]
fn save_rejects_malformed_existing_oci_layout_json() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("oci-layout"), b"not json").unwrap();

    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("oci-layout") && msg.contains("JSON"),
        "expected oci-layout JSON error, got: {msg}"
    );
    assert!(!path.join("index.json").exists());
}

#[test]
fn save_rejects_existing_oci_layout_missing_version() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("oci-layout"), br#"{"other":"field"}"#).unwrap();

    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("imageLayoutVersion"),
        "expected missing-version error, got: {msg}"
    );
    assert!(!path.join("index.json").exists());
}

#[test]
fn save_rejects_malformed_existing_index_json() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(path.join("index.json"), b"{not valid json").unwrap();

    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("index.json"),
        "expected index.json error, got: {msg}"
    );
    assert_eq!(
        std::fs::read(path.join("index.json")).unwrap(),
        b"{not valid json",
        "save must not overwrite a malformed existing index.json"
    );
}

/// A snapshot blob whose bytes have been replaced (with length
/// preserved so descriptor sizes still match) must be rejected via
/// digest mismatch.
#[test]
fn checked_load_rejects_snapshot_blob_byte_mutation() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    // Flip one byte in the middle of the snapshot blob. Length is
    // preserved so only a digest re-hash can detect this.
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

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("hash") || msg.contains("sha256"),
        "expected digest-mismatch error, got: {}",
        msg
    );
}

/// Config-blob byte mutation must be caught by digest verification
/// before any structural validator runs.
#[test]
fn checked_load_rejects_config_blob_byte_mutation() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let cfg_path = find_config_blob(&path);
    let mut bytes = std::fs::read(&cfg_path).unwrap();
    // Length-preserving byte flip so the digest layer rejects before
    // the JSON parser.
    bytes[0] = b' ';
    std::fs::write(&cfg_path, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("hash") || msg.contains("sha256"),
        "expected digest-mismatch error, got: {}",
        msg
    );
}

// Input validation for `checked_load`.

fn save_for_mutation() -> (tempfile::TempDir, std::path::PathBuf) {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();
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
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "oci-layout");
}

#[test]
fn oci_layout_missing_version_field_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::write(path.join("oci-layout"), r#"{"unrelated":"field"}"#).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "imageLayoutVersion");
}

#[test]
fn malformed_index_json_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::write(path.join("index.json"), b"{not json").unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "index.json");
}

#[test]
fn empty_index_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        idx["manifests"] = Value::Array(Vec::new());
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "no manifest tagged");
}

/// Two manifests sharing one `org.opencontainers.image.ref.name`
/// annotation are ambiguous, so the load is refused.
#[test]
fn checked_load_rejects_duplicate_tag_in_index() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let first = idx["manifests"][0].clone();
        idx["manifests"].as_array_mut().unwrap().push(first);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "multiple manifests tagged");
}

#[test]
fn missing_manifest_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    std::fs::remove_file(manifest_path(&path)).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
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
        // `oci-spec` validates descriptor digests on parse and rejects
        // values lacking the algorithm prefix.
        idx["manifests"][0]["digest"] = Value::from("deadbeef");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("digest") || msg.contains("index.json"),
        "expected digest or parse error, got: {}",
        msg
    );
}

/// `load` reaches the manifest JSON parser. The digest
/// path is covered by `checked_load_rejects_manifest_blob_byte_mutation`.
#[test]
fn malformed_manifest_json_rejected() {
    let (_dir, path) = save_for_mutation();
    let mp = manifest_path(&path);
    std::fs::write(&mp, b"{not json").unwrap();
    // Match the descriptor size so the JSON parser runs, not the size
    // check.
    let new_len = std::fs::metadata(&mp).unwrap().len();
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["size"] = Value::from(new_len);
    });
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
    assert_err_contains(err, "manifest");
}

#[test]
fn wrong_manifest_schema_version_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["schemaVersion"] = Value::from(99u32);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "schemaVersion");
}

#[test]
fn unknown_config_media_type_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["config"]["mediaType"] = Value::from("application/vnd.example.unknown.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "config media type");
}

#[test]
fn empty_layers_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["layers"] = Value::Array(Vec::new());
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "layer");
}

#[test]
fn extra_layers_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        let first = m["layers"][0].clone();
        m["layers"].as_array_mut().unwrap().push(first);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "layer");
}

#[test]
fn unknown_snapshot_layer_media_type_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["layers"][0]["mediaType"] = Value::from("application/vnd.example.unknown.v1");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "snapshot layer media type");
}

/// Annotations injected by third-party tools (cosign, ORAS, build
/// pipelines) must not break load. The OCI envelope around
/// `OciSnapshotConfig` is parsed via `oci-spec`'s lenient types.
#[test]
fn manifest_and_index_annotations_tolerated() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

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

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    assert_eq!(sbox2.call::<i32>("GetStatic", ()).unwrap(), 0);
}

#[test]
fn config_blob_size_descriptor_mismatch_rejected() {
    let (_dir, path) = save_for_mutation();
    // Bump the config descriptor's claimed size, leaving the blob as written.
    rewrite_manifest(&path, |m| {
        let sz = m["config"]["size"].as_u64().unwrap();
        m["config"]["size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "config blob size mismatch");
}

/// `load` reaches the config JSON parser. The digest path
/// is covered by `checked_load_rejects_config_blob_byte_mutation`.
#[test]
fn malformed_config_json_rejected() {
    let (_dir, path) = save_for_mutation();
    let cfg_path = find_config_blob(&path);
    std::fs::write(&cfg_path, b"{not json").unwrap();
    // Match descriptor sizes so the JSON parser runs, not the size
    // check.
    let new_cfg_len = std::fs::metadata(&cfg_path).unwrap().len();
    rewrite_manifest(&path, |m| {
        m["config"]["size"] = Value::from(new_cfg_len);
    });
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
    assert_err_contains(err, "config JSON");
}

#[test]
fn memory_size_zero_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["memory_size"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "memory_size");
}

#[test]
fn memory_size_unaligned_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        let sz = cfg["memory_size"].as_u64().unwrap();
        cfg["memory_size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    // Either the page-alignment check or the file-size check trips.
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
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "init_data_permissions");
}

#[test]
fn entrypoint_addr_outside_snapshot_region_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // Far above any plausible snapshot region and outside guest
        // mapped memory.
        cfg["entrypoint_addr"] = Value::from(0xDEAD_BEEF_0000u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "entrypoint addr");
}

#[test]
fn entrypoint_addr_below_base_address_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // Below BASE_ADDRESS (0x1000).
        cfg["entrypoint_addr"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "entrypoint addr");
}

#[test]
fn original_entrypoint_addr_outside_snapshot_region_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["original_entrypoint_addr"] = Value::from(0xDEAD_BEEF_0000u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "original entrypoint addr");
}

#[test]
fn original_entrypoint_addr_zero_accepted() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["original_entrypoint_addr"] = Value::from(0u64);
    });
    Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
}

// `load`: skips blob digest verification, runs every
// other validator.

#[test]
fn load_round_trips() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let loaded = Snapshot::load(&path, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox2 =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    let result: String = sbox2.call("Echo", "hi\n".to_string()).unwrap();
    assert_eq!(result, "hi\n");
}

/// Field-level validators (arch, abi, hypervisor, layout and entrypoint
/// bounds) still fire under `load`.
#[test]
fn load_still_validates_config_fields() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["arch"] = Value::from(if cfg!(target_arch = "x86_64") {
            "aarch64"
        } else {
            "x86_64"
        });
    });
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
    let msg = format!("{}", err);
    assert!(
        msg.contains("architecture") || msg.contains("arch"),
        "expected architecture mismatch under load, got: {}",
        msg
    );
}

/// A length-preserving byte flip breaks the snapshot blob's sha256 but
/// leaves the layout valid. `checked_load` rejects it on the digest,
/// `load` loads it.
#[test]
fn load_accepts_digest_mismatched_snapshot_blob() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let snap_path = find_snapshot_blob(&path);
    let mut bytes = std::fs::read(&snap_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&snap_path, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "digest");

    let _ = Snapshot::load(&path, OciTag::new("latest").unwrap())
        .expect("load loads a digest-mismatched blob");
}

/// Flipping a manifest body byte while the index's descriptor digest is
/// stale must be caught by digest verification before any field-level
/// manifest validator runs.
#[test]
fn checked_load_rejects_manifest_blob_byte_mutation() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let mp = manifest_path(&path);
    let mut bytes = std::fs::read(&mp).unwrap();
    // Length-preserving flip.
    bytes[0] ^= 0x20;
    std::fs::write(&mp, &bytes).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "digest mismatch");
}

#[test]
fn checked_load_unknown_tag_lists_available_tags() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("alpha").unwrap()).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("missing").unwrap(),
    ));
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

/// External tools (`oras`, `crane manifest`, `skopeo inspect`) read the
/// tag from the `ref.name` annotation on the manifest descriptor.
#[test]
fn manifest_descriptor_carries_ref_name_annotation() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("production-v3").unwrap())
        .unwrap();

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

// Tag validation. Grammar is enforced when an [`OciTag`] is parsed.

#[test]
fn empty_tag_rejected() {
    assert!(OciTag::new("").is_err());
}

#[test]
fn tag_with_illegal_leading_char_rejected() {
    assert!(OciTag::new(".dotleader").is_err());
    assert!(OciTag::new("-dashleader").is_err());
}

#[test]
fn tag_with_illegal_chars_rejected() {
    assert!(OciTag::new("with/slash").is_err());
    assert!(OciTag::new("with space").is_err());
}

#[test]
fn long_tag_within_limit_accepted() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let long = OciTag::new("a".repeat(128)).unwrap();
    snap.save(dir.path().join("snap"), &long).unwrap();
    let _ = Snapshot::checked_load(dir.path().join("snap"), long).unwrap();
}

#[test]
fn over_long_tag_rejected() {
    assert!(OciTag::new("a".repeat(129)).is_err());
}

// Save-shape invariants. The on-disk JSON must match what the OCI spec
// prescribes.

#[test]
fn manifest_descriptor_uses_image_manifest_media_type() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    assert_eq!(
        index["manifests"][0]["mediaType"].as_str().unwrap(),
        "application/vnd.oci.image.manifest.v1+json"
    );
}

/// A descriptor that does not advertise an OCI image manifest is
/// refused even when the blob would parse.
#[test]
fn manifest_descriptor_non_image_manifest_rejected() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["mediaType"] = Value::from("application/vnd.oci.image.index.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{}", err);
    assert!(
        msg.contains("unexpected media type"),
        "expected manifest-descriptor media type error, got: {}",
        msg
    );
}

#[test]
fn manifest_uses_correct_config_and_layer_media_types() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
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
    // that falls back to `config.mediaType` sees the same value.
    assert_eq!(
        manifest["artifactType"].as_str().unwrap(),
        "application/vnd.hyperlight.snapshot.config.v1+json"
    );
}

#[test]
fn manifest_missing_artifact_type_rejected() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    rewrite_manifest(&path, |m| {
        m.as_object_mut().unwrap().remove("artifactType");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "missing required artifactType");
}

#[test]
fn manifest_mismatched_artifact_type_rejected() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    rewrite_manifest(&path, |m| {
        m["artifactType"] = Value::from("application/vnd.example.bogus.v1+json");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "does not match config media type");
}

#[test]
fn save_writes_oci_layout_marker() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let marker: Value =
        serde_json::from_slice(&std::fs::read(path.join("oci-layout")).unwrap()).unwrap();
    assert_eq!(marker["imageLayoutVersion"].as_str().unwrap(), "1.0.0");
}

// Tag selection edge cases.

#[test]
fn tag_lookup_is_case_sensitive() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("MyTag").unwrap()).unwrap();

    let err = unwrap_err_snapshot(Snapshot::checked_load(&path, OciTag::new("mytag").unwrap()));
    assert_err_contains(err, "no manifest tagged");

    let _ = Snapshot::checked_load(&path, OciTag::new("MyTag").unwrap()).unwrap();
}

/// A miscased annotation key like `org.OpenContainers.image.ref.name`
/// leaves the manifest untagged from the loader's perspective.
#[test]
fn ref_name_annotation_key_is_case_sensitive() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let anns = idx["manifests"][0]["annotations"].as_object_mut().unwrap();
        let value = anns.remove("org.opencontainers.image.ref.name").unwrap();
        anns.insert("org.OpenContainers.image.ref.name".to_string(), value);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "no manifest tagged");
}

#[test]
fn tag_with_all_valid_special_chars_accepted() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    let valid = OciTag::new("v1.2.3-rc.1_build").unwrap();
    snap.save(&path, &valid).unwrap();
    let _ = Snapshot::checked_load(&path, valid).unwrap();
}

/// A standard ref.name annotation resolves by tag even alongside
/// unrelated annotations (cosign signatures, build pipelines).
#[test]
fn other_descriptor_annotations_do_not_interfere() {
    let (_dir, path) = save_for_mutation();
    rewrite_index(&path, |idx| {
        let anns = idx["manifests"][0]["annotations"].as_object_mut().unwrap();
        anns.insert(
            "dev.sigstore.cosign/signature".to_string(),
            Value::from("MEUCIQDfake"),
        );
        anns.insert("io.example.build.id".to_string(), Value::from("12345"));
    });
    let _ = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
}

// Bad sha256 digest format on the inner descriptors (config and snapshot
// layer). The index-side equivalent is `bad_digest_format_rejected`.

#[test]
fn bad_config_descriptor_digest_format_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        m["config"]["digest"] = Value::from("md5:deadbeef");
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
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
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{err}");
    assert!(
        msg.contains("digest"),
        "expected digest-format error, got: {msg}"
    );
}

// Missing inner blobs.

#[test]
fn missing_config_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    let cfg_path = find_config_blob(&path);
    std::fs::remove_file(&cfg_path).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    let msg = format!("{err}");
    assert!(
        msg.contains("open") || msg.contains("No such") || msg.contains("not found"),
        "expected missing-config-blob error, got: {msg}"
    );
}

// Size-bound enforcement.

/// The manifest reader bounds input to 1 MiB. The descriptor size is
/// matched so the bound trips before any size-mismatch check.
#[test]
fn manifest_blob_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    let mp = manifest_path(&path);
    let huge = vec![b'a'; (1024 * 1024 + 16) as usize];
    std::fs::write(&mp, &huge).unwrap();
    rewrite_index(&path, |idx| {
        idx["manifests"][0]["size"] = Value::from(huge.len() as u64);
    });
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
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
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
    assert_err_contains(err, "exceeds maximum allowed");
}

#[test]
fn oci_layout_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    let huge = vec![b'a'; 1024 * 1024 + 16];
    std::fs::write(path.join("oci-layout"), &huge).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "exceeds maximum allowed");
}

#[test]
fn index_json_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    let huge = vec![b'a'; 1024 * 1024 + 16];
    std::fs::write(path.join("index.json"), &huge).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "exceeds maximum allowed");
}

#[test]
fn index_json_too_large_on_write_rejected() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    snap.save(&path, &OciTag::new("keep").unwrap()).unwrap();

    // Pad one annotation so the index sits just under the read cap.
    // Each filler byte adds one byte of output, so the target length is
    // exact. The file still reads, so save parses it, then the new
    // "latest" descriptor pushes the index over the cap.
    let index_path = path.join("index.json");
    let base = {
        let idx: Value = serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
        idx["manifests"][0].clone()
    };
    let build = |filler_len: usize| -> Vec<u8> {
        let mut d = base.clone();
        d["annotations"]["dev.hyperlight.test.filler"] = Value::from("a".repeat(filler_len));
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [d],
        });
        serde_json::to_vec_pretty(&index).unwrap()
    };
    let target = 1024 * 1024 - 50;
    let filler = target - build(0).len();
    let bytes = build(filler);
    assert!(
        bytes.len() <= 1024 * 1024,
        "crafted index must pass the read bound"
    );
    std::fs::write(&index_path, &bytes).unwrap();

    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    assert_err_contains(err, "index.json");

    // The check runs before the index is written, so the crafted index
    // stays on disk.
    assert_eq!(std::fs::read(&index_path).unwrap(), bytes);
}

#[test]
fn config_blob_too_large_on_write_rejected() {
    let guest = simple_guest_as_string().unwrap();
    let mut u = UninitializedSandbox::new(GuestBinary::FilePath(guest), None).unwrap();
    // Each host function adds its name and signature to the config
    // JSON. Long names reach the 1 MiB cap with a modest count.
    let long = "h".repeat(300);
    for i in 0..3000 {
        u.register_host_function(&format!("{long}{i}"), |a: i32, b: i32| Ok(a + b))
            .unwrap();
    }
    let mut sbox = u.evolve().unwrap();
    let snap = sbox.snapshot().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    let err = snap
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap_err();
    assert_err_contains(err, "config blob");
}

#[test]
fn memory_size_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // 16 GiB exceeds MAX_MEMORY_SIZE.
        cfg["memory_size"] = Value::from(16u64 * 1024 * 1024 * 1024);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "memory_size");
}

#[test]
fn layout_field_too_large_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        // 64 GiB exceeds MAX_MEMORY_SIZE for an individual region.
        cfg["layout"]["heap_size"] = Value::from(64u64 * 1024 * 1024 * 1024);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "heap_size");
}

#[test]
fn stack_top_gva_zero_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["stack_top_gva"] = Value::from(0u64);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "stack_top_gva");
}

#[test]
fn stack_top_gva_out_of_range_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_config(&path, |cfg| {
        cfg["stack_top_gva"] = Value::from(u64::MAX);
    });
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    assert_err_contains(err, "stack_top_gva");
}

#[test]
#[cfg(unix)]
fn symlink_snapshot_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    // Replace the snapshot blob with a symlink to its real bytes. A
    // content-addressed blob must be a regular file, so the loader
    // refuses to follow the link.
    let blob = find_snapshot_blob(&path);
    let real = blob.with_extension("real");
    std::fs::rename(&blob, &real).unwrap();
    std::os::unix::fs::symlink(&real, &blob).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    // "link" is common to the `ELOOP` wording of every C library.
    assert_err_contains(err, "link");
}

#[test]
#[cfg(unix)]
fn symlink_config_blob_rejected() {
    let (_dir, path) = save_for_mutation();
    // The config blob is read through `read_bounded`, which opens
    // with `O_NOFOLLOW`. Replacing it with a symlink to its real
    // bytes makes the open fail.
    let blob = find_config_blob(&path);
    let real = blob.with_extension("real");
    std::fs::rename(&blob, &real).unwrap();
    std::os::unix::fs::symlink(&real, &blob).unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(
        &path,
        OciTag::new("latest").unwrap(),
    ));
    // "link" is common to the `ELOOP` wording of every C library.
    assert_err_contains(err, "link");
}

#[test]
#[cfg(unix)]
fn save_replaces_symlink_snapshot_blob_with_regular_file() {
    let snapshot = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snap");
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    // Replace the snapshot blob with a symlink to its real bytes. A
    // content-addressed blob must be a regular file, so the writer
    // must not trust the symlink as an already-present blob.
    let blob = find_snapshot_blob(&path);
    let real = blob.with_extension("real");
    std::fs::rename(&blob, &real).unwrap();
    std::os::unix::fs::symlink(&real, &blob).unwrap();

    // Re-save. `put_blob_if_absent` sees the path is a symlink, not a
    // regular file, and rewrites it via an atomic rename.
    snapshot
        .save(&path, &OciTag::new("latest").unwrap())
        .unwrap();

    let meta = std::fs::symlink_metadata(&blob).unwrap();
    assert!(
        meta.file_type().is_file() && !meta.file_type().is_symlink(),
        "expected the snapshot blob to be a regular file after re-save"
    );

    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let mut sbox =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
    let result: String = sbox.call("Echo", "hello\n".to_string()).unwrap();
    assert_eq!(result, "hello\n");
}

/// A snapshot descriptor claiming a size different from the blob file is
/// rejected before mmap.
#[test]
fn snapshot_descriptor_size_disagrees_with_file_rejected() {
    let (_dir, path) = save_for_mutation();
    rewrite_manifest(&path, |m| {
        let sz = m["layers"][0]["size"].as_u64().unwrap();
        m["layers"][0]["size"] = Value::from(sz + 1);
    });
    let err = unwrap_err_snapshot(Snapshot::load(&path, OciTag::new("latest").unwrap()));
    let msg = format!("{err}");
    assert!(
        msg.contains("snapshot blob size"),
        "expected snapshot-blob descriptor disagreement error, got: {msg}"
    );
}

// `load` runs every non-digest validator. The unverified
// path is faster, not more permissive.

// Round-trip data fidelity for fields not exercised by the
// load-then-call-the-guest tests above.

#[test]
fn round_trip_preserves_stack_top_gva() {
    let snap = create_snapshot();
    let original = snap.stack_top_gva();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(loaded.stack_top_gva(), original);
}

#[test]
fn round_trip_preserves_non_default_scratch_size() {
    use crate::sandbox::SandboxConfiguration;
    let mut cfg = SandboxConfiguration::default();
    let custom_scratch: usize = 256 * 1024;
    cfg.set_scratch_size(custom_scratch);
    let mut sbox = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(cfg),
    )
    .unwrap()
    .evolve()
    .unwrap();
    let snap = sbox.snapshot().unwrap();
    let original = snap.layout().get_scratch_size();
    assert_eq!(original, custom_scratch);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(loaded.layout().get_scratch_size(), custom_scratch);
}

#[test]
fn snapshot_config_records_entrypoint_and_sregs() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    assert!(
        cfg["entrypoint_addr"].is_u64(),
        "config must carry entrypoint_addr"
    );
    assert!(cfg["sregs"].is_object(), "config must carry sregs");
}

#[test]
fn round_trip_preserves_host_function_signatures() {
    let mut sbox = create_sandbox_with_custom_host_funcs();
    let snap = sbox.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

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
    let loaded = Snapshot::checked_load(&path, OciTag::new("latest").unwrap()).unwrap();
    let _ = MultiUseSandbox::from_snapshot(Arc::new(loaded), host_funcs_with_matching_add(), None)
        .unwrap();
}

#[test]
fn snapshot_with_no_host_functions_round_trips() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    // A config that records no host functions must load. Clearing the
    // array breaks the config digest, so the load skips verification.
    rewrite_config(&path, |cfg| {
        cfg["host_functions"] = Value::Array(Vec::new());
    });
    let cfg: Value =
        serde_json::from_slice(&std::fs::read(find_config_blob(&path)).unwrap()).unwrap();
    assert!(cfg["host_functions"].as_array().unwrap().is_empty());

    let loaded = Snapshot::load(&path, OciTag::new("latest").unwrap()).unwrap();
    let _ =
        MultiUseSandbox::from_snapshot(Arc::new(loaded), HostFunctions::default(), None).unwrap();
}

// Snapshot lineage and restore semantics. `restore` accepts any
// snapshot whose memory layout and host-function set match the sandbox.
// Snapshots within a compatible set are interchangeable.

#[test]
fn linear_chain_restore_in_order() {
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
fn restore_idempotent() {
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
fn separate_oci_loads_are_mutually_restore_compatible() {
    let mut seed = create_test_sandbox();
    let snap = seed.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("v1").unwrap()).unwrap();

    let s_x = Arc::new(Snapshot::checked_load(&path, OciTag::new("v1").unwrap()).unwrap());
    let s_y = Arc::new(Snapshot::checked_load(&path, OciTag::new("v1").unwrap()).unwrap());

    let mut sbox_x =
        MultiUseSandbox::from_snapshot(s_x.clone(), HostFunctions::default(), None).unwrap();
    sbox_x.restore(s_y.clone()).unwrap();
    assert_eq!(sbox_x.call::<i32>("GetStatic", ()).unwrap(), 0);

    sbox_x.restore(s_x.clone()).unwrap();
    assert_eq!(sbox_x.call::<i32>("GetStatic", ()).unwrap(), 0);
}

/// Snapshots taken before and after a save+load round-trip remain
/// mutually restore-compatible.
#[test]
fn oci_loaded_snapshot_supports_full_lifecycle() {
    let mut seed = create_test_sandbox();
    let snap = seed.snapshot().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("v1").unwrap()).unwrap();

    let loaded = Arc::new(Snapshot::checked_load(&path, OciTag::new("v1").unwrap()).unwrap());
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

    let s_post = sbox.snapshot().unwrap();
    sbox.call::<i32>("AddToStatic", 50i32).unwrap();
    sbox.restore(s_post.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 0);
    sbox.restore(s3.clone()).unwrap();
    assert_eq!(sbox.call::<i32>("GetStatic", ()).unwrap(), 3);
}

// Typed references: `OciTag`, `OciDigest`, `OciReference`.

/// The digest returned by `save` addresses the tag's manifest and
/// loads the same snapshot.
#[test]
fn save_returns_manifest_digest_that_loads() {
    let mut sbox = create_test_sandbox();
    sbox.call::<String>("Echo", "x".to_string()).unwrap();
    let snap = sbox.snapshot().unwrap();
    let expected_gen = snap.snapshot_generation();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    let digest = snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let loaded = Snapshot::checked_load(&path, digest).unwrap();
    assert_eq!(loaded.snapshot_generation(), expected_gen);
}

/// The returned digest is the sha256 of the manifest blob, matching the
/// digest recorded for that tag's manifest descriptor in `index.json`.
#[test]
fn save_returns_digest_matching_index_manifest_descriptor() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    let digest = snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let index: Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let descriptor_digest = index["manifests"][0]["digest"].as_str().unwrap();
    assert_eq!(digest.as_str(), descriptor_digest);

    // The digest also matches the sha256 of the manifest blob bytes.
    let manifest_hex = descriptor_digest.strip_prefix("sha256:").unwrap();
    let manifest_bytes =
        std::fs::read(path.join("blobs").join("sha256").join(manifest_hex)).unwrap();
    assert_eq!(
        digest.as_str(),
        format!("sha256:{}", sha256_hex(&manifest_bytes))
    );
}

/// Loading by digest selects the matching manifest regardless of how
/// many tags share the layout.
#[test]
fn checked_load_by_digest_selects_correct_manifest_among_tags() {
    let mut sbox = create_test_sandbox();
    sbox.call::<String>("Echo", "a".to_string()).unwrap();
    let snap_a = sbox.snapshot().unwrap();
    let gen_a = snap_a.snapshot_generation();
    sbox.call::<String>("Echo", "b".to_string()).unwrap();
    let snap_b = sbox.snapshot().unwrap();
    let gen_b = snap_b.snapshot_generation();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    let digest_a = snap_a.save(&path, &OciTag::new("a").unwrap()).unwrap();
    let digest_b = snap_b.save(&path, &OciTag::new("b").unwrap()).unwrap();
    assert_ne!(digest_a.as_str(), digest_b.as_str());

    let loaded_a = Snapshot::checked_load(&path, digest_a).unwrap();
    let loaded_b = Snapshot::checked_load(&path, digest_b).unwrap();
    assert_eq!(loaded_a.snapshot_generation(), gen_a);
    assert_eq!(loaded_b.snapshot_generation(), gen_b);
}

#[test]
fn checked_load_accepts_reference_value() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("v1").unwrap()).unwrap();

    let reference: OciReference = "v1".parse().unwrap();
    let _ = Snapshot::checked_load(&path, reference).unwrap();
}

#[test]
fn unknown_digest_reports_missing_manifest() {
    let snap = create_snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("layout");
    snap.save(&path, &OciTag::new("latest").unwrap()).unwrap();

    let absent: OciDigest = format!("sha256:{}", "0".repeat(64)).parse().unwrap();
    let err = unwrap_err_snapshot(Snapshot::checked_load(&path, absent));
    assert_err_contains(err, "no manifest with digest");
}

#[test]
fn oci_digest_parsing_accepts_canonical_sha256() {
    let canonical = format!("sha256:{}", "a".repeat(64));
    let digest: OciDigest = canonical.parse().unwrap();
    assert_eq!(digest.as_str(), canonical);
}

#[test]
fn oci_digest_parsing_rejects_malformed_values() {
    // Bare hex without the algorithm prefix.
    assert!("a".repeat(64).parse::<OciDigest>().is_err());
    // Uppercase hex is outside the canonical sha256 grammar.
    assert!(
        format!("sha256:{}", "A".repeat(64))
            .parse::<OciDigest>()
            .is_err()
    );
    // Wrong digest length.
    assert!("sha256:deadbeef".parse::<OciDigest>().is_err());
    // Unsupported algorithm.
    assert!(
        format!("sha512:{}", "a".repeat(128))
            .parse::<OciDigest>()
            .is_err()
    );
}

#[test]
fn oci_reference_parsing_disambiguates_on_colon() {
    let tag_ref: OciReference = "latest".parse().unwrap();
    assert!(matches!(tag_ref, OciReference::Tag(_)));

    let digest_ref: OciReference = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
    assert!(matches!(digest_ref, OciReference::Digest(_)));
}

/// Adding a new tag to a layout that a live `Snapshot` is already
/// mapped from must not disturb that mapping. `save` writes only new
/// content-addressed blobs and swaps `index.json` atomically, so the
/// blob the mapping holds open stays byte-for-byte identical.
#[test]
fn save_new_tag_into_loaded_layout_preserves_live_mapping() {
    let snap_a = create_snapshot();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store");
    snap_a.save(&path, &OciTag::new("a").unwrap()).unwrap();

    // Load tag "a" and keep the mapping live.
    let loaded_a = Arc::new(Snapshot::checked_load(&path, OciTag::new("a").unwrap()).unwrap());

    // Record the full mapped image and every on-disk blob before the
    // second save, so any byte change is caught.
    let mapping_before = loaded_a.memory.as_slice().to_vec();
    let blobs_dir = path.join("blobs").join("sha256");
    let blobs_before = read_blob_dir(&blobs_dir);

    // While the mapping is live, write a different snapshot under a
    // new tag into the same layout.
    let mut other = create_test_sandbox();
    other.call::<i32>("AddToStatic", 42i32).unwrap();
    let snap_b = other.snapshot().unwrap();
    snap_b.save(&path, &OciTag::new("b").unwrap()).unwrap();

    // The live mapping is unchanged, byte for byte.
    assert_eq!(
        loaded_a.memory.as_slice(),
        mapping_before.as_slice(),
        "live snapshot mapping changed after a new tag was written"
    );

    // The blob the mapping holds open is still present and unchanged,
    // and the second save only adds blobs.
    let blobs_after = read_blob_dir(&blobs_dir);
    for (name, bytes) in &blobs_before {
        assert_eq!(
            blobs_after.get(name),
            Some(bytes),
            "existing blob {name:?} was modified by the second save"
        );
    }

    // A sandbox built on the live mapping still restores cleanly.
    let mut live =
        MultiUseSandbox::from_snapshot(loaded_a.clone(), HostFunctions::default(), None).unwrap();
    live.call::<i32>("AddToStatic", 7i32).unwrap();
    assert_eq!(live.call::<i32>("GetStatic", ()).unwrap(), 7);
    live.restore(loaded_a).unwrap();
    assert_eq!(live.call::<i32>("GetStatic", ()).unwrap(), 0);

    // Both tags resolve and load independently.
    let _ = Snapshot::checked_load(&path, OciTag::new("a").unwrap()).unwrap();
    let _ = Snapshot::checked_load(&path, OciTag::new("b").unwrap()).unwrap();
}

/// Read every file in a `blobs/sha256` directory into a name-keyed map
/// for byte-for-byte comparison.
fn read_blob_dir(
    blobs_dir: &std::path::Path,
) -> std::collections::BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(blobs_dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name(), std::fs::read(e.path()).unwrap())
        })
        .collect()
}

// =============================================================================
// `from_snapshot` config plumbing.
// =============================================================================
//
// `from_snapshot` accepts a caller-supplied `SandboxConfiguration`.
// Layout fields must be silently overridden by the snapshot (the
// on-disk memory blob already encodes those sizes). Runtime fields
// must take effect.

/// Layout fields supplied via `SandboxConfiguration` must be silently
/// overridden. The snapshot's own layout is authoritative.
#[test]
fn from_snapshot_silently_ignores_layout_overrides() {
    use crate::sandbox::SandboxConfiguration;

    let mut sbox = create_test_sandbox();
    let snapshot = sbox.snapshot().unwrap();
    let original_input = snapshot.layout().input_data_size();
    let original_output = snapshot.layout().output_data_size();
    let original_heap = snapshot.layout().heap_size();
    let original_scratch = snapshot.layout().get_scratch_size();

    let mut config = SandboxConfiguration::default();
    config.set_input_data_size(original_input * 2);
    config.set_output_data_size(original_output * 2);
    config.set_heap_size((original_heap as u64) * 2);
    config.set_scratch_size(original_scratch * 2);

    let mut sbox2 =
        MultiUseSandbox::from_snapshot(snapshot.clone(), HostFunctions::default(), Some(config))
            .unwrap();

    sbox2.call::<i32>("GetStatic", ()).unwrap();

    let new_snap = sbox2.snapshot().unwrap();
    assert_eq!(new_snap.layout().input_data_size(), original_input);
    assert_eq!(new_snap.layout().output_data_size(), original_output);
    assert_eq!(new_snap.layout().heap_size(), original_heap);
    assert_eq!(new_snap.layout().get_scratch_size(), original_scratch);
}

/// `from_snapshot` honors `guest_core_dump=true` so that
/// `generate_crashdump_to_dir` writes a file.
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
        "expected core dump file when guest_core_dump=true"
    );
}

/// `from_snapshot` honors `guest_core_dump=false` so that
/// `generate_crashdump_to_dir` produces no file.
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

/// Non-default `init_data_permissions` survive an OCI round-trip
/// byte-for-byte. The default code path uses `READ`, so this pins
/// `READ | WRITE` instead. A regression in the permission
/// serialisation would silently downgrade or upgrade access to the
/// init_data region.
#[test]
fn round_trip_preserves_non_default_init_data_permissions() {
    use crate::mem::memory_region::MemoryRegionFlags;
    use crate::sandbox::uninitialized::{GuestBlob, GuestEnvironment};

    let path = simple_guest_as_string().unwrap();
    let data: &[u8] = b"perm-pinned-init-data";
    let env = GuestEnvironment {
        guest_binary: GuestBinary::FilePath(path),
        init_data: Some(GuestBlob {
            data,
            permissions: MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
        }),
    };
    let mut sbox = UninitializedSandbox::new(env, None)
        .unwrap()
        .evolve()
        .unwrap();
    let snap = sbox.snapshot().unwrap();
    let expected = snap.layout().init_data_permissions();
    assert_eq!(
        expected,
        Some(MemoryRegionFlags::READ | MemoryRegionFlags::WRITE),
        "fixture must produce non-default init_data_permissions",
    );

    let dir = tempfile::tempdir().unwrap();
    let oci_dir = dir.path().join("layout");
    snap.save(&oci_dir, &OciTag::new("latest").unwrap())
        .unwrap();
    let loaded = Snapshot::checked_load(&oci_dir, OciTag::new("latest").unwrap()).unwrap();
    assert_eq!(loaded.layout().init_data_permissions(), expected);
}
