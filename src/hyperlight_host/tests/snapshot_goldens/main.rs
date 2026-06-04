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

//! Snapshot goldens custom-harness test binary.
//!
//! Default mode runs the libtest-mimic harness with one trial per
//! row in `checks::CHECKS`, loading each kind's golden from
//! `target/snapshot-goldens-cache/{version}/{tag}/`. The
//! `generate [out-dir]` subcommand writes the canonical snapshots
//! for the local platform as OCI Image Layouts under `out-dir`,
//! defaulting to the verify cache for a local round-trip.
//!
//! Populate the cache with `just snapshot-goldens-pull` or
//! `just snapshot-goldens-generate`. Set `HYPERLIGHT_GOLDENS_HV`
//! to force the hypervisor name when more than one is available.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use hyperlight_host::sandbox::snapshot::Snapshot;
use hyperlight_host::{HostFunctions, MultiUseSandbox};
use libtest_mimic::{Arguments, Failed, Trial};

mod checks;
mod fixtures;
mod oci;
mod platform;

use checks::Check;
use platform::{Kind, Platform};

fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1);
    if argv.next().as_deref() == Some("generate") {
        let out = argv
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(oci::cache_root);
        return run_generate(&out);
    }
    run_verify()
}

fn run_verify() -> ExitCode {
    let args = Arguments::from_args();
    let Some(platform) = Platform::detect() else {
        eprintln!(
            "snapshot goldens: skipping verify: no (hypervisor, cpu, profile) platform detected on this host",
        );
        return ExitCode::SUCCESS;
    };
    println!(
        "snapshot goldens: verifying platform={} version={}",
        platform.suffix(),
        platform::GOLDENS_VERSION,
    );
    let trials = checks::CHECKS.iter().map(|c| trial(&platform, c)).collect();
    libtest_mimic::run(&args, trials).exit_code()
}

fn trial(platform: &Platform, check: &'static Check) -> Trial {
    let tag = platform.tag(check.kind);
    Trial::test(check.name, move || {
        let dir = oci::golden_dir(&tag).map_err(Failed::from)?;
        let mut sbox = load_sandbox(&dir, &tag, check.kind).map_err(Failed::from)?;
        (check.run)(&mut sbox).map_err(Failed::from)
    })
}

fn load_sandbox(golden_dir: &Path, tag: &str, kind: Kind) -> Result<MultiUseSandbox, String> {
    let snap = Snapshot::from_oci(golden_dir, tag)
        .map_err(|e| format!("Snapshot::from_oci({tag}): {e}"))?;
    let mut funcs = HostFunctions::default();
    if matches!(kind, Kind::Call) {
        fixtures::register_host_echo_fns(&mut funcs);
    }
    MultiUseSandbox::from_snapshot(Arc::new(snap), funcs, None)
        .map_err(|e| format!("MultiUseSandbox::from_snapshot({tag}): {e}"))
}

fn run_generate(out_dir: &Path) -> ExitCode {
    let Some(platform) = Platform::detect() else {
        eprintln!(
            "snapshot goldens: generate: no (hypervisor, cpu, profile) platform detected on this host",
        );
        return ExitCode::FAILURE;
    };
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        eprintln!("snapshot goldens: generate: create {out_dir:?}: {e}");
        return ExitCode::FAILURE;
    }
    println!(
        "snapshot goldens: generating platform={} version={} into {}",
        platform.suffix(),
        platform::GOLDENS_VERSION,
        out_dir.display(),
    );
    for kind in [Kind::Init, Kind::Call] {
        let tag = platform.tag(kind);
        let dir = out_dir.join(&tag);
        let snap = fixtures::generate(kind);
        if let Err(e) = snap.to_oci(&dir, &tag) {
            eprintln!("snapshot goldens: generate: to_oci({tag}): {e}");
            return ExitCode::FAILURE;
        }
        println!("  wrote {tag} -> {}", dir.display());
    }
    ExitCode::SUCCESS
}
