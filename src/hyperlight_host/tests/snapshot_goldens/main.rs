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

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hyperlight_host::sandbox::snapshot::OciTag;
use libtest_mimic::{Arguments, Failed, Trial};

mod checks;
mod fixtures;
mod goldens_version;
mod oci;
mod platform;

use checks::Check;
use platform::Platform;

/// The first CLI argument selects the mode:
///
/// * `generate [out-dir]` writes the canonical snapshot for the local
///   platform under `out-dir`, defaulting to the verify directory.
/// * `verify` verifies the local platform's golden.
/// * no token is a no-op success, so the target sits in the
///   `cargo test --test '*'` glob without a staged golden cache.
///
/// `verify` and `generate` need their golden staged on disk by
/// `just snapshot-goldens-pull` or `just snapshot-goldens-generate`.
/// Arguments after the mode token pass through to libtest-mimic.
fn main() -> ExitCode {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    match args.get(1).and_then(|a| a.to_str()) {
        Some("generate") => {
            let out = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(oci::goldens_root);
            run_generate(&out)
        }
        Some("verify") => {
            args.remove(1);
            run_verify(&args)
        }
        _ => {
            eprintln!(
                "snapshot goldens: no mode selected, skipping. Run via \
                 `just snapshot-goldens-verify` or `just snapshot-goldens-generate`."
            );
            libtest_mimic::run(&Arguments::from_iter(args), Vec::new()).exit_code()
        }
    }
}

fn run_verify(args: &[OsString]) -> ExitCode {
    let args = Arguments::from_iter(args.iter().cloned());
    let Some(platform) = Platform::detect() else {
        eprintln!("snapshot goldens: no (hypervisor, cpu, profile) platform detected on this host",);
        return ExitCode::FAILURE;
    };
    // Verify the current version and every kept old major. A check runs
    // against a golden only when its `since_abi` is at or below the
    // golden's major, so a newer check stays clear of an older golden
    // that predates the state it reads.
    let mut trials = Vec::new();
    for version in goldens_version::verify_versions() {
        let golden = match Golden::resolve(platform, version) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("snapshot goldens: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!("snapshot goldens: verifying {}", golden.tag);
        let golden_abi = goldens_version::abi_major(version);
        trials.extend(
            checks::CHECKS
                .iter()
                .filter(|c| c.since_abi_major <= golden_abi)
                .map(|c| golden.trial(c)),
        );
    }
    let conclusion = libtest_mimic::run(&args, trials);
    if conclusion.has_failed() {
        eprintln!(
            "snapshot goldens: a golden failed to load or verify. This usually means a change \
             broke the on-disk snapshot format. Do not regenerate the goldens to make this pass. \
             See docs/snapshot-versioning.md."
        );
    }
    conclusion.exit_code()
}

/// A golden staged on disk for one platform and version, ready to
/// verify.
struct Golden {
    version: &'static str,
    tag: String,
    cpu: &'static str,
    dir: PathBuf,
}

impl Golden {
    fn resolve(platform: Platform, version: &'static str) -> Result<Self, String> {
        let tag = platform.tag_for(version);
        let dir = oci::golden_dir(&tag)?;
        Ok(Self {
            version,
            cpu: platform.cpu_str(),
            tag,
            dir,
        })
    }

    fn trial(&self, check: &'static Check) -> Trial {
        let tag = self.tag.clone();
        let dir = self.dir.clone();
        let name = format!("{} [{} {}]", check.name, self.cpu, self.version);
        Trial::test(name, move || {
            let golden = checks::GoldenTest::new(&dir, &tag);
            (check.run)(&golden).map_err(Failed::from)
        })
    }
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
    let tag = platform.tag();
    let oci_tag = match OciTag::new(&tag) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("snapshot goldens: generate: invalid tag {tag}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dir = out_dir.join(&tag);
    let snap = fixtures::generate();
    if let Err(e) = snap.save(&dir, &oci_tag) {
        eprintln!("snapshot goldens: generate: save({tag}): {e}");
        return ExitCode::FAILURE;
    }
    println!("snapshot goldens: wrote {tag} -> {}", dir.display());
    ExitCode::SUCCESS
}
