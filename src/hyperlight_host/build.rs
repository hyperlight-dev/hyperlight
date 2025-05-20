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

use anyhow::Result;
#[cfg(feature = "build-metadata")]
use built::write_built_file;

fn main() -> Result<()> {
    // re-run the build if this script is changed (or deleted!),
    // even if the rust code is completely unchanged.
    println!("cargo:rerun-if-changed=build.rs");

    // Windows requires the hyperlight_surrogate.exe binary to be next to the executable running
    // hyperlight. We are using rust-ebmed to include the binary in the hyperlight-host library
    // and then extracting it at runtime why the surrogate process manager starts and needed pass
    // the location of the binary to the rust build.
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=src/hyperlight_surrogate/src/main.rs");

        // Build hyperlight_surrogate and
        // Set $HYPERLIGHT_SURROGATE_DIR env var during rust build so we can
        // use it with RustEmbed to specify where hyperlight_surrogate.exe is
        // to include as an embedded resource in the surrogate_process_manager

        // We need to copy/rename the source for hyperlight surrogate into a
        // temp directory because we cannot include a file name `Cargo.toml`
        // inside this package.
        let out_dir = std::env::var("OUT_DIR")?;
        std::fs::create_dir_all(format!("{out_dir}/hyperlight_surrogate/src"))?;
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        std::fs::copy(
            format!("{manifest_dir}/src/hyperlight_surrogate/src/main.rs"),
            format!("{out_dir}/hyperlight_surrogate/src/main.rs"),
        )?;
        std::fs::copy(
            format!("{manifest_dir}/src/hyperlight_surrogate/Cargo.toml_temp_name"),
            format!("{out_dir}/hyperlight_surrogate/Cargo.toml"),
        )?;
        let target_manifest_path = format!("{out_dir}/hyperlight_surrogate/Cargo.toml");

        // Note: When we build hyperlight_surrogate.exe CARGO_TARGET_DIR cannot
        // be the same as the CARGO_TARGET_DIR for the hyperlight-host otherwise
        // the build script will hang. Using a sub directory works tho!
        // xref - https://github.com/rust-lang/cargo/issues/6412
        let target_dir = std::path::PathBuf::from(&out_dir).join("..\\..\\hls");

        let profile = std::env::var("PROFILE")?;
        let build_profile = if profile.to_lowercase() == "debug" {
            "dev".to_string()
        } else {
            profile.clone()
        };

        std::process::Command::new("cargo")
            .env("CARGO_TARGET_DIR", &target_dir)
            .arg("build")
            .arg("--manifest-path")
            .arg(&target_manifest_path)
            .arg("--profile")
            .arg(build_profile)
            .arg("--verbose")
            .output()
            .unwrap();

        println!("cargo:rustc-env=PROFILE={}", profile);
        let surrogate_binary_dir = std::path::PathBuf::from(&target_dir).join(profile);

        println!(
            "cargo:rustc-env=HYPERLIGHT_SURROGATE_DIR={}",
            &surrogate_binary_dir.display()
        );
    }

    // Makes #[cfg(kvm)] == #[cfg(all(feature = "kvm", target_os = "linux"))]
    // and #[cfg(mshv)] == #[cfg(all(any(feature = "mshv2", feature = "mshv3"), target_os = "linux"))].
    // Essentially the kvm and mshv features are ignored on windows as long as you use #[cfg(kvm)] and not #[cfg(feature = "kvm")].
    // You should never use #[cfg(feature = "kvm")] or #[cfg(feature = "mshv")] in the codebase.
    cfg_aliases::cfg_aliases! {
        gdb: { all(feature = "gdb", debug_assertions, any(feature = "kvm", feature = "mshv2", feature = "mshv3"), target_os = "linux") },
        kvm: { all(feature = "kvm", target_os = "linux") },
        mshv: { all(any(feature = "mshv2", feature = "mshv3"), target_os = "linux") },
        crashdump: { all(feature = "crashdump") },
        // print_debug feature is aliased with debug_assertions to make it only available in debug-builds.
        print_debug: { all(feature = "print_debug", debug_assertions) },
        // the following features are mutually exclusive but rather than enforcing that here we are enabling mshv3 to override mshv2 when both are enabled
        // because mshv2 is in the default feature set we want to allow users to enable mshv3 without having to set --no-default-features and the re-enable
        // the other features they want.
        mshv2: { all(feature = "mshv2", not(feature="mshv3"), target_os = "linux") },
        mshv3: { all(feature = "mshv3", target_os = "linux") },
    }

    #[cfg(feature = "build-metadata")]
    write_built_file()?;

    Ok(())
}
