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

use anyhow::{Context, Result};
#[cfg(feature = "build-metadata")]
use built::write_built_file;

fn main() -> Result<()> {
    // re-run the build if this script is changed (or deleted!),
    // even if the rust code is completely unchanged.
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = std::env::var("OUT_DIR")?;
    let out_path = std::path::PathBuf::from(&out_dir);
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;

    // Windows requires the hyperlight_surrogate.exe binary to be next to the executable running
    // hyperlight. We are using rust-embed to include the binary in the hyperlight-host library
    // and then extracting it at runtime when the surrogate process manager starts. We need to pass
    // the location of the binary to the rust build.
    // This logic runs when targeting Windows, even if cross-compiling from Linux.
    if std::env::var("CARGO_CFG_TARGET_OS")? == "windows" {
        println!("cargo:rerun-if-changed=src/hyperlight_surrogate/src/main.rs");
        println!("cargo:rerun-if-changed=src/hyperlight_surrogate/build.rs");
        println!("cargo:rerun-if-changed=src/hyperlight_surrogate/Cargo.toml_temp_name");

        // Build hyperlight_surrogate and
        // Set $HYPERLIGHT_SURROGATE_DIR env var during rust build so we can
        // use it with RustEmbed to specify where hyperlight_surrogate.exe is
        // to include as an embedded resource in the surrogate_process_manager

        // We need to copy/rename the source for hyperlight surrogate into a
        // temp directory because we cannot include a file name `Cargo.toml`
        // inside this package.
        std::fs::create_dir_all(format!("{out_dir}/hyperlight_surrogate/src"))?;
        std::fs::copy(
            format!("{manifest_dir}/src/hyperlight_surrogate/src/main.rs"),
            format!("{out_dir}/hyperlight_surrogate/src/main.rs"),
        )?;
        std::fs::copy(
            format!("{manifest_dir}/src/hyperlight_surrogate/build.rs"),
            format!("{out_dir}/hyperlight_surrogate/build.rs"),
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
        let target_dir = out_path.join("../../hls");

        let profile = std::env::var("PROFILE")?;
        let build_profile = if profile.to_lowercase() == "debug" {
            "dev".to_string()
        } else {
            profile.clone()
        };

        let target_triple = std::env::var("TARGET")?;

        let status = std::process::Command::new("cargo")
            .env("CARGO_TARGET_DIR", &target_dir)
            .arg("build")
            .arg("--manifest-path")
            .arg(&target_manifest_path)
            .arg("--target")
            .arg(&target_triple)
            .arg("--profile")
            .arg(build_profile)
            .arg("--verbose")
            .status()
            .expect("Failed to execute cargo build for surrogate");

        if !status.success() {
            panic!("Failed to build hyperlight surrogate");
        }

        println!("cargo:rustc-env=PROFILE={}", profile);
        let surrogate_binary_dir = std::path::PathBuf::from(&target_dir)
            .join(&target_triple)
            .join(profile);

        println!(
            "cargo:rustc-env=HYPERLIGHT_SURROGATE_DIR={}",
            &surrogate_binary_dir.display()
        );
    }

    if std::env::var("CARGO_CFG_TARGET_OS")? == "macos"
        && std::env::var("CARGO_FEATURE_HVF").is_ok()
    {
        println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");
        println!(
            "cargo:rerun-if-changed=src/hyperlight_host/src/hypervisor/virtual_machine/hvf/bindings.h"
        );
        println!(
            "cargo:rerun-if-changed=src/hyperlight_host/src/hypervisor/virtual_machine/hvf/fp_abi.c"
        );
        println!("cargo:rustc-link-lib=framework=Hypervisor");
        bindgen::Builder::default()
            .clang_args(&["-framework", "Hypervisor"])
            .clang_args(&[
                "-I",
                &format!("{manifest_dir}/src/hypervisor/virtual_machine/hvf"),
            ])
            // The hvf simd register functions use C simd vector
            // parameters/returns for the register value, which Rust
            // does not presently stably support for `extern "C"`
            // code. So, we don't generate native bindings for these
            // functions, and instead generate C stubs (see `fp_abi.c`,
            // which is built below)
            .blocklist_type("hv_simd_fp_uchar16_t")
            .blocklist_function("hv_vcpu_get_simd_fp_reg")
            .blocklist_function("hv_vcpu_set_simd_fp_reg")
            .default_alias_style(bindgen::AliasVariation::NewType)
            .type_alias("hv_memory_flags_t")
            .newtype_enum("hv_reg_t")
            .newtype_enum("hv_simd_fp_reg_t")
            .newtype_enum("hv_sys_reg_t")
            .newtype_enum("hv_exit_reason_t")
            .no_debug("hv_return_t")
            .formatter(bindgen::Formatter::Prettyplease)
            .header(format!(
                "{manifest_dir}/src/hypervisor/virtual_machine/hvf/bindings.h"
            ))
            .generate()
            .context("Unable to generate hvf bindings")?
            .write_to_file(out_path.join("hvf_bindings.rs"))
            .context("Couldn't write hvf bindings")?;

        cc::Build::new()
            .opt_level(3)
            .file(format!(
                "{manifest_dir}/src/hypervisor/virtual_machine/hvf/fp_abi.c"
            ))
            .compile("hyperlight_host_hvf_abi_wrapper");
    }

    // Makes #[cfg(kvm)] == #[cfg(all(feature = "kvm", target_os = "linux"))]
    // Essentially the kvm and mshv3 features are ignored on windows as long as you use #[cfg(kvm)] and not #[cfg(feature = "kvm")].
    // You should never use #[cfg(feature = "kvm")] or #[cfg(feature = "mshv3")] in the codebase.
    cfg_aliases::cfg_aliases! {
        gdb: { all(feature = "gdb", debug_assertions, target_arch = "x86_64") },
        kvm: { all(feature = "kvm", target_os = "linux") },
        mshv3: { all(feature = "mshv3", target_os = "linux") },
        hvf: { all(feature = "hvf", target_os = "macos") },
        crashdump: { all(feature = "crashdump", target_arch = "x86_64") },
        // print_debug feature is aliased with debug_assertions to make it only available in debug-builds.
        print_debug: { all(feature = "print_debug", debug_assertions) },
        // the gdb feature (only temporarily!) needs to use
        // writable/un-shared snapshot memories.
        unshared_snapshot_mem: { feature = "gdb" },
        // The `ReadableSharedMemory` trait in `mem::layout` is only
        // needed in two situations:
        //   1. The `gdb` debug path reads guest memory through it
        //      (`ResolvedGpa::copy_to_slice`), which only exists under
        //      the `gdb` cfg (gdb feature + debug build).
        //   2. The `mem_profile` stack unwinder reads guest memory
        //      through it — but ONLY when snapshots are shared/read-only
        //      (`not(unshared_snapshot_mem)`). When the gdb feature
        //      forces un-shared snapshots, `mem_profile` instead reads
        //      via the inherent `HostSharedMemory::copy_to_slice`, so
        //      the trait is genuinely unused.
        // Gating the trait (and its impls) on this exact condition means
        // we never have to `#[allow(dead_code)]` it.
        readable_shared_mem: { any(gdb, all(feature = "mem_profile", not(unshared_snapshot_mem))) },
    }

    #[cfg(feature = "build-metadata")]
    write_built_file()?;

    Ok(())
}
