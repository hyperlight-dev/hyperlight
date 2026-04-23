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

mod build_files;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use build_files::{LIBC_FILES, LIBC_FILES_X86, LIBM_FILES, LIBM_FILES_X86};

fn copy_includes<P: AsRef<Path>, Q: AsRef<Path> + std::fmt::Debug>(
    include_dir: P,
    base: Q,
) -> Result<()> {
    let entries =
        fs::read_dir(&base).with_context(|| format!("could not open include dir {:?}", base))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("could not read include dir {:?}", base))?;
        let src = entry.path();
        let dst = include_dir.as_ref().join(entry.file_name());
        let kind = entry
            .file_type()
            .with_context(|| format!("could not find type of {:?}", src))?;

        if kind.is_dir() {
            fs::create_dir_all(&dst)
                .with_context(|| format!("could not create include dir {:?}", &dst))?;
            copy_includes(&dst, src)?;
        } else if Some(std::ffi::OsStr::new("h")) == src.extension() {
            fs::copy(&src, &dst).with_context(|| format!("could not copy header {:?}", &src))?;
        }
    }

    Ok(())
}

fn cc_build(picolibc_dir: &PathBuf, target: &str) -> Result<cc::Build> {
    let mut build = cc::Build::new();
    let compiler = env::var("HYPERLIGHT_GUEST_clang").unwrap_or("clang".to_string());

    build.compiler(compiler).std("c18").opt_level(3);

    build
        .flag("-fPIC")
        .flag("-nostdlib")
        .flag("-ffreestanding")
        .flag("-fno-common")
        .flag("-fno-builtin")
        .flag("-fdiagnostics-color=always")
        .flag("-Wall")
        .flag("-Winvalid-pch")
        .flag("-Wno-unused-command-line-argument")
        .flag("-Wno-unsupported-floating-point-opt")
        .flag("-Wextra")
        .flag("-Werror=vla")
        .flag("-Warray-bounds")
        .flag("-Werror=double-promotion")
        .flag("-Werror=implicit-function-declaration")
        .flag("-Werror=unreachable-code-fallthrough")
        .flag("-Wmissing-declarations")
        .flag("-Wold-style-definition")
        .flag("-Wno-implicit-int")
        .flag("-Wno-missing-braces")
        .flag("-Wno-return-type")
        // We don't support stack protectors at the moment, but Arch Linux clang
        // auto-enables them for -linux platforms, so explicitly disable them.
        .flag("-fno-stack-protector")
        .flag("-fstack-clash-protection")
        .flag("-mstack-probe-size=4096")
        // Hyperlight's stack management was not designed with a redzone in mind,
        // so we leave it disabled for now
        .flag("-mno-red-zone")
        // This is a terrible hack, because
        // - we need stack clash protection, because we have put the
        //   stack right smack in the middle of everything in the guest
        // - clang refuses to do stack clash protection unless it is
        //   required by a target ABI (Windows, MacOS) or the target is
        //   is Linux or FreeBSD (see Clang.cpp RenderSCPOptions
        //   https://github.com/llvm/llvm-project/blob/1bb52e9/clang/lib/Driver/ToolChains/Clang.cpp#L3724).
        //   Hopefully a flag to force stack clash protection on generic
        //   targets will eventually show up.
        .flag("--target=x86_64-unknown-linux-none");

    build
        .flag_if_supported("-fdirect-access-external-data")
        .flag_if_supported("-frounding-math")
        .flag_if_supported("-fsignaling-nans")
        .flag_if_supported("-fno-builtin-copysignl")
        .flag_if_supported("-mstack-protector-guard=global")
        .flag_if_supported("-fstrict-flex-arrays=3");

    build
        .flag("-U_FORTIFY_SOURCE")
        .define("ABORT_PROVIDED", "1")
        .define("DEFINE_MEMALIGN", "1")
        .define("DEFINE_POSIX_MEMALIGN", "1")
        .define("_LIBC", None)
        .define("_FILE_OFFSET_BITS", "64");

    match target {
        "x86" | "x86_64" => {
            build.include(picolibc_dir.join("libm/machine/x86"));
            build.include(picolibc_dir.join("libc/machine/x86"));
        }
        arch => {
            bail!("Unsupported target architecture: {arch}");
        }
    }

    build
        .include(picolibc_dir)
        .include(picolibc_dir.join("libc/stdio"))
        .include(picolibc_dir.join("libc/locale"))
        .include(picolibc_dir.join("libc/include"));

    Ok(build)
}

fn add_libc(build: &mut cc::Build, picolibc_dir: &Path, target: &str) -> Result<()> {
    let base = LIBC_FILES.iter();
    let files = match target {
        "x86" | "x86_64" => base.chain(LIBC_FILES_X86.iter()),
        arch => bail!("Unsupported target architecture: {arch}"),
    };

    for file in files {
        let source_path = picolibc_dir.join("libc").join(file);
        build.file(&source_path);
    }

    Ok(())
}

fn add_libm(build: &mut cc::Build, picolibc_dir: &Path, target: &str) -> Result<()> {
    build.include(picolibc_dir.join("libm/common"));

    let base = LIBM_FILES.iter();
    let files = match target {
        "x86" | "x86_64" => base.chain(LIBM_FILES_X86.iter()),
        arch => bail!("Unsupported target architecture: {arch}"),
    };

    for file in files {
        let source_path = picolibc_dir.join("libm").join(file);
        build.file(&source_path);
    }

    Ok(())
}

fn init_submodule() -> Result<()> {
    let status = Command::new("git")
        .args(["submodule", "update", "--init"])
        .status()?;

    if !status.success() {
        bail!("git submodule update --init failed");
    }

    Ok(())
}

fn cargo_main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=third_party/picolibc");
    println!("cargo:rerun-if-changed=include/picolibc.h");
    println!("cargo:rerun-if-env-changed=HYPERLIGHT_GUEST_TOOLCHAIN_ROOT");

    let out_dir = env::var("OUT_DIR").expect("cargo OUT_DIR not set");
    let target = env::var("CARGO_CFG_TARGET_ARCH").expect("cargo TARGET_ARCH not set");

    let include_dir = PathBuf::from(&out_dir).join("include");
    fs::create_dir_all(&include_dir)
        .with_context(|| format!("Could not create include dir {include_dir:?}"))?;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("cargo MANIFEST_DIR not set");
    let manifest_dir = PathBuf::from(manifest_dir);
    let picolibc_dir = manifest_dir.join("third_party/picolibc");

    if cfg!(feature = "libc") {
        if !picolibc_dir.join("COPYING.picolibc").exists() {
            eprintln!("Setting up submodules");
            init_submodule().with_context(|| "failed to init picolibc submodule")?;
        }

        let mut build = cc_build(&picolibc_dir, &target)?;

        // include for picolibc configuration: picolibc.h
        build.include(manifest_dir.join("include"));

        add_libc(&mut build, &picolibc_dir, &target)?;
        add_libm(&mut build, &picolibc_dir, &target)?;

        if cfg!(windows) {
            unsafe { env::set_var("AR_x86_64_unknown_none", "llvm-ar") };
        }

        build.compile("hyperlight_guest_bin");
        copy_includes(&include_dir, picolibc_dir.join("libc/include"))?;
        copy_includes(&include_dir, manifest_dir.join("include"))?;
    }

    let include_str = include_dir
        .to_str()
        .with_context(|| "out dir include dir was not valid utf-8")?;

    println!("cargo::metadata=include={}", include_str);

    /* Correctly setting up the libc include paths for downstream
     * libraries which depend on -sys packages which need to build C
     * libraries is surprisingly difficult. Ideally, we would
     * eventually build and publish clang toolchains targeting
     * hyperlight directly, but until then we need a way for
     * downstream crates to get at the include files in this crate.
     * Copying them into our output directory, using `links = "c"`
     * (since we're libc), and using cargo metadata keys (as we have
     * just done above) mostly works for crates whose build scripts we
     * control. However, since our downstreams might also need to use
     * -sys packages that have their own detection logic (in
     * cc-rs/bindgen/clang-sys/etc), it would be nice to provide a
     * wrapped version of clang that searches all the correct include
     * paths. (Downstream crates also can't just use
     * BINDGEN_EXTRA_CLANG_ARGS="--sysroot ..." or similar, since the
     * include directory that we generate in this script ends up in
     * target/build under some unpredictable name). Cargo doesn't
     * (yet) give us an easy way to provide binaries that downstream
     * crates can use at build time, so we do an extremely ugly thing
     * here and simply write wrapper binaries into wherever an env var
     * set by downstream tells us to. Because we don't have an easy
     * way to build binaries for the host target when the library is
     * being cross-built, we do an even uglier thing and simply use
     * this build script as a multi-call binary to be those
     * wrappers. We should revisit this approach as relevant cargo
     * features like -Zartifact-dependencies, -Zout-dir,
     * -Zforced-target, etc. are stabilised, or if we decide to
     * publish a proper sysroot when the cbindgen C API is ready.
     *
     * Since we're already doing this for clang, we take advantage of
     * the same approach to provide the ml64.exe binary that cc-rs is
     * hardcoded to look for when assembling targeting msvc targets.
     * On linux, ml64.exe doesn't exist, so we replace it with a
     * wrapper that calls the compatible llvm-ml -m64.
     *
     * In general, to take advantage of this, a downstream binary
     * crate needs to:
     * - Set HYPERLIGHT_GUEST_TOOLCHAIN_ROOT to somewhere sensible
     * - Ensure that other packages look for relevant binaries in that
     *   directory, e.g. by setting CLANG_PATH for clang-sys's include
     *   path autodetection logic (used by bindgen).
     * - Ensure that hyperlight-guest is built before any packages
     *   which might need to use the toolchain, even if they don't
     *   directly depend on it, e.g. by running `cargo build -p
     *   hyperlight-guest` before building anything else.
     */
    if let Ok(binroot) = env::var("HYPERLIGHT_GUEST_TOOLCHAIN_ROOT") {
        let binroot = PathBuf::from(binroot);
        let binpath = env::current_exe().expect("couldn't get build script path");
        fs::create_dir_all(&binroot)
            .unwrap_or_else(|e| panic!("Could not create binary root {:?}: {}", &binroot, e));
        fs::write(binroot.join(".out_dir"), out_dir).expect("Could not write out_dir");
        fs::copy(&binpath, binroot.join("clang")).expect("Could not copy to clang");
        fs::copy(&binpath, binroot.join("clang.exe")).expect("Could not copy to clang.exe");
    }

    Ok(())
}

#[derive(PartialEq)]
enum Tool {
    CargoBuildScript,
    Clang,
}

impl From<&std::ffi::OsStr> for Tool {
    fn from(x: &std::ffi::OsStr) -> Tool {
        if x == "clang" || x == "clang.exe" {
            Tool::Clang
        } else {
            Tool::CargoBuildScript
        }
    }
}

fn find_next(root_dir: &Path, tool_name: &str) -> PathBuf {
    if let Some(path) = env::var_os(format!("HYPERLIGHT_GUEST_{tool_name}")) {
        return path.into();
    }

    let path = env::var_os("PATH").expect("$PATH should exist");
    let paths: Vec<_> = env::split_paths(&path).collect();
    for path in &paths {
        let abs_path = fs::canonicalize(path);
        /* since path entries may not exist (especially on Windows),
         * use the original if there are any errors. */
        let abs_path = abs_path.as_ref().unwrap_or(path);
        if abs_path == root_dir {
            continue;
        }
        let base_path = path.join(tool_name);
        if base_path.exists() {
            return base_path;
        }
        let exe_path = base_path.with_extension("exe");
        if exe_path.exists() {
            return exe_path;
        }
    }
    panic!("Could not find another implementation of {}", tool_name);
}

fn main() -> std::process::ExitCode {
    let exe = env::current_exe().expect("expected program name");
    let name = Path::file_name(exe.as_ref()).expect("program name should not be directory");
    let tool: Tool = name.into();

    if tool == Tool::CargoBuildScript {
        if let Err(err) = cargo_main() {
            eprintln!("{:#}", err);
            return std::process::ExitCode::FAILURE;
        }
        return std::process::ExitCode::SUCCESS;
    }

    let exe_abs = fs::canonicalize(&exe).expect("program name should be possible to canonicalize");
    let root_dir = exe_abs
        .parent()
        .expect("program name should be in a directory");
    let out_dir = std::fs::read_to_string(root_dir.join(".out_dir"))
        .expect(".out_dir should have a valid path in it");
    let mut args = env::args();
    args.next(); // ignore the exe name
    let include_dir = <String as AsRef<Path>>::as_ref(&out_dir).join("include");

    match tool {
        Tool::CargoBuildScript => unreachable!("cargo build script should not be called directly"),
        Tool::Clang => {
            std::process::Command::new(find_next(root_dir, "clang"))
                // terrible hack, see above
                .arg("--target=x86_64-unknown-linux-none")
                .args([
                    // We don't support stack protectors at the moment, but Arch Linux clang
                    // auto-enables them for -linux platforms, so explicitly disable them.
                    "-fno-stack-protector",
                    "-fstack-clash-protection",
                    "-mstack-probe-size=4096",
                    "-mno-red-zone",
                ])
                .arg("-nostdinc")
                .arg("-isystem")
                .arg(include_dir)
                .args(args)
                .status()
                .ok()
                .and_then(|x| x.code())
                .map(|x| (x as u8).into())
                .unwrap_or(std::process::ExitCode::FAILURE)
        }
    }
}
