/*
Copyright 2024 The Hyperlight Authors.

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

use std::path::{Path, PathBuf};
use std::{env, fs};

fn copy_includes<P: AsRef<Path>, Q: AsRef<Path> + std::fmt::Debug>(include_dir: P, base: Q) {
    let entries = fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("could not open include dir {:?}: {}", base, e));
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("could not read include dir {:?}: {}", base, e));
        let src = entry.path();
        let dst = include_dir.as_ref().join(entry.file_name());
        let kind = entry
            .file_type()
            .unwrap_or_else(|e| panic!("could not find type of {:?}: {}", src, e));
        if kind.is_dir() {
            fs::create_dir_all(&dst)
                .unwrap_or_else(|e| panic!("could not create include dir {:?}, {}", &dst, e));
            copy_includes(&dst, src);
        } else if Some(std::ffi::OsStr::new("h")) == src.extension() {
            fs::copy(&src, &dst)
                .unwrap_or_else(|e| panic!("could not copy header {:?}, {}", &src, e));
        }
    }
}

fn cargo_main() {
    println!("cargo:rerun-if-changed=third_party");
    println!("cargo:rerun-if-changed=src/alloca");
    println!("cargo:rerun-if-changed=include");

    let mut cfg = cc::Build::new();

    if cfg!(feature = "printf") {
        cfg.include("third_party/printf")
            .file("third_party/printf/printf.c");
    }

    if cfg!(feature = "libc") {
        let entries = glob::glob("third_party/musl/**/*.[cs]") // .c and .s files
            .expect("glob pattern should be valid")
            .filter_map(Result::ok);
        cfg.files(entries);

        cfg.include("third_party/musl/src/include")
            .include("third_party/musl/include")
            .include("third_party/musl/src/internal")
            .include("third_party/musl/arch/generic")
            .include("third_party/musl/arch/x86_64");
    }

    if cfg!(feature = "alloca") {
        cfg.file("src/alloca/alloca.c")
            .define("_alloca", "_alloca_wrapper")
            .flag("-Wno-return-stack-address");
    }

    let is_pe = env::var("CARGO_CFG_WINDOWS").is_ok();

    if cfg!(any(
        feature = "printf",
        feature = "libc",
        feature = "alloca"
    )) {
        cfg.define("HYPERLIGHT", None); // used in certain musl files for conditional compilation

        // silence compiler warnings
        cfg.flag("-Wno-unused-command-line-argument") // including .s files makes clang believe arguments are unused
            .flag("-Wno-sign-compare")
            .flag("-Wno-bitwise-op-parentheses")
            .flag("-Wno-unknown-pragmas")
            .flag("-Wno-shift-op-parentheses")
            .flag("-Wno-logical-op-parentheses")
            .flag("-Wno-unused-but-set-variable")
            .flag("-Wno-unused-parameter")
            .flag("-Wno-string-plus-int");

        if is_pe {
            cfg.flag("-Wno-unused-label");
            cfg.flag("-Wno-unused-variable");
            cfg.compiler("clang-cl");
        } else {
            cfg.flag("-fPIC");
            // This is a terrible hack, because
            // - we need stack clash protection, because we have put the
            //   stack right smack in the middle of everything in the guest
            // - clang refuses to do stack clash protection unless it is
            //   required by a target ABI (Windows, MacOS) or the target is
            //   is Linux or FreeBSD (see Clang.cpp RenderSCPOptions
            //   https://github.com/llvm/llvm-project/blob/1bb52e9/clang/lib/Driver/ToolChains/Clang.cpp#L3724).
            //   Hopefully a flag to force stack clash protection on generic
            //   targets will eventually show up.
            cfg.flag("--target=x86_64-unknown-linux-none");

            // We don't support stack protectors at the moment, but Arch Linux clang
            // auto-enables them for -linux platforms, so explicitly disable them.
            cfg.flag("-fno-stack-protector");
            cfg.flag("-fstack-clash-protection");
            cfg.flag("-mstack-probe-size=4096");
            cfg.compiler("clang");
        }

        if cfg!(windows) {
            env::set_var("AR_x86_64_unknown_none", "llvm-ar");
        } else {
            env::set_var("AR_x86_64_pc_windows_msvc", "llvm-lib");
        }

        cfg.compile("hyperlight_guest");
    }

    let out_dir = env::var("OUT_DIR").expect("cargo OUT_DIR not set");
    let include_dir = PathBuf::from(&out_dir).join("include");
    fs::create_dir_all(&include_dir)
        .unwrap_or_else(|e| panic!("Could not create include dir {:?}: {}", &include_dir, e));
    if cfg!(feature = "printf") {
        copy_includes(&include_dir, "third_party/printf/");
    }
    if cfg!(feature = "libc") {
        copy_includes(&include_dir, "include");
        copy_includes(&include_dir, "third_party/musl/include");
        copy_includes(&include_dir, "third_party/musl/arch/generic");
        copy_includes(&include_dir, "third_party/musl/arch/x86_64");
        copy_includes(&include_dir, "third_party/musl/src/internal");
    }
    /* do not canonicalize: clang has trouble with UNC paths */
    let include_str = include_dir
        .to_str()
        .expect("out dir include dir was not valid utf-8");
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
        fs::copy(&binpath, binroot.join("ml64.exe")).expect("Could not copy to ml64.exe");
        fs::copy(&binpath, binroot.join("clang")).expect("Could not copy to clang");
        fs::copy(&binpath, binroot.join("clang.exe")).expect("Could not copy to clang.exe");
        fs::copy(&binpath, binroot.join("clang-cl")).expect("Could not copy to clang-cl");
        fs::copy(&binpath, binroot.join("clang-cl.exe")).expect("Could not copy to clang-cl.exe");
    }
}

#[derive(PartialEq)]
enum Tool {
    CargoBuildScript,
    Ml64,
    Clang,
    ClangCl,
}
impl From<&std::ffi::OsStr> for Tool {
    fn from(x: &std::ffi::OsStr) -> Tool {
        if x == "ml64.exe" {
            Tool::Ml64
        } else if x == "clang" || x == "clang.exe" {
            Tool::Clang
        } else if x == "clang-cl" || x == "clang-cl.exe" {
            Tool::ClangCl
        } else {
            Tool::CargoBuildScript
        }
    }
}

fn find_next(root_dir: &Path, tool_name: &str) -> PathBuf {
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
        cargo_main();
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
        Tool::Ml64 => std::process::Command::new("llvm-ml")
            .arg("-m64")
            .args(args)
            .status()
            .ok()
            .and_then(|x| (x.code()))
            .map(|x| (x as u8).into())
            .unwrap_or(std::process::ExitCode::FAILURE),
        Tool::Clang => std::process::Command::new(find_next(root_dir, "clang"))
            // terrible hack, see above
            .arg("--target=x86_64-unknown-linux-none")
            .args([
                // We don't support stack protectors at the moment, but Arch Linux clang
                // auto-enables them for -linux platforms, so explicitly disable them.
                "-fno-stack-protector",
                "-fstack-clash-protection",
                "-mstack-probe-size=4096",
            ])
            .arg("-nostdinc")
            .arg("-isystem")
            .arg(include_dir)
            .args(args)
            .status()
            .ok()
            .and_then(|x| (x.code()))
            .map(|x| (x as u8).into())
            .unwrap_or(std::process::ExitCode::FAILURE),
        Tool::ClangCl => std::process::Command::new(find_next(root_dir, "clang-cl"))
            .arg("-nostdinc")
            .arg("/external:I")
            .arg(include_dir)
            .args(args)
            .status()
            .ok()
            .and_then(|x| (x.code()))
            .map(|x| (x as u8).into())
            .unwrap_or(std::process::ExitCode::FAILURE),
        _ => std::process::ExitCode::FAILURE,
    }
}
