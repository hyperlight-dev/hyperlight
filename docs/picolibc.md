# Picolibc Integration

Hyperlight uses [picolibc](https://github.com/picolibc/picolibc) as its C standard library for guest
binaries, replacing the previous musl-based approach. Picolibc is a lightweight C library designed
for embedded systems, making it well-suited for Hyperlight's micro-VM environment.

## Overview

The picolibc integration is controlled by the `libc` feature flag on the `hyperlight-guest-bin`
crate (enabled by default). When enabled, the build script compiles picolibc from source using the
vendored submodule at `src/hyperlight_guest_bin/third_party/picolibc`.

The submodule points to [picolibc-bsd](https://github.com/hyperlight-dev/picolibc-bsd), a
redistribution of picolibc with all copyleft-licensed files (GPL/AGPL) removed from the tree and
history. Only BSD/MIT/permissive-licensed source files are present. See `NOTICE.txt` for full
licensing details.

## Host Function Stubs

When the `libc` feature is enabled, the POSIX stubs in `src/hyperlight_guest_bin/src/libc.rs`
provide C-compatible implementations of `read`, `write`, `clock_gettime`, `gettimeofday`, and other
functions that picolibc calls internally.

### Read (stdin)

The `read()` stub returns **EOF (0)** immediately for stdin (fd 0) without contacting the host.
Other file descriptors return `EBADF`.

### Write (stdout / stderr)

The `write()` stub delegates to the `HostPrint` host function. Only stdout (fd 1) and stderr (fd 2)
are supported; both map to the same `HostPrint` call, which accepts a `String` parameter and returns
an `Int`. Other file descriptors return `EBADF`.

### Time

The `clock_gettime()`, `gettimeofday()`, stubs do **not** call out to the host. Instead they return
a synthetic monotonically-increasing timestamp: the first call returns Unix epoch + 1 s
(`1970-01-01 00:00:01`), the second returns epoch + 2 s, and so on. The nanosecond/microsecond
component is always zero.

## Build Configuration

The build script (`build.rs`) generates a `picolibc.h` configuration header that controls which
picolibc features are enabled. Key features:

- Single-threaded: no locking or TLS support
- Global errno: uses a single global `errno` variable
- Tiny stdio: minimal stdio implementation
- No malloc: memory allocation is handled by the Rust global allocator
- IEEE math: math library without errno side effects

For full details on available picolibc build options, see the
[picolibc build documentation](https://github.com/picolibc/picolibc/blob/main/doc/build.md).

The file list of picolibc sources to compile is maintained in `build_files.rs`.

## Updating Picolibc

To update picolibc to a new version:

1. Import new upstream commits into the
   [picolibc-bsd](https://github.com/hyperlight-dev/picolibc-bsd) fork. See `picolibc-bsd` README.md
   for instructions how to do that.

2. Update the submodule in hyperlight:

    ```bash
    cd src/hyperlight_guest_bin/third_party/picolibc
    git fetch origin
    git checkout <new-fork-tag>
    cd ../../../..
    git add src/hyperlight_guest_bin/third_party/picolibc
    ```

3. Verify licensing: The fork's CI runs scancode-toolkit to ensure no copyleft files are present.
   Review the CI results on the fork.

4. Update `build_files.rs`: Compare the file list against the new version's meson build files. Files
   may have been added, removed, or renamed. The meson build definitions in `libc/meson.build` and
   `libm/meson.build` (and their subdirectory `meson.build` files) are the source of truth for which
   files to compile.

5. Update version strings in `build.rs`: Update the `__PICOLIBC_VERSION__`, `__PICOLIBC__`,
   `__PICOLIBC_MINOR__`, `__PICOLIBC_PATCHLEVEL__`, `_NEWLIB_VERSION`, and related defines in
   `gen_config_file()`.

6. Update `NOTICE.txt`: Bump the version number in the picolibc entry.

7. Build and test:
    ```bash
    just guests
    just test
    ```
