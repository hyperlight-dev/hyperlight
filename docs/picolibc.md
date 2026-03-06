# Picolibc Integration

Hyperlight uses [picolibc](https://github.com/picolibc/picolibc) as its C
standard library for guest binaries, replacing the previous musl-based
approach. Picolibc is a lightweight C library designed for embedded systems,
making it well-suited for Hyperlight's micro-VM environment.

## Overview

The picolibc integration is controlled by the `libc` feature flag on the
`hyperlight-guest-bin` crate (enabled by default). When enabled, the build
script compiles picolibc from source using the vendored submodule at
`src/hyperlight_guest_bin/third_party/picolibc`.

The build uses a sparse checkout to exclude GPL/AGPL-licensed test and script
files — only BSD/MIT/permissive-licensed source files are included. See
`NOTICE.txt` for full licensing details.

## Host Function Stubs

When the `libc` feature is enabled, the POSIX stubs in
`src/hyperlight_guest_bin/src/host_bridge.rs` provide C-compatible
implementations of `read`, `write`, `clock_gettime`, `gettimeofday`, and
other functions that picolibc calls internally.

These stubs can optionally delegate to host functions. If the host registers
these functions, the corresponding libc functionality becomes available to
guest code. If not registered, the stubs return appropriate errors.

| Host Function   | Parameters             | Return Type | Description |
|-----------------|------------------------|-------------|-------------|
| `HostPrint`     | `String`               | `Int`       | Used by the `write()` stub. Only stdout (fd 1) and stderr (fd 2) are supported; both delegate to this single host function. Other file descriptors return `EBADF`. |
| `HostRead`      | `ULong` (byte count)   | `VecBytes`  | Used by the `read()` stub. Only stdin (fd 0) is supported; other file descriptors return `EBADF`. |
| `CurrentTime`   | _(none)_               | `VecBytes`  | Used by `clock_gettime()` and `gettimeofday()`. Should return 16 bytes: 8 bytes of seconds + 8 bytes of nanoseconds. If not provided, a monotonic fallback starting at Unix timestamp `1609459200` (2021-01-01) is used. |

## Build Configuration

The build script (`build.rs`) generates a `picolibc.h` configuration header
that controls which picolibc features are enabled. Key features:

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

1. Update the submodule:
   ```bash
   cd src/hyperlight_guest_bin/third_party/picolibc
   git fetch origin
   git checkout <new-version-tag>
   cd ../../../..
   git add src/hyperlight_guest_bin/third_party/picolibc
   ```

2. Verify licensing: Check that no new GPL/AGPL-licensed source files
   have been added to the directories we compile. The sparse checkout
   (configured in `build.rs` `sparse_checkout()`) excludes `test/`,
   `scripts/`, and `COPYING.GPL2`, but review any new files.

3. Update `build_files.rs`: Compare the file list against the new
   version's meson build files. Files may have been added, removed, or
   renamed. The meson build definitions in `libc/meson.build` and
   `libm/meson.build` (and their subdirectory `meson.build` files)
   are the source of truth for which files to compile.

4. Update version strings in `build.rs`: Update the `__PICOLIBC_VERSION__`,
   `__PICOLIBC__`, `__PICOLIBC_MINOR__`, `__PICOLIBC_PATCHLEVEL__`,
   `_NEWLIB_VERSION`, and related defines in `gen_config_file()`.

5. Update `NOTICE.txt`: Bump the version number in the picolibc entry.

6. Build and test:
   ```bash
   just guests
   just test
   ```
