# hyperlight-libc

This crate provides a C standard library implementation for Hyperlight guest binaries based on
[picolibc](https://github.com/picolibc/picolibc). It compiles picolibc from source and generates
Rust bindings to the C library types and functions using [bindgen](https://github.com/rust-lang/rust-bindgen).

## Overview

`hyperlight-libc` is designed to be used together with `hyperlight-guest-bin` to build Hyperlight
guest binaries. When the `libc` feature is enabled on `hyperlight-guest-bin` (enabled by default),
this crate is automatically included as a dependency.

The crate:
- Builds picolibc from source during compilation
- Generates Rust bindings to libc types (e.g., `timespec`, `timeval`, `clockid_t`) and constants
  (e.g., `EINVAL`, `EBADF`, `CLOCK_REALTIME`)
- Exports the include directory via cargo metadata for downstream C compilation needs

## Picolibc Configuration

Picolibc is configured for Hyperlight's micro-VM environment with:

- **Single-threaded**: No locking or TLS support
- **Global errno**: Uses a single global `errno` variable
- **Tiny stdio**: Minimal stdio implementation
- **No malloc**: Memory allocation is handled by the Rust global allocator
- **IEEE math**: Math library without errno side effects

The configuration is defined in `include/picolibc.h`.

## Using the Bindings

When using `hyperlight-guest-bin` with the `libc` feature enabled, the bindings are re-exported as
`hyperlight_guest_bin::libc`:

```rust
use hyperlight_guest_bin::libc::{errno, timespec, EINVAL, CLOCK_REALTIME};
```

## POSIX Stub Requirements

Picolibc expects certain POSIX functions to be available at link time. When using this crate,
downstream code must provide implementations for these functions. The `hyperlight-guest-bin` crate
provides these in `src/libc_stubs.rs`, which can serve as a reference.

Required stubs include:

| Function | Purpose |
|----------|---------|
| `read` | Read from file descriptor (e.g., stdin support) |
| `write` | Write to file descriptor (e.g., stdout/stderr for `printf`) |
| `clock_gettime` | Get current time |
| `_exit` | Terminate the program |
| `lseek` | Seek in file (can return `ENOSYS` for basic stdio support) |
| `close` | Close file descriptor |

### Example Stub Implementation

Here's an example of how to implement the `write` stub that delegates to a host function:

```rust
use alloc::string::String;
use core::ffi::{c_int, c_void};
use hyperlight_guest_bin::host_function;
use hyperlight_guest_bin::libc::{errno, EINVAL, EBADF, EIO};

#[host_function("HostPrint")]
fn host_print(message: String) -> i32;

#[unsafe(no_mangle)]
extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    // Validate input buffer
    if buf.is_null() && count > 0 {
        unsafe { errno = EINVAL as _ };
        return -1;
    }

    // Only support stdout (1) and stderr (2)
    if fd != 1 && fd != 2 {
        unsafe { errno = EBADF as _ };
        return -1;
    }

    // Read the buffer and convert to a String
    let buf = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    let text = String::from_utf8_lossy(buf).into_owned();

    // Delegate to the host function
    host_print(text);

    count as isize
}
```

## Picolibc Source

The picolibc source is vendored as a git submodule at `third_party/picolibc`, pointing to
[picolibc-bsd](https://github.com/hyperlight-dev/picolibc-bsd) - a redistribution of picolibc with
all copyleft-licensed files (GPL/AGPL) removed. Only BSD/MIT/permissive-licensed source files are
present.

See `NOTICE.txt` in the `picolibc-bsd` repository root for full licensing details.

## For More Information

For detailed information about the picolibc integration, including how to update picolibc to a new
version, see [docs/picolibc.md](../../docs/picolibc.md).
