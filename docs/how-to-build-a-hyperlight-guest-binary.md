# Building a Hyperlight guest binary

This document explains how to build a binary to be used as a Hyperlight guest.

A Hyperlight guest is a regular ELF binary built for a custom target. It runs
without an operating system, exposes functions that the host can call, and may
call functions registered by the host. Builds use `cargo hyperlight build`,
which sets up the target, sysroot, and environment variables.

Install [`cargo-hyperlight`](https://github.com/hyperlight-dev/cargo-hyperlight)
with:

```sh
cargo install --locked cargo-hyperlight
```

To scaffold a working host plus guest project, run:

```sh
cargo hyperlight new my-project
```

Pass `--no-host` to generate only a guest crate, or `--no-guest` to generate
only a host crate.

The rest of this document explains what the generated guest contains and how to
build one by hand.

## Rust guest binary

### Minimal guest

A minimal Rust guest depends only on `hyperlight-guest-bin` and uses its
attribute macros to register guest functions and declare host functions.

`Cargo.toml`:

```toml
[package]
name = "my-guest"
version = "0.1.0"
edition = "2024"

[dependencies]
hyperlight-guest-bin = "*"  # use the latest version from crates.io
```

`src/main.rs`:

```rust
#![no_std]
#![no_main]
extern crate alloc;

use alloc::string::String;

use hyperlight_guest_bin::error::Result;
use hyperlight_guest_bin::{guest_function, host_function};

// Declare a host function the guest can call. The string is the name the
// host registered it under. If omitted, the Rust function name is used.
#[host_function("GetWeekday")]
fn get_weekday() -> Result<String>;

// Register a guest function the host can call.
#[guest_function("SayHello")]
fn say_hello(name: String) -> Result<String> {
    let weekday = get_weekday()?;
    Ok(alloc::format!("Hello, {name}! Today is {weekday}."))
}
```

Build with:

```sh
cargo hyperlight build
```

The resulting binary in `target/x86_64-hyperlight-none/<profile>/my-guest` is
what the host loads with `GuestBinary::FilePath(...)`.

#### What the macros generate

* `#[guest_function]` registers the function with the guest runtime so the host
  can call it by name. Argument and return types must be supported parameter
  and return types, or `Result<T, HyperlightGuestError>` wrapping one.
* `#[host_function]` turns an `extern`-style signature into a stub that
  marshals arguments to the host and returns the host's reply.
* The runtime provides a default `hyperlight_main` entry point and a default
  dispatch function. You do not need to write either one for a typical guest.

#### Required attributes

* `#![no_std]` because there is no operating system in the guest.
* `#![no_main]` because the entry point is `hyperlight_main`, not `main`.
* `extern crate alloc` to use `Vec`, `String`, and other heap types.

### Advanced: manual entry point and dispatch

The macros are optional. A guest can define the underlying symbols directly,
which is useful for advanced setup work or custom dispatch logic (for example
the WIT-based guests in `src/tests/rust_guests/witguest`).

The host expects two guest symbols:

* `pub extern "C" fn hyperlight_main()` runs once at guest startup. Use it to
  register functions or initialize global state.
* `pub extern "Rust" fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>, HyperlightGuestError>`
  is invoked when the host calls a function name that is not registered.

`hyperlight-guest-bin` exposes `#[main]` and `#[dispatch]` macros that generate
these symbols from a regular Rust function, so most "advanced" guests still use
the macros rather than writing the raw `extern "C"` items themselves.

If you mix the manual form with `#[guest_function]`, registrations from the
macro still happen automatically. Your `hyperlight_main` only needs to do
whatever extra setup the macros do not cover.

### Troubleshooting

#### "duplicate lang item `panic_impl`" error

This error means the standard library's panic handler is being linked
alongside `hyperlight_guest_bin`'s. To fix:

1. Ensure your crate has `#![no_std]` at the top of `main.rs`.
2. Confirm any transitive dependency on `hyperlight-common` uses
   `default-features = false`.
3. Run `cargo clean` to clear stale artifacts.
4. Build with `cargo hyperlight build`, not `cargo build`.

#### Build errors with dependencies

If you see errors building dependencies (such as `serde`), make sure you are
using `cargo hyperlight build`. It sets up the environment variables and
sysroot needed for the custom Hyperlight target.

## C guest binary

For the binary written in C, the generated C bindings can be downloaded from the
latest release page that contain: the `hyperlight_guest.h` header and the
C API library.
The `hyperlight_guest.h` header contains the corresponding APIs to register
guest functions and call host functions from within the guest.

See [src/tests/c_guests/c_simpleguest/main.c](../src/tests/c_guests/c_simpleguest/main.c)
for a complete example.

## Version compatibility

Guest binaries built with `hyperlight-guest-bin` automatically embed the crate
version in an ELF note section (`.note.hyperlight-version`). When the host
loads a guest binary, it checks this version and rejects the binary if it does
not match the host's version of `hyperlight-host`.

Hyperlight currently provides no backwards compatibility guarantees for guest
binaries — the guest and host crate versions must match exactly. If you see a
`GuestBinVersionMismatch` error, rebuild the guest binary with a matching
version of `hyperlight-guest-bin`.
