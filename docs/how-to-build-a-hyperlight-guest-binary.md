# Building a Hyperlight guest binary

This document explains how to build a binary to be used as a Hyperlight guest.

When building a guest, one needs to follow some rules so that the resulting
binary can be used with Hyperlight:
- the binary must not use the standard library
- the expected entrypoint function signature is `void hyperlight_main(void)` or
  `pub fn hyperlight_main()`
- Hyperlight expects 
  `hl_Vec* c_guest_dispatch_function(const hl_FunctionCall *functioncall)` or
  `pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>>`
  to be defined in the binary so that in case the host calls a function that is
  not registered by the guest, this function is called instead.
- to be callable by the host, a function needs to be registered by the guest in
  the `hyperlight_main` function.

## Rust guest binary

In the case of a binary that is written in Rust, one needs to make use of the
Hyperlight crate, `hyperlight_guest` and `hyperlight_guest_bin` that contains the types and APIs that enable
the guest to:
- register functions that can be called by the host application
- call host functions that have been registered by the host.

### Requirements

- **`#![no_std]`**: Hyperlight guests run in a minimal environment without an operating system
- **`#![no_main]`**: The entry point is `hyperlight_main`, not the standard `main` function
- **`extern crate alloc`**: Required for heap allocations (Vec, String, etc.)
- **`extern crate hyperlight_guest_bin`**: Required to link the guest runtime (panic handler, etc.)

### Troubleshooting

#### "duplicate lang item `panic_impl`" error

This error occurs when the standard library's panic handler conflicts with
`hyperlight_guest_bin`'s panic handler. To fix this:

1. Ensure `hyperlight-common` has `default-features = false` in your `Cargo.toml`
2. Make sure your crate has `#![no_std]` at the top of `main.rs`
3. Run `cargo clean` to clear any stale build artifacts
4. Use `cargo hyperlight build` instead of `cargo build`

#### Build errors with dependencies

If you see errors related to building dependencies (like serde), ensure you're using
`cargo hyperlight build`. This sets up the proper environment variables and sysroot
for the custom Hyperlight target.

## C guest binary

For the binary written in C, the generated C bindings can be downloaded from the
latest release page that contain: the `hyperlight_guest.h` header and the
C API library.
The `hyperlight_guest.h` header contains the corresponding APIs to register
guest functions and call host functions from within the guest.

## Version compatibility

Guest binaries built with `hyperlight-guest-bin` automatically embed the crate
version in an ELF note section (`.note.hyperlight-version`). When the host
loads a guest binary, it checks this version and rejects the binary if it does
not match the host's version of `hyperlight-host`.

Hyperlight currently provides no backwards compatibility guarantees for guest
binaries — the guest and host crate versions must match exactly. If you see a
`GuestBinVersionMismatch` error, rebuild the guest binary with a matching
version of `hyperlight-guest-bin`.
