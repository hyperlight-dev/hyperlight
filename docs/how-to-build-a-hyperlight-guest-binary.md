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

## C guest binary

For the binary written in C, the generated C bindings can be downloaded from the
latest release page that contain: the `hyperlight_guest.h` header and the
C API library.
The `hyperlight_guest.h` header contains the corresponding APIs to register
guest functions and call host functions from within the guest.
