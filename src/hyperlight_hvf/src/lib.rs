/*
Copyright 2026 The Hyperlight Authors.

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

//! Shared Hypervisor.framework (HVF) support for macOS on aarch64.
//!
//! - [`core`]: a thin, safe-ish wrapper over the HVF C API (VM/vCPU lifecycle,
//!   register access, vCPU run loop with exit decoding). Used both by the
//!   direct `hyperlight-host` backend and by the surrogate server.
//! - [`proto`]: the IPC protocol between `hyperlight-host` (client) and the
//!   `hvf_surrogate` process (server) that owns a VM when multiple sandboxes
//!   must coexist in one host process (HVF allows only one VM per process).
//!
//! Everything in this crate is only meaningful on `aarch64-apple-darwin`;
//! on all other targets the crate compiles empty.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod core;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod proto;
