// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#[cfg(feature = "process-isolation")]
use hyperlight_host::process::{HostFunctionContract, Idempotency};

#[cfg(feature = "process-isolation")]
pub const ECHO: HostFunctionContract<(String,), String> =
    HostFunctionContract::new("HostEchoString", Idempotency::Idempotent);
#[cfg(feature = "process-isolation")]
pub const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);

pub fn echo(message: String) -> String {
    message
}

pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
