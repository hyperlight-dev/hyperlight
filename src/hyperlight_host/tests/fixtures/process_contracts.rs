// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use crate::process::{HostFunctionContract, Idempotency};

pub const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
pub const PID: HostFunctionContract<(), u32> =
    HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
