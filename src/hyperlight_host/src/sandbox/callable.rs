// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use crate::Result;
use crate::func::{ParameterTuple, SupportedReturnType};

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
pub trait Callable {
    /// Call a guest function dynamically
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output>;
}
