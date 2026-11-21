// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use crate::{HyperlightError, Result};
use crate::func::{ParameterTuple, SupportedReturnType};

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
pub trait Callable {
    /// Call a guest function dynamically
    fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output>;

    type AsyncHandle: Clone;
    async fn block_on<'a, R, E: From<HyperlightError>, FR: Future<Output = core::result::Result<R, E>> + 'a>(
        &'a mut self,
        fut: impl FnOnce(Self::AsyncHandle) -> FR,
    ) -> core::result::Result<R, E>;
    fn call_async<Output: SupportedReturnType>(
        slf: &Self::AsyncHandle,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> impl Future<Output = Result<Output>>;
}
