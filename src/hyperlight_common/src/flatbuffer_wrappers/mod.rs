// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

mod codec;
pub mod function_call;
pub mod function_types;
pub mod guest_error;
/// cbindgen:ignore
pub mod guest_log_data;
/// cbindgen:ignore
pub mod guest_log_level;
/// cbindgen:ignore
#[cfg(feature = "trace_guest")]
pub mod guest_trace_data;
/// cbindgen:ignore
pub mod host_function_definition;
/// cbindgen:ignore
pub mod host_function_details;
pub mod util;

pub use codec::{ExternalValueRef, ExternalValueRefs, ExternalValueSink, ExternalValueSource};
