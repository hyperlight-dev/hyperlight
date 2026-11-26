// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Futures, streams that carry one value.
//!
//! [`new`] creates a future and returns its [`FutureReader`] and [`FutureWriter`]. The writer
//! writes one value and ends the stream. Awaiting the reader reads the value. [`FutureValue`]
//! encodes values to bytes. [`producer`] creates a future and the task that resolves it.

mod endpoint;
mod producer;
mod value;

pub use endpoint::{FutureRead, FutureReader, FutureWriter, new};
pub use producer::producer;
pub use value::FutureValue;

/// The most bytes a value encodes to.
///
/// A reader holds a value's bytes until the stream ends, so this bounds the memory a writer on
/// the peer can make it hold.
pub const MAX_VALUE: usize = 16384;
