// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Futures for guest functions, streams that carry one value.
//!
//! [`FutureWriter::write`] never waits, so a guest function can write a value and return its
//! [`FutureReader`]. [`produce`] resolves a future in a guest task, so the value can come from
//! work that waits on streams.

use hyperlight_common::future::producer;
pub use hyperlight_common::future::{
    FutureRead, FutureReader, FutureValue, FutureWriter, MAX_VALUE, new,
};

use crate::task;

/// Create a future that `work` resolves in a guest task, and return its reader.
///
/// `work`'s outcome ends the future.
///
/// * `Ok` writes the value. A value over [`MAX_VALUE`] bytes aborts the future.
/// * `Err` aborts the future. The reader fails with
///   [`StreamError::Aborted`](crate::stream::StreamError::Aborted). The error value is dropped.
///
/// The task runs `work` to completion even after the reader closes, then drops the value.
/// Dropping `work` early would drop the stream writers it holds, which ends their streams as if
/// they were complete. A task that never finishes holds its memory.
///
/// Each turn polls the task when it is ready, after the guest function returns. A guest function
/// cannot wait for it.
pub fn produce<F, T, E>(work: F) -> FutureReader<T>
where
    F: Future<Output = Result<T, E>> + 'static,
    T: FutureValue + 'static,
{
    let (reader, future) = producer(work);
    task::spawn(future);
    reader
}
