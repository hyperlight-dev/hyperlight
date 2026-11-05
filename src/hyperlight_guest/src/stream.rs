// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Byte streams for guest functions.
//!
//! A guest function returns a [`StreamReader`] and leaves its production to a task. [`produce`]
//! creates both.

use hyperlight_common::stream::producer;
pub use hyperlight_common::stream::{StreamError, StreamReader, StreamWriter, new};

use crate::task;

/// Create a stream that `f` fills in a guest task, and return its reader.
///
/// The task lends the stream's writer to `f`, and `f`'s outcome ends the stream.
///
/// * `Ok` closes it. The reader reads the written bytes, then sees EOF.
/// * `Err` aborts it. The reader reads the written bytes, then fails with
///   [`StreamError::Aborted`]. The error value is dropped.
/// * Closing the reader drops `f`'s future.
///
/// Each turn polls the task when it is ready, after the guest function returns. A guest function
/// cannot wait for it.
pub fn produce<F, E>(f: F) -> StreamReader<u8>
where
    F: AsyncFnOnce(&mut StreamWriter<u8>) -> Result<(), E> + 'static,
    E: 'static,
{
    let (reader, future) = producer(f);
    task::spawn(future);
    reader
}
