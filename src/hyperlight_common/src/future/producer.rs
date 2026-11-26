// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Producer tasks, which resolve a future with the outcome of async work.

use super::{FutureReader, FutureValue, new};

/// Create a future that `work` resolves, and return its reader and the task that runs `work`.
///
/// `work`'s outcome ends the future.
///
/// * `Ok` writes the value. A value over [`MAX_VALUE`](super::MAX_VALUE) bytes aborts the future.
/// * `Err` aborts the future. The reader fails with
///   [`StreamError::Aborted`](crate::stream::StreamError::Aborted). The error value is dropped.
///
/// The task runs `work` to completion even after the reader closes, then drops the value.
/// Dropping `work` early would drop the stream writers it holds, which ends their streams as if
/// they were complete.
///
/// Dropping the task drops `work` and aborts the future.
pub fn producer<F, T, E>(work: F) -> (FutureReader<T>, impl Future<Output = ()> + 'static)
where
    F: Future<Output = Result<T, E>> + 'static,
    T: FutureValue + 'static,
{
    let (reader, writer) = new();

    let task = async move {
        match work.await {
            // The task has nowhere to report a failed write. A closed reader drops the value, and
            // an oversized value aborts the future.
            Ok(value) => {
                let _ = writer.write(value);
            }
            // Dropping the writer unwritten aborts the future.
            Err(_) => drop(writer),
        }
    };

    (reader, task)
}

#[cfg(all(test, not(loom)))]
mod tests {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use bytes::Bytes;

    use super::*;
    use crate::stream::{self, DEFAULT_WINDOW, StreamError};

    /// Poll `future` once with a waker that does nothing.
    fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn ok_writes_the_value() {
        let (reader, task) = producer(async { Ok::<_, ()>(String::from("ab")) });

        assert_eq!(poll_once(task), Poll::Ready(()));
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Ok(String::from("ab")))
        );
    }

    #[test]
    fn err_aborts_the_future() {
        let (reader, task) = producer(async { Err::<String, _>(()) });

        assert_eq!(poll_once(task), Poll::Ready(()));
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Err(StreamError::Aborted))
        );
    }

    #[test]
    fn reader_close_leaves_the_work_running() {
        let window = DEFAULT_WINDOW.get() as usize;
        let data = vec![7; window + 1];
        let (mut output, mut writer) = stream::new();

        let (reader, task) = producer(async move {
            writer.write_chunk(data.into()).await?;
            writer.close();
            Ok::<_, StreamError>(())
        });
        let mut task = pin!(task);

        // The work fills the window and waits for room.
        assert_eq!(poll_once(task.as_mut()), Poll::Pending);
        drop(reader);

        let mut bytes = vec![0; window];
        assert_eq!(
            poll_once(output.read_exact(&mut bytes)),
            Poll::Ready(Ok(()))
        );

        // The work writes the last byte and closes its stream.
        assert_eq!(poll_once(task.as_mut()), Poll::Ready(()));
        assert_eq!(
            poll_once(output.read_chunk()),
            Poll::Ready(Ok(Some(Bytes::from_static(&[7]))))
        );
        assert_eq!(poll_once(output.read_chunk()), Poll::Ready(Ok(None)));
    }
}
