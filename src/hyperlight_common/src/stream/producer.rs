// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Producer tasks, which fill a stream for its reader.

use alloc::sync::Arc;
use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;

use super::{StreamReader, StreamWriter, new};

/// Create a stream that `f` fills, and return its reader and the task that runs `f`.
///
/// The task lends the stream's writer to `f`, and `f`'s outcome ends the stream.
///
/// * `Ok` closes the stream. The reader reads the written bytes, then sees EOF.
/// * `Err` aborts it. The reader reads the written bytes, then fails with
///   [`StreamError::Aborted`](super::StreamError::Aborted). The error value is dropped.
/// * When the reader closes before `f` finishes, the task drops `f`'s future and completes.
///
/// Dropping the task drops the writer, which closes the stream.
pub fn producer<F, E>(f: F) -> (StreamReader<u8>, impl Future<Output = ()> + 'static)
where
    F: AsyncFnOnce(&mut StreamWriter<u8>) -> Result<(), E> + 'static,
    E: 'static,
{
    let (reader, mut writer) = new();
    let pipe = Arc::clone(writer.pipe());

    let work = async move {
        // `f`'s future borrows the writer, so it drops at the end of this block.
        let outcome = {
            let mut work = pin!(f(&mut writer));

            poll_fn(|cx| {
                if pipe.poll_reader_closed(cx).is_ready() {
                    return Poll::Ready(None);
                }

                work.as_mut().poll(cx).map(Some)
            })
            .await
        };

        match outcome {
            Some(Err(_)) => writer.abort(),
            Some(Ok(())) | None => writer.close(),
        }
    };

    (reader, work)
}

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::task::Wake;
    use core::future::pending;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Waker};

    use bytes::Bytes;

    use super::*;
    use crate::stream::StreamError;

    /// Poll `future` once with a waker that does nothing.
    fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    /// A flag set by waking its waker or dropping its [`DropGuard`].
    #[derive(Default)]
    struct Flag(AtomicBool);

    impl Flag {
        fn set(&self) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn is_set(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.set();
        }
    }

    /// Sets its flag when dropped.
    struct DropGuard(Arc<Flag>);

    impl Drop for DropGuard {
        fn drop(&mut self) {
            self.0.set();
        }
    }

    #[test]
    fn ok_closes_and_err_aborts_after_the_bytes() {
        for (result, end) in [(Ok(()), Ok(None)), (Err(()), Err(StreamError::Aborted))] {
            let (mut reader, task) = producer(async move |writer| {
                writer.write_all(b"ab").await.map_err(drop)?;
                result
            });

            assert_eq!(poll_once(task), Poll::Ready(()));
            assert_eq!(
                poll_once(reader.read_chunk()),
                Poll::Ready(Ok(Some(Bytes::from_static(b"ab"))))
            );
            assert_eq!(poll_once(reader.read_chunk()), Poll::Ready(end));
        }
    }

    #[test]
    fn reader_close_wakes_the_task_and_drops_the_work() {
        let woken = Arc::new(Flag::default());
        let dropped = Arc::new(Flag::default());
        let guard = DropGuard(Arc::clone(&dropped));

        let (reader, task) = producer(async move |_| {
            let _guard = guard;
            pending::<Result<(), ()>>().await
        });

        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);
        let mut task = pin!(task);

        assert_eq!(task.as_mut().poll(&mut cx), Poll::Pending);

        reader.close();
        assert!(woken.is_set());
        assert!(!dropped.is_set());

        assert_eq!(task.as_mut().poll(&mut cx), Poll::Ready(()));
        assert!(dropped.is_set());
    }
}
