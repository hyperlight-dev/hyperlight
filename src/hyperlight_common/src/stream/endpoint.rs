// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Stream readers and writers.
//!
//! Each handle owns one end of a [`Pipe`]. The handles uphold the pipe's contract. An end has one
//! owner, `&mut self` methods allow one pending operation, and closing consumes the handle.

use alloc::sync::Arc;
use core::fmt;
use core::future::poll_fn;
use core::marker::PhantomData;

use bytes::Bytes;

use super::pipe::Pipe;
use super::{DEFAULT_WINDOW, StreamError, StreamItem};

// Function call values carry readers between threads.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}

    send_sync::<StreamReader<u8>>();
    send_sync::<StreamWriter<u8>>();
};

/// Create a stream and return its reader and writer.
///
/// The ends share a pipe that holds at most [`DEFAULT_WINDOW`] unread bytes.
pub fn new<T: StreamItem>() -> (StreamReader<T>, StreamWriter<T>) {
    let pipe = Arc::new(Pipe::new(DEFAULT_WINDOW.get() as usize));

    let reader = StreamReader {
        pipe: Arc::clone(&pipe),
        _item: PhantomData,
    };
    let writer = StreamWriter {
        pipe,
        _item: PhantomData,
    };

    (reader, writer)
}

/// The read end of a stream. Dropping it closes it.
pub struct StreamReader<T: StreamItem> {
    pipe: Arc<Pipe>,
    _item: PhantomData<fn() -> T>,
}

impl<T: StreamItem> StreamReader<T> {
    /// Close the reader.
    ///
    /// Unread bytes are dropped. Pending and later writes fail with
    /// [`StreamError::ReaderClosed`].
    pub fn close(self) {
        drop(self);
    }

    /// Create a reader of `pipe`, which has no other reader.
    pub(crate) fn from_pipe(pipe: Arc<Pipe>) -> Self {
        Self {
            pipe,
            _item: PhantomData,
        }
    }

    /// The pipe the reader reads.
    pub(crate) fn pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }
}

impl StreamReader<u8> {
    /// Fill `buf` with the next bytes.
    ///
    /// Fails with [`StreamError::UnexpectedEof`] when the stream ends first, and like
    /// [`read`](Self::read) otherwise. The contents of `buf` are unspecified after a failure.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), StreamError> {
        let mut filled = 0;

        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;

            if n == 0 {
                return Err(StreamError::UnexpectedEof);
            }

            filled += n;
        }

        Ok(())
    }

    /// Read bytes into `buf` and return how many were read.
    ///
    /// Waits while the stream is empty. Returns 0 at EOF or for an empty `buf`. Fails with
    /// [`StreamError::Aborted`] once the bytes written before an abort are read.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, StreamError> {
        poll_fn(|cx| self.pipe.poll_read(cx, buf)).await
    }

    /// Take the next buffered chunk without copying it.
    ///
    /// Waits while the stream is empty. Returns `None` at EOF and fails like
    /// [`read`](Self::read). Chunk boundaries do not delimit messages.
    pub async fn read_chunk(&mut self) -> Result<Option<Bytes>, StreamError> {
        poll_fn(|cx| self.pipe.poll_read_chunk(cx)).await
    }
}

impl<T: StreamItem> Drop for StreamReader<T> {
    fn drop(&mut self) {
        self.pipe.close_reader();
    }
}

/// The write end of a stream. Dropping it closes it.
pub struct StreamWriter<T: StreamItem> {
    pipe: Arc<Pipe>,
    _item: PhantomData<fn() -> T>,
}

impl<T: StreamItem> StreamWriter<T> {
    /// Close the writer.
    ///
    /// The reader reads the buffered bytes, then sees EOF.
    pub fn close(self) {
        drop(self);
    }

    /// Abort the writer to report a failure.
    ///
    /// The reader reads the buffered bytes, then fails with [`StreamError::Aborted`].
    pub fn abort(self) {
        // The drop that follows leaves the aborted end as it is.
        self.pipe.abort_writer();
    }

    /// The pipe the writer writes.
    pub(crate) fn pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }
}

impl StreamWriter<u8> {
    /// Write bytes from `buf` and return how many were written.
    ///
    /// Waits while the stream is full. Returns 0 for an empty `buf`. Fails with
    /// [`StreamError::ReaderClosed`] once the reader is closed.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamError> {
        poll_fn(|cx| self.pipe.poll_write(cx, buf)).await
    }

    /// Write all of `buf`, waiting for room as needed.
    ///
    /// Fails with [`StreamError::ReaderClosed`] when the reader closes first.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamError> {
        let mut written = 0;

        while written < buf.len() {
            written += self.write(&buf[written..]).await?;
        }

        Ok(())
    }

    /// Write all of `chunk` without copying it, waiting for room as needed.
    ///
    /// Fails with [`StreamError::ReaderClosed`] when the reader closes first.
    pub async fn write_chunk(&mut self, mut chunk: Bytes) -> Result<(), StreamError> {
        while !chunk.is_empty() {
            poll_fn(|cx| self.pipe.poll_write_chunk(cx, &mut chunk)).await?;
        }

        Ok(())
    }
}

impl<T: StreamItem> fmt::Debug for StreamReader<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamReader")
            .field("pipe", &Arc::as_ptr(&self.pipe))
            .finish()
    }
}

/// Readers are equal when they read the same stream.
impl<T: StreamItem> PartialEq for StreamReader<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pipe, &other.pipe)
    }
}

impl<T: StreamItem> Drop for StreamWriter<T> {
    fn drop(&mut self) {
        self.pipe.close_writer();
    }
}

impl<T: StreamItem> fmt::Debug for StreamWriter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamWriter")
            .field("pipe", &Arc::as_ptr(&self.pipe))
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::task::Wake;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::thread::{self, Thread};

    use super::*;

    const WINDOW: usize = DEFAULT_WINDOW.get() as usize;

    /// A waker that unparks the thread polling its future.
    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    /// Poll `future` to completion on this thread, parking while it waits.
    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);

        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }

            thread::park();
        }
    }

    #[test]
    fn bytes_cross_threads_past_the_window() {
        // A prime period keeps the pattern unaligned with the window.
        let data: Bytes = (0..4 * WINDOW).map(|i| (i % 251) as u8).collect();
        let (mut reader, mut writer) = new();

        let producer = thread::spawn({
            let data = data.clone();

            move || {
                block_on(async {
                    writer.write_all(&data[..2 * WINDOW]).await?;
                    writer.write_chunk(data.slice(2 * WINDOW..)).await
                })
            }
        });

        let received = block_on(async {
            let mut received = vec![0; WINDOW + 1];
            reader.read_exact(&mut received).await.unwrap();

            let mut buf = [0; 1000];

            loop {
                let n = reader.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..n]);

                let Some(chunk) = reader.read_chunk().await.unwrap() else {
                    break;
                };

                received.extend_from_slice(&chunk);
            }

            received
        });

        assert_eq!(producer.join().unwrap(), Ok(()));
        assert_eq!(received, data);
    }

    #[test]
    fn read_exact_fails_at_early_eof() {
        let (mut reader, mut writer) = new();
        let mut buf = [0; 4];

        block_on(writer.write_all(b"abc")).unwrap();
        writer.close();

        assert_eq!(
            block_on(reader.read_exact(&mut buf)),
            Err(StreamError::UnexpectedEof)
        );
    }

    #[test]
    fn abort_fails_reads_after_buffered_bytes() {
        let (mut reader, mut writer) = new();
        let mut buf = [0; 4];

        block_on(writer.write_all(b"abc")).unwrap();
        writer.abort();

        assert_eq!(block_on(reader.read(&mut buf)), Ok(3));
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(block_on(reader.read(&mut buf)), Err(StreamError::Aborted));
        assert_eq!(block_on(reader.read_chunk()), Err(StreamError::Aborted));
    }

    #[test]
    fn reader_close_fails_writes() {
        let (reader, mut writer) = new();

        // Two windows never fit, so the write fails whether the close comes before or during it.
        let producer = thread::spawn(move || {
            let result = block_on(writer.write_all(&[0; 2 * WINDOW]));
            (writer, result)
        });

        reader.close();

        let (mut writer, result) = producer.join().unwrap();
        assert_eq!(result, Err(StreamError::ReaderClosed));
        assert_eq!(block_on(writer.write(b"a")), Err(StreamError::ReaderClosed));
        assert_eq!(
            block_on(writer.write_chunk(Bytes::from_static(b"a"))),
            Err(StreamError::ReaderClosed)
        );
    }
}
