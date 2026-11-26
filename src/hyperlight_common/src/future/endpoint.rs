// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Future readers and writers.
//!
//! Each handle wraps one end of a byte stream. Writing the value ends the stream, and the read
//! decodes the value once the stream ends.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use core::{fmt, mem};

use bytes::Bytes;

use super::{FutureValue, MAX_VALUE};
use crate::stream::{self, StreamError, StreamReader, StreamWriter};

/// Create a future and return its reader and writer.
pub fn new<T: FutureValue>() -> (FutureReader<T>, FutureWriter<T>) {
    let (reader, writer) = stream::new();

    let writer = FutureWriter {
        writer,
        _value: PhantomData,
    };

    (FutureReader::from_stream(reader), writer)
}

/// The read end of a future. Awaiting it reads the value, and dropping it closes it.
pub struct FutureReader<T> {
    reader: StreamReader<u8>,
    _value: PhantomData<fn() -> T>,
}

impl<T> FutureReader<T> {
    /// Create a reader of the value that `reader`'s stream carries.
    pub(crate) fn from_stream(reader: StreamReader<u8>) -> Self {
        Self {
            reader,
            _value: PhantomData,
        }
    }

    /// Return the reader of the stream that carries the value.
    pub(crate) fn into_stream(self) -> StreamReader<u8> {
        self.reader
    }
}

impl<T: FutureValue> IntoFuture for FutureReader<T> {
    type Output = Result<T, StreamError>;
    type IntoFuture = FutureRead<T>;

    fn into_future(self) -> Self::IntoFuture {
        FutureRead {
            reader: self.reader,
            chunks: Vec::new(),
            len: 0,
            _value: PhantomData,
        }
    }
}

/// The read of a future's value, which awaiting a [`FutureReader`] runs.
///
/// It reads the stream to its end, then decodes the bytes. It takes each chunk out of the stream
/// as it arrives. A peer sends at most a window of unread bytes, and a value can exceed the
/// window. Taking the chunks lets the peer send the rest.
///
/// * An aborted stream fails with [`StreamError::Aborted`].
/// * More than [`MAX_VALUE`] bytes fail with [`StreamError::ValueTooLarge`] before the end.
/// * Bytes that do not decode fail with [`StreamError::InvalidValue`].
///
/// Dropping it closes the future.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct FutureRead<T> {
    reader: StreamReader<u8>,
    chunks: Vec<Bytes>,
    len: usize,
    _value: PhantomData<fn() -> T>,
}

impl<T: FutureValue> Future for FutureRead<T> {
    type Output = Result<T, StreamError>;

    /// Take chunks until the stream ends, then decode them.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let Some(chunk) = ready!(this.reader.pipe().poll_read_chunk(cx))? else {
                let bytes = join(mem::take(&mut this.chunks));
                return Poll::Ready(T::decode(bytes).ok_or(StreamError::InvalidValue));
            };

            this.len += chunk.len();

            if this.len > MAX_VALUE {
                return Poll::Ready(Err(StreamError::ValueTooLarge));
            }

            this.chunks.push(chunk);
        }
    }
}

/// Join `chunks` into one `Bytes`, copying only when there is more than one.
fn join(chunks: Vec<Bytes>) -> Bytes {
    match <[Bytes; 1]>::try_from(chunks) {
        Ok([chunk]) => chunk,
        Err(chunks) => Bytes::from(chunks.concat()),
    }
}

/// The write end of a future. Dropping it unwritten aborts it.
///
/// The reader of an aborted future fails with [`StreamError::Aborted`].
pub struct FutureWriter<T> {
    writer: StreamWriter<u8>,
    _value: PhantomData<fn(T)>,
}

impl<T: FutureValue> FutureWriter<T> {
    /// Write `value` and end the future.
    ///
    /// The write never waits for room. It appends the value's bytes whatever the stream's
    /// capacity.
    pub fn write(self, value: T) -> Result<(), StreamError> {
        let mut bytes = value.encode();

        if bytes.len() > MAX_VALUE {
            return Err(StreamError::ValueTooLarge);
        }

        self.writer.pipe().write_last(&mut bytes)
    }
}

impl<T> Drop for FutureWriter<T> {
    fn drop(&mut self) {
        // A written value closed the stream, and an abort leaves a closed end as it is.
        self.writer.pipe().abort_writer();
    }
}

impl<T> fmt::Debug for FutureReader<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FutureReader")
            .field("reader", &self.reader)
            .finish()
    }
}

impl<T> fmt::Debug for FutureRead<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FutureRead")
            .field("reader", &self.reader)
            .field("len", &self.len)
            .finish()
    }
}

impl<T> fmt::Debug for FutureWriter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FutureWriter")
            .field("writer", &self.writer)
            .finish()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use core::pin::pin;
    use core::task::Waker;

    use super::*;

    /// Poll `future` once with a waker that does nothing.
    fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn bytes_value_crosses() {
        let (reader, writer) = new::<Bytes>();

        assert_eq!(writer.write(Bytes::from_static(b"ab")), Ok(()));
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Ok(Bytes::from_static(b"ab")))
        );
    }

    #[test]
    fn string_value_crosses() {
        let (reader, writer) = new::<String>();

        assert_eq!(writer.write(String::from("ab")), Ok(()));
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Ok(String::from("ab")))
        );
    }

    #[test]
    fn unit_value_crosses() {
        let (reader, writer) = new::<()>();

        assert_eq!(writer.write(()), Ok(()));
        assert_eq!(poll_once(reader.into_future()), Poll::Ready(Ok(())));
    }

    #[test]
    fn writer_drop_aborts() {
        let (reader, writer) = new::<()>();

        drop(writer);
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Err(StreamError::Aborted))
        );
    }

    #[test]
    fn reader_close_fails_the_write() {
        let (reader, writer) = new::<String>();

        drop(reader);
        assert_eq!(
            writer.write(String::from("ab")),
            Err(StreamError::ReaderClosed)
        );
    }

    #[test]
    fn reader_close_fails_a_unit_write() {
        let (reader, writer) = new::<()>();

        drop(reader);
        assert_eq!(writer.write(()), Err(StreamError::ReaderClosed));
    }

    #[test]
    fn value_at_the_bound_crosses() {
        let (reader, writer) = new::<Vec<u8>>();
        let value = vec![7; MAX_VALUE];

        assert_eq!(writer.write(value.clone()), Ok(()));
        assert_eq!(poll_once(reader.into_future()), Poll::Ready(Ok(value)));
    }

    #[test]
    fn oversized_write_fails_and_aborts() {
        let (reader, writer) = new::<Vec<u8>>();

        assert_eq!(
            writer.write(vec![7; MAX_VALUE + 1]),
            Err(StreamError::ValueTooLarge)
        );
        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Err(StreamError::Aborted))
        );
    }

    #[test]
    fn read_fails_past_the_bound_before_the_end() {
        let (reader, mut writer) = stream::new();
        let mut read = FutureReader::<Bytes>::from_stream(reader).into_future();

        // The stream's window holds the whole bound.
        assert_eq!(
            poll_once(writer.write_all(&[7; MAX_VALUE])),
            Poll::Ready(Ok(()))
        );
        assert_eq!(poll_once(&mut read), Poll::Pending);
        assert_eq!(poll_once(writer.write(b"a")), Poll::Ready(Ok(1)));
        assert_eq!(
            poll_once(&mut read),
            Poll::Ready(Err(StreamError::ValueTooLarge))
        );
    }

    #[test]
    fn invalid_utf8_fails_the_read() {
        let (reader, mut writer) = stream::new();

        assert_eq!(poll_once(writer.write(&[0xff])), Poll::Ready(Ok(1)));
        writer.close();

        let read = FutureReader::<String>::from_stream(reader).into_future();
        assert_eq!(poll_once(read), Poll::Ready(Err(StreamError::InvalidValue)));
    }

    #[test]
    fn trailing_bytes_fail_a_unit_read() {
        let (reader, mut writer) = stream::new();

        assert_eq!(poll_once(writer.write(b"a")), Poll::Ready(Ok(1)));
        writer.close();

        let read = FutureReader::<()>::from_stream(reader).into_future();
        assert_eq!(poll_once(read), Poll::Ready(Err(StreamError::InvalidValue)));
    }

    #[test]
    fn abort_after_bytes_fails_the_read() {
        let (reader, mut writer) = stream::new();

        assert_eq!(poll_once(writer.write(b"ab")), Poll::Ready(Ok(2)));
        writer.abort();

        let read = FutureReader::<Bytes>::from_stream(reader).into_future();
        assert_eq!(poll_once(read), Poll::Ready(Err(StreamError::Aborted)));
    }

    #[test]
    fn stream_chunks_read_as_one_value() {
        let (reader, mut writer) = stream::new();

        assert_eq!(poll_once(writer.write(b"ab")), Poll::Ready(Ok(2)));
        assert_eq!(poll_once(writer.write(b"cd")), Poll::Ready(Ok(2)));
        writer.close();

        let read = FutureReader::<String>::from_stream(reader).into_future();
        assert_eq!(poll_once(read), Poll::Ready(Ok(String::from("abcd"))));
    }
}
