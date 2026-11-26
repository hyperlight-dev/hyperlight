// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Byte pipes, the state behind each stream.
//!
//! A stream's writer and reader share one pipe. It holds the bytes written and not read. Its
//! capacity bounds them, so a fast writer waits for a slow reader.
//!
//! # Moving the reader
//!
//! A stream starts with both ends on one side, joined by its pipe. The reader can move to the
//! other side as a call argument or result. Bytes it left unread stay in the pipe. The `Mux` reads
//! the pipe in the reader's place and sends its bytes across. The other side writes them into a
//! second pipe that the moved reader reads.
//!
//! An end the `Mux` holds is remote. Progress at the other end rings the session's [`Doorbell`],
//! so the `Mux` learns of bytes to send, bytes read, and closes.
//!
//! # Locking
//!
//! Wakers and byte owners can reenter a pipe. Wake and drop them outside its lock.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use core::ops::Range;
use core::task::{Context, Poll, Waker, ready};

use bytes::Bytes;
use smallvec::SmallVec;

use super::StreamError;
use super::sync::{Doorbell, Mutex};

// Stream handles share a pipe across threads.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}

    send_sync::<Pipe>();
};

/// A bounded byte buffer between one reader and one writer.
///
/// Each end has one owner: a handle with at most one pending operation, or a `Mux`. So the pipe
/// keeps one waker or doorbell per end. An owner stops using its end after closing it. The design
/// follows loosely tokio's `simplex`.
pub(crate) struct Pipe {
    state: Mutex<State>,
}

impl Pipe {
    /// Create an empty pipe that holds at most `capacity` bytes.
    ///
    /// A zero capacity becomes one, so writes can always make progress.
    pub(crate) fn new(capacity: usize) -> Self {
        Self::with_writer(capacity, Owner::Local(None))
    }

    /// Create an empty pipe with a local reader end and a writer end that belongs to `writer`.
    fn with_writer(capacity: usize, writer: Owner) -> Self {
        Self {
            state: Mutex::new(State {
                buffer: VecDeque::new(),
                len: 0,
                capacity: capacity.max(1),
                reader: Endpoint::open(Owner::Local(None)),
                writer: Endpoint::open(writer),
                close: None,
            }),
        }
    }

    /// Copy buffered bytes into `buf` and return how many were copied.
    ///
    /// - An empty `buf` returns 0.
    /// - With bytes buffered, copy as many as fit, wake the writer, and return the count.
    /// - With nothing buffered and the writer closed, return 0 for EOF, or
    ///   [`StreamError::Aborted`] when it aborted.
    /// - Otherwise register the reader's waker and return `Pending`.
    pub(crate) fn poll_read(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, StreamError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunks = self.poll_read_with(cx, SmallVec::new(), |state| state.take_prefix(buf.len()));
        let mut copied = 0;

        for chunk in ready!(chunks)? {
            let end = copied + chunk.len();
            buf[copied..end].copy_from_slice(&chunk);
            copied = end;
        }

        Poll::Ready(Ok(copied))
    }

    /// Take the oldest buffered chunk without copying it.
    ///
    /// - With bytes buffered, remove the first chunk, wake the writer, and return it.
    /// - With nothing buffered and the writer closed, return `None` for EOF, or
    ///   [`StreamError::Aborted`] when it aborted.
    /// - Otherwise register the reader's waker and return `Pending`.
    pub(crate) fn poll_read_chunk(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.poll_read_with(cx, None, |state| {
            let chunk = state.buffer.pop_front()?;
            state.len -= chunk.len();
            Some(chunk)
        })
    }

    /// Copy bytes from `buf` into the pipe and return how many were copied.
    ///
    /// - A closed reader returns [`StreamError::ReaderClosed`].
    /// - An empty `buf` returns 0.
    /// - A full pipe registers the writer's waker and returns `Pending`.
    /// - Otherwise copy as many bytes as fit, wake the reader, and return the count.
    pub(crate) fn poll_write(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, StreamError>> {
        // TODO: Coalesce small writes into a `BytesMut` tail. Each write allocates its own chunk.
        self.poll_write_with(cx, buf.len(), |n| Bytes::copy_from_slice(&buf[..n]))
    }

    /// Move bytes from the front of `chunk` into the pipe without copying them.
    ///
    /// Follows the steps of [`poll_write`](Self::poll_write). Bytes that do not fit stay in
    /// `chunk`.
    pub(crate) fn poll_write_chunk(
        &self,
        cx: &mut Context<'_>,
        chunk: &mut Bytes,
    ) -> Poll<Result<usize, StreamError>> {
        self.poll_write_with(cx, chunk.len(), |n| chunk.split_to(n))
    }

    /// Close the reader end.
    ///
    /// - Mark the reader closed and defer dropping its waker.
    /// - Drop the buffered bytes, since nothing can read them.
    /// - Wake the writer, so a pending write returns [`StreamError::ReaderClosed`].
    /// - Wake the task waiting in [`poll_reader_closed`](Self::poll_reader_closed).
    pub(crate) fn close_reader(&self) {
        self.with(|state, deferred| {
            deferred.stale = state.reader.close();
            deferred.close = state.close.take();
            state.len = 0;
            deferred.wake = state.writer.notify();
            mem::take(&mut state.buffer)
        });
    }

    /// Wait for the reader end to close.
    ///
    /// The waker has its own slot, so it does not replace the waker of a pending write.
    pub(crate) fn poll_reader_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.with(|state, deferred| {
            if state.reader.is_closed() {
                return Poll::Ready(());
            }

            match &mut state.close {
                Some(waker) if waker.will_wake(cx.waker()) => {}
                slot => deferred.stale = slot.replace(cx.waker().clone()),
            }

            Poll::Pending
        })
    }

    /// Close the writer end.
    ///
    /// - Mark the writer closed and defer dropping its waker.
    /// - Wake the reader, so a pending read sees EOF once the buffered bytes are read.
    pub(crate) fn close_writer(&self) {
        self.with(|state, deferred| {
            deferred.stale = state.writer.close();
            deferred.wake = state.reader.notify();
        });
    }

    /// Abort the writer end.
    ///
    /// Follows the steps of [`close_writer`](Self::close_writer). Reads fail with
    /// [`StreamError::Aborted`] once the buffered bytes are read.
    pub(crate) fn abort_writer(&self) {
        self.with(|state, deferred| {
            deferred.stale = state.writer.abort();
            deferred.wake = state.reader.notify();
        });
    }

    /// Append `chunk` whatever the capacity, then close the writer end.
    pub(crate) fn write_last(&self, chunk: &mut Bytes) -> Result<(), StreamError> {
        self.with(|state, deferred| {
            if state.reader.is_closed() {
                return Err(StreamError::ReaderClosed);
            }

            let chunk = mem::take(chunk);

            if !chunk.is_empty() {
                state.len += chunk.len();
                state.buffer.push_back(chunk);
            }

            deferred.stale = state.writer.close();
            deferred.wake = state.reader.notify();
            Ok(())
        })
    }

    /// Run the read steps, taking buffered bytes with `take` and returning `eof` at EOF.
    fn poll_read_with<T>(
        &self,
        cx: &mut Context<'_>,
        eof: T,
        take: impl FnOnce(&mut State) -> T,
    ) -> Poll<Result<T, StreamError>> {
        self.with(|state, deferred| {
            if state.len > 0 {
                let out = take(state);
                deferred.wake = state.writer.notify();
                return Poll::Ready(Ok(out));
            }

            match state.writer.state {
                EndState::Open => {
                    deferred.stale = state.reader.register(cx.waker());
                    Poll::Pending
                }
                EndState::Closed => Poll::Ready(Ok(eof)),
                EndState::Aborted => Poll::Ready(Err(StreamError::Aborted)),
            }
        })
    }

    /// Run the write steps for `len` bytes, taking the first `n` that fit with `take(n)`.
    fn poll_write_with(
        &self,
        cx: &mut Context<'_>,
        len: usize,
        take: impl FnOnce(usize) -> Bytes,
    ) -> Poll<Result<usize, StreamError>> {
        self.with(|state, deferred| {
            if state.reader.is_closed() {
                return Poll::Ready(Err(StreamError::ReaderClosed));
            }

            if len == 0 {
                return Poll::Ready(Ok(0));
            }

            let avail = state.capacity.saturating_sub(state.len);
            if avail == 0 {
                deferred.stale = state.writer.register(cx.waker());
                return Poll::Pending;
            }

            let n = len.min(avail);
            state.buffer.push_back(take(n));
            state.len += n;

            deferred.wake = state.reader.notify();
            Poll::Ready(Ok(n))
        })
    }

    /// Run `f` under the lock, then run the work it deferred.
    fn with<R>(&self, f: impl FnOnce(&mut State, &mut Deferred) -> R) -> R {
        let mut deferred = Deferred::default();

        let out = {
            let mut state = self.state.lock();
            f(&mut state, &mut deferred)
        };

        deferred.run();
        out
    }
}

/// The `Mux` side of a pipe.
///
/// The `Mux` reads a send stream's pipe in place of its reader, which is on the peer. It fills a
/// receive stream's pipe in place of its writer.
impl Pipe {
    /// Create an empty pipe for a reader whose writer is on the peer.
    ///
    /// The `Mux` that owns `doorbell` fills it, so its reader can move only back to the stream's
    /// origin.
    pub(crate) fn remote(capacity: usize, doorbell: Arc<Doorbell>) -> Self {
        Self::with_writer(capacity, Owner::Remote(doorbell))
    }

    /// Whether a `Mux` fills the pipe for a writer on the peer.
    pub(crate) fn is_remote(&self) -> bool {
        matches!(self.state.lock().writer.owner, Owner::Remote(_))
    }

    /// Give the reader end to the `Mux` that owns `doorbell`, for a reader moving to the peer.
    pub(crate) fn set_remote_reader(&self, doorbell: Arc<Doorbell>) {
        self.set_reader(Owner::Remote(doorbell));
    }

    /// Give the reader end back to a handle, for a reader returning from the peer.
    pub(crate) fn set_local_reader(&self) {
        self.set_reader(Owner::Local(None));
    }

    /// Give the reader end to `owner`, dropping the old owner after the lock is released.
    fn set_reader(&self, owner: Owner) {
        let old = self.with(|state, _| mem::replace(&mut state.reader.owner, owner));
        drop(old);
    }

    /// Set the most bytes the pipe holds. A larger capacity wakes the writer.
    ///
    /// Buffered bytes stay when they exceed a smaller capacity. A zero capacity becomes one.
    pub(crate) fn set_capacity(&self, capacity: usize) {
        self.with(|state, deferred| {
            let cap = capacity.max(1);
            if cap > state.capacity {
                deferred.wake = state.writer.notify();
            }

            state.capacity = cap;
        });
    }

    /// Read the buffered byte count and the state of both ends at one instant.
    pub(crate) fn state(&self) -> PipeState {
        let state = self.state.lock();

        PipeState {
            len: state.len,
            reader: state.reader.state,
            writer: state.writer.state,
        }
    }

    /// Clone the buffered bytes in `range` into `out` without removing them.
    ///
    /// The clones share storage with the buffered chunks.
    pub(crate) fn peek(&self, range: Range<usize>, out: &mut impl Extend<Bytes>) {
        let state = self.state.lock();
        let mut skip = range.start;
        let mut left = range.len();

        for chunk in &state.buffer {
            if left == 0 {
                break;
            }

            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }

            let n = left.min(chunk.len() - skip);
            out.extend(Some(chunk.slice(skip..skip + n)));

            skip = 0;
            left -= n;
        }
    }

    /// Remove the first `n` buffered bytes and wake the writer.
    pub(crate) fn consume(&self, n: usize) {
        self.with(|state, deferred| {
            let chunks = state.take_prefix(n);
            deferred.wake = state.writer.notify();
            chunks
        });
    }

    /// Append received chunks and wake the reader.
    ///
    /// The `Mux` bounds them by the window, so the capacity does not apply. A closed reader drops
    /// them.
    pub(crate) fn push(&self, chunks: Vec<Bytes>) {
        let mut chunks = chunks;
        chunks.retain(|chunk| !chunk.is_empty());

        self.with(|state, deferred| {
            if state.reader.is_closed() {
                return;
            }

            for chunk in chunks.drain(..) {
                state.len += chunk.len();
                state.buffer.push_back(chunk);
            }

            deferred.wake = state.reader.notify();
        });
    }
}

/// A pipe's buffered byte count and end states at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PipeState {
    /// Bytes written and not yet read.
    pub(crate) len: usize,
    /// The reader end.
    pub(crate) reader: EndState,
    /// The writer end.
    pub(crate) writer: EndState,
}

/// The state of a pipe end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndState {
    /// The end is open.
    Open,
    /// The owner closed the end or dropped it.
    Closed,
    /// The owner aborted the end.
    Aborted,
}

/// The pipe state behind its lock.
struct State {
    /// Chunks written and not yet read, oldest first. No chunk is empty.
    buffer: VecDeque<Bytes>,
    /// Bytes in `buffer`, kept to avoid summing its chunks.
    len: usize,
    /// The most bytes `buffer` holds.
    capacity: usize,
    /// The reader end, woken by writes and by the writer closing.
    reader: Endpoint,
    /// The writer end, woken by reads and by the reader closing.
    writer: Endpoint,
    /// The waker of a task waiting for the reader to close.
    close: Option<Waker>,
}

impl State {
    /// Remove up to `max` bytes so the caller can use or drop them after unlocking.
    fn take_prefix(&mut self, max: usize) -> SmallVec<[Bytes; 1]> {
        let mut chunks = SmallVec::new();
        let mut left = max.min(self.len);
        self.len -= left;

        while left > 0
            && let Some(chunk) = self.buffer.front_mut()
        {
            if left < chunk.len() {
                chunks.push(chunk.split_to(left));
                break;
            }

            left -= chunk.len();
            chunks.extend(self.buffer.pop_front());
        }

        chunks
    }
}

/// The pipe's view of one end.
struct Endpoint {
    /// Whether the owner closed or aborted the end.
    state: EndState,
    /// The owner, told of progress at the other end.
    owner: Owner,
}

/// The owner of a pipe end.
enum Owner {
    /// A handle on this side, with the waker of its pending operation if any.
    Local(Option<Waker>),
    /// A `Mux` acting for a handle on the peer.
    Remote(Arc<Doorbell>),
}

impl Endpoint {
    /// Create an open end that belongs to `owner`.
    fn open(owner: Owner) -> Self {
        Self {
            state: EndState::Open,
            owner,
        }
    }

    /// Store `waker` for a pending operation and return the waker it replaces.
    ///
    /// The stored waker stays when it already wakes the same task. Only an open local end stores
    /// one.
    fn register(&mut self, waker: &Waker) -> Option<Waker> {
        match (self.state, &mut self.owner) {
            (EndState::Open, Owner::Local(Some(old))) if old.will_wake(waker) => None,
            (EndState::Open, Owner::Local(slot)) => slot.replace(waker.clone()),
            _ => None,
        }
    }

    /// Tell the owner of progress at the other end, and return the waker to wake for it.
    ///
    /// A local end gives its pending operation's waker. A remote end rings the session doorbell
    /// even when closed. A receive stream's writer end closes at END, and reads and closes after
    /// it still leave CREDIT or CLOSE_READER to send.
    fn notify(&mut self) -> Option<Waker> {
        match &mut self.owner {
            Owner::Local(waker) => waker.take(),
            Owner::Remote(doorbell) => doorbell.ring(),
        }
    }

    /// Mark an open end closed and return its waker.
    ///
    /// A closed or aborted end stays as it is, so the close that follows an abort keeps it.
    fn close(&mut self) -> Option<Waker> {
        self.finish(EndState::Closed)
    }

    /// Mark an open end aborted and return its waker.
    fn abort(&mut self) -> Option<Waker> {
        self.finish(EndState::Aborted)
    }

    /// Move an open end to `state` and take a local end's waker.
    ///
    /// The owner stays, so a remote end still hears of progress at the other end.
    fn finish(&mut self, state: EndState) -> Option<Waker> {
        if self.is_closed() {
            return None;
        }

        self.state = state;

        match &mut self.owner {
            Owner::Local(waker) => waker.take(),
            Owner::Remote(_) => None,
        }
    }

    /// Whether the end is closed or aborted.
    fn is_closed(&self) -> bool {
        self.state != EndState::Open
    }
}

/// Wakes and waker drops held until the pipe lock is released.
#[derive(Default)]
struct Deferred {
    /// The other end's waker, woken by progress or close.
    wake: Option<Waker>,
    /// The close watch's waker, woken when the reader closes.
    close: Option<Waker>,
    /// A waker replaced by a new registration or taken from a closing end.
    stale: Option<Waker>,
}

impl Deferred {
    /// Wake the other end and the close watch, then drop the stale waker.
    fn run(self) {
        if let Some(waker) = self.wake {
            waker.wake();
        }

        if let Some(waker) = self.close {
            waker.wake();
        }

        drop(self.stale);
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn noop() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    /// A waker that counts its wakes.
    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Counter {
        fn waker() -> (Arc<Self>, Waker) {
            let counter = Arc::new(Self::default());
            let waker = Waker::from(Arc::clone(&counter));

            (counter, waker)
        }

        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A waker that checks another thread can lock the pipe when it wakes or drops.
    struct Probe {
        pipe: Arc<Pipe>,
        checks: Arc<AtomicUsize>,
    }

    impl Probe {
        fn waker(pipe: &Arc<Pipe>, checks: &Arc<AtomicUsize>) -> Waker {
            Waker::from(Arc::new(Self {
                pipe: Arc::clone(pipe),
                checks: Arc::clone(checks),
            }))
        }

        /// Fail instead of deadlocking when the pipe stays locked.
        fn check(&self) {
            let pipe = Arc::clone(&self.pipe);
            let (send, recv) = mpsc::channel();

            let locker = thread::spawn(move || {
                drop(pipe.state.lock());
                let _ = send.send(());
            });

            recv.recv_timeout(Duration::from_secs(5))
                .expect("waker ran under the pipe lock");

            locker.join().unwrap();
            self.checks.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.check();
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.check();
        }
    }

    impl AsRef<[u8]> for Probe {
        fn as_ref(&self) -> &[u8] {
            b"x"
        }
    }

    #[test]
    fn consumed_and_discarded_byte_owners_drop_after_unlock() {
        let pipe = Arc::new(Pipe::new(3));
        let checks = Arc::new(AtomicUsize::new(0));
        let chunk = || {
            Bytes::from_owner(Probe {
                pipe: pipe.clone(),
                checks: checks.clone(),
            })
        };
        pipe.push(vec![chunk(), chunk(), chunk()]);

        assert_eq!(pipe.poll_read(&mut noop(), &mut [0]), Poll::Ready(Ok(1)));
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        pipe.consume(1);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        pipe.close_reader();
        assert_eq!(checks.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn read_copies_across_chunks() {
        let pipe = Pipe::new(8);
        let mut buf = [0; 4];

        assert_eq!(pipe.poll_write(&mut noop(), b"abc"), Poll::Ready(Ok(3)));
        assert_eq!(pipe.poll_write(&mut noop(), b"def"), Poll::Ready(Ok(3)));
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(4)));
        assert_eq!(&buf, b"abcd");
        assert_eq!(
            pipe.poll_read_chunk(&mut noop()),
            Poll::Ready(Ok(Some(Bytes::from_static(b"ef"))))
        );
    }

    #[test]
    fn full_pipe_waits_for_read() {
        let pipe = Pipe::new(4);
        let (writer, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0; 3];

        assert_eq!(pipe.poll_write(&mut cx, b"abcdef"), Poll::Ready(Ok(4)));
        assert_eq!(pipe.poll_write(&mut cx, b"ef"), Poll::Pending);
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(3)));
        assert_eq!(writer.count(), 1);
        assert_eq!(pipe.poll_write(&mut cx, b"ef"), Poll::Ready(Ok(2)));
    }

    #[test]
    fn write_wakes_latest_reader() {
        let pipe = Pipe::new(4);
        let (old, old_waker) = Counter::waker();
        let (new, new_waker) = Counter::waker();

        assert_eq!(
            pipe.poll_read_chunk(&mut Context::from_waker(&old_waker)),
            Poll::Pending
        );
        assert_eq!(
            pipe.poll_read_chunk(&mut Context::from_waker(&new_waker)),
            Poll::Pending
        );
        assert_eq!(pipe.poll_write(&mut noop(), b"a"), Poll::Ready(Ok(1)));
        assert_eq!((old.count(), new.count()), (0, 1));
    }

    #[test]
    fn writer_close_ends_after_buffered_bytes() {
        let pipe = Pipe::new(4);
        let mut buf = [0; 4];

        assert_eq!(pipe.poll_write(&mut noop(), b"ab"), Poll::Ready(Ok(2)));
        pipe.close_writer();
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(2)));
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(0)));
        assert_eq!(pipe.poll_read_chunk(&mut noop()), Poll::Ready(Ok(None)));
    }

    #[test]
    fn writer_close_wakes_reader() {
        let pipe = Pipe::new(4);
        let (reader, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(pipe.poll_read_chunk(&mut cx), Poll::Pending);
        pipe.close_writer();
        assert_eq!(reader.count(), 1);
        assert_eq!(pipe.poll_read_chunk(&mut cx), Poll::Ready(Ok(None)));
    }

    #[test]
    fn write_last_skips_capacity_and_closes_the_writer() {
        let pipe = Pipe::new(1);
        let (reader, waker) = Counter::waker();
        let mut chunk = Bytes::from_static(b"abc");

        assert_eq!(
            pipe.poll_read_chunk(&mut Context::from_waker(&waker)),
            Poll::Pending
        );

        assert_eq!(pipe.write_last(&mut chunk), Ok(()));
        assert_eq!(reader.count(), 1);
        assert!(chunk.is_empty());
        assert_eq!(
            pipe.state(),
            PipeState {
                len: 3,
                reader: EndState::Open,
                writer: EndState::Closed,
            }
        );
        assert_eq!(
            pipe.poll_read_chunk(&mut noop()),
            Poll::Ready(Ok(Some(Bytes::from_static(b"abc"))))
        );
        assert_eq!(pipe.poll_read_chunk(&mut noop()), Poll::Ready(Ok(None)));
    }

    #[test]
    fn write_last_to_a_closed_reader_keeps_the_chunk() {
        let pipe = Pipe::new(4);
        let mut chunk = Bytes::from_static(b"abc");

        pipe.close_reader();

        assert_eq!(pipe.write_last(&mut chunk), Err(StreamError::ReaderClosed));
        assert_eq!(chunk, b"abc"[..]);
        assert_eq!(
            pipe.state(),
            PipeState {
                len: 0,
                reader: EndState::Closed,
                writer: EndState::Open,
            }
        );
    }

    #[test]
    fn reader_close_fails_writes_and_drops_bytes() {
        let pipe = Pipe::new(2);
        let (writer, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);
        let chunk = Bytes::from(vec![1, 2]);

        assert_eq!(
            pipe.poll_write_chunk(&mut cx, &mut chunk.clone()),
            Poll::Ready(Ok(2))
        );
        assert_eq!(pipe.poll_write(&mut cx, b"c"), Poll::Pending);
        assert!(!chunk.is_unique());

        pipe.close_reader();
        assert_eq!(writer.count(), 1);
        assert!(chunk.is_unique());
        assert_eq!(
            pipe.poll_write(&mut cx, b"c"),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    }

    #[test]
    fn reader_close_wakes_a_pending_write_and_the_close_watch() {
        let pipe = Pipe::new(1);
        let (writer, writer_waker) = Counter::waker();
        let (watch, watch_waker) = Counter::waker();
        let mut writer_cx = Context::from_waker(&writer_waker);
        let mut watch_cx = Context::from_waker(&watch_waker);

        assert_eq!(pipe.poll_write(&mut writer_cx, b"ab"), Poll::Ready(Ok(1)));
        assert_eq!(pipe.poll_write(&mut writer_cx, b"b"), Poll::Pending);
        assert_eq!(pipe.poll_reader_closed(&mut watch_cx), Poll::Pending);

        pipe.close_reader();
        assert_eq!((writer.count(), watch.count()), (1, 1));
        assert_eq!(pipe.poll_reader_closed(&mut watch_cx), Poll::Ready(()));
    }

    #[test]
    fn write_chunk_moves_storage() {
        let pipe = Pipe::new(3);
        let mut chunk = Bytes::from_static(b"abcde");
        let start = chunk.as_ptr();

        assert_eq!(
            pipe.poll_write_chunk(&mut noop(), &mut chunk),
            Poll::Ready(Ok(3))
        );
        assert_eq!(chunk, b"de"[..]);

        let Poll::Ready(Ok(Some(moved))) = pipe.poll_read_chunk(&mut noop()) else {
            panic!("expected a chunk");
        };
        assert_eq!(moved, b"abc"[..]);
        assert_eq!(moved.as_ptr(), start);
    }

    #[test]
    fn empty_requests_do_not_wait() {
        let pipe = Pipe::new(0);

        assert_eq!(pipe.poll_read(&mut noop(), &mut []), Poll::Ready(Ok(0)));
        assert_eq!(pipe.poll_write(&mut noop(), b"ab"), Poll::Ready(Ok(1)));
        assert_eq!(pipe.poll_write(&mut noop(), b""), Poll::Ready(Ok(0)));
        assert_eq!(
            pipe.poll_write_chunk(&mut noop(), &mut Bytes::new()),
            Poll::Ready(Ok(0))
        );
    }

    #[test]
    fn wakers_run_after_unlock() {
        let pipe = Arc::new(Pipe::new(1));
        let checks = Arc::new(AtomicUsize::new(0));
        let mut buf = [0; 1];

        // The pipe holds the only clone of each probe, so the waker it replaces drops.
        for _ in 0..2 {
            let reader = Probe::waker(&pipe, &checks);
            let mut cx = Context::from_waker(&reader);
            assert_eq!(pipe.poll_read(&mut cx, &mut buf), Poll::Pending);
        }

        assert_eq!(checks.load(Ordering::SeqCst), 1);

        // The write wakes the second reader, which then drops.
        assert_eq!(pipe.poll_write(&mut noop(), b"a"), Poll::Ready(Ok(1)));
        assert_eq!(checks.load(Ordering::SeqCst), 3);

        // Closing the writer drops its own waker.
        let writer = Probe::waker(&pipe, &checks);
        let mut cx = Context::from_waker(&writer);
        assert_eq!(pipe.poll_write(&mut cx, b"b"), Poll::Pending);
        drop(writer);
        pipe.close_writer();
        assert_eq!(checks.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn peek_shares_bytes_without_removing_them() {
        let pipe = Pipe::new(8);
        let abc = Bytes::from_static(b"abc");
        let mut chunks = Vec::new();
        let mut buf = [0; 8];

        assert_eq!(
            pipe.poll_write_chunk(&mut noop(), &mut abc.clone()),
            Poll::Ready(Ok(3))
        );
        assert_eq!(pipe.poll_write(&mut noop(), b"def"), Poll::Ready(Ok(3)));

        pipe.peek(1..5, &mut chunks);
        assert_eq!(chunks, [&b"bc"[..], &b"de"[..]]);
        assert_eq!(chunks[0].as_ptr(), abc[1..].as_ptr());
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(6)));
    }

    #[test]
    fn consume_drops_front_bytes_and_wakes_writer() {
        let pipe = Pipe::new(4);
        let (writer, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0; 4];

        assert_eq!(pipe.poll_write(&mut cx, b"ab"), Poll::Ready(Ok(2)));
        assert_eq!(pipe.poll_write(&mut cx, b"cdef"), Poll::Ready(Ok(2)));
        assert_eq!(pipe.poll_write(&mut cx, b"ef"), Poll::Pending);

        pipe.consume(3);
        assert_eq!(writer.count(), 1);
        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(1)));
        assert_eq!(buf[0], b'd');
    }

    #[test]
    fn capacity_change_keeps_buffered_bytes() {
        let pipe = Pipe::new(4);
        let (writer, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);

        assert_eq!(pipe.poll_write(&mut cx, b"abcd"), Poll::Ready(Ok(4)));
        pipe.set_capacity(2);
        assert_eq!(pipe.poll_write(&mut cx, b"e"), Poll::Pending);
        assert_eq!(pipe.state().len, 4);

        pipe.set_capacity(2);
        assert_eq!(writer.count(), 0);

        pipe.set_capacity(6);
        assert_eq!(writer.count(), 1);
        assert_eq!(pipe.poll_write(&mut cx, b"efgh"), Poll::Ready(Ok(2)));
    }

    #[test]
    fn push_skips_capacity_and_closed_readers() {
        let pipe = Pipe::remote(1, Arc::new(Doorbell::new()));
        let (reader, waker) = Counter::waker();
        let chunk = Bytes::from(vec![1, 2]);
        let c = Bytes::from_static(b"c");

        assert_eq!(
            pipe.poll_read_chunk(&mut Context::from_waker(&waker)),
            Poll::Pending
        );

        pipe.push(vec![chunk.clone(), Bytes::new(), c.clone()]);
        assert_eq!(reader.count(), 1);
        assert_eq!(
            pipe.poll_read_chunk(&mut noop()),
            Poll::Ready(Ok(Some(chunk.clone())))
        );
        assert_eq!(pipe.poll_read_chunk(&mut noop()), Poll::Ready(Ok(Some(c))));

        pipe.close_reader();
        pipe.push(vec![chunk.clone()]);
        assert!(chunk.is_unique());
    }

    #[test]
    fn writes_notify_a_remote_reader() {
        let pipe = Pipe::new(4);
        let doorbell = Arc::new(Doorbell::new());
        let (driver, waker) = Counter::waker();
        let mut cx = Context::from_waker(&waker);

        pipe.set_remote_reader(Arc::clone(&doorbell));
        assert_eq!(pipe.poll_write(&mut noop(), b"a"), Poll::Ready(Ok(1)));
        assert_eq!(doorbell.poll(&mut cx), Poll::Ready(()));
        assert_eq!(doorbell.poll(&mut cx), Poll::Pending);

        pipe.close_writer();
        assert_eq!(driver.count(), 1);
        assert_eq!(doorbell.poll(&mut cx), Poll::Ready(()));
    }

    #[test]
    fn reads_notify_a_remote_writer_after_end() {
        let doorbell = Arc::new(Doorbell::new());
        let pipe = Pipe::remote(4, Arc::clone(&doorbell));
        let mut buf = [0; 1];

        pipe.push(vec![Bytes::from_static(b"ab")]);
        pipe.close_writer();
        assert_eq!(doorbell.poll(&mut noop()), Poll::Pending);

        assert_eq!(pipe.poll_read(&mut noop(), &mut buf), Poll::Ready(Ok(1)));
        assert_eq!(doorbell.poll(&mut noop()), Poll::Ready(()));

        pipe.close_reader();
        assert_eq!(doorbell.poll(&mut noop()), Poll::Ready(()));
    }
}
