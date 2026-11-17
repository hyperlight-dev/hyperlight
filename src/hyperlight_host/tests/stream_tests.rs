// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Byte streams and futures that cross the sandbox boundary.

#![cfg(feature = "streams")]

use std::cell::Cell;
use std::future::{pending, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use std::{assert_matches, thread};

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::func::Bytes;
use hyperlight_common::stream::{DEFAULT_WINDOW, MAX_STREAMS};
use hyperlight_host::future::{self, FutureReader};
use hyperlight_host::stream::{self, StreamError, StreamReader, StreamWriter};
use hyperlight_host::{HyperlightError, SandboxBuilder};

pub mod common; // pub to disable dead_code warning
use crate::common::{with_c_sandbox, with_rust_sandbox, with_rust_sandbox_from};

#[test]
fn call_only_guest_rejects_a_reader_signature() {
    with_c_sandbox(|mut sandbox| {
        assert_eq!(sandbox.call::<f64>("EchoDouble", 0.5f64).unwrap(), 0.5);

        let result = sandbox.call::<StreamReader<u8>>("EchoDouble", 0.5f64);
        assert_matches!(result, Err(HyperlightError::GuestAborted(_, message))
            if message.contains("streams are disabled"));
    });
}

/// Poll `future` once with a no-op waker.
fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

/// Append the chunks that `reader` holds to `bytes`, and return whether the stream ended.
fn read_received(reader: &mut StreamReader<u8>, bytes: &mut Vec<u8>) -> bool {
    loop {
        match poll_once(reader.read_chunk()) {
            Poll::Ready(Ok(Some(chunk))) => bytes.extend_from_slice(&chunk),
            Poll::Ready(Ok(None)) => return true,
            Poll::Ready(Err(error)) => panic!("stream failed: {error}"),
            Poll::Pending => return false,
        }
    }
}

/// Write what fits of `data` without waiting, and return how many bytes were written.
fn write_ready(writer: &mut StreamWriter<u8>, data: &[u8]) -> usize {
    let mut written = 0;

    while written < data.len() {
        match poll_once(writer.write(&data[written..])) {
            Poll::Ready(Ok(len)) => written += len,
            Poll::Ready(Err(error)) => panic!("stream failed: {error}"),
            Poll::Pending => break,
        }
    }

    written
}

/// The error of a drive's work, which a sandbox or a stream failure can cause.
#[derive(Debug)]
enum DriveError {
    Sandbox(HyperlightError),
    Stream(StreamError),
}

impl From<HyperlightError> for DriveError {
    fn from(error: HyperlightError) -> Self {
        Self::Sandbox(error)
    }
}

impl From<StreamError> for DriveError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

/// Both directions cross several windows with only two queue entries available.
#[test]
fn block_on_drives_duplex_streams_past_the_window() {
    let window = DEFAULT_WINDOW.get() as usize;
    let data: Vec<u8> = (0..4 * window + 17).map(|i| (i % 251) as u8).collect();
    let configure = |builder: SandboxBuilder| {
        builder
            .h2g_queue_size(2)
            .g2h_queue_size(2)
            .h2g_buffer_size(4096)
            .g2h_buffer_size(4096)
    };

    with_rust_sandbox_from(configure, |mut sandbox| {
        let (input, mut writer) = stream::new();
        let mut reader: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();

        let send = async {
            writer.write_all(&data).await?;
            writer.close();
            Ok::<_, DriveError>(())
        };
        let receive = async {
            let mut received = Vec::new();

            while let Some(chunk) = reader.read_chunk().await? {
                received.extend_from_slice(&chunk);
            }

            Ok::<_, DriveError>(received)
        };

        let ((), received) = sandbox
            .block_on(async { tokio::try_join!(send, receive) })
            .unwrap();

        assert_eq!(received, data);
    });
}

/// A producer's failure follows all of its bytes and leaves the sandbox usable.
#[test]
fn block_on_reports_a_guest_stream_abort() {
    let window = DEFAULT_WINDOW.get() as usize;
    let data: Vec<u8> = (0..window + 1).map(|i| (i % 251) as u8).collect();

    with_rust_sandbox(|mut sandbox| {
        let mut reader: StreamReader<u8> =
            sandbox.call("StreamBytes", (data.clone(), true)).unwrap();
        let mut received = Vec::new();

        let result = sandbox.block_on(async {
            while let Some(chunk) = reader.read_chunk().await? {
                received.extend_from_slice(&chunk);
            }

            Ok::<_, DriveError>(())
        });

        assert_matches!(result, Err(DriveError::Stream(StreamError::Aborted)));
        assert_eq!(received, data);
        assert!(sandbox.status().is_ready());
    });
}

/// A failed guest turn poisons the sandbox before more host work can run.
#[test]
fn block_on_propagates_a_guest_task_panic() {
    with_rust_sandbox(|mut sandbox| {
        let mut reader: StreamReader<u8> = sandbox.call("StreamPanic", ()).unwrap();
        let mut bytes = vec![0; DEFAULT_WINDOW.get() as usize + 1];

        let result =
            sandbox.block_on(async { Ok::<_, DriveError>(reader.read_exact(&mut bytes).await?) });

        assert_matches!(
            result,
            Err(DriveError::Sandbox(HyperlightError::GuestAborted(_, message)))
                if message.contains("stream task panic")
        );
        assert!(sandbox.status().is_poisoned());

        let polled = Cell::new(false);

        let result = sandbox.block_on(async {
            polled.set(true);
            Ok::<_, HyperlightError>(())
        });

        assert_matches!(result, Err(HyperlightError::PoisonedSandbox));
        assert!(!polled.get());
    });
}

#[test]
fn poisoning_wakes_stream_readers_and_writers() {
    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    with_rust_sandbox(|mut sandbox| {
        let (input, mut writer) = stream::new();
        let mut reader: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();
        let window = DEFAULT_WINDOW.get() as usize;
        assert_eq!(write_ready(&mut writer, &vec![0; window]), window);

        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let mut read = pin!(reader.read_chunk());
        let mut write = pin!(writer.write(b"x"));
        assert!(read.as_mut().poll(&mut cx).is_pending());
        assert!(write.as_mut().poll(&mut cx).is_pending());

        let result = sandbox.call::<()>("guest_panic", String::from("end this session"));
        assert_matches!(result, Err(HyperlightError::GuestAborted(..)));
        assert!(sandbox.status().is_poisoned());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 2);
        assert_matches!(read.poll(&mut cx), Poll::Ready(Err(StreamError::Aborted)));
        assert_matches!(
            write.poll(&mut cx),
            Poll::Ready(Err(StreamError::ReaderClosed))
        );
    });
}

/// A host writer wakes the driver through the Mux while the guest task waits for input.
#[test]
fn block_on_wakes_for_a_stream_written_on_another_thread() {
    with_rust_sandbox(|mut sandbox| {
        let (input, mut writer) = stream::new();
        let mut reader: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();
        let (wake_tx, wake_rx) = mpsc::channel::<Waker>();
        let (done_tx, done_rx) = mpsc::channel();

        let producer = thread::spawn(move || {
            let fallback = wake_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            thread::sleep(Duration::from_millis(10));

            assert_matches!(poll_once(writer.write_all(b"wake")), Poll::Ready(Ok(())));
            writer.close();

            if done_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                fallback.wake();
                panic!("stream doorbell did not wake the driver");
            }
        });

        let received = sandbox
            .block_on(async {
                poll_fn(|cx| {
                    wake_tx.send(cx.waker().clone()).unwrap();
                    Poll::Ready(())
                })
                .await;

                let mut received = Vec::new();

                while let Some(chunk) = reader.read_chunk().await? {
                    received.extend_from_slice(&chunk);
                }

                Ok::<_, DriveError>(received)
            })
            .unwrap();

        done_tx.send(()).unwrap();
        producer.join().unwrap();
        assert_eq!(received, b"wake");
    });
}

/// A completed host future leaves pending guest work for a later drive.
#[test]
fn block_on_returns_when_its_future_completes() {
    let configure = |builder: SandboxBuilder| builder.g2h_queue_size(2);

    with_rust_sandbox_from(configure, |mut sandbox| {
        let mut reader: StreamReader<u8> = sandbox
            .call("StreamBytes", (b"later".to_vec(), false))
            .unwrap();

        assert_matches!(poll_once(reader.read_chunk()), Poll::Pending);
        assert_matches!(
            sandbox.block_on(async { Ok::<_, HyperlightError>(7) }),
            Ok(7)
        );
        assert_matches!(poll_once(reader.read_chunk()), Poll::Pending);

        let mut read_chunk =
            || sandbox.block_on(async { Ok::<_, DriveError>(reader.read_chunk().await?) });

        assert_matches!(read_chunk(), Ok(Some(chunk)) if chunk == b"later".as_slice());
        assert_matches!(read_chunk(), Ok(None));
    });
}

/// A self-wake survives a future consuming the park token, without entering an idle guest.
#[test]
fn block_on_preserves_wakes_when_the_park_token_is_consumed() {
    with_rust_sandbox(|mut sandbox| {
        let snapshot = sandbox.snapshot().unwrap();
        let polls = Rc::new(Cell::new(0));
        let work = poll_fn(|cx| {
            polls.set(polls.get() + 1);

            if polls.get() == 1 {
                cx.waker().wake_by_ref();
                thread::park_timeout(Duration::ZERO);
                Poll::Pending
            } else {
                Poll::Ready(Ok::<_, HyperlightError>(42))
            }
        });

        assert_eq!(sandbox.block_on(work).unwrap(), 42);
        assert_eq!(polls.get(), 2);
        assert!(Arc::ptr_eq(&snapshot, &sandbox.snapshot().unwrap()));
    });
}

#[test]
fn one_byte_of_credit_unblocks_a_duplex_stream() {
    let window = DEFAULT_WINDOW.get() as usize;
    let full = vec![0; window];

    with_rust_sandbox(|mut sandbox| {
        let (input, mut writer) = stream::new();
        assert_eq!(write_ready(&mut writer, &full), window);
        let mut output: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();

        // The echo is blocked writing one byte. The next window fills its input.
        assert_eq!(write_ready(&mut writer, b"x"), 1);
        sandbox.call::<()>("NoOp", ()).unwrap();
        assert_eq!(write_ready(&mut writer, &full), window);
        sandbox.call::<()>("NoOp", ()).unwrap();
        assert!(poll_once(writer.write(b"y")).is_pending());
        assert_eq!(poll_once(output.read(&mut [0])), Poll::Ready(Ok(1)));

        // Yield once so a missed wake fails the assertion rather than hanging the test.
        let write = sandbox
            .block_on(async {
                tokio::task::yield_now().await;
                Ok::<_, HyperlightError>(poll_once(writer.write(b"y")))
            })
            .unwrap();

        assert_eq!(write, Poll::Ready(Ok(1)));
    });
}

/// A kill on another thread wakes a parked driver, and ends the drive without poisoning.
#[test]
fn block_on_wakes_for_a_kill_on_another_thread() {
    with_rust_sandbox(|mut sandbox| {
        let handle = sandbox.interrupt_handle();
        let (wake_tx, wake_rx) = mpsc::channel::<Waker>();
        let (done_tx, done_rx) = mpsc::channel();

        let killer = thread::spawn(move || {
            let fallback = wake_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            thread::sleep(Duration::from_millis(10));

            // The guest is not running, so the kill interrupts no vCPU.
            assert!(!handle.kill());

            if done_rx.recv_timeout(Duration::from_secs(2)).is_err() {
                fallback.wake();
                panic!("kill did not wake the driver");
            }
        });

        let result = sandbox.block_on(async {
            poll_fn(|cx| {
                wake_tx.send(cx.waker().clone()).unwrap();
                Poll::Ready(())
            })
            .await;

            pending::<Result<(), HyperlightError>>().await
        });

        done_tx.send(()).unwrap();
        killer.join().unwrap();
        assert_matches!(result, Err(HyperlightError::ExecutionCanceledByHost()));
        assert!(sandbox.status().is_ready());

        // The call ignores the earlier kill.
        assert_eq!(sandbox.call::<i32>("EchoI32", 7).unwrap(), 7);
    });
}

/// A kill between progress turns ends the drive, and a later drive resumes its streams.
#[test]
fn block_on_kill_between_turns_keeps_streams_usable() {
    with_rust_sandbox(|mut sandbox| {
        let handle = sandbox.interrupt_handle();
        let (input, mut writer) = stream::new();
        let mut reader: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();

        let result = sandbox.block_on(async {
            let mut echoed = [0; 3];

            writer.write_all(b"one").await?;
            reader.read_exact(&mut echoed).await?;
            assert_eq!(&echoed, b"one");

            assert!(!handle.kill());
            writer.write_all(b"two").await?;
            Ok::<_, DriveError>(reader.read_chunk().await?)
        });

        assert_matches!(
            result.unwrap_err(),
            DriveError::Sandbox(HyperlightError::ExecutionCanceledByHost())
        );
        assert!(sandbox.status().is_ready());

        // A fresh drive ignores the earlier kill.
        writer.close();

        let received = sandbox
            .block_on(async {
                let mut received = Vec::new();

                while let Some(chunk) = reader.read_chunk().await? {
                    received.extend_from_slice(&chunk);
                }

                Ok::<_, DriveError>(received)
            })
            .unwrap();

        assert_eq!(received, b"two");
    });
}

/// Entries 1 and 2 of the `hello` example. Capture fails until entry 2.
#[test]
fn guest_function_returns_a_written_stream() {
    with_rust_sandbox(|mut sandbox| {
        let greeting = b"Hello, world!".to_vec();
        let mut reader: StreamReader<u8> = sandbox
            .call("StreamBytes", (greeting.clone(), false))
            .unwrap();

        assert_matches!(
            poll_once(reader.read_chunk()),
            Poll::Ready(Ok(Some(chunk))) if chunk == greeting
        );
        assert_matches!(poll_once(reader.read_chunk()), Poll::Ready(Ok(None)));
        reader.close();

        // The host's CLOSE_READER has not reached the guest.
        let Err(error) = sandbox.snapshot() else {
            panic!("expected a live stream to block the snapshot");
        };

        assert_matches!(&error, HyperlightError::StreamsActive);
        assert!(!sandbox.status().is_poisoned());

        // The next call carries CLOSE_READER, which releases the stream on both sides.
        sandbox.call::<i32>("EchoI32", 0).unwrap();
        sandbox.snapshot().unwrap();
    });
}

/// The call that moves a host stream's reader also carries its bytes.
#[test]
fn guest_function_reads_a_host_stream_in_the_same_call() {
    with_rust_sandbox(|mut sandbox| {
        let greeting = b"Hello, guest!";
        let (input, mut writer) = stream::new::<u8>();

        assert_matches!(poll_once(writer.write_all(greeting)), Poll::Ready(Ok(())));
        writer.close();

        let mut output: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();
        let mut received = Vec::new();

        assert!(read_received(&mut output, &mut received));
        assert_eq!(received, greeting);
    });
}

/// An echo moves one window per call. CREDIT in each direction reopens the windows.
#[test]
fn echo_moves_one_window_per_call() {
    let window = DEFAULT_WINDOW.get() as usize;
    let data: Vec<u8> = (0..4 * window).map(|i| (i % 251) as u8).collect();

    with_rust_sandbox(|mut sandbox| {
        let (input, mut writer) = stream::new();
        let mut written = write_ready(&mut writer, &data);
        assert_eq!(written, window);

        let mut output: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();
        let mut received = Vec::new();

        loop {
            assert!(!read_received(&mut output, &mut received));
            assert_eq!(received.len(), written);

            let len = write_ready(&mut writer, &data[written..]);
            assert_eq!(len, window);
            written += len;

            if written == data.len() {
                break;
            }

            sandbox.call::<i32>("EchoI32", 0).unwrap();
        }

        // The last window and END share a call.
        writer.close();
        sandbox.call::<i32>("EchoI32", 0).unwrap();

        assert!(read_received(&mut output, &mut received));
        assert_eq!(received, data);
    });
}

/// A guest producer moves one window per call. The host's CREDIT wakes it.
#[test]
fn guest_producer_moves_one_window_per_call() {
    let window = DEFAULT_WINDOW.get() as usize;
    let pattern: Vec<u8> = (0..4 * window).map(|i| (i % 251) as u8).collect();

    with_rust_sandbox(|mut sandbox| {
        let mut reader: StreamReader<u8> =
            sandbox.call("StreamPattern", pattern.len() as u32).unwrap();
        let mut received = Vec::new();

        for windows in 1..4 {
            assert!(!read_received(&mut reader, &mut received));
            assert_eq!(received.len(), windows * window);

            sandbox.call::<i32>("EchoI32", 0).unwrap();
        }

        assert!(read_received(&mut reader, &mut received));
        assert_eq!(received, pattern);
    });
}

#[test]
fn guest_abort_fails_the_host_reader_after_its_bytes() {
    with_rust_sandbox(|mut sandbox| {
        let bytes = b"partial".to_vec();
        let mut reader: StreamReader<u8> =
            sandbox.call("StreamBytes", (bytes.clone(), true)).unwrap();

        assert_matches!(
            poll_once(reader.read_chunk()),
            Poll::Ready(Ok(Some(chunk))) if chunk == bytes
        );
        assert_matches!(
            poll_once(reader.read_chunk()),
            Poll::Ready(Err(StreamError::Aborted))
        );
    });
}

/// The turn that applies CLOSE_READER drops the guest producer after the guest function.
#[test]
fn host_reader_close_drops_the_guest_producer() {
    with_rust_sandbox(|mut sandbox| {
        let mut reader: StreamReader<u8> = sandbox.call("StreamThenWait", b"abc".to_vec()).unwrap();
        let mut received = Vec::new();

        assert!(!read_received(&mut reader, &mut received));
        assert_eq!(received, b"abc");
        assert_eq!(sandbox.call::<u32>("LiveProducers", ()).unwrap(), 1);

        reader.close();
        assert_eq!(sandbox.call::<u32>("LiveProducers", ()).unwrap(), 1);
        assert_eq!(sandbox.call::<u32>("LiveProducers", ()).unwrap(), 0);

        sandbox.snapshot().unwrap();
    });
}

/// A host function reader from another sandbox fails the guest's call. Dropping the result closes
/// the reader, and both sandboxes stay usable.
#[test]
fn host_function_reader_from_another_sandbox_fails_the_call() {
    with_rust_sandbox(|mut origin| {
        let reader: StreamReader<u8> = origin.call("StreamThenWait", b"abc".to_vec()).unwrap();
        let mut reader = Some(reader);
        let configure = |builder: SandboxBuilder| {
            builder.host_function("HostStream", move || reader.take().unwrap())
        };

        with_rust_sandbox_from(configure, |mut sandbox| {
            let result = sandbox.call::<StreamReader<u8>>("ForwardHostStream", ());

            assert_matches!(
                result,
                Err(HyperlightError::GuestError(ErrorCode::HostFunctionError, message))
                    if message == "stream reader belongs to another session"
            );
            assert!(sandbox.status().is_ready());
        });

        assert_eq!(origin.call::<u32>("LiveProducers", ()).unwrap(), 1);
        assert_eq!(origin.call::<u32>("LiveProducers", ()).unwrap(), 0);
    });
}

/// Dropping the failed result closes its reader, which drops the producer in the next call.
#[test]
fn reader_result_past_the_stream_limit_fails_the_call() {
    with_rust_sandbox(|mut sandbox| {
        let _readers: Vec<StreamReader<u8>> = (0..MAX_STREAMS)
            .map(|_| sandbox.call("StreamThenWait", Vec::<u8>::new()).unwrap())
            .collect();

        let result = sandbox.call::<StreamReader<u8>>("StreamThenWait", Vec::<u8>::new());

        assert_matches!(
            result,
            Err(HyperlightError::GuestError(ErrorCode::GuestError, message))
                if message == "too many streams to the peer"
        );
        assert!(sandbox.status().is_ready());

        let live = MAX_STREAMS as u32;
        assert_eq!(sandbox.call::<u32>("LiveProducers", ()).unwrap(), live + 1);
        assert_eq!(sandbox.call::<u32>("LiveProducers", ()).unwrap(), live);
    });
}

/// A full G2H queue leaves stream records pending for a later call.
#[test]
fn full_g2h_queue_defers_stream_messages() {
    const G2H_BUFFER_SIZE: usize = 4096;

    // Each message holds under 4 KiB of DATA, so 12 KiB takes four.
    let data: Vec<u8> = (0..12 * 1024).map(|i| (i % 251) as u8).collect();

    // The queue holds a Response, two Stream messages, and the STATUS room.
    let configure =
        |builder: SandboxBuilder| builder.g2h_queue_size(4).g2h_buffer_size(G2H_BUFFER_SIZE);

    with_rust_sandbox_from(configure, |mut sandbox| {
        let mut reader: StreamReader<u8> =
            sandbox.call("StreamBytes", (data.clone(), false)).unwrap();
        let mut received = Vec::new();

        assert!(!read_received(&mut reader, &mut received));
        assert!((G2H_BUFFER_SIZE..2 * G2H_BUFFER_SIZE).contains(&received.len()));

        // The rest and END take the two Stream messages of the next call.
        sandbox.call::<i32>("EchoI32", 0).unwrap();

        assert!(read_received(&mut reader, &mut received));
        assert_eq!(received, data);
    });
}

/// A retained host reply holds the only upper G2H slot, so stream messages take lower slots.
#[test]
fn retained_host_replies_leave_lower_slots_for_streams() {
    let data: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();

    // 16 lower slots of 256 bytes and one 4 KiB upper slot.
    let configure = |builder: SandboxBuilder| {
        builder
            .g2h_pool_pages(2)
            .g2h_buffer_size(4096)
            .guest_log_level(tracing_core::LevelFilter::OFF)
            .host_function("HostEchoByteChunks", |_: Vec<Bytes>| {
                vec![Bytes::from_static(b"retained")]
            })
    };

    with_rust_sandbox_from(configure, |mut sandbox| {
        let retained: i32 = sandbox
            .call("RetainHostByteChunks", Vec::<Bytes>::new())
            .unwrap();
        assert_eq!(retained, 8);

        let mut reader: StreamReader<u8> =
            sandbox.call("StreamBytes", (data.clone(), false)).unwrap();
        let mut received = Vec::new();

        assert!(read_received(&mut reader, &mut received));
        assert_eq!(received, data);
    });
}

/// A full H2G queue leaves stream records pending, and each later call sends one more message.
#[test]
fn full_h2g_queue_defers_stream_messages() {
    const H2G_BUFFER_SIZE: usize = 4096;

    // Each message holds under 4 KiB of DATA, so 12 KiB takes four.
    let data: Vec<u8> = (0..12 * 1024).map(|i| (i % 251) as u8).collect();

    // The queue holds a Request and one Stream message.
    let configure =
        |builder: SandboxBuilder| builder.h2g_queue_size(2).h2g_buffer_size(H2G_BUFFER_SIZE);

    with_rust_sandbox_from(configure, |mut sandbox| {
        let (input, mut writer) = stream::new::<u8>();

        assert_matches!(poll_once(writer.write_all(&data)), Poll::Ready(Ok(())));
        writer.close();

        let mut output: StreamReader<u8> = sandbox.call("EchoStream", input).unwrap();
        let mut received = Vec::new();

        for _ in 0..3 {
            let before = received.len();

            assert!(!read_received(&mut output, &mut received));
            assert!((1..H2G_BUFFER_SIZE).contains(&(received.len() - before)));

            sandbox.call::<i32>("EchoI32", 0).unwrap();
        }

        assert!(read_received(&mut output, &mut received));
        assert_eq!(received, data);
    });
}

/// No STATUS follows a result without stream state, so the result can take the whole G2H queue.
#[test]
fn guest_result_without_stream_state_fills_g2h() {
    const G2H_BUFFER_SIZE: usize = 4096;

    // The result takes four G2H buffers.
    const RESULT_LEN: usize = 3 * G2H_BUFFER_SIZE + G2H_BUFFER_SIZE / 2;

    let configure =
        |builder: SandboxBuilder| builder.g2h_queue_size(4).g2h_buffer_size(G2H_BUFFER_SIZE);

    with_rust_sandbox_from(configure, |mut sandbox| {
        sandbox
            .call::<()>("AllocAndWritePattern", RESULT_LEN as u64)
            .unwrap();

        let pattern: Vec<u8> = sandbox.call("ReadPattern", ()).unwrap();
        assert_eq!(pattern.len(), RESULT_LEN);
    });
}

#[test]
fn guest_result_with_an_idle_task_fills_g2h() {
    let configure = |builder: SandboxBuilder| builder.g2h_queue_size(4).g2h_buffer_size(4096);
    let len = 14 * 1024;

    with_rust_sandbox_from(configure, |mut sandbox| {
        sandbox
            .call::<()>("AllocAndWritePattern", len as u64)
            .unwrap();
        sandbox.call::<()>("StartLocalTask", ()).unwrap();

        let pattern: Vec<u8> = sandbox.call("ReadPattern", ()).unwrap();
        assert_eq!(pattern.len(), len);
    });
}

/// The last STATUS is ACTIVE, so the result leaves room for the STATUS that clears it. A result
/// that needs the room fails the call.
#[test]
fn guest_result_keeps_g2h_room_for_status() {
    const G2H_BUFFER_SIZE: usize = 4096;

    // The result takes four G2H buffers.
    const RESULT_LEN: usize = 3 * G2H_BUFFER_SIZE + G2H_BUFFER_SIZE / 2;

    let configure =
        |builder: SandboxBuilder| builder.g2h_queue_size(4).g2h_buffer_size(G2H_BUFFER_SIZE);

    with_rust_sandbox_from(configure, |mut sandbox| {
        sandbox
            .call::<()>("AllocAndWritePattern", RESULT_LEN as u64)
            .unwrap();

        let reader: StreamReader<u8> = sandbox.call("StreamThenWait", Vec::<u8>::new()).unwrap();
        drop(reader);

        // The call applies CLOSE_READER and drops the producer.
        let result = sandbox.call::<Vec<u8>>("ReadPattern", ());

        assert_matches!(
            result,
            Err(HyperlightError::GuestError(ErrorCode::GuestError, message))
                if message == "Guest response exceeds virtqueue capacity"
        );
        assert!(sandbox.status().is_ready());

        // The last STATUS is zero.
        let pattern: Vec<u8> = sandbox.call("ReadPattern", ()).unwrap();
        assert_eq!(pattern.len(), RESULT_LEN);
    });
}

/// The Request's flush carries the value, so the guest function reads it in the same call.
#[test]
fn guest_function_reads_a_host_future_in_the_same_call() {
    with_rust_sandbox(|mut sandbox| {
        let (reader, writer) = future::new();
        writer.write("hello".to_string()).unwrap();

        let value: String = sandbox.call("ReadFuture", reader).unwrap();
        assert_eq!(value, "hello");
    });
}

/// The Response's flush carries the value, so the host reads it once the call returns.
#[test]
fn guest_function_returns_a_written_future() {
    with_rust_sandbox(|mut sandbox| {
        let reader: FutureReader<String> =
            sandbox.call("WriteFuture", "hello".to_string()).unwrap();

        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Ok("hello".to_string()))
        );
    });
}

/// The guest flushes no stream records before a host call, so the value follows the Response.
#[test]
fn host_function_receives_a_guest_future() {
    let (sender, receiver) = mpsc::channel();
    let configure = |builder: SandboxBuilder| {
        builder.host_function("HostKeepFuture", move |reader: FutureReader<String>| {
            sender.send(reader).unwrap();
        })
    };

    with_rust_sandbox_from(configure, |mut sandbox| {
        sandbox
            .call::<()>("SendFuture", "hello".to_string())
            .unwrap();

        let reader = receiver.try_recv().unwrap();

        assert_eq!(
            poll_once(reader.into_future()),
            Poll::Ready(Ok("hello".to_string()))
        );
    });
}

/// Register `HostFuture`, which returns a future of its argument.
fn register_host_future(builder: SandboxBuilder) -> SandboxBuilder {
    builder.host_function("HostFuture", |value: String| {
        let (reader, writer) = future::new();
        writer.write(value).unwrap();
        reader
    })
}

/// A host function reply carries no stream records, so the value crosses with the next call.
#[test]
fn host_function_returns_a_future() {
    with_rust_sandbox_from(register_host_future, |mut sandbox| {
        sandbox
            .call::<()>("KeepHostFuture", "hello".to_string())
            .unwrap();

        let value: String = sandbox.call("ReadKeptFuture", ()).unwrap();
        assert_eq!(value, "hello");
    });
}

/// The guest's `Result` declaration of `HostFuture` receives the future too.
#[test]
fn host_function_returns_a_future_through_a_result() {
    with_rust_sandbox_from(register_host_future, |mut sandbox| {
        sandbox
            .call::<()>("TryKeepHostFuture", "hello".to_string())
            .unwrap();

        let value: String = sandbox.call("ReadKeptFuture", ()).unwrap();
        assert_eq!(value, "hello");
    });
}

/// A guest task reads the host stream across several windows, then resolves the future.
#[test]
fn produced_future_counts_a_host_stream() {
    let window = DEFAULT_WINDOW.get() as usize;
    let data: Vec<u8> = (0..4 * window + 17).map(|i| (i % 251) as u8).collect();

    with_rust_sandbox(|mut sandbox| {
        let (input, mut writer) = stream::new();
        let len: FutureReader<String> = sandbox.call("CountStream", input).unwrap();

        let len = sandbox
            .block_on(async {
                writer.write_all(&data).await?;
                writer.close();
                Ok::<_, DriveError>(len.await?)
            })
            .unwrap();

        assert_eq!(len, data.len().to_string());
    });
}

/// The host reads the stream to its end before awaiting the future. Awaiting first would stall
/// once the stream fills its window.
#[test]
fn produced_future_resolves_after_a_stream_kept_by_the_host() {
    // The Request carries `data`, so it fits one H2G entry.
    let window = DEFAULT_WINDOW.get() as usize;
    let data: Vec<u8> = (0..window + 17).map(|i| (i % 251) as u8).collect();
    let (sender, receiver) = mpsc::channel();
    let configure = |builder: SandboxBuilder| {
        builder.host_function("HostKeepStream", move |reader: StreamReader<u8>| {
            sender.send(reader).unwrap();
        })
    };

    with_rust_sandbox_from(configure, |mut sandbox| {
        let done: FutureReader<()> = sandbox.call("SendStream", data.clone()).unwrap();
        let mut reader = receiver.try_recv().unwrap();

        let received = sandbox
            .block_on(async {
                let mut received = Vec::new();

                while let Some(chunk) = reader.read_chunk().await? {
                    received.extend_from_slice(&chunk);
                }

                done.await?;
                Ok::<_, DriveError>(received)
            })
            .unwrap();

        assert_eq!(received, data);
    });
}
