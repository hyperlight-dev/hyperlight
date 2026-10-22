# HIP 0005 - Streams over virtqueues

**Status:** Draft. Stream support and execution-driving APIs are proposed.

## Vocabulary

CM: Component Model

## Summary

Add streams to Hyperlight's host and guest APIs over the existing virtqueues. Support stream
arguments and results through `Sandbox::call`, guest function registration and WIT binding
generation. Follow the WebAssembly Component Model (CM) stream ownership rules. Optional WIT
bindings map `stream<u8>` to these endpoints.

A function can return a stream before producing its contents. Rust applications use async stream
operations. A host driver and a small `no_std` guest task runner make a stream progress.

MVP scope: byte streams only (`u8` elements). Other stream payloads, CM `future<T>`, and CM async
functions are later work.

## Motivation

Today `VecBytes` and `ByteChunks` transport complete byte values. Streams let a producer generate
data as they become available. This supports request bodies, generated output, and in general
transformations larger than the shared-memory pools. Transport memory stays bounded regardless of
the total stream length.

## Proposal

### Relationship to the Component Model

In the [Component Model][component-model], a stream has a readable end and a writable end:

```text
producer keeps writer  ---- bytes ---->  receiver owns reader
```

- Only the readable end crosses a function boundary. Following the CM rule for `stream<T>` arguments
  and results, a call moves the reader to the receiver while the producer keeps its writer.
- The call and stream have separate lifetimes: a call can return while the producer still has work
  to do. Neither endpoint is clonable.
- Writes make progress through matching reads, so copying bytes into a virtqueue does not by itself
  complete a write. Operations can make partial progress.
- The reader and writer each allow one pending [operation][stream-operations], so a read and a write
  can be pending together. Passing or returning a reader requires it to be [idle][stream-transfer]
  because an unfinished read still uses the old owner's buffer and completion state. The read or its
  cancellation must finish and its result must be collected before the transfer.

The MVP supports byte-stream readers in function parameters and results for both host and guest
producers. WIT bindings map these readers to `stream<u8>`, including inside supported aggregates
such as `result` and `option`. Other payloads, CM `future<T>`, and CM async functions are deferred.

## Design Details

### Type system

The user-facing types are small:

| Concept                          | Rust API                                              |
| -------------------------------- | ----------------------------------------------------- |
| Native stream argument or result | Owned `StreamReader<u8>`.                             |
| Private producer                 | Owned `StreamWriter<u8>`. It stays with the producer. |
| read, write, close               | Methods returning Rust operation futures.             |
| Drive execution                  | `Sandbox::block_on` or `Sandbox::run_until`.          |

These Rust futures represent pending operations, so awaiting `read_chunk(n)` does not require CM
futures or an async function ABI.

Later CM `future<T>` support can specialize the stream core for a single element, sharing its
transport and operation machinery while keeping a distinct type, one-shot completion, and
future-specific drop rules.

The examples use proposed stream APIs. Their task and driving functions are similar to
[`wit_bindgen::spawn_local`][wit-spawn-local] and [`wit_bindgen::block_on`][wit-block-on]:
scheduling local tasks and driving async work from synchronous code.

**Native Rust guest.** Stream/task admission errors use the existing guest-call error reply.

```rust
#[hyperlight_guest_bin::guest_function]
fn hello() -> hyperlight_guest::error::Result<StreamReader<u8>> {
    let (reader, mut writer) = stream::new::<u8>()?;

    task::spawn_local(async move {
        writer
            .write_all(Bytes::from_static(b"hello, world\n"))
            .await?;

        writer.close().await
    })?;

    Ok(reader)
}
```

`spawn_local` queues a runtime-owned task for a later poll, letting `hello` return the reader while
the task keeps the writer. Since the task can outlive the call, it must own its state without
borrowing from the call frame, and the runtime must report any errors it produces.

**Native Rust host.** Use the core `Sandbox` directly.

```rust
let mut sandbox = SandboxBuilder::from_file("guest.bin").build()?;
let mut body: StreamReader<u8> = sandbox.call("hello", ())?;

sandbox.block_on(async move {
    while let Some(bytes) = body.read_chunk(4096).await? {
        std::io::stdout().write_all(&bytes)?;
    }

    body.close().await?;
    Ok::<(), anyhow::Error>(())
})?;
```

`read_chunk(n)` returns an owned chunk of up to `n` bytes or `None` at EOF, with `n > 0` required
for every read. On the writing side, `write_all` handles partial writes. The sandbox drives these
operations through `block_on`, which advances the supplied future and the VM and propagates errors
from either. Async hosts use `sandbox.run_until(work).await` to drive the same work.

Host producers use `sandbox.new_stream::<u8>()` to create the same reader/writer pair, bound to that
sandbox's session. They move the reader into a guest call and drive the writer's work.

This keeps `hello` synchronous: handlers return a reader and schedule their stream work for later.
Waiting for stream data before returning requires the later async-call design.

### C example

Proposed native C API

```c
// Runs at a later Progress entry, outside transport locks.
static void hello_written(void *writer, hl_write_result result) {
    hl_task_report_write(result);
    hl_stream_writer_drop(writer);
}

// Register as "hello" with return type hl_ReturnType_StreamReader.
static hl_ReturnValue *hello(const hl_FunctionCall *call) {
    (void)call;
    const uint8_t message[] = "hello, world\n";
    hl_stream_reader *reader;
    hl_stream_writer *writer;
    hl_status status = hl_stream_new_u8(&reader, &writer);

    if (status != HL_OK) {
        goto error;
    }

    // Copies the stack buffer. On success, the callback owns writer cleanup.
    status = hl_stream_write_all_copy(
        writer, message, sizeof(message) - 1, hello_written, writer);

    if (status != HL_OK) {
        hl_stream_reader_drop(reader);
        hl_stream_writer_drop(writer);
        goto error;
    }

    // Moves the reader into the RPC result.
    return hl_result_from_StreamReader(reader);

error:
    hl_set_error(hl_ErrorCode_GuestError, hl_status_message(status));
    return NULL;
}
```

### WIT bindings

WIT can describe the same operation:

```wit
package demo:hello;

interface greeter {
    hello: func() -> result<stream<u8>, string>;
}

world hello {
    export greeter;
}
```

Here the WIT `result` carries stream/task admission errors. The shared bindings map `stream<u8>` to
the native reader type, including inside `result`, `option` etc.

`host_bindgen!` already generates a world-specific wrapper around a sandbox. The proposed
stream-valued bindings and forwarding methods for `new_stream`, `block_on`, and `run_until` extend
that wrapper while sharing the core runtime and driver.

This synchronous `hello` uses Hyperlight's runtime-owned tasks. A `wit-bindgen` Wasm producer that
keeps working after returning uses a CM async export task and [`async func`][wit-async]. That
async-function integration is out of scope.

### Stream lifecycle and driving

**The `Sandbox` driver owns progress.** Endpoint methods queue work without entering the VM.

- `spawn_local`: queue guest tasks for later polling.
- `block_on`: poll host work, pump queues, and run guest on the calling thread.
- `run_until`: expose async driving that a host task can await on an executor like Tokio.

```text
return reader -> read demand -> guest write -> host acceptance -> write completion -> close
```

Release endpoints after both ends close and all pending operations are finished.

Each guest dispatch starts at the saved stack top, so a task that outlives its call needs storage
outside that call's stack frame. The runtime keeps task futures pinned on the heap and uses Rust
[wakers][rust-future-poll] to mark them ready for another poll. It releases its queue and
task-registry locks or borrows before polling tasks or invoking callbacks, since that code can
re-enter the runtime to queue more work.

Before waiting for more work, the host driver follows [Linux's notification ordering][linux-ring]:
arm queue notifications, apply the required memory barrier, then recheck the queues. This catches
work that arrived while notifications were disabled, preventing the driver from waiting with work
already queued. The wait mechanism must also preserve wakeups arriving between the final check and
the start of the wait.

`wit-bindgen` keeps `block_on` running until its spawned tasks finish. Hyperlight's `block_on`
returns as soon as its supplied future completes, so any remaining work needs a later drive or
cleanup during sandbox teardown. Stream progress depends on returning control to the driver:
callbacks must not block on stream operations, and duplex streams must be fed and drained
concurrently. Turn budgets are cooperative, which means guest code that never yields requires
interruption.

### Cancellation and failure

This is modeled after CM.

| Event                                              | What happens                                                                                                                                            |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Drop a read or write future                        | Request cancellation. The runtime keeps state and buffers until the result is known.                                                                    |
| Cancel a read or write                             | Report how many bytes were accepted and whether the operation finished, was cancelled, or the other end closed. Cancelling does not close the endpoint. |
| Close the reader early                             | Tell the producer to stop. Pending writes report that the reader closed and how many bytes were accepted.                                               |
| Drop a reader or writer                            | Queue cancellation and closure without waiting. Keep driving the sandbox to finish cleanup.                                                             |
| Guest failure, forced stop, or sandbox destruction | Fail pending operations and wake waiting tasks. Cleanup must work without running the guest again.                                                      |
| Restore a snapshot                                 | End the old session and reject its handles. Late results must not affect the restored sandbox.                                                          |
| Take a snapshot                                    | Reject until all endpoints are released and all operations and tasks finish, even for cached snapshots. Stream activity makes cached state outdated.    |

The transport keeps EOF, cancellation, resource-limit errors, and transport failures separate. EOF
only says that the writer closed its end, so a producer that can fail after returning must also
report whether its work succeeded. The MVP can carry this final status in application framing within
the byte stream, with a separate CM future as a later option.

### Batching and VM transitions

The plan builds on existing `SubmitBatch` and packed-ring event suppression, using the batching and
scheduling patterns from [Linux virtio-vsock][linux-vsock] and [vhost-vsock][linux-vhost]. [Credit
updates][linux-credits] can travel alongside function-call traffic, while the queues retain space
for control messages.

Stream progress uses Hyperlight's existing halt-based result handoff, letting the host drain queues
before deciding whether to re-enter the guest. Synchronous host calls require an immediate `outb`
and reply.

**Future work.** [Eventfd-based notifications][linux-ioeventfd] and [coalesced
I/O][linux-coalesced-io] could reduce userspace exits.

## Implementation History

- 2026-10-20: Draft proposal. No implementation under this HIP.

## References

- CM specification references use revision `0220da84209397d9067c19cac83dae969aa85a7b`. 
- Linux references use revision `b95f03f04d475aa6719d15a636ddf32222d55657`.

- [Canonical ABI][canonical-abi] and [Python reference][canonical-reference].
- [Component type validity][component-binary].
- [Concurrency and stream ownership][concurrency], including [stream readiness][stream-readiness].
- [Stream reads and writes][stream-operations] and [reader transfer][stream-transfer].
- [wit-bindgen async binding rules][wit-async].
- [Hyper body streams][hyper-body] and [Tokio blocking workers][tokio-blocking].
- [HIP 0001: Virtio-inspired ring buffer][hip-0001].
- [HIP 0002: Serialized envelope and external byte stream][hip-0002].
- Linux [virtio-vsock][linux-vsock], [vhost-vsock][linux-vhost], and [virtio-net][linux-net].
- Linux [notification ordering][linux-ring] and [vsock credit updates][linux-credits].
- KVM [eventfd routing][linux-ioeventfd] and [coalesced I/O][linux-coalesced-io].

[hip-0001]: ../0001-rng-buf/README.md
[hip-0002]: ../0002-envelope-external-byte-stream/README.md
[component-model]: https://component-model.bytecodealliance.org/
[canonical-abi]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/CanonicalABI.md
[canonical-reference]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/canonical-abi/definitions.py
[component-binary]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/Binary.md
[concurrency]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/Concurrency.md
[stream-operations]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/Explainer.md#-streamread-and-streamwrite
[stream-transfer]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/CanonicalABI.md?plain=1#L2422-L2448
[stream-readiness]:
    https://github.com/WebAssembly/component-model/blob/0220da84209397d9067c19cac83dae969aa85a7b/design/mvp/Concurrency.md#stream-readiness
[wit-async]:
    https://github.com/bytecodealliance/wit-bindgen/blob/4f7496b180e4c0eaf787b0bc5ef4a3ac5c68151a/crates/core/src/async_.rs#L26-L28
[wit-spawn-local]: https://docs.rs/wit-bindgen/0.63.0/wit_bindgen/fn.spawn_local.html
[wit-block-on]: https://docs.rs/wit-bindgen/0.63.0/wit_bindgen/fn.block_on.html
[rust-future-poll]: https://doc.rust-lang.org/core/future/trait.Future.html#tymethod.poll
[hyper-body]: https://hyper.rs/guides/1/server/echo/#body-streams
[tokio-blocking]: https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html
[linux-vsock]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport.c#L151-L205
[linux-vhost]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/vhost/vsock.c
[linux-net]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/net/virtio_net.c#L3336-L3393
[linux-ring]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/virtio/virtio_ring.c#L3138-L3217
[linux-credits]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport_common.c#L451-L643
[linux-ioeventfd]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/Documentation/virt/kvm/api.rst#L2093-L2137
[linux-coalesced-io]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/Documentation/virt/kvm/api.rst#L5000-L5028
