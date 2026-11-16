# HIP 0009 - Streams over virtqueues

**Status:** Draft. Stream support and execution-driving APIs are proposed.

## Vocabulary

- CM: WebAssembly Component Model
- vsock: virtio-vsock, the virtio socket device for host and guest communication

## Summary

Add byte streams to Hyperlight's host and guest APIs over the existing virtqueues. Support stream
arguments and results through `Sandbox::call`, guest function registration and WIT binding
generation.

The transport follows Linux vsock. Records for many streams share the virtqueues, and credit-based
flow control bounds the bytes each stream buffers. Endpoints follow the CM ownership rules, so
optional WIT bindings map `stream<u8>` to them.

A function can return a stream before producing its contents. Rust applications use async stream
operations. A host driver and a small `no_std` guest task runner make a stream progress.

MVP scope: byte streams only (`u8` elements). Other stream payloads, CM `future<T>`, and CM async
functions are later work.

## Motivation

Today `VecBytes` and `ByteChunks` carry complete byte values. Each value must exist in full before
the call and fit in the shared-memory pools. Larger or incremental data can span repeated calls, but
each application then builds its own transfer protocol: IDs, state kept between calls, end of data,
cancellation, and cleanup. Streams build that protocol into Hyperlight:

- A reader is a value. A function can return it before the data exists, and it outlives the call.
- A producer is an ordinary async loop. Its task keeps its state between calls.
- WIT interfaces can use `stream<u8>`, as WASI 0.3 does for stdio, files, sockets, and HTTP bodies.
- One guest entry carries data and credit for every open stream, in both directions.
- The same records work when host and guest run concurrently on separate threads.

Examples include HTTP bodies, model output, uploads, and transformations of data larger than the
pools. A stream costs about one guest entry per window of data, as
[Flow control and VM transitions](#flow-control-and-vm-transitions) shows. 

## Proposal

### Relationship to completion-based I/O

Streams use completion-based I/O, as Linux [io_uring][io-uring] and Windows
[I/O completion ports][iocp] do. A program starts an operation with its buffer, and the system
reports the result when the operation completes. Stream operations start when called, and their
Rust futures or C callbacks deliver the result.

The transport works like io_uring and virtio. Two sides share rings in memory. One side posts
requests or buffers, and the other side completes them. Hyperlight's [virtqueues][hip-0001] are
modeled on virtio, with the guest as the driver. As a [virtio-net][linux-net] driver does for
outgoing and incoming packets, the guest posts buffers that hold its records and empty buffers that
the host fills.

A kernel or virtio device runs on its own. A Hyperlight guest runs only while the host enters it,
and each entry acts like one `io_uring_enter` call that submits a batch and waits for completions.
An operation that waits on the other side, such as a host read of guest data, needs an entry to
complete. Calls and the `Sandbox` drivers run the entries, as
[Stream lifecycle and driving](#stream-lifecycle-and-driving) describes.

### Relationship to vsock

A vsock device lets a VM and its host talk over socket connections. Each connection carries a byte
stream, and all connections share the device's virtqueues. Streams have the same needs. vsock meets
them with one small protocol for both sides. Linux shares one [transport][linux-vsock] between its
guest driver and its [vhost-vsock][linux-vhost] host backend.

vsock bounds memory with credits. A receiver sets a buffer size for each connection and reports how
many bytes its application has read. The sender sends only what fits in the free space. Each read
frees space, and a [credit update][linux-credits] lets the sender continue. A slow reader holds back
its writer, so buffers stay bounded.

Streams apply the same rule. A stream's window caps the bytes its writer has written and its reader
has not consumed. DATA records carry the bytes. The reader sends CREDIT as it consumes them, which
reopens the window. END marks the end of the data, and CLOSE_READER tells the writer that the reader
is gone. Records for all streams share Hyperlight's existing virtqueues and move at guest entries
and halts, as described in [Flow control and VM transitions](#flow-control-and-vm-transitions).

A stream is simpler than a vsock connection. It is one-way, so duplex traffic uses two streams. It
opens without a handshake or ports. The writer's side picks the stream ID, and function calls move
the reader. A vsock device would add a virtio device model, a guest socket layer, and three queues,
so streams reuse only vsock's flow control and closure rules.

### Relationship to the Component Model

The [Component Model][component-model] sets the endpoint rules, so WIT `stream<u8>` maps onto these
endpoints:

```text
producer keeps writer  ---- bytes ---->  receiver owns reader
```

- Only the readable end crosses a function boundary. Following the CM rule for `stream<T>` arguments
  and results, a call moves the reader to the receiver while the producer keeps its writer.
- The call and stream have separate lifetimes: a call can return while the producer still has work
  to do. Neither endpoint is cloneable.
- The reader and writer each allow one pending [operation][stream-operations], so a read and a write
  can be pending together. Passing or returning a reader requires it to be [idle][stream-transfer],
  with no read pending. Unread bytes stay with the stream and reach the reader's new owner.
- A write completes once its bytes enter the window, as a vsock send does. A CM write completes only
  when a read takes its bytes. A [hyperlight-wasm][hyperlight-wasm] bridge would act as a
  component's CM reader, so the component's writes complete once their bytes enter the window.
  Operations can make partial progress.

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
scheduling local tasks and driving async work from synchronous code. Each example streams from the
guest to the host, and the other direction works the same way.

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
sandbox's stream context. They move the reader into a guest call and drive the writer's work.

This keeps `hello` synchronous: handlers return a reader and schedule their stream work for later.
Waiting for stream data before returning requires the later async-call design.

### C example

Proposed native C API

```c
// Runs after the write completes and hello returns, outside transport locks.
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
return reader -> write fills window -> data -> read -> credit reopens window -> close
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

Cancellation follows the CM and completes locally, without a round trip.

| Event                                                           | What happens                                                                                                                                         |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Drop a read future                                              | The read ends and takes no bytes.                                                                                                                    |
| Cancel or drop a write                                          | The write ends at once and reports how many bytes were accepted. Accepted bytes stay readable. Cancelling does not close the endpoint.               |
| Close the reader early                                          | Tell the producer to stop and discard unread bytes. Pending writes report that the reader closed and how many bytes were accepted.                   |
| Drop a reader or writer                                         | Close it without waiting. Keep driving the sandbox to finish cleanup.                                                                                |
| Guest failure, kill during a guest turn, or sandbox destruction | Fail pending operations and wake waiting tasks. Cleanup must work without running the guest again.                                                   |
| Take a snapshot                                                 | Reject until all endpoints are released and all operations and tasks finish, even for cached snapshots. Stream activity makes cached state outdated. |

The transport keeps EOF, cancellation, resource-limit errors, and transport failures separate. EOF
only says that the writer closed its end, so a producer that can fail after returning must also
report whether its work succeeded. The MVP can carry this final status in application framing within
the byte stream, with a separate CM future as a later option.

### Flow control and VM transitions

A stream advances up to one window per round trip, since the reader's CREDIT reopens the window.
`window` is 16 KiB unless the host configures another size. A larger window takes fewer round trips
and buffers more bytes per stream.

Stream records travel in existing `SubmitBatch` submissions with packed-ring event suppression.
Control records go first, so data never delays credit or closure. Records depend only on queue
order, so the protocol carries over to a host and guest running on separate threads.

The MVP keeps Hyperlight's halt-based result handoff. After each halt the host drains the queues and
re-enters the guest only to deliver records or poll ready guest tasks. A call also polls ready tasks
once its function returns, so a returned stream's first data shares the call's halt. Synchronous
host calls keep an immediate `outb` and reply.

**Example.** Suppose the `hello` task writes 40 KiB. With a 16 KiB window, the call and the host's
`block_on` loop take four guest entries. Right arrows carry host records in at an entry. Left
arrows carry guest records back at the halt. `(n)` counts the 4 KiB queue buffers that carry the
data.

```text
Host (reader)                                           Guest (writer task)

== entry 1, call =========================================================================
                          Request ------------------->  hello() returns the reader,
                                                        task writes, 16K enters the window
takes the reader and 16K  <---- Response, DATA 16K (5)  write waits for credit
reads 16K, owes credit

== entry 2 ===============================================================================
                          CREDIT 16K ---------------->  next 16K enters the window
holds 16K                 <-------------- DATA 16K (5)  write waits for credit
reads 16K, owes credit

== entry 3 ===============================================================================
                          CREDIT 16K ---------------->  last 8K enters, write completes,
                                                        task closes the writer
holds 8K and EOF          <---------- DATA 8K (3), END
reads 8K and EOF, closes

== entry 4 ===============================================================================
close completes           CLOSE_READER -------------->  stream released
```

Entry 1 returns the first window with the Response. Entries 2 and 3 run because the host owes
credit, and each brings back the next window. Credit never needs a round trip of its own. When
data flows both ways, as in an echo of stream A into stream B, credit shares buffers with data.
Each bracket is one buffer:

```text
entry  -->  [CREDIT B | DATA A] [DATA A] [DATA A] ...
halt   <--  [CREDIT A | DATA B] [DATA B] [DATA B] ...
```

**Future work.** A guest running on its own thread, idle halts with wakeups,
[eventfd-based notifications][linux-ioeventfd], and [coalesced I/O][linux-coalesced-io] could
remove most userspace exits.

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
- Linux [io_uring][io-uring] and Windows [I/O completion ports][iocp].
- Linux [vsock transport][linux-vsock], [vhost-vsock][linux-vhost], and [virtio-net][linux-net].
- vsock [header][linux-vsock-hdr], [credit updates][linux-credits],
  [receive path][linux-vsock-recv], and [transport reset][linux-vsock-reset].
- Linux [notification ordering][linux-ring].
- KVM [eventfd routing][linux-ioeventfd] and [coalesced I/O][linux-coalesced-io].

[hip-0001]: ../0001-rng-buf/README.md
[hip-0002]: ../0002-envelope-external-byte-stream/README.md
[component-model]: https://component-model.bytecodealliance.org/
[hyperlight-wasm]: https://github.com/hyperlight-dev/hyperlight-wasm
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
[io-uring]: https://man7.org/linux/man-pages/man7/io_uring.7.html
[iocp]: https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports
[linux-vsock]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport_common.c
[linux-vsock-hdr]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/include/uapi/linux/virtio_vsock.h#L56-L96
[linux-vsock-recv]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport_common.c#L1411-L1474
[linux-vsock-reset]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport.c#L435-L446
[linux-vhost]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/vhost/vsock.c
[linux-net]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/net/virtio_net.c#L2749-L2790
[linux-ring]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/drivers/virtio/virtio_ring.c#L3138-L3217
[linux-credits]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/net/vmw_vsock/virtio_transport_common.c#L451-L643
[linux-ioeventfd]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/Documentation/virt/kvm/api.rst#L2093-L2137
[linux-coalesced-io]:
    https://github.com/torvalds/linux/blob/b95f03f04d475aa6719d15a636ddf32222d55657/Documentation/virt/kvm/api.rst#L5000-L5028
