# Virtio host/guest communication

Hyperlight's virtio communication path is built on packed virtqueues. It is
intended to replace stack-oriented host/guest calls with a transport that can
support request/response calls, async calls, streams, batching, and large
payloads.

The implementation is layered so that low-level virtqueue mechanics stay
separate from the protocol and dispatch logic that uses them.

## Queue directions

Hyperlight uses two logical queues:

| Queue | Producer | Consumer | Typical payloads |
| --- | --- | --- | --- |
| Guest-to-host (G2H) | Guest | Host | Host function calls, guest logs, H2G function-call responses |
| Host-to-guest (H2G) | Guest, via prefilled writable chains | Host | Host-to-guest function calls/events |

The H2G queue is intentionally subtle: the guest owns the producer side and
prefills the queue with device-writable receive capacity. The host consumes
those chains, writes H2G requests into the writable buffers, and completes the
chains. The guest then observes those completed chains as incoming data through
its producer.

## Layering

The virtqueue code is split into these layers:

| Layer | Main types | Responsibility |
| --- | --- | --- |
| Ring primitives | `RingProducer`, `RingConsumer`, `BufferChain`, `BufferElement`, `Descriptor` | Packed-ring descriptor publication, polling, event suppression, and memory ordering. |
| Allocation | `BufferProvider`, `Allocation`, `BufferPool`, `RecyclePool`, `PoolAlloc`, `BufferOwner` | Allocate shared-memory buffers and keep pool ownership tied to chain lifetime. |
| High-level chain API | `VirtqProducer`, `VirtqConsumer`, `SendChain`, `RecvChain`, `ReplyChain`, `WritableChain`, `AckChain`, `UsedChain` | Manage buffer allocation, chain lifecycle, safe payload views, and notifications. |
| Payload view | `Segments`, `SegmentsBuf` | Preserve ordered byte segment boundaries and provide explicit contiguous conversion when needed. |
| Protocol | `VirtqMsgHeader`, FlatBuffer wrappers | Interpret bytes as calls, results, logs, and future stream/batch messages. |

The low-level `BufferChain` is descriptor-oriented: it contains addresses,
lengths, and writable flags. The high-level `Segments` type is payload-oriented:
it contains ordered `Bytes` values after shared-memory access has been resolved.
These are deliberately separate abstractions.

## Readable and writable buffers

Readable and writable are named from the device/consumer perspective:

- A **readable** buffer is written by the producer before submission and read by
  the consumer after polling.
- A **writable** buffer is reserved by the producer and filled by the consumer
  before completion.

Virtio requires readable descriptors to appear before writable descriptors in a
chain. The high-level API preserves that ordering.

## Chain lifecycle

The high-level lifecycle uses these names:

| Type | Owner | Meaning |
| --- | --- | --- |
| `SendChain` | Producer | A chain being prepared for submission. |
| `RecvChain` | Consumer | A received chain whose readable payload has been copied into `Segments`. |
| `ReplyChain` | Consumer | The capability to complete a `RecvChain`; either writable capacity or ack-only. |
| `WritableChain` | Consumer | The writable form of `ReplyChain`; used to write response bytes. |
| `AckChain` | Consumer | The ack-only form of `ReplyChain`; used for chains with no writable buffers. |
| `UsedChain` | Producer | The producer-observed result after the consumer completes a chain. |

In the common request/response case:

```text
producer.chain()
    -> SendChain
    -> producer.submit(SendChain) -> Token

consumer.poll()
    -> (RecvChain, ReplyChain)
    -> consumer.complete(ReplyChain)

producer.poll()
    -> UsedChain
```

For fire-and-forget chains with no writable buffers, the producer receives
`UsedChain::Ack(Token)`. For chains with writable buffers, the producer receives
`UsedChain::Data(Token, Segments)`.

## Payload segments

`Segments` is the high-level payload shape. It preserves ordered byte segment
boundaries instead of forcing every chain into one contiguous allocation.

Use segment-aware APIs when possible:

```rust
let segments = recv_chain.segments();
let mut cursor = segments.cursor();
```

Use explicit contiguous conversion only when a compatibility path needs it:

```rust
let bytes = recv_chain.to_bytes();
let bytes = used_chain.into_bytes();
```

`Segments::to_bytes()` and `Segments::into_bytes()` are O(1) for zero or one
segment. They allocate and copy when multiple segments must be flattened.

`SegmentsBuf` implements `bytes::Buf`, so protocol code can parse across segment
boundaries without collecting the entire payload. This is useful for fixed-size
headers such as `VirtqMsgHeader`.

## Writable replies and used lengths

The virtio used ring reports one aggregate written length for a completed
descriptor chain. It does not report per-writable-descriptor lengths.

For that reason, `WritableChain` writes sequentially across writable buffers.
When the producer later observes `UsedChain::Data`, it reconstructs returned
segments greedily from the aggregate length:

```text
writable capacities: [4096, 4096, 4096]
used length:          5000
returned segments:    [4096, 904]
```

Random writes into arbitrary writable descriptors would make this reconstruction
ambiguous, so the public write path preserves a sequential-write invariant.

## Notifications and batching

Submission and completion notification use virtio event suppression:

- `VirtqProducer::submit` publishes one `SendChain` and notifies if suppression
  allows.
- `VirtqProducer::batch` publishes multiple chains and kicks at most once when
  `finish` is called.
- `VirtqConsumer::complete` marks one received chain used and notifies the
  producer if suppression allows.
- `notify_backpressure` bypasses suppression when the peer needs to drain work
  to free descriptors or pool buffers.

This keeps the common path simple while allowing higher-level code to batch
calls, logs, stream chunks, or prefilled receive buffers.

## FlatBuffer boundary

FlatBuffer roots still need contiguous bytes. The current dispatch paths may
explicitly call `to_bytes()` before verifying or decoding a FlatBuffer envelope.

Large payloads should not depend on a single large contiguous allocation. The
intended direction is:

```text
small contiguous envelope/header
ordered Segments for large bytes, strings, stream data, or chunk messages
```

If a future schema references external payload segments, those segments need
their own validation and ownership rules. FlatBuffer verification only validates
the bytes inside the FlatBuffer buffer.

## Current limitations and follow-ups

- Some host/guest dispatch paths still collect `Segments` into contiguous
  `Bytes` for existing FlatBuffer wrappers.
- Large payload chunking is a protocol/schema follow-up; it is not part of the
  chain lifecycle itself.
- The allocator can become simpler once large logical payloads consistently use
  bounded `Segments` instead of requiring large contiguous allocations.
- Snapshot/reset ownership for outstanding `UsedChain::Data` buffers remains a
  separate design point.
