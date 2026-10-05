# Virtqueue host and guest communication

Hyperlight transports typed function calls over two shared memory VIRTIO
packed virtqueues. It uses the packed ring layout and ownership rules, but it
is not a discoverable VIRTIO device. Queue configuration, arena placement, and
notification behavior are part of the Hyperlight ABI.

## Architecture

The guest is the driver (producer) for both queues. The host is the device
(consumer) for both queues.

A **descriptor** is a 16-byte queue entry that points to a shared-memory
buffer and records its length and flags. The payload lives in the buffer.

**Readable** means the host can read it. **Writable** means the host can
write it. Multiple descriptors can form a **descriptor chain** for one
transfer.

```text
 Guest                                                    Host

 G2H producer  === G2H packed ring and buffer pool ===>  G2H consumer

 H2G producer  === H2G packed ring and buffer pool ===>  H2G consumer
```

Producer ownership describes who publishes descriptors. It does not always
describe the direction in which payload bytes move.

* **G2H** carries guest requests, guest function results, and logs. Guest
  readable descriptors carry bytes to the host. A guest call to a host
  function also includes writable descriptors in the same chain for the host
  response.
* **H2G** carries host requests to guest functions and internal control
  requests. The guest preposts writable buffers. The host fills and completes
  them before entering the VM.

Two queues keep directional validation and capacity independent. H2G always
contains uniform preposted receive buffers. G2H supports readable messages and
optional writable response capacity.

## Transport arena

Both rings, the transport mailbox, and both pools occupy one fixed prefix of
guest scratch memory.

```text
 scratch base
     |
     v
 +----------+-----+----------+-----+-----+-----+----------+----------+
 | G2H ring | pad | H2G ring | pad | mbx | pad | G2H pool | H2G pool |
 +----------+-----+----------+-----+-----+-----+----------+----------+
```

The host derives this layout from `SandboxConfiguration`. Ring starts follow
packed ring alignment rules. The mailbox is `u64` aligned. Pools are page
aligned.

The default layout is:

| Region | Default size or capacity |
|---|---:|
| G2H ring | 64 descriptors |
| H2G ring | 32 descriptors |
| Mailbox | one `u64` |
| G2H pool | 12 pages |
| H2G pool | 8 pages |
| Arena | 21 pages total |

Offsets after the G2H ring depend on configured queue sizes and pool pages.
`TransportArena` addresses are GPAs. The guest converts them to scratch GVAs
when constructing rings and pools. Descriptor buffer addresses are GVAs.

### Buffer pools

* **H2G** provides equal-sized buffers for host requests. The guest makes
  them available before it knows the next message size.
* **G2H** allocates buffers for guest requests, results, and logs. Small
  control messages can use 256-byte buffers, leaving larger buffers free
  for data.

**Why do guest replies use G2H rather than H2G?** The guest publishes buffer
descriptors for both queues. H2G is prefilled with writable buffers for host
messages, consumed in queue order. A guest reply appended there would sit
behind those unused receive buffers. G2H lets the host receive guest replies
without first handling the pending H2G buffers.

```text
H2G pool
[ h2g_buffer_size ][ h2g_buffer_size ] ...

G2H pool
[ 16 x 256 B small buffers ][ g2h_buffer_size ][ g2h_buffer_size ] ...
  first 4 KiB page           remaining pages
```

Both configurable buffer sizes default to 4 KiB. G2H's small buffers stay
256 bytes even when the data buffers grow.

When a guest-sent G2H payload exactly fills one or more data buffers, its
metadata is allocated separately. Metadata of at most 256 bytes can use a
small buffer. Other messages keep metadata and payload together.

### Configuration

Configure queue sizes, buffer sizes, and pool page counts through
`SandboxBuilder` or `SandboxConfiguration`:

```rust
use hyperlight_host::SandboxBuilder;

let sandbox = SandboxBuilder::from_file("guest.bin")
    .scratch_size(512 * 1024)
    .g2h_queue_size(128)
    .h2g_queue_size(16)
    .g2h_buffer_size(8192)
    .h2g_buffer_size(2048)
    .g2h_pool_pages(16)
    .h2g_pool_pages(6)
    .build()?;
```

Both APIs use the same normalization. Larger queues or pools may need more
scratch memory. Snapshot restores use the saved transport layout.

### Capacity and latency

Pool size sets the transport budget. Buffer size determines how many buffers
share that budget.

The guest cannot know the size of a `String`, `VecBytes`, or `ByteChunks` reply
in advance. It reserves as many reply buffers as the pool and queue allow.
Even a small reply can therefore require many buffers to be managed.

Consider a 4 KiB request and a 4 KiB reply, each fitting in one buffer.
With enough queue entries, the same call can have these layouts:

```text
Space for message buffers   Buffer size   Buffers used or reserved
32 KiB                      16 KiB        [request][reply]
 4 MiB                      16 KiB        [request][reply][254 unused]
 4 MiB                     256 KiB        [request][reply][ 14 unused]
```

Unused reply buffers still need descriptors to be prepared, read, and
reclaimed. The second row adds that work without carrying more data.

**Tune pool size and buffer size together:**

* **Only small messages:** use a small pool.
* **Small and large messages:** allow space for the largest request and reply
  together. Use larger buffers to avoid managing hundreds of small ones.

Larger buffers reduce chunking, but each small message occupies more space.
Measure the mix of message sizes your application actually uses.

### Initialization

The host writes the normalized queue sizes, pool page counts, buffer sizes,
and arena GPA into fixed metadata at the top of scratch. It creates both
consumers at cursor zero without reading uninitialized ring contents.

On the first VM entry, the guest:

1. Reads the published configuration.
2. Reconstructs `TransportArena`.
3. Converts each transport GPA into its scratch GVA.
4. Constructs a `GuestContext` and installs it with `set_global_context`.
   H2G receives one writable descriptor per available slot, bounded by queue size.

Dispatch starts with `transport::maybe_refresh`, before logging or tracing.
Runtime operations borrow the context through `transport::with_ctx`.

After user initialization and trace flushing, the guest calls
`transport::prepare_snapshot`, then halts. The host resets its consumers and
requires `MailboxValue::CheckpointComplete`. Initial snapshots include values
retained during initialization.

## Wire format

Every logical message has this byte layout:

```text
 +----------------+-----------------------------+---------------------+
 | MsgHeader      | size-prefixed FlatBuffer    | external byte data  |
 | 12 bytes       | control data                | zero or more values |
 +----------------+-----------------------------+---------------------+
```

`MsgHeader` contains:

* `kind: u8`
* three reserved zero bytes
* `cid: u32`
* `payload_len: u32`

`payload_len` covers the control data and all external bytes. RPC correlation
IDs are nonzero. Responses echo the request ID. Logs and snapshot checkpoints
use ID zero.

The active message kinds are:

* `Request`
* `Response`
* `Log`
* `SnapshotCheckpoint`

The FlatBuffer holds the typed function call or result and the lengths of
external byte values. External bytes follow it in the same logical message.
A logical message may span several descriptors or several H2G receive buffers.

The guest reads control data directly when it occupies one segment. It copies
fragmented control data into one contiguous buffer. Host decoding always copies
control data out of guest writable scratch.

### Choosing a value type

* `String`: UTF-8 text, encoded inside the FlatBuffer.
* `VecBytes`: small binary values, or a receiver that needs a contiguous `Vec<u8>`.
* `ByteChunks`: large binary data or data already held in chunks.

For small `String` or `VecBytes` values, aim to fit the complete guest-sent G2H
message in 256 bytes. The payload budget is `256 - 12 - envelope_overhead`.
The 12-byte header is fixed. FlatBuffer overhead includes its size prefix
and metadata, and varies with the call. This is a sizing guideline, not a
limit on the value types.

### External byte values

`VecBytes` and `ByteChunks` payloads stay outside the FlatBuffer. It contains the
total logical value length and whether the value is chunked. The encoder can
then reference the caller's byte slices directly without first copying them into
one contiguous FlatBuffer.

`ExternalValueSource` is implemented by `RecvChain` for host decoding and by
`Segments` for guest decoding.

Payload copying for `ByteChunks` follows the receiver's ownership model:

```text
 H2G request / G2H reply: host  --copy--> pool slots --borrow--> guest ByteChunks
 G2H request / result:   guest --copy--> pool slots --copy----> host ByteChunks
```

Guest views use `Bytes::from_owner` and keep each slot allocated until its
final owner drops. Host copies isolate host code from guest writable scratch.
`VecBytes` copies external data into one contiguous `Vec<u8>`.

C guest function parameters expose `ByteChunks` as a borrowed
`hl_ByteChunks` array. Each `hl_ByteChunk` contains a pointer and length. The
descriptor array is allocated, but its payload pointers reference the
underlying `Bytes` directly. The view is valid until the guest function
returns. `hl_get_host_return_value_as_ByteChunks` returns an owning view that
must be released with `hl_free_byte_chunks`. Chunk arrays produced by C are
copied by `hl_result_from_ByteChunks`.

The wire format does not preserve the sender's `Vec<Bytes>` boundaries. It
records one total length, not each source chunk length. The receiver sees the
logical byte sequence split where it intersects transport buffers.

Each payload letter represents 1 KiB. Metadata size varies with the call.
It combines the fixed 12-byte message header and the size-prefixed
FlatBuffer. This example uses 1 KiB of metadata.

```text
Sender chunks:      [AB] [CDEFG] [HIJ]    2 + 5 + 3 KiB
H2G slots (4 KiB):  [metadata: 1 KiB | ABC] [DEFG] [HIJ | unused: 1 KiB]
Guest ByteChunks:                     [ABC] [DEFG] [HIJ]    3 + 4 + 3 KiB
```

Guest chunks exclude the metadata and unused space.

H2G chunking follows the preposted H2G slot size. G2H responses returned to
the guest follow the G2H writable slot size. The message header and FlatBuffer
can consume part of the first slot. The final slot can also be partial.

#### Example: keeping a payload in one chunk

An application can keep a payload in one piece while using the guest's
zero-copy receive path through `ByteChunks`. For example, consider one
8 KiB payload with at most 256 bytes of metadata:

* **Host to guest:** allow space for both payload and metadata.
  Use `h2g_buffer_size(8 * 1024 + 256)` for host requests.
  For host replies on G2H, apply that size to `g2h_buffer_size`.
* **Guest to host:** `g2h_buffer_size(8 * 1024)` fits the payload exactly,
  so metadata travels separately. If host replies must also arrive in one
  piece, use the larger G2H size described above.

## Host calls a guest function

```text
 Host                      H2G                    Guest
  |                         |                       |
  | encode Request(cid)     |                       |
  | fill posted buffers ----+---------------------->|
  | complete buffers        |      poll and decode  |
  |                         |      run guest call   |
  |                         |                       |
  |<----------------------- G2H Response(cid) ------|
  | poll after guest halt                           |
```

The complete flow is:

1. The host encodes a `FunctionCall` and external values.
2. The host polls enough H2G receive buffers for the complete message.
3. The host writes the message and completes each buffer.
4. The host enters the VM.
5. The guest polls completed H2G buffers, reconstructs the message, and
   invokes the registered guest function.
6. The guest submits a G2H `Response` with the same correlation ID.
7. The guest refills H2G and halts without notifying for the deferred response.
8. The host polls G2H, decodes the result, and completes the chain.

An H2G request containing external bytes must leave one posted buffer
available. This reserve allows a later control call to release retained guest
values.

## Guest calls a host function

```text
 Guest                     G2H                     Host
  |                         |                       |
  | Request(cid)            |                       |
  | readable request -------+---------------------->|
  | writable reply buffers  |   copy and decode     |
  | OUT notification        |   run host function   |
  |                         |                       |
  |<---------------- same chain completed ----------|
  | poll and decode Response(cid)                   |
```

The complete flow is:

1. The guest encodes a `FunctionCall`. The G2H producer allocates its readable
   regions and reserves writable response capacity.
2. The guest submits one G2H chain. Its readable region contains the request.
   Its writable region reserves the response.
3. The guest notifies the host through `OutBAction::VirtqNotify`.
4. The host polls G2H and copies all request data out of guest writable scratch.
5. The host invokes the registered host function.
6. The host writes a `Response` into the writable region and completes the
   same chain.
7. The VM resumes. The guest polls the completion and checks its correlation
   ID.

Variable-sized replies reserve one configured-size G2H buffer before taking
the remaining capacity within the descriptor budget. If reply capacity stays
unavailable after the backpressure retry, the call returns a guest error
without publishing the request.

The host never retains references into guest scratch. It verifies framing,
copies control and external data into host owned values, then invokes host
code.

Logs use readable G2H chains without writable response capacity. The host
drains and acknowledges them during the same VM exit.

## Buffer ownership

Guest `SlotPool` instances own all transport buffers. Pool clones share one
allocation bitmap with each producer.
Each producer pairs its backend with that pool. Completion leases carry the
original slot addresses and full capacities. Backing owns fixed scratch-to-alias
translation and paging. The backend holds only scratch bounds.
Guest completion mapping checks scratch bounds. Allocation ownership and
initialized lengths follow the `BufferMap` safety contract.

```text
 Free -> allocated -> published -> completed -> owner-backed Bytes -> Free
```

Some stages are skipped by one-way messages. Final ownership matters for
external `ByteChunks`:

* H2G `ByteChunks` can retain host written receive slots after a guest function
  returns.
* G2H host responses can become owner-backed guest `Bytes`.
* `VecBytes` values copy into a contiguous `Vec<u8>`.
* Multiple `Bytes` clones or slices backed by one owner keep one slot live.
* The final owner returns its original `BufferLease`. Active pool mappings
  remain available across ordinary calls.

Producer reset releases allocations still owned by queue bookkeeping. After
both producers reset and before H2G prefill, every live pool slot belongs to
guest retained `Bytes`. H2G prefills free slots up to the queue size.

Checkpoint preparation requires stopped host consumers with no live chain
handles. The host resets both consumers before processing more queue traffic.

### Retained virtual addresses

Each pool has a stable virtual alias range, mapped eagerly at initialization.
Completed `GuestMapping` owners keep their original leases.
Capture, restore, and cloning preserve their pointers and contents.

Checkpoint preparation records the live slots. After restore, aliases of their
pages reach captured data. The first transport entry copies the recorded slots
into scratch and maps every pool alias to scratch. Only recorded slots are
copied, so neighboring slots keep host writes such as the first request.

### Trust boundary

The host treats guest rings, descriptors, headers, FlatBuffers, and payload
lengths as untrusted.

* Rings and payloads use checked copies and atomics within mapped scratch.
  Runtime payloads may be outside the pools. Live guest-backed host slices
  are unsupported.
* H2G descriptors must be writable, single buffer chains of the configured
  size before the host writes to them.
* G2H control and external values are copied into host owned storage before
  host code receives them.
* Capture and load require the canonical transport state described below.

## Snapshot checkpoint

The transport arena lives in scratch and is not captured as ordinary guest
memory. Guest producer and pool bookkeeping is normal guest state, while ring
and pool bytes live in scratch. Snapshot capture needs a canonical transport
state. Retained aliases map live payload pages outside the scratch map, so
capture copies them as ordinary memory.

`Sandbox` tracks whether queue traffic occurred after the last
canonical boundary. A cached or clean snapshot needs no VM entry. A dirty
snapshot uses this flow:

```text
 Host                                 Guest
  |                                     |
  | mailbox = CheckpointPending         |
  | H2G SnapshotCheckpoint ------------>|
  | enter VM                            |
  |                                     | reclaim completed G2H work
  |                                     | reset G2H producer
  |                                     | reset H2G producer
  |                                     | record live slots
  |                                     | unmap pages outside live slots
  |                                     | prefill free H2G slots
  |                                     | mailbox = CheckpointComplete
  |<------------------------------------| halt
  | reset both consumers                |
  | require CheckpointComplete          |
  | read and validate ring images       |
  | capture memory                      |
```

Checkpoint preparation keeps retained leases and aliases intact without
payload copying. Capture leaves the source queues and allocator ready for
continued use, including when memory capture fails.

The canonical state is:

* G2H is empty at cursor zero.
* H2G starts at cursor zero with one writable descriptor per free slot,
  bounded by queue size. Each descriptor names a distinct, configured-size
  slot aligned relative to the pool start. Available descriptors form a prefix
  followed by zeroed descriptors.
* Guest producer and pool bookkeeping matches the rings and retained leases.
* Driver and device event suppression is normalized.
* Host consumers start at cursor zero.

The snapshot stores normal guest memory plus the two canonical ring images.
Construction and loading validate the ring images against the finalized
layout. The layout and copied ring images remain immutable.
The OCI representation places ring images in the
[transport layer](./snapshot-oci-format.md). Retained payloads use the ordinary
memory layer through their aliases. The mailbox and host consumer cursors are
not stored.

### Restore

Capture and load validate scratch size, ring lengths, and canonical transport
state against the layout. Admitted images and their layout remain immutable.

Transport admission precedes changes to sandbox status, the cached snapshot,
and memory mappings.

Restore writes the arena GPA metadata, a `CheckpointComplete` mailbox value,
and both ring images into fresh scratch. It attaches new host consumers at
cursor zero. Normal guest memory restores the matching producers, pools,
leases, and aliases.
Initialized `restore` and `from_snapshot` are ready for the first H2G request
before guest entry. Pre-initialization snapshots use normal guest startup.

The first request fits the H2G capacity posted at checkpoint. Retained slots
reduce pool capacity but hold no ring descriptors. Framing, slot rounding, ring
size, and the external-byte control reserve still apply.

The first transport entry after checkpoint maps missing pool pages to scratch.
After restore, it also copies recorded slots from captured aliases into scratch
and remaps their pages. This applies to logs and host callbacks before request
dispatch as well as ordinary H2G calls. Pool ownership, descriptors, and
cursors stay unchanged, preserving the submitted request.

Result completion prefills free H2G slots. This requires no preparatory guest
entry or application warmup for the checkpoint-posted capacity.

## Transport mailbox

The mailbox holds a `MailboxValue` encoded as one `u64` in the ring to pool
alignment gap. It is outside both rings and pools. Both sides derive its
address from trusted arena geometry. The host accesses it before VM entry and
after guest halt.

The mailbox avoids a G2H checkpoint response. G2H can remain empty in the
canonical image even when retained G2H slots reduce available capacity.

Before a dirty checkpoint, the host writes `CheckpointPending`.
The guest writes `CheckpointComplete` after producer reset and free-slot H2G prefill.
The host reads the value after a successful guest halt and after resetting
both consumers.

* `CheckpointPending` (`0`) is a fatal incomplete checkpoint.
* `CheckpointComplete` (`1`) permits snapshot capture.
* Every other value is a fatal invalid status.

## Placement and relocation limitations

The fixed-pool runtime places both rings, the mailbox, and both pools in one
host-owned arena at the scratch base. The guest reconstructs that layout from
host metadata.

Descriptors, pool owners, and producer state contain absolute GVAs. Restore
adopts the snapshot's scratch size, queue geometry, and transport addresses,
even when the target sandbox was created with a different layout.

Transport capacity is fixed when the sandbox is created. Runtime queue resize
and VIRTIO feature negotiation are not supported.

## Source map

* Shared framing: [`src/hyperlight_common/src/transport.rs`](../src/hyperlight_common/src/transport.rs)
* Packed rings and pools: [`src/hyperlight_common/src/virtq`](../src/hyperlight_common/src/virtq)
* Arena layout: [`src/hyperlight_common/src/layout.rs`](../src/hyperlight_common/src/layout.rs)
* Guest transport: [`src/hyperlight_guest/src/transport`](../src/hyperlight_guest/src/transport)
* Guest initialization: [`src/hyperlight_guest_bin/src/transport.rs`](../src/hyperlight_guest_bin/src/transport.rs)
* Host runtime transport: [`src/hyperlight_host/src/mem/mgr.rs`](../src/hyperlight_host/src/mem/mgr.rs)
* Host validation and snapshots: [`src/hyperlight_host/src/mem/virtq`](../src/hyperlight_host/src/mem/virtq)
