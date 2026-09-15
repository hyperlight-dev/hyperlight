# Virtqueue host and guest communication

Hyperlight transports typed function calls over two shared memory VIRTIO
packed virtqueues. It uses the packed ring layout and ownership rules, but it
is not a discoverable VIRTIO device. Queue configuration, arena placement, and
notification behavior are part of the Hyperlight ABI.

This document describes the fixed-pool runtime, which rejects snapshots with
retained buffers. The [future design](#future-guest-allocated-pools-and-retained-snapshots)
describes planned retained-buffer support.

## Architecture

The guest is the driver (producer) for both queues. The host is the device
(consumer) for both queues.

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

Both rings, the checkpoint mailbox, and both pools occupy one fixed prefix of
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

The configured upper buffer size is 4 KiB by default. The G2H pool uses two
slot tiers:

* The first page contains sixteen 256 byte slots for control messages and
  logs.
* Complete configured size slots occupy the remaining pages.

The lower tier is a memory efficiency optimization. Most control messages,
scalar function arguments, and scalar results fit in a small slot. Giving each
of them a full upper slot would waste most of that slot and reduce the number
of concurrent allocations the pool can hold.

G2H senders allocate the header and control prefix separately when the external
byte stream aligns to the upper slot size. A small prefix uses a lower slot
while the external payload fills complete upper slots. Unaligned streams stay
combined to avoid adding a descriptor.

The H2G pool contains uniform configured size slots. The same tier selection
does not fit its preposted receive model. The guest publishes writable buffers
before it knows the size of the next host written payload. Uniform slots let
the host calculate how many buffers it needs without negotiating a size class
or searching the ring.

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

### Initialization

The host writes the normalized queue sizes, pool page counts, buffer sizes,
and arena GPA into fixed metadata at the top of scratch. It creates both
consumers at cursor zero without reading uninitialized ring contents.

On the first VM entry, the guest:

1. Reads the published configuration.
2. Reconstructs `TransportArena`.
3. Converts each transport GPA into its scratch GVA.
4. Creates both packed ring producers and slot pools.
5. Prefills H2G with one writable descriptor per available H2G slot, bounded
   by queue size.
6. Publishes the resulting `GuestContext`.

The host consumers observe the descriptors after guest initialization.

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

### External byte values

`ByteChunks` values stay outside the FlatBuffer. The FlatBuffer contains the
total logical value length and whether the value is chunked. The encoder can
then reference the caller's byte slices directly without first copying them into
one contiguous FlatBuffer.

`ExternalValueSource` is implemented by `RecvChain` for host decoding and by
`Segments` for guest decoding.

On the guest, completed shared memory allocations can become
`Bytes::from_owner` values. `ByteChunks` can therefore map transport storage
directly and keep its pool slots allocated until the final `Bytes` owner
drops. `VecBytes` deliberately copies into one contiguous `Vec<u8>`. The host
also copies every G2H external value before passing it to host code because
guest writable scratch is untrusted. External values remove intermediate
serialization copies. They do not guarantee that every direction is
end-to-end zero copy.

C guest function parameters expose `ByteChunks` as a borrowed
`hl_ByteChunks` array. Each `hl_ByteChunk` contains a pointer and length. The
descriptor array is allocated, but its payload pointers reference the
underlying `Bytes` directly. The view is valid until the guest function
returns. `hl_get_host_return_value_as_ByteChunks` returns an owning view that
must be released with `hl_free_byte_chunks`. Chunk arrays produced by C are
copied by `hl_result_from_ByteChunks`.

The wire format does not preserve the sender's `Vec<Bytes>` boundaries. It
records one total length, not each source chunk length. The receiver sees the
logical byte sequence split where it intersects transport buffers:

```text
 sender chunks:       [------][----------][----]
 logical byte stream: [------------------------]
 transport buffers:   [--][--------][--------][--------]
 receiver chunks:     [--][--------][--------][--------]
```

H2G chunking follows the preposted H2G slot size. G2H responses returned to
the guest follow the G2H writable slot size. The message header and FlatBuffer
can consume part of the first slot. The final slot can also be partial.

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
* The slot returns to the pool when the final owner drops.

Producer reset releases allocations still owned by queue bookkeeping. After
both producers reset and before H2G prefill, every live pool slot belongs to
guest retained `Bytes`.

### Trust boundary

The host treats guest rings, descriptors, headers, FlatBuffers, and payload
lengths as untrusted.

* Ring and pool access use separately bounded memory views.
* H2G descriptors must be writable, single buffer chains of the configured
  size before the host writes to them.
* G2H control and external values are copied into host owned storage before
  host code receives them.
* Canonical snapshot validation checks descriptor structure, addresses,
  lengths, alignment, pool bounds, uniqueness, and overlap.

## Snapshot checkpoint

The transport arena lives in scratch and is not captured as ordinary guest
memory. Guest producer and pool bookkeeping is normal guest state, while ring
and pool bytes live in scratch. Snapshot capture needs a canonical transport
state.

`MultiUseSandbox` tracks whether queue traffic occurred after the last
canonical boundary. A cached or clean snapshot needs no VM entry. A dirty
snapshot uses this flow:

```text
 Host                                 Guest
  |                                     |
  | mailbox = u64::MAX                  |
  | H2G SnapshotCheckpoint ------------>|
  | enter VM                            |
  |                                     | reclaim completed G2H work
  |                                     | reset G2H producer
  |                                     | reset H2G producer
  |                                     | count live pool slots
  |                                     | publish mailbox count
  |                                     | prefill H2G
  |<------------------------------------| halt
  | reset both consumers                |
  | read mailbox                        |
  | capture memory and rings            |
  | validate ring images                |
```

The canonical state is:

* G2H is empty at cursor zero.
* H2G starts at cursor zero with one writable descriptor per complete free
  slot, bounded by queue size.
* Guest producer and pool bookkeeping matches the rings.
* Driver and device event suppression is normalized.
* Host consumers start at cursor zero.

The snapshot stores normal guest memory plus the two canonical ring images.
Construction and loading validate the ring images against the finalized
layout. The layout and copied ring images remain immutable.
The OCI representation places ring images in the
[transport layer](./snapshot-oci-format.md). Pool payload bytes, the mailbox,
and host consumer cursors are not stored.

### Restore

Fixed-pool restore validates the persisted queue configuration, scratch size,
ring lengths, canonical descriptor structure, H2G slot alignment, pool bounds,
and descriptor overlap before exposing either queue.

Transport admission precedes changes to sandbox status, the cached snapshot,
and memory mappings.

It writes the arena GPA metadata and both ring images into fresh scratch, then
attaches new host consumers at cursor zero. Normal guest memory restores the
matching producer and pool bookkeeping. Restore does not need a preparatory VM
entry.

## Retention mailbox

The mailbox is one `u64` in the ring to pool alignment gap. It is outside both
rings and pools. Both sides derive its address from trusted arena geometry.
The host accesses it before VM entry and after guest halt.

The mailbox avoids a G2H checkpoint response. G2H can remain empty in the
canonical image even when retained G2H slots reduce available capacity.

Before a dirty checkpoint, the host writes `u64::MAX` as a pending marker.
After producer reset, the guest writes:

```text
g2h_producer.pool().num_live() + h2g_producer.pool().num_live()
```

The host reads the value after a successful guest halt and after resetting
both consumers.

* `u64::MAX` is a fatal incomplete checkpoint.
* Zero permits snapshot capture.
* A nonzero count rejects capture without poisoning the sandbox.

A nonzero rejection leaves the queues usable and keeps transport dirty.
Guest code can release retained values and retry the snapshot.

The count only answers whether retained slots exist. It does not contain pool
identity, addresses, or initialized lengths. Retained pool payloads cannot be
restored because pool bytes are absent from the snapshot.

## Placement and relocation limitations

The fixed-pool runtime places both rings, the mailbox, and both pools in one
host-owned arena at the scratch base. The guest reconstructs that layout from
host metadata. Canonical capture and attachment require the published arena
address to match the configured address.

Descriptors, pool owners, and producer state contain absolute GVAs. Restore
adopts the snapshot's scratch size, queue geometry, and transport addresses,
even when the target sandbox was created with a different layout.

Transport capacity is fixed when the sandbox is created. Runtime queue resize
and VIRTIO feature negotiation are not supported.

## Future guest allocated pools and retained snapshots

The planned design preserves retained `Bytes` and `ByteChunks` across capture,
restore, and cloning. It keeps the existing producer, consumer, and public byte
APIs. Retained-buffer rejection stays until alias mapping, ownership cleanup,
sanitization, and restore bootstrap are all connected.

Only rings and the mailbox occupy the fixed control arena. The guest allocates
whole pool backings with `alloc_phys_pages` after paging is ready. Pool capacity
still contributes to the scratch budget.

### Retained virtual addresses

Each pool generation reserves one page-aligned alias range. A completed buffer
uses `alias_base + pool_offset`. A monotonic cursor in `GuestContext` assigns
reservations. They are never reassigned to another pool in that timeline.

The alias cursor is ordinary snapshotted guest state. Restore replaces the
discarded timeline's mappings and owners together. Physical scratch allocation
uses its separate host-reset cursor.

`Bytes::from_owner` and pointers derived from it use stable alias GVAs.
Restore must preserve those addresses. Fresh scratch pools and physical backing
may have different placement. Separate sandboxes can use the same alias GVAs
with independent writable backing.

### Ownership and sanitization

`GuestMemOps` and `GuestMapping` share one backing record per pool. It holds the
pool extent, alias range, page pins, and active or retired state. `SlotPool`
remains the authority for slot allocation.

Only pages intersecting an owner's initialized prefix are pinned and mapped.
Owners on the same page share its alias mapping. `Bytes` clones and slices
share the existing owner and pins. The owner's full initialized prefix remains
retained even when a slice exposes fewer bytes.

Sanitization follows these rules:

* Zero each whole pool backing at creation, including padding outside slots.
* Clear an allocation's unused tail before exposing its mapping owner.
* At checkpoint, reset transport-owned allocations and clear free slots in
  active pools with retained pages.
* On final owner release, clear its initialized bytes on pages with other pins.
  Unmap pages whose pin count reaches zero. Complete translation invalidation
  before returning the lease to its original pool.

Retired backings accept no new allocations. Release cleanup keeps their shared
pages clean without a retired-pool registry or checkpoint sweep. Retired owners
access payloads only through stable aliases. Their old allocation addresses
remain metadata keys for lease release.

Unmapping removes aliases but does not free physical frames. Snapshot
compaction and physical-allocator reset recover space from omitted mappings.

### Host validation

Ring access stays bounded to fixed control storage. Payload bounds come from
the host's layout-derived guest-allocator scratch range. They exclude rings,
the mailbox, reserved page-table storage, scratch-top metadata, and exception
stacks. The guest-writable allocator cursor does not define these bounds.
Stable aliases are retention addresses, not transport descriptor addresses.

Validate complete payload ranges, direction, flags, chain limits, unique IDs,
configured H2G lengths, and overlap across simultaneously owned buffers.
Dynamic pools have no host-known base for slot-relative alignment checks.

Canonical validation distinguishes these H2G states:

| State | Available descriptors |
|---|---|
| Live checkpoint | Bounded by configured capacity. Retained owners can reduce prefill. |
| Fresh bootstrap | Full configured prefill. |
| Proposed persisted bootstrap image | Zero. |

### Checkpoint

The mailbox reports completion of checkpoint and restore preparation.
`u64::MAX` means pending and zero means ready. Unexpected values or an
incomplete guest exit are errors.

1. The host stops application traffic, writes pending, and publishes the
   header-only `SnapshotCheckpoint`.
2. Guest dispatch drops temporary request views, reclaims completed work,
   resets both producers, and sanitizes active pools.
3. The guest prefills H2G for continued source-sandbox execution, writes ready,
   and halts.
4. The host requires successful completion, resets its consumers, validates
   live canonical transport, and captures memory.

### Restore bootstrap

Initialized restore and snapshot-based construction share this path.
Pre-initialization snapshots use normal guest startup.

1. Preflight format and geometry before unmapping current regions.
2. Restore guest memory, alias mappings, and captured registers. Recreate
   scratch, publish the host snapshot generation, and reset physical allocation.
3. Keep H2G publication disabled, write pending, and enter the dispatch
   entrypoint without a request.
4. Before H2G receive or transport-dependent tracing, the guest checks the
   generation, resets old producers, and retires their backing. Reset may touch
   fixed rings but must not access old pool bytes.
5. Allocate and zero fresh pools, reserve fresh alias ranges, construct both
   producers, and prefill H2G.
6. Record the generation, write ready, and halt without an application call.
7. The host validates fresh rings and payload bounds, attaches or resets its
   consumers, and enables normal traffic.

The sandbox stays poisoned or internally unavailable until bootstrap succeeds.
Cancellation and abort cleanup use the same guest-entry lifecycle as calls and
checkpoints. An H2G checkpoint message requires a usable queue, so it cannot
initiate this bootstrap.

### Persistence

Retained payloads enter the ordinary memory snapshot through alias mappings.
The snapshot walker preserves their GVAs and copies each mapped physical page
once. The transport layer stores control state, not retained payloads.

The preferred representation keeps the existing transport container with
canonical empty bootstrap rings. This representation requires confirmation
before implementation. Captured ring images could also serve as structural
metadata. In either case, normal traffic requires freshly rebuilt queues.

## Source map

* Shared framing: [`src/hyperlight_common/src/transport.rs`](../src/hyperlight_common/src/transport.rs)
* Packed rings and pools: [`src/hyperlight_common/src/virtq`](../src/hyperlight_common/src/virtq)
* Arena layout: [`src/hyperlight_common/src/layout.rs`](../src/hyperlight_common/src/layout.rs)
* Guest transport: [`src/hyperlight_guest/src/transport`](../src/hyperlight_guest/src/transport)
* Guest initialization: [`src/hyperlight_guest_bin/src/transport.rs`](../src/hyperlight_guest_bin/src/transport.rs)
* Host runtime transport: [`src/hyperlight_host/src/mem/mgr.rs`](../src/hyperlight_host/src/mem/mgr.rs)
* Host validation and snapshots: [`src/hyperlight_host/src/mem/virtq`](../src/hyperlight_host/src/mem/virtq)
