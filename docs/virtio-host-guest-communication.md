# Virtqueue host and guest communication

Hyperlight transports typed function calls over two shared memory VIRTIO
packed virtqueues. It uses the packed ring layout and ownership rules, but it
is not a discoverable VIRTIO device. Queue configuration, arena placement, and
notification behavior are part of the Hyperlight ABI.

This document describes the runtime transport, snapshot checkpoint, retention
mailbox, and placement constraints.

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

Offsets after the G2H ring depend on configured queue depths and pool pages.
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

The H2G pool contains uniform configured size slots. The same tier selection
does not fit its preposted receive model. The guest publishes writable buffers
before it knows the size of the next host written payload. Uniform slots let
the host calculate how many buffers it needs without negotiating a size class
or searching the ring.

Queue depths, upper buffer sizes, and pool page counts are configurable when
the sandbox is created.

### Initialization

The host writes the normalized queue depths, pool page counts, buffer sizes,
and arena GPA into fixed metadata at the top of scratch. It creates both
consumers at cursor zero without reading uninitialized ring contents.

On the first VM entry, the guest:

1. Reads the published configuration.
2. Reconstructs `TransportArena`.
3. Converts each transport GPA into its scratch GVA.
4. Creates both packed ring producers and slot pools.
5. Prefills H2G with one writable descriptor per available H2G slot, bounded
   by queue depth.
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

### External byte values

Large `VecBytes` and `ByteChunks` values stay outside the FlatBuffer. The
FlatBuffer contains the total logical value length and whether the value is
chunked. The encoder can then reference the caller's byte slices directly
without first copying them into one contiguous FlatBuffer.

On the guest, completed shared memory allocations can become
`Bytes::from_owner` values. `ByteChunks` can therefore map transport storage
directly and keep its pool slots allocated until the final `Bytes` owner
drops. `VecBytes` deliberately copies into one contiguous `Vec<u8>`. The host
also copies every G2H external value before passing it to host code because
guest writable scratch is untrusted. External values remove intermediate
serialization copies. They do not guarantee that every direction is
end-to-end zero copy.

The wire format does not preserve the sender's `Vec<Bytes>` boundaries. It
records one total length, not each source chunk length. The receiver sees the
logical byte sequence split where it intersects transport buffers:

```text
 sender chunks:       [------][----------][----]
 logical byte stream: [------------------------]
 transport buffers:   [--------][--------][--------][--]
 receiver chunks:     [--------][--------][--------][--]
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

1. The guest encodes a `FunctionCall` and calculates bounded response
   capacity from free G2H descriptors and slots.
2. The guest submits one G2H chain. Its readable region contains the request.
   Its writable region reserves the response.
3. The guest notifies the host through `OutBAction::VirtqNotify`.
4. The host polls G2H and copies all request data out of guest writable scratch.
5. The host invokes the registered host function.
6. The host writes a `Response` into the writable region and completes the
   same chain.
7. The VM resumes. The guest polls the completion and checks its correlation
   ID.

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
  | validate and capture rings          |
```

The canonical state is:

* G2H is empty at cursor zero.
* H2G starts at cursor zero with one writable descriptor per complete free
  slot, bounded by queue depth.
* Guest producer and pool bookkeeping matches the rings.
* Driver and device event suppression is normalized.
* Host consumers start at cursor zero.

The snapshot stores normal guest memory plus the two canonical ring images.
The OCI representation places ring images in the
[transport layer](./snapshot-oci-format.md). Pool payload bytes, the mailbox,
and host consumer cursors are not stored.

### Restore

Restore validates the persisted queue configuration, scratch size, ring
lengths, canonical descriptor structure, H2G slot alignment, pool bounds, and
descriptor overlap before exposing either queue.

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
g2h_pool.num_live() + h2g_pool.num_live()
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

### Planned retained payload snapshots

The mailbox is intended to carry a bounded, size-prefixed FlatBuffer manifest.
The planned manifest has separate G2H and H2G vectors. Each retained range
contains:

```text
offset: u64    pool-relative slot start
len:    u32    initialized payload length
```

The host can validate exact slot starts and bounds, zero the retained backing,
copy only initialized ranges, and include that sanitized backing in the
snapshot. Free slots, posted H2G buffers, unused slot tails, and unrelated
bytes sharing a retained page remain zero.

The size prefix is published last. The host bounds it by trusted mailbox
capacity before FlatBuffer verification, then validates every range against
the configured pool geometry.

## Placement and relocation limitations

Arena placement is host owned. `SandboxMemoryLayout` places it at the scratch
base, publishes the GPA, and requires the guest to reconstruct that exact
layout. Host attachment rejects any published arena base that differs from the
configured address. The guest cannot choose placement around its other scratch
allocations.

The transport also stores absolute guest virtual addresses in descriptors,
pool owners, and guest producer state. Snapshot restore depends on the same
scratch size, queue geometry, and transport addresses.

### Retained virtual addresses

Pool relocation cannot transparently change a retained buffer's GVA.
`Bytes::from_owner` stores an absolute data pointer. Its clones and slices can
exist anywhere in guest state. Unsafe Rust and C guests can also retain raw
pointers derived from a live value. The host cannot discover and rebase every
such pointer during restore.

Wrapping `Bytes` does not solve this because the wrapped `Bytes` still contains
an absolute pointer. A relocatable value would need to replace `Bytes` with an
arena relative handle that resolves its address on every access and does not
promise a stable borrowed slice. That would be a different guest API and would
not constrain pointers created by unsafe code.

Snapshots containing retained transport values must restore each pool at the same 
GVA. The GPA or host backing may move only if page tables and host memory access 
preserve that GVA. Restore must fail if it cannot reserve or recreate the original 
virtual range. 

A guest allocated transport needs a stronger publication and relocation
contract:

* The guest allocates rings and pools from scratch and publishes all regions.
* The host validates alignment, bounds, ordering, overlap, and capacity before
  attaching consumers.
* Snapshot metadata records the published region placement.
* Restore preserves pool GVAs when retained values exist.
* GVA relocation is limited to snapshots without retained values, where known
  ring, pool, producer, and guest context state can be rebuilt, or to a future
  offset based guest API.

This contract is part of the
[snapshot ABI](./snapshot-versioning.md) and needs an explicit format change.

Transport capacity is also fixed when the sandbox is created. Runtime queue
resize and VIRTIO feature negotiation are not supported.

## Source map

* Shared framing: [`src/hyperlight_common/src/transport.rs`](../src/hyperlight_common/src/transport.rs)
* Packed rings and pools: [`src/hyperlight_common/src/virtq`](../src/hyperlight_common/src/virtq)
* Arena layout: [`src/hyperlight_common/src/layout.rs`](../src/hyperlight_common/src/layout.rs)
* Guest transport: [`src/hyperlight_guest/src/transport`](../src/hyperlight_guest/src/transport)
* Guest initialization: [`src/hyperlight_guest_bin/src/transport.rs`](../src/hyperlight_guest_bin/src/transport.rs)
* Host runtime transport: [`src/hyperlight_host/src/mem/mgr.rs`](../src/hyperlight_host/src/mem/mgr.rs)
* Host validation and snapshots: [`src/hyperlight_host/src/mem/virtq`](../src/hyperlight_host/src/mem/virtq)
