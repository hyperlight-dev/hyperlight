# HIP 0001 - Virtio-Inspired Ring Buffer for Hyperlight I/O

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
    - [Goals](#goals)
    - [Non-Goals](#non-goals)
- [Proposal](#proposal)
    - [User Stories](#user-stories)
        - [Story 1: Stream-based Communication](#story-1-stream-based-communication)
        - [Story 2: High-throughput RPC](#story-2-high-throughput-rpc)
    - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
    - [Packed Virtqueue Overview](#packed-virtqueue-overview)
        - [Bidirectional Communication](#bidirectional-communication)
        - [Memory Layout](#memory-layout)
        - [Request-Response Flow](#request-response-flow)
        - [Publishing and Consumption Protocol](#publishing-and-consumption-protocol)
    - [Performance Optimizations](#performance-optimizations)
    - [Dynamic Response Sizing](#dynamic-response-sizing)
    - [Type System Design](#type-system-design)
        - [Low Level API](#low-level-api)
        - [Higher-Level API](#higher-level-api)
    - [Test Plan](#test-plan)
- [Implementation History](#implementation-history)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
    <!-- /toc -->

## Summary

This HIP proposes implementing a ring buffer mechanism for Hyperlight I/O, loosely based on the
virtio packed virtqueue
[specification](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-720008).
The ring buffer will serve as the foundation for host-guest communication, supporting use cases such
as streams, RPC, and other I/O patterns in both single-threaded and multi-threaded environments.

The design leverages virtio's well-defined publishing/consumption semantics and memory safety
guarantees while adapting them to Hyperlight's specific needs. Since we control both ends of the
queue, we can deviate from strict virtio compliance where it makes sense (see
[Difference from virtio spec](#difference-from-virtio-spec) section).

## Motivation

Currently, Hyperlight lacks a good I/O story. Each interaction between host and guest relies on
individual VM exits, which, while providing strong shared memory access safety guarantees, also
introduces significant overhead. Supporting streaming communication patterns through this mechanism
is hard as exiting the VM context for each memory chunk transferred in either direction would result
in performance degradation. A ring buffer can mitigate this overhead by:

- **Reducing VM exits**: Batch multiple requests, responses, and function calls, only exiting when
  necessary
- **Foundation for streams**: Enable bidirectional, streaming I/O patterns
- **Foundation for futures**: Support futures as a special case of a stream with a single element
- **Better cache locality**: The packed queue format improves cache characteristics. While this
  claim is speculative, it's worth noting that improving the cache behavior of the split queue,
  which managed state across three separate tables, was a primary motivation for developing the
  packed virtqueue specification.

### Goals

- Implement a low-level ring buffer based on virtio packed virtqueue semantics
- Support both single-threaded (host and guest on the same thread) and multi-threaded scenarios
- Maintains backward compatibility, which means current function call model can be ported to queue
  without changes in public API - as such the ring buffer is an implementation detail
- Provide memory-safe abstractions over shared memory regions
- Enable batching and notification suppression to minimize VM exits
- Establish the foundation for higher-level APIs (streams, async I/O)

### Non-Goals

- 100% virtio specification compliance
- Indirect descriptor table support (deferred to future work if needed)
- Immediate async/await integration (deferred to future work)

## Proposal

We propose implementing a ring buffer mechanism based on the virtio packed virtqueue specification.
The packed format offers superior cache characteristics compared to the split queue format by
keeping descriptors, driver area, and device area in contiguous memory. Both sides of the ring only
need to poll a single memory address to detect the next available or used slot.

### User Stories

#### Story 1: Stream-based Communication

As a Hyperlight user, I want to stream data between host and guest (e.g., file I/O, network sockets)
without incurring a VM exit for each small read/write operation. The ring buffer should allow me to
batch multiple operations and only exit when buffers are full or when I explicitly flush.

#### Story 2: High-throughput RPC

As a Hyperlight developer, I want to make multiple function calls from guest to host with minimal
overhead. The ring buffer should let me queue multiple requests, suppress notifications, and process
responses in batches.

### Risks and Mitigations

**Risk**: Malicious guest corrupting the queue
**Mitigation**: The host must treat all guest-provided data as untrusted:

- **Address validation**: Before accessing any buffer, verify that the GPA falls within the
  permitted guest memory region (scratch/shared memory). Reject descriptors pointing outside
  this region.
- **No racy access**: Even if a guest violates the synchronization protocol and modifies a buffer
  while the host is reading it, the host must not exhibit undefined behavior. Use volatile reads
  for buffer contents after the synchronizing acquire load.
- **Invariant checking**: Assert queue state invariants after each operation. If any invariant is
  violated (e.g., wrap counter inconsistency, invalid descriptor chain), poison the sandbox
  immediately.
- **Bound checking**: Validate `len` fields to prevent out-of-bounds access. A malicious guest
  could set `len` larger than the actual buffer allocation.
- **No double-use**: Track which buffers are currently owned by each side. The host should never
  read from a buffer it hasn't acquired via the proper protocol.


**Risk**: Complexity of implementing a lock-free ring buffer with proper memory ordering
**Mitigation**: Follow established virtio semantics; use atomic operations with appropriate memory
orderings; implement comprehensive testing

**Risk**: Potential deadlocks in backpressure scenarios **Mitigation**: Provide clear documentation
of blocking behavior; consider timeout mechanisms; shuttle testing

**Risk**: Memory safety issues with shared buffer management **Mitigation**: Employ a strong type
system; implement ownership tracking; perform thorough validation and fuzzing

## Design Details

### Packed Virtqueue Overview

Before diving into the specifics, it will be useful to agree on some terminology. We borrow terms
from the virtio spec:

- **Driver**: The side that allocates buffers in shared memory and submits descriptors. In
  Hyperlight, this is always the **guest**, since only the guest can allocate memory accessible to
  both sides. The driver is essentially providing buffers for the device to use.
- **Device**: The side that reads from and writes to driver-provided buffers on request. In
  Hyperlight, this is always the **host**. The host acts as a paravirtualized device, processing
  requests and writing responses into guest-provided buffers.

This mapping is fixed regardless of communication direction. For host-to-guest calls, the guest
pre-populates writable buffers that the host fills with incoming work. For guest-to-host calls,
the guest submits request buffers with attached response buffers.

#### Bidirectional Communication

For full bidirectional communication between host and guest, we need two queues:

1. Host-to-Guest Queue: Host acts as driver (producer), guest acts as device (consumer), e.g. queue
   elements represent host to guest function calls,
2. Guest-to-Host Queue: Guest acts as driver (producer), host acts as device (consumer), e.g. queue
   elements represent guest to host function calls,

Each queue is independent and implements the same packed virtqueue semantics described below.

#### Memory Layout

The queue structure reside in shared memory and are accessible to both host and guest. The layout
for queue that allocates the buffer from buffer pool that resides in shared memory could look like
in the picture below. The `addr` field contains an offset (or physical address, depending on
implementation) pointing to where the actual buffer data lives in the shared memory region. The
descriptor itself only contains metadata about the buffer and is agnostic to where the address
points. The only requirements for the address is that both host and guest can translate it to
referenceable pointer to the buffer memory. The `addr` field does not preserve Rust's notion of
pointer provenance.

Each descriptor is 16 bytes and has the following layout:

```rust
struct Descriptor {
    addr: u64,  // Guest Physical Address where buffer resides
    len: u32,   // Buffer length in bytes
    id: u16,    // Buffer ID for tracking
    flags: u16, // AVAIL, USED, WRITE, NEXT, INDIRECT, etc.
}
```

<img width="768" height="935" alt="layout" src="https://github.com/user-attachments/assets/e39d1b4e-c00a-4776-98a1-ceaf485d82e0" />

#### Request-Response Flow

The typical flow for a request-response interaction works as follows:

1. Driver allocate buffers: The driver allocates buffers from the shared memory pool
2. Driver submits descriptors: The driver writes one or more descriptors into the ring:
    - Read descriptors: Point to buffers containing request data (device reads from these)
    - Write descriptors: Point to empty buffers where the device should write responses
3. Device processes request: The device reads data from read-buffers and writes results into
   write-buffers
4. Device marks completion: The device updates the descriptor flags to indicate completion

**Step 1:** Driver submits request with read buffer (request) and write buffer (response)

<img width="1324" height="726" alt="submit" src="https://github.com/user-attachments/assets/a3ee2dea-a55b-4d50-8b96-1702617a21f0" />

**Step 2:** Device processes and writes response

<img width="1375" height="714" alt="process" src="https://github.com/user-attachments/assets/6ae27a64-29c6-47a4-80a9-f8bd4ad0c161" />

Note how the driver pre-allocates the response buffer and provides it to the device via a write
descriptor. The device then writes its response directly into this buffer. The `len` field in the
used descriptor tells the driver how many bytes were actually written (128 in this example, even
though 256 bytes were available). The driver is allowed to use the same descriptor for read and
write in which case the request data could be overwritten.

#### Publishing and Consumption Protocol

The packed virtqueue uses a circular descriptor ring where both driver and device maintain their own
wrap counters. Each descriptor has two key flags:

- `AVAIL`: Indicates availability from the driver's perspective. After setting this flag, descriptor
  ownership is transferred to the device and descriptor cannot be mutated by the driver.
- `USED`: Indicates usage from the device's perspective. Similarly, after setting this flag,
  descriptor ownership is transferred back to the driver and the slot can be reused.

In this scheme, both sides only need to poll a single memory location (the next descriptor in order)
to detect new work or completions.

The driver will publish buffers until there is no space left in the descriptor ring, at which point
it must wait for the device to process some descriptors before it can continue. Both publishing and
processing wrap around when reaching the end of the descriptor table, with the wrap counter flipping
to indicate the beginning of a new round through the ring.

This mechanism ensures that no locks are required for synchronization, only memory barriers combined
with atomic publishing of flags ensure that the other side will never observe a partial update:

- Driver: Write descriptor fields ? memory barrier ? atomic Release-store flags
- Device: Atomic Acquire-load flags ? memory barrier ? read descriptor fields

Because the packed ring reuses the same descriptor slot for both `available` and `used` states and
both sides only poll a single next slot, each side needs to differentiate between "this change
belongs to the current lap in the ring" and "this is an old value from the previous lap." This is
done using "wrap" counters:

- Each side keeps a boolean "wrap" flag that toggles when it passes the last descriptor in the ring,
- When the driver publishes an available descriptor, it sets `AVAIL` to its wrap bit and `USED` to
  the inverse. When the device publishes a used descriptor, it sets both `AVAIL` and `USED` to its
  wrap bit.
- The reader of a descriptor then compares the flags it reads to its own current wrap to decide if
  the descriptor is newly available/used now, or is it lagging behind.

### Comparison with current implementation

Hyperlight uses two separate shared-memory stacks to pass function calls and returns between host
and guest:

- an input stack the guest pops from (host -> guest calls) and
- an output stack the guest pushes to (guest -> host returns).

Each of these memory regions begins with an 8-byte header that stores a relative offset pointing to
the next free byte in the stack.

When pushing, the payload which is flatbuffer-serialized message is written at the current stack
pointer, followed by the 8-byte footer that containing just written payload's starting offset.
Finally, the header is advanced to point past the footer. This makes each item a pair of
`payload + back-pointer`, so the top of the stack can always be found in O(1) without extra
metadata.

Popping from the stack mirrors this process. The guest reads stack pointer from the input stack's
header. It then reads the 8-byte back-pointer located just before stack pointer to get last element
offset in the buffer. It treats the slice starting at that offset as the flatbuffer-serialized
payload. The last step is to deserialize the slice, rewind the stack pointer to just consumed
payload offset.

This model is a natural fit for synchronous, in-order communication, but the LIFO stack semantics
makes asynchronous constructs with out-of-order completion impossible to implement. This proposal
suggests we replace current implementation with ring buffer approach because the virtio-queue can
support both sync and async work completion.

<img width="921" height="772" alt="hl-model" src="https://github.com/user-attachments/assets/0ee9cf15-200d-4ef4-8c9b-6ffaac05d4c0" />


| Aspect                    | Current (Stack-based)                      | Proposed (Ring Buffer)                                  |
|-------------------------- | ------------------------------------------ | ------------------------------------------------------- |
| **Guest→Host call**      | `push()` -> `outb` -> VM Exit -> `pop()`   | `submit()` × N -> `notify()` -> VM Exit -> `poll()` × N |
| **VM exits per N calls**  | N exits                                    | 1 exit (batched)                                        |
| **Completion order**      | LIFO (stack)                               | FIFO or out-of-order                                    |
| **Async support**         | Not possible                               | Supported via descriptor IDs                            |
| **Flow control**          | Implicit (stack size)                      | Explicit (ring capacity + event suppression)            |
| **Memory access pattern** | Two separate regions (input/output stacks) | Single contiguous ring + buffer pool                    |

### Performance Optimizations

The primary performance benefits of the ring buffer come from reducing number of expensive
operations, specifically VM exits, but also improving memory access patterns. This section discusses
the potential performance improvements that stems from using ring buffer.

In the current Hyperlight model, every host-guest interaction triggers a VM exit. While this
provides strong isolation guarantees, it comes at a significant cost. Each VM exit involves:

- Saving the guest CPU state
- Switching to the hypervisor/host context
- Processing the request
- Restoring guest CPU state and resuming execution

For I/O-intensive workloads, this overhead dominates execution time. Consider a scenario where a
host needs to transfer data as stream to the guest and each stream chunk triggers VM exit.

**1. Notification Suppression**

The virtio queue defines event suppression mechanism that allow both sides to control when they want
to be notified about the submissions or completions in the queue. Notification suppression allow for
different batching strategies. For example:

- A driver can queue multiple requests, suppress notifications, and only notify the device once when
  ready
- A device can process descriptors in batches and only notify the driver when a certain threshold is
  reached or when the ring is about to fill up

**2. Event based notifications**

In the single threaded application the notification involve VM exit but in multi-thread environment
where host and guest are running in separate threads we can leverage event-based notifications (for
example `ioeventfd` for kvm). This is especially useful for streaming scenarios where the guest can
continue processing while the host consumes data asynchronously.

**3. Inline Descriptors**

An interesting optimization that is not part of virtio-queue spec but is worth considering is
embedding "tiny" payloads into descriptor. Virtio model, no matter the size of the payload,
requires:

1. Allocating a buffer in shared memory
2. Writing the data to that buffer
3. Pointing a descriptor at the buffer
4. The receiver reading from the buffer

We can eliminate all the steps for small messages by embedding the data directly into the
descriptor:

```rust
const INLINE: u16 = 1 << 8;  // New flag

struct Descriptor {
    addr: u64,
    len: u16,
    data: [u8; 16],  // addr is unused, data is written inline in the descriptor
    id: u16,
    flags: u16,
}
```

or

```rust
struct Descriptor {
    // When INLINE is set, reinterpret addr/len as data:
    data: [u8; 12],  // addr(8) + len(4) repurposed as inline data
    id: u16,
    flags: u16,
}

```

When the `INLINE` flag is set, the `addr` is unused. This optimization, inspired by io_uring,
eliminates memory indirection for common small messages, improving both latency and cache behavior.
The tradeoff is the increased size of descriptor table. Alternatively we could repurpose the `addr`
and `len` as raw bytes providing 12 bytes of inline storage. We should asses if any of flatbuffer
schema serialized data can actually fit into small inline data.

**4. Descriptor Chaining - scatter gather list**

Descriptors can be chained using the `NEXT` flag. This enables zero-copy scatter-gather I/O
patterns. Imagine again the stream running on the host. We want to gather few chunks before sending
it to the guest. For each incoming chunk we can grab the buffer from the buffer pool and write data
to it. After reaching some threshold we want to present all the buffers to guest. scatter-gather
list allow us to represent the chunks as descriptor chain without need to copy it to contiguous
memory.

### Dynamic Response Sizing

A slightly annoying consequence of using virtio model is that we have to account for the fact that
the driver pre-allocates response buffers, but the device may produce variable-length responses.
This means that the pre allocated size might not be enough to write a complete response. The
proposed solution to that is to use truncation protocol. The protocol can be implemented in the
descriptor layer or in the flatbuffer schema:

1. Driver allocates buffer of estimated size
2. Device writes up to buffer length
3. Device sets actual written length in descriptor
4. If `actual_length > buffer_length`, device sets a `TRUNCATED` flag,
5. Driver can re-submit with larger buffer if needed

### Snapshotting

Snapshotting requires that the descriptor table has no in-flight guest-to-host requests and any
attempt to snapshot a sandbox with such pending requests will result in a snapshot failure.

### Difference from virtio spec

- Do not support indirect descriptor table (can be deferred to future work if needed),
- Do not support feature negotiation, set of features is fixed for driver and device,
- Only support packed queue,
- Introduce inline data optimization in descriptor (only if benchmarks support the claim)

### Type System Design

This section provides an overview of the implemented type system. The API is internal to Hyperlight.

#### Memory Access Abstraction

The `MemOps` trait abstracts memory access, allowing the virtqueue to work with different backends
(host vs guest memory). This decouples the ring logic from the underlying memory representation.

```rust
/// Backend-provided memory access for virtqueue.
///
/// Implementations must ensure that:
/// - Pointers passed to methods are valid for the duration of the call
/// - Memory ordering guarantees are upheld as documented
/// - Reads and writes don't cause undefined behavior (alignment, validity)
pub trait MemOps {
    type Error;

    /// Read bytes from physical memory.
    /// Used for reading buffer contents pointed to by descriptors.
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write bytes to physical memory.
    fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error>;

    /// Load a u16 with acquire semantics.
    /// `addr` must translate to a valid, aligned AtomicU16 in shared memory.
    fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error>;

    /// Store a u16 with release semantics.
    /// `addr` must translate to a valid AtomicU16 in shared memory.
    fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error>;
}
```

#### Descriptor and Event Suppression

The descriptor format follows the VIRTIO packed virtqueue specification. Each descriptor
represents a memory buffer in a scatter-gather list.

```rust
bitflags! {
    /// Descriptor flags as defined by VIRTIO specification.
    pub struct DescFlags: u16 {
        const NEXT     = 1 << 0;   // Buffer continues via next descriptor
        const WRITE    = 1 << 1;   // Device write-only (otherwise read-only)
        const INDIRECT = 1 << 2;   // Buffer contains list of descriptors
        const AVAIL    = 1 << 7;   // Available flag for wrap counter
        const USED     = 1 << 15;  // Used flag for wrap counter
    }
}

#[repr(C)]
pub struct Descriptor {
    /// Physical address of the buffer
    pub addr: u64,
    /// Length in bytes (for used: bytes written by device)
    pub len: u32,
    /// Buffer ID for correlating completions with submissions
    pub id: u16,
    /// Flags (NEXT, WRITE, INDIRECT, AVAIL, USED)
    pub flags: u16,
}

impl Descriptor {
    /// Read descriptor with acquire semantics for flags.
    /// This is the primary synchronization point for consuming descriptors.
    pub fn read_acquire<M: MemOps>(mem: &M, addr: u64) -> Result<Self, M::Error>;

    /// Write descriptor with release semantics for flags.
    /// This is the primary synchronization point for publishing descriptors.
    pub fn write_release<M: MemOps>(&self, mem: &M, addr: u64) -> Result<(), M::Error>;

    /// Did the driver mark this descriptor available in current round?
    pub fn is_avail(&self, wrap: bool) -> bool;

    /// Did the device mark this descriptor used in current round?
    pub fn is_used(&self, wrap: bool) -> bool;
}

bitflags! {
    pub struct EventFlags: u16 {
        const ENABLE  = 0x0;  // Always notify
        const DISABLE = 0x1;  // Never notify (polling mode)
        const DESC    = 0x2;  // Notify at specific descriptor index
    }
}

/// Event suppression structure for controlling notifications.
/// Both sides can control when they want to be notified.
#[repr(C)]
pub struct EventSuppression {
    /// bits 0-14: descriptor offset, bit 15: wrap counter
    pub off_wrap: u16,
    /// bits 0-1: flags (ENABLE/DISABLE/DESC), bits 2-15: reserved
    pub flags: u16,
}
```

#### Buffer Pool

An allocator for virtio buffer management. This will operate on guest physical
addresses from page allocator.

```rust
/// Trait for buffer providers.
pub trait BufferProvider {
    /// Allocate at least `len` bytes.
    fn alloc(&self, len: usize) -> Result<Allocation, AllocError>;

    /// Free a previously allocated block.
    fn dealloc(&self, alloc: Allocation) -> Result<(), AllocError>;

    /// Resize by trying in-place grow; otherwise reserve new block and free old.
    fn resize(&self, old: Allocation, new_len: usize) -> Result<Allocation, AllocError>;
}

/// Allocation result
pub struct Allocation {
    /// Starting address of the allocation
    pub addr: u64,
    /// Length in bytes rounded up to slab size
    pub len: usize,
}

/// Two-tier buffer pool with small and large slabs.
/// - Lower tier (L=256): for control messages, small descriptors
/// - Upper tier (U=4096): for larger data buffers
/// Small allocations try lower tier first, falling back to upper on OOM.
pub struct BufferPool<const L: usize = 256, const U: usize = 4096>;
```

#### Ring Producer/Consumer

The core ring types implement the packed virtqueue protocol. The producer submits buffer chains
and polls for completions; the consumer polls for available buffers and marks them used.

```rust
/// Producer (driver) side of a packed virtqueue.
/// Submits buffer chains for the device to process and polls for completions.
pub struct RingProducer<M: MemOps> {
    mem: M,
    avail_cursor: RingCursor,      // Next available descriptor position
    used_cursor: RingCursor,       // Next used descriptor position
    num_free: usize,               // Free slots in the ring
    desc_table: DescTable,         // Descriptor table in shared memory
    id_free: SmallVec<[u16; 256]>, // Stack of free IDs (allows out-of-order completion)
    id_num: SmallVec<[u16; 256]>,  // Chain length per ID
    drv_evt_addr: u64,             // Controls when device notifies about used buffers
    dev_evt_addr: u64,             // Reads device event to check notification preference
}

impl<M: MemOps> RingProducer<M> {
    /// Submit a buffer chain to the ring.
    /// Returns the descriptor ID assigned to this chain.
    pub fn submit_available(&mut self, chain: &BufferChain) -> Result<u16, RingError>;

    /// Submit with notification check based on device's event suppression settings.
    pub fn submit_available_with_notify(&mut self, chain: &BufferChain) -> Result<SubmitResult, RingError>;

    /// Poll for a used buffer. Returns WouldBlock if no completions available.
    pub fn poll_used(&mut self) -> Result<UsedBuffer, RingError>;

    /// Enable/disable used-buffer notifications from device.
    pub fn enable_used_notifications(&mut self) -> Result<(), RingError>;
    pub fn disable_used_notifications(&mut self) -> Result<(), RingError>;
}

/// Consumer (device) side of a packed virtqueue.
/// Polls for available buffer chains and marks them as used after processing.
pub struct RingConsumer<M: MemOps> {
    mem: M,
    avail_cursor: RingCursor,
    used_cursor: RingCursor,
    desc_table: DescTable,
    id_num: SmallVec<[u16; 256]>,  // Per-ID chain length learned when polling
    num_inflight: usize,
    drv_evt_addr: u64,
    dev_evt_addr: u64,
}

impl<M: MemOps> RingConsumer<M> {
    /// Poll for an available buffer chain.
    /// Returns the chain ID and BufferChain containing all buffers.
    pub fn poll_available(&mut self) -> Result<(u16, BufferChain), RingError>;

    /// Mark a chain as used. `written_len` is total bytes written to writable buffers.
    pub fn submit_used(&mut self, id: u16, written_len: u32) -> Result<(), RingError>;

    /// Submit used with notification check based on driver's event suppression settings.
    pub fn submit_used_with_notify(&mut self, id: u16, len: u32) -> Result<bool, RingError>;
}

/// Result of submitting a buffer to the ring.
pub struct SubmitResult {
    pub id: u16,      // Descriptor ID assigned
    pub notify: bool, // Whether to notify the other side
}

/// A buffer returned after being used by the device.
pub struct UsedBuffer {
    pub id: u16,   // Descriptor ID
    pub len: u32,  // Bytes written by device
}
```

#### Buffer Chain Builder

Type-state pattern enforces that readable buffers are added before writable buffers, preventing
invalid chain construction at compile time.

```rust
/// Type-state: Can add readable buffers
pub struct Readable;

/// Type-state: Can add writable buffers (no more readables allowed)
pub struct Writable;

/// Builder for buffer chains using type-state to enforce readable/writable order.
/// Invariants enforced by the type system:
/// - At least one buffer must be present in the chain
/// - Readable buffers must be added before writable buffers
pub struct BufferChainBuilder<T> {
    elems: SmallVec<[BufferElement; 16]>,
    split: usize,  // Index separating readables from writables
    marker: PhantomData<T>,
}

impl BufferChainBuilder<Readable> {
    /// Create a new builder in Readable state.
    pub fn new() -> Self;

    /// Add a readable buffer (device reads from this).
    pub fn readable(self, addr: u64, len: u32) -> Self;

    /// Add a writable buffer. Transitions to Writable state,
    /// preventing further readable additions.
    pub fn writable(self, addr: u64, len: u32) -> BufferChainBuilder<Writable>;

    /// Build the chain. Fails if empty.
    pub fn build(self) -> Result<BufferChain, RingError>;
}

impl BufferChainBuilder<Writable> {
    /// Add another writable buffer.
    pub fn writable(self, addr: u64, len: u32) -> Self;

    /// Build the chain.
    pub fn build(self) -> Result<BufferChain, RingError>;
}

/// A chain of buffers ready for submission.
pub struct BufferChain {
    elems: SmallVec<[BufferElement; 16]>,
    split: usize,
}

impl BufferChain {
    pub fn readables(&self) -> &[BufferElement];
    pub fn writables(&self) -> &[BufferElement];
}
```

#### High-Level Virtqueue API

Wraps ring primitives with buffer management and notification handling. This layer abstracts
buffer allocation and provides a request/response model with token-based correlation. For
simplicity this draft omits a batching API.

```rust
/// Trait for notifying about new requests in the virtqueue.
pub trait Notifier {
    fn notify(&self, stats: QueueStats);
}

pub struct QueueStats {
    pub num_free: usize,
    pub num_inflight: usize,
}

/// A token representing a sent request, used for correlating responses.
pub struct Token(pub u16);

/// A request received from the driver side.
pub struct Request {
    pub token: Token,
    pub data: Bytes,
}

/// A response received after the device processes a request.
pub struct Response {
    pub token: Token,
    pub data: Bytes,
    pub written: usize,
}

/// High-level virtqueue producer for sending requests and receiving responses.
/// Manages buffer allocation and tracks in-flight requests.
pub struct VirtqProducer<M: MemOps, N: Notifier, P: BufferProvider> {
    inner: RingProducer<M>,
    notifier: N,
    pool: P,
    inflight: Vec<Option<ProducerInflight>>,
}

impl<M: MemOps, N: Notifier, P: BufferProvider + Clone> VirtqProducer<M, N, P> {
    /// Send a request with pre-allocated response capacity.
    /// Returns a token for correlating with the response.
    pub fn send(&mut self, req: &[u8], resp_cap: usize) -> Result<Token, VirtqError>;

    /// Poll for a single response. Returns None if no completions available.
    pub fn poll_once(&mut self) -> Result<Option<Response>, VirtqError>;

    /// Drain all available responses, calling `f` for each.
    pub fn drain(&mut self, f: impl FnMut(Token, Bytes)) -> Result<(), VirtqError>;
}

/// High-level virtqueue consumer for receiving requests and sending responses.
pub struct VirtqConsumer<M: MemOps, N: Notifier> {
    inner: RingConsumer<M>,
    notifier: N,
    inflight: Vec<Option<ConsumerInflight>>,
}

impl<M: MemOps, N: Notifier> VirtqConsumer<M, N> {
    /// Poll for a single request. Returns None if no requests available.
    pub fn poll_once(&mut self, max_req: usize) -> Result<Option<Request>, VirtqError>;

    /// Complete a request by sending the response.
    pub fn complete(&mut self, token: Token, resp: &[u8]) -> Result<(), VirtqError>;
}
```

### Test Plan

**Unit tests**:

- Descriptor read/write with proper memory ordering
- Wrap counter transitions
- Buffer chain building and validation
- Event suppression logic
- Miri testing

**Integration tests**:

- Single-threaded producer-consumer patterns
- Multi-threaded scenarios with concurrent access
- Shuttle tests (https://github.com/awslabs/shuttle)
- Backpressure behavior (queue full, memory exhausted)
- Truncation protocol for oversized responses
- Notification suppression and batching

**Property-based tests**:

- Invariants hold across all valid sequences of operations
- No lost or duplicated messages
- Wrap counter consistency

**e2e tests**:

- Actual host-guest communication via ring buffer
- Performance benchmarks vs. current VM exit approach
- Stress testing under high load

### Implementation Plan

As proposed, the queue will eventually replace the current stack‑based mechanism for function calls.
The initial implementation will be gated behind a feature flag. The work can be roughly broken down
into:

- Introduce a low‑level queue implementation that operates on shared memory.
- Introduce a serialization trait for data that can be safely sent through the queue.
- Introduce a high‑level API over the queue.
- Integrate the queue infrastructure with the existing memory model and function‑call API.

Future work includes:

- Adding `Future` and `Stream` as function argument and return types.
- Supporting host and guest running on separate threads.
- Providing an asynchronous API for function calls, streams, and related workflows.

## Implementation History

- **2025-11-12**: HIP proposed

## Drawbacks

- **Complexity**: Ring buffer logic with wrap counters and memory ordering is subtle
- **Fixed size**: Queue size must be known upfront; resizing requires reallocation
- **Learning curve**: Developers need to understand packed virtqueue semantics
- **Debugging**: Race conditions and memory ordering issues can be hard to diagnose

## Alternatives

**1. Split Virtqueue**

- A ready to use to crate that would require adopting their memory model (probably an overkill)
- Simpler descriptor management
- Worse cache characteristics due to separated rings
- Still used in production, proven design

**2. Lock-based Queue**

- Simpler implementation
- Much higher overhead due to lock contention
- Doesn't leverage hypervisor-specific optimizations
- no locks other than spin available on guest
