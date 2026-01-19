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

**Risk**: Malicious guest corrupting the queue **Mitigation**: Do not expose low level queue API to
the guest. Assert queue state invariants after each producer and consumer operation, poison sandbox
if any invariant is not upheld

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
specific for virtio spec. Throughout this document, when we refer to the `driver`, we mean the
`producer` side of the queue (the side that submits elements). When we refer to the `device`, we
mean the `consumer` side (the side that processes queue elements). In the virtio specification,
these terms come from the traditional device driver model, but in our case, either the host or guest
can act as driver or device depending on the direction of communication.

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
    addr: u64,  // Offset into shared memory where buffer resides
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

The goal of this section is not to pin exactly the API for queue semantics but rather give an
overview of type system that represents the concepts outlined above. The presented API is intended
for internal Hyperlight usage and won't be exposed to Hyperlight user.

#### Low Level API

```rust
bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct DescFlags: u16 {
        const NEXT     = 1 << 0;
        const WRITE    = 1 << 1;
        const INDIRECT = 1 << 2;
        const AVAIL    = 1 << 7;
        const USED     = 1 << 15;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub id: u16,
    pub flags: u16,
}

impl Descriptor {
    /// Interpret flags as DescFlags
    pub fn flags(&self) -> DescFlags { }
    /// Did the driver mark this descriptor in the current driver round?
    pub fn is_avail(&self, wrap: bool) -> bool { }
    /// Did the device mark this descriptor used in the current device round?
    pub fn is_used(&self, wrap: bool) -> bool { }
    /// Mark descriptor as available according to the driver's wrap bit.
    pub fn mark_avail(&mut self, wrap: bool) { }
    /// Mark descriptor as used according to the device's wrap bit.
    pub fn mark_used(&mut self, wrap: bool) { }
}

/// A view into a Descriptor stored in shared memory.
///
/// Allows reading/writing the descriptor with proper memory ordering.
pub struct DescriptorView<'t> {
    base: NonNull<Descriptor>,
    owner: PhantomData<&'t DescTable<'t>>,
}

impl<'t> DescriptorView<'t> {
    /// # Safety: base must be valid for reads/writes for 't
    pub unsafe fn new(base: NonNull<Descriptor>) -> Self { }
    /// Read descriptor from memory: Acquire-load flags then volatile-read other fields.
    pub fn read(&self) -> Descriptor { }
    /// Write descriptor fields except flags (volatile), then publish flags atomically (Release).
    pub fn write(&self, desc: &Descriptor) { }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct EventFlags: u16 {
        /// Always send notifications
        const ENABLE = 1 << 0;
        /// Never send notifications (polling mode)
        const DISABLE = 1 << 1;
        /// Only notify when a specific descriptor is processed
        const DESC_SPECIFIC = 1 << 2;
    }
}

/// Event suppression structure controls notification behavior between driver and device
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct EventSuppression {
    /// Packed descriptor event offset
    desc: u16,
    /// Event flags
    flags: u16,
}

/// A table of descriptors stored in shared memory.
struct DescTable<'t> {
    base: NonNull<Descriptor>,
    size: u16,
    owner: PhantomData<&'t [Descriptor]>,
}

impl<'t> DescTable<'t> {
    /// # Safety: base must be valid for reads/writes for size descriptors
    pub unsafe fn init_mem(base: NonNull<Descriptor>, size: u16) -> Self { }
    /// # Safety: base must be valid for reads/writes for size descriptors
    pub unsafe fn from_mem(base: NonNull<Descriptor>, size: u16) -> Self { }
    /// Get descriptor at index or None if idx is out of bounds
    pub fn get(&self, idx: u16) -> Option<DescriptorView<'_>> { }
    /// Set descriptor at index
    pub fn set(&self, idx: u16, desc: &Descriptor) { }
    /// Get number of descriptors in table
    pub fn len(&self) -> u16 { }
}

/// A buffer element (part of a scatter-gather list).
#[derive(Debug, Clone)]
pub struct BufferElement {
    /// Physical address of buffer
    pub addr: u64,
    /// Length in bytes
    pub len: u32,
}

/// A buffer returned from the ring after being used by the device.
struct UsedBuffer {
    /// Descriptor ID associated with this used buffer
    pub id: u16,
    /// Length in bytes of data written by device
    pub len: u32,
}


/// Type-state: Can add readable buffers
pub struct Readable;

/// Type-state: Can add writable buffers (no more readables allowed)
pub struct Writable;

/// A builder for buffer chains using type-state to enforce readable/writable order.
/// Upholds invariants:
/// - at least one buffer must be present in the chain,
/// - readable buffers must be added before writable buffers.
#[derive(Debug, Default)]
struct BufferChainBuilder<T> {
    readables: Vec<BufferElement>,
    writables: Vec<BufferElement>,
    marker: PhantomData<T>,
}

impl BufferChainBuilder<Readable> {
    /// Create a new builder starting in Readable state.
    pub fn new() -> Self { }
    /// Add a readable buffer (device reads from this).
    pub fn readable(mut self, addr: u64, len: u32) -> Self { }
    /// Add a writable buffer (device writes to this). This transitions to Writable
    /// state so no more readable buffers can be added.
    pub fn writable(mut self, addr: u64, len: u32) -> BufferChainBuilder<Writable> { }
    /// Chain must have at least one buffer otherwise an error is returned.
    pub fn build(self) -> Result<BufferChain, RingError> { }
}


impl BufferChainBuilder<Writable> {
    /// Add writable buffer
    pub fn writable(mut self, addr: u64, len: u32) -> Self { }
    /// Build the buffer chain.
    pub fn build(self) -> Result<BufferChain, RingError> { }
}

#[derive(Debug, Default)]
struct BufferChain {
    readables: Vec<BufferElement>,
    writables: Vec<BufferElement>,
}

impl BufferChain {
    /// Get slice of readable buffers
    pub fn readables(&self) -> &[BufferElement] { }
    /// Get slice of writable buffers
    pub fn writables(&self) -> &[BufferElement] { }
}

#[derive(Debug)]
struct RingProducer<'t> {
    /// Next available descriptor position
    avail_cursor: RingCursor,
    /// Next used descriptor position
    used_cursor: RingCursor,
    /// Free slots in the ring
    num_free: usize,
    /// Descriptor table in shared memory
    desc_table: DescTable<'t>,
    /// stack of free IDs, allows out-of-order completion
    id_free: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
    // chain length per ID, index = ID,
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
}


/// The producer side of a packed ring.
impl<'t> RingProducer<'t> {
    /// Submit a buffer chain to the ring.
    pub fn submit(&self, chain: &BufferChain) -> Result<u16, RingError> { }
    /// Poll the ring for a used buffer.
    pub fn poll(&self) -> Result<UsedBuffer, RingError> { }
}


/// The consumer side of a packed ring.
#[derive(Debug)]
pub struct RingConsumer<'t> {
    /// Cursor for reading available (driver-published) descriptors
    avail_cursor: RingCursor,
    /// Cursor for writing used descriptors
    used_cursor: RingCursor,
    /// Shared descriptor table
    desc_table: DescTable<'t>,
    /// Per-ID chain length learned when polling (index = ID)
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
}


impl<'t> RingConsumer<'t> {
    /// Poll the ring for an available buffer chain.
    pub fn poll(&self) -> Result<BufferChain, RingError> { }
    /// Submit a used buffer back to the ring.
    pub fn submit(&self, used: &UsedBuffer) -> Result<(), RingError> { }
}

```

#### Higher-Level API

The low-level ring buffer implementation provides the foundation for safe and efficient
communication, but working directly with descriptors, buffer allocation, and notification
suppression requires in-depth knowledge about the virtqueue semantics. The higher-level API aims to
provide an ergonomic, type-safe interface for common communication patterns. Specifically:

- abstracts buffer allocation,
- abstracts notification strategy,
- enforces type safety by requiring ring payloads to be `FlatbufferSerializable`

```rust
use allocator_api2::alloc::{AllocError, Allocator};

/// Trait for types that can be serialized/deserialized via flatbuffers
pub trait FlatbufferSerializable: Sized + Sealed {
    type Error: Into<RingError>;

    /// Estimate the serialized size (hint for buffer allocation)
    fn size_hint(&self) -> usize;
    /// Serialize into the provided buffer
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    /// Deserialize from the provided buffer
    fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>;
}

/// Notification strategy trait - determines when to notify the other side about new descriptors.
pub trait NotificationStrategy {
    /// Returns true if notification should be sent.
    fn should_notify(&self, stats: &RingStats) -> bool;
}

/// Notification strategy that will notify the device after each send
struct AlwaysNotify;

impl NotificationStrategy for AlwaysNotify {
    fn should_notify(&self, _stats: &RingStats) -> bool { true };
}

struct BufferPool { }

impl Allocator for BufferPool {
    /// Allocate a buffer with the given layout from the pool.
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> { }
    /// Return buffer to the pool.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) { }
}

/// Split ring into separate sender and receiver
///
/// Sender owns the allocator and notification strategy since only
/// it needs to allocate buffers and decide when to notify.
pub struct RingSender<A = BufferPool, N = AlwaysNotify>
where
    A: Allocator,
    N: NotificationStrategy,
{
    /// The sync version needs to handle concurrent access properly
    inner: Arc<Mutex<Inner>>,
}

/// Receiver only needs to know the receive type
pub struct RingReceiver
{
    /// The sync version needs to handle concurrent access properly
    inner: Arc<Mutex<Inner>>,
}

impl<A, N> Ring<A, N>
where
    A: Allocator,
    N: NotificationStrategy,
{
    /// Split into separate sender and receiver
    pub fn split(self) -> (RingSender<A, N>, RingReceiver) {
        unimplemented!("split is not implemented in this example");
    }
}

impl<A, N> RingSender<A, N>
where
    A: Allocator,
    N: NotificationStrategy,
{
    /// Send a message, use token for out-of-order completion
    pub fn send<T>(&mut self, message: T) -> Result<Token, RingError>
    where
        T: FlatbufferSerializable;

    /// Try to send without blocking
    pub fn try_send<T>(&mut self, message: T) -> Result<Token, RingError>
    where
        T: FlatbufferSerializable;
}

impl RingReceiver
{
    /// Receive a message of the specified type
    pub fn recv<T>(&mut self) -> Result<T, RingError>
    where
        T: FlatbufferSerializable;

    /// Try to receive a message without blocking
    pub fn try_recv<T>(&mut self) -> Result<T, RingError>
    where
        T: FlatbufferSerializable;
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
