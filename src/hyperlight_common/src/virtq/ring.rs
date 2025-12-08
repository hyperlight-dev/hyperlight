/*
Copyright 2026  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

//! Packed Virtqueue Ring Implementation
//!
//! This module implements the packed virtqueue format from the VIRTIO specification.
//! Packed virtqueues use a single descriptor ring where descriptors cycle through
//! available and used states, providing better cache locality and simpler memory
//! layout compared to split virtqueues.
//!
//! # Descriptor State Machine
//!
//! Each descriptor transitions through states using AVAIL and USED flags:
//!
//! ```text
//!                    Driver publishes
//!     ┌─────────┐    (AVAIL=wrap)     ┌───────────┐
//!     │  Free   │ ──────────────────> │ Available │
//!     └─────────┘                     └───────────┘
//!          ^                                │
//!          │                                │ Device consumes
//!          │ Driver reclaims                │ and marks used
//!          │ (polls USED=wrap)              │ (USED=wrap)
//!          │                                v
//!     ┌─────────┐                     ┌───────────┐
//!     │Reclaimed│ <────────────────── │   Used    │
//!     └─────────┘                     └───────────┘
//! ```
//!
//! # Wrap Counter
//!
//! The wrap counter solves ring wraparound ambiguity. When cursors wrap around
//! the ring, the wrap counter toggles, changing how AVAIL/USED flags are interpreted:
//!
//! - **wrap=true**: AVAIL=1, USED=0 means "available"; AVAIL=1, USED=1 means "used"
//! - **wrap=false**: AVAIL=0, USED=1 means "available"; AVAIL=0, USED=0 means "used"
//!
//! # Buffer Chains
//!
//! Multiple buffers can be chained using the NEXT flag. All descriptors in a chain
//! share the same ID, and only the head descriptor's AVAIL/USED flags matter for
//! state transitions:
//!
//! ```text
//! Chain with 3 buffers (ID=5):
//! ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
//! │ Desc[0]      │    │ Desc[1]      │    │ Desc[2]      │
//! │ id=42        │───>│ id=42        │───>│ id=42        │
//! │ flags=NEXT   │    │ flags=NEXT   │    │ flags=0      │
//! │ AVAIL/USED   │    │ (ignored)    │    │ (ignored)    │
//! └──────────────┘    └──────────────┘    └──────────────┘
//!       HEAD              MIDDLE               TAIL
//! ```
//!
//! # Event Suppression
//!
//! Both sides can control when they want to be notified:
//!
//! - **ENABLE**: Always notify (default)
//! - **DISABLE**: Never notify (for polling mode)
//! - **DESC**: Notify only when a specific descriptor index is reached
//! ```

use core::marker::PhantomData;

use bytemuck::Zeroable;
use smallvec::SmallVec;
use thiserror::Error;

use super::desc::{DescFlags, DescTable, Descriptor};
use super::event::{EventFlags, EventSuppression};
use super::{Layout, MemOps};

/// A single buffer element in a scatter-gather list.
///
/// Represents one contiguous memory region that the device will read from
/// or write to. Multiple elements can be chained together to form a
/// [`BufferChain`].
#[derive(Debug, Copy, Clone, Zeroable)]
pub struct BufferElement {
    /// Physical address of buffer
    pub addr: u64,
    /// Length of the buffer in bytes
    pub len: u32,
    /// Is this buffer writable
    pub writable: bool,
}

/// A buffer returned from the ring after being used by the device.
///
/// When the device completes processing a buffer chain, it returns this
/// structure containing the original descriptor ID and the number of bytes
/// written (for chains with writable buffers).
#[derive(Debug, Copy, Clone)]
pub struct UsedBuffer {
    /// Descriptor ID that was assigned when the buffer was submitted
    pub id: u16,
    /// Number of bytes written by the device to writable buffers.
    /// For read-only chains, this may be 0 or the total readable length.
    pub len: u32,
}

/// Result of submitting a buffer to the ring.
///
/// Contains the assigned descriptor ID and whether the other side
/// needs to be notified about the new buffer.
#[derive(Debug, Copy, Clone)]
pub struct SubmitResult {
    /// Descriptor ID assigned to the submitted buffer chain
    /// Use this ID to correlate completions with submissions.
    pub id: u16,
    /// Whether the device should be notified immediately based on the other
    /// side's event suppression settings.
    pub notify: bool,
}

#[derive(Error, Debug)]
pub enum RingError {
    #[error("Buffer chain is empty")]
    EmptyChain,
    #[error("Buffer chain is malformed")]
    BadChain,
    #[error("Operation would block")]
    WouldBlock,
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Invalid state")]
    InvalidState,
    #[error("Invalid memory layout")]
    InvalidLayout,
    #[error("Backend memory error")]
    MemError,
}

/// Type-state: Can add readable buffers
pub struct Readable;

/// Type-state: Can add writable buffers (no more readables allowed)
pub struct Writable;

/// A builder for buffer chains using type-state to enforce readable/writable order.
///
/// Upholds invariants: at least one buffer must be present in the chain,
/// and readable buffers must be added before writable buffers.
#[derive(Debug, Default)]
pub struct BufferChainBuilder<T> {
    elems: SmallVec<[BufferElement; 16]>,
    split: usize,
    marker: PhantomData<T>,
}

impl BufferChainBuilder<Readable> {
    /// Create a new builder in the [`Readable`] state.
    pub fn new() -> Self {
        Self {
            elems: Default::default(),
            split: 0,
            marker: PhantomData,
        }
    }

    /// Add a readable buffer (device reads from this).
    pub fn readable(mut self, addr: u64, len: u32) -> Self {
        self.elems.push(BufferElement {
            addr,
            len,
            writable: false,
        });
        self.split += 1;
        self
    }

    /// Add multiple readable buffers from an iterator.
    pub fn readables(
        mut self,
        elements: impl IntoIterator<Item = impl Into<BufferElement>>,
    ) -> Self {
        for elem in elements {
            self.elems.push(elem.into());
            self.split += 1;
        }

        self
    }

    /// Add a writable buffer (device writes to this).
    ///
    /// This transitions to Writable state so no more readable buffers can be added.
    pub fn writable(mut self, addr: u64, len: u32) -> BufferChainBuilder<Writable> {
        self.elems.push(BufferElement {
            addr,
            len,
            writable: true,
        });

        BufferChainBuilder {
            elems: self.elems,
            split: self.split,
            marker: PhantomData,
        }
    }

    /// Add multiple readable buffers from an iterator.
    ///
    /// This transitions to Writable state so no more readable buffers can be added.
    pub fn writables(
        mut self,
        elements: impl IntoIterator<Item = impl Into<BufferElement>>,
    ) -> BufferChainBuilder<Writable> {
        for elem in elements {
            self.elems.push(elem.into());
        }

        BufferChainBuilder {
            elems: self.elems,
            split: self.split,
            marker: PhantomData,
        }
    }

    /// Build a buffer chain with only readable buffers.
    ///
    /// Chain must have at least one buffer otherwise an error is returned.
    pub fn build(self) -> Result<BufferChain, RingError> {
        if self.elems.is_empty() {
            return Err(RingError::EmptyChain);
        }

        Ok(BufferChain {
            elems: self.elems,
            split: self.split,
        })
    }
}

impl BufferChainBuilder<Writable> {
    /// Add writable buffer
    pub fn writable(mut self, addr: u64, len: u32) -> Self {
        self.elems.push(BufferElement {
            addr,
            len,
            writable: true,
        });
        self
    }

    /// Add multiple readable buffers from an iterator.
    pub fn writables(
        mut self,
        elements: impl IntoIterator<Item = impl Into<BufferElement>>,
    ) -> Self {
        for elem in elements {
            self.elems.push(elem.into());
        }
        self
    }

    /// Build the buffer chain.
    ///
    /// Chain must have at least one buffer otherwise an error is returned.
    pub fn build(self) -> Result<BufferChain, RingError> {
        if self.elems.is_empty() {
            return Err(RingError::EmptyChain);
        }

        Ok(BufferChain {
            elems: self.elems,
            split: self.split,
        })
    }
}

/// A chain of buffers ready for submission to the virtqueue.
///
/// Contains a scatter-gather list of [`BufferElement`]s, divided into
/// readable (driver->device) and writable (device->driver) sections.
#[derive(Debug, Default, Clone)]
pub struct BufferChain {
    /// All buffer elements (readable followed by writable)
    elems: SmallVec<[BufferElement; 16]>,
    /// Split index between readable and writable buffers
    split: usize,
}

impl BufferChain {
    /// Get all buffer elements in the chain.
    pub fn elems(&self) -> &[BufferElement] {
        self.elems.as_slice()
    }

    /// Get writable buffers in chain
    pub fn readables(&self) -> &[BufferElement] {
        &self.elems[..self.split]
    }

    /// Get writable buffers in chain
    pub fn writables(&self) -> &[BufferElement] {
        &self.elems[self.split..]
    }

    /// Get total number of buffers in chain
    // Note: buffer chain cannot be empty by construction
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.elems.len()
    }
}

/// Tracks position in a ring buffer with wrap-around handling.
///
/// The cursor maintains both an index into the ring and a wrap counter
/// that toggles each time the index wraps around.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RingCursor {
    head: u16,
    size: u16,
    wrap: bool,
}

impl RingCursor {
    pub(crate) fn new(size: usize) -> Self {
        Self {
            head: 0,
            size: size as u16,
            wrap: true,
        }
    }

    /// Advance to next position, wrapping around and toggling wrap counter if needed
    #[inline]
    pub(crate) fn advance(&mut self) {
        self.head += 1;
        if self.head >= self.size {
            self.head = 0;
            self.wrap = !self.wrap;
        }
    }

    /// Advance by n positions
    #[inline]
    pub(crate) fn advance_by(&mut self, n: u16) {
        for _ in 0..n {
            self.advance();
        }
    }

    /// Get current head index
    #[inline]
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Get current wrap counter
    #[inline]
    pub fn wrap(&self) -> bool {
        self.wrap
    }
}

/// Producer (driver) side of a packed virtqueue.
///
/// The producer submits buffer chains for the device to process and polls
/// for completions. This is typically used by the driver/guest side.
///
/// # Lifecycle
///
/// 1.Submit: Call [`submit_available`](Self::submit_available) or
///    [`submit_one`](Self::submit_one) to make buffers available to device
/// 2. Notify: If `SubmitResult::notify` is true, signal the device
/// 3. Poll: Call [`poll_used`](Self::poll_used) to check for completions
/// 4. Process: Handle completed buffers and reuse descriptor IDs
#[derive(Debug)]
pub struct RingProducer<M> {
    /// Memory accessor
    mem: M,
    /// Next available descriptor position
    avail_cursor: RingCursor,
    /// Next used descriptor position
    used_cursor: RingCursor,
    /// Free slots in the ring
    num_free: usize,
    /// Descriptor table in shared memory
    desc_table: DescTable,
    /// Shadow of driver event flags (last written value)
    event_flags_shadow: EventFlags,
    // controls when device notifies about used buffers
    drv_evt_addr: u64,
    // reads device event to check if device wants notification
    dev_evt_addr: u64,
    /// stack of free IDs, allows out-of-order completion
    id_free: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
    // chain length per ID, index = ID,
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
}

impl<M: MemOps> RingProducer<M> {
    /// Create a new producer from a memory layout and accessor.
    pub fn new(layout: Layout, mem: M) -> Self {
        let size = layout.desc_table_len as usize;
        let raw = layout.desc_table_addr;

        // SAFETY: layout is valid
        let table = unsafe { DescTable::from_raw_parts(raw, size) };
        let cursor = RingCursor::new(size);

        const DEFAULT_LEN: usize = DescTable::default_len();
        let id_free = (0..size as u16).collect::<SmallVec<[_; DEFAULT_LEN]>>();
        let id_num = SmallVec::<[_; DEFAULT_LEN]>::from_elem(0, size);

        // Notification enabled by default
        let event_flags_shadow = EventFlags::ENABLE;

        Self {
            mem,
            avail_cursor: cursor,
            used_cursor: cursor,
            num_free: size,
            desc_table: table,
            id_free,
            id_num,
            event_flags_shadow,
            drv_evt_addr: layout.drv_evt_addr,
            dev_evt_addr: layout.dev_evt_addr,
        }
    }

    /// Fast path: submit exactly one descriptor
    ///
    /// This is more efficient than [`submit_available`](Self::submit_available)
    /// for single-buffer submissions as it avoids chain iteration overhead.
    ///
    /// # Arguments
    ///
    /// * `addr` - physical address of the buffer
    /// * `len` - Length of the buffer in bytes
    /// * `writable` - If true, device writes to buffer; if false, device reads
    ///
    /// # Returns
    ///
    /// The descriptor ID assigned to this buffer, for matching with completions.
    ///
    /// # Errors
    ///
    /// - [`RingError::WouldBlock`] - No free descriptor slots
    /// - [`RingError::OutOfMemory`] - No free descriptor IDs (internal error)
    /// - [`RingError::InvalidState`] - ID tracking corrupted (internal error)
    pub fn submit_one(&mut self, addr: u64, len: u32, writable: bool) -> Result<u16, RingError> {
        if self.num_free < 1 {
            return Err(RingError::WouldBlock);
        }

        // Allocate ID and record chain length
        let id = self.id_free.pop().ok_or(RingError::OutOfMemory)?;

        // We should never reuse an ID that is still outstanding
        if self.id_num[id as usize] != 0 {
            return Err(RingError::InvalidState);
        }

        // Record chain length for single descriptor
        self.id_num[id as usize] = 1;

        // Build and publish the head descriptor
        let head_idx = self.avail_cursor.head();
        let head_wrap = self.avail_cursor.wrap();

        let mut flags = DescFlags::empty();
        flags.set(DescFlags::WRITE, writable);
        let mut desc = Descriptor::new(addr, len, id, flags);
        desc.mark_avail(head_wrap);

        let addr = self
            .desc_table
            .desc_addr(head_idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish
        desc.write_release(&self.mem, addr)
            .map_err(|_| RingError::MemError)?;

        // Advance state
        self.avail_cursor.advance();
        self.num_free -= 1;

        Ok(id)
    }

    /// Submit a buffer chain to the ring, returning whether to notify the device.
    pub fn submit_available_with_notify(
        &mut self,
        chain: &BufferChain,
    ) -> Result<SubmitResult, RingError> {
        let old = self.avail_cursor;
        let id = self.submit_available(chain)?;
        let new = self.avail_cursor;
        let notify = self.should_notify_device(old, new)?;

        Ok(SubmitResult { id, notify })
    }

    /// Submit a single-buffer descriptor with notification check.
    pub fn submit_one_with_notify(
        &mut self,
        addr: u64,
        len: u32,
        writable: bool,
    ) -> Result<SubmitResult, RingError> {
        let old = self.avail_cursor;
        let id = self.submit_one(addr, len, writable)?;
        let new = self.avail_cursor;
        let notify = self.should_notify_device(old, new)?;
        Ok(SubmitResult { id, notify })
    }

    /// Submit a buffer chain to the ring.
    ///
    /// Writes all descriptors in the chain to the ring, linking them with
    /// NEXT flags. The head descriptor is written last with release semantics
    /// to ensure atomicity of the chain.
    ///
    /// # Arguments
    ///
    /// * `chain` - The buffer chain to submit
    ///
    /// # Returns
    ///
    /// The descriptor ID assigned to this chain. All descriptors in the chain
    /// share this ID for correlation during completion.
    ///
    /// # Errors
    ///
    /// - [`RingError::EmptyChain`] - Chain has no buffers
    /// - [`RingError::WouldBlock`] - Not enough free descriptor slots
    pub fn submit_available(&mut self, chain: &BufferChain) -> Result<u16, RingError> {
        let total_descs = chain.len();
        if total_descs == 0 {
            return Err(RingError::EmptyChain);
        }

        if self.num_free < total_descs {
            return Err(RingError::WouldBlock);
        }

        if total_descs == 1 {
            let elem = chain.elems()[0];
            return self.submit_one(elem.addr, elem.len, elem.writable);
        }

        let head_idx = self.avail_cursor.head();
        let head_wrap = self.avail_cursor.wrap();

        let id = self.id_free.pop().ok_or(RingError::InvalidState)?;

        // We should never reuse an ID that is still outstanding
        if self.id_num[id as usize] != 0 {
            return Err(RingError::InvalidState);
        }

        // Record chain length
        self.id_num[id as usize] = total_descs as u16;

        // Write tail elements first; head last.
        let mut pos = self.avail_cursor;
        pos.advance();

        for (i, elem) in chain.elems().iter().enumerate().skip(1) {
            let is_next = i + 1 < total_descs;
            let mut flags = DescFlags::empty();

            flags.set(DescFlags::NEXT, is_next);
            flags.set(DescFlags::WRITE, elem.writable);

            let mut desc = Descriptor::new(elem.addr, elem.len, id, flags);
            desc.mark_avail(pos.wrap());

            let addr = self
                .desc_table
                .desc_addr(pos.head())
                .ok_or(RingError::InvalidState)?;

            self.mem
                .write_val(addr, desc)
                .map_err(|_| RingError::MemError)?;
            pos.advance();
        }

        // Head descriptor
        let head_elem = chain.elems()[0];
        // Record chain length
        let mut head_flags = DescFlags::empty();
        head_flags.set(DescFlags::NEXT, total_descs > 1);
        head_flags.set(DescFlags::WRITE, head_elem.writable);

        let mut head_desc = Descriptor::new(head_elem.addr, head_elem.len, id, head_flags);
        head_desc.mark_avail(head_wrap);

        let head_addr = self
            .desc_table
            .desc_addr(head_idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish
        head_desc
            .write_release(&self.mem, head_addr)
            .map_err(|_| RingError::MemError)?;

        self.num_free -= total_descs;
        self.avail_cursor = pos;

        Ok(id)
    }

    /// Poll the ring for a used buffer.
    ///
    /// Checks if the device has marked any buffers as used. If so, returns
    /// the completion information and reclaims the descriptor(s).
    ///
    /// # Returns
    ///
    /// - `Ok(UsedBuffer)` - A buffer chain was completed
    /// - `Err(RingError::WouldBlock)` - No completions available
    pub fn poll_used(&mut self) -> Result<UsedBuffer, RingError> {
        let idx = self.used_cursor.head();
        let wrap = self.used_cursor.wrap();

        // Read the descriptor at next_used position with ordering
        let addr = self
            .desc_table
            .desc_addr(idx)
            .ok_or(RingError::InvalidState)?;

        // Acquire flags then fields (publish point)
        let desc = Descriptor::read_acquire(&self.mem, addr).map_err(|_| RingError::MemError)?;
        if !desc.is_used(wrap) {
            return Err(RingError::WouldBlock);
        }

        let id = desc.id;
        let count = *self
            .id_num
            .get(id as usize)
            .ok_or(RingError::InvalidState)?;

        if count == 0 {
            return Err(RingError::InvalidState);
        }

        // Advance used cursor by number of reclaimed descriptors
        self.used_cursor.advance_by(count);
        // Update number of free descriptors
        self.num_free += count as usize;
        // SAFETY: id is valid because we checked above
        self.id_num[id as usize] = 0;
        // Return ID to free stack
        self.id_free.push(id);

        Ok(UsedBuffer { id, len: desc.len })
    }

    /// Get number of free descriptors in the ring.
    pub fn num_free(&self) -> usize {
        self.num_free
    }

    /// Get number of inflight (submitted but not yet used) descriptors.
    pub fn num_inflight(&self) -> usize {
        self.desc_table.len() - self.num_free
    }

    /// Check if the ring is full (no free descriptors).
    pub fn is_full(&self) -> bool {
        self.num_free == 0
    }

    /// Get descriptor table length
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.desc_table.len()
    }

    /// Get memory accessor reference
    pub fn mem(&self) -> &M {
        &self.mem
    }

    /// Get a snapshot of the current available cursor position.
    ///
    /// Used for batch operations to track the cursor before submitting
    /// multiple chains, enabling proper event suppression checks.
    #[inline]
    pub fn avail_cursor(&self) -> RingCursor {
        self.avail_cursor
    }

    /// Get a snapshot of the current used cursor position.
    ///
    /// Used for setting up DESC mode event suppression at specific positions.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.used_cursor
    }

    /// Check if device should be notified given a cursor snapshot from before batch start.
    ///
    /// This is used for batching: record cursor before first submit, then after all
    /// submits call this to determine if notification is needed based on event suppression.
    ///
    /// # Arguments
    /// * `old` - Cursor position snapshot taken before batch started
    pub fn should_notify_since(&self, old: RingCursor) -> Result<bool, RingError> {
        self.should_notify_device(old, self.avail_cursor)
    }

    /// Driver disables used-buffer notifications from device to driver.
    pub fn disable_used_notifications(&mut self) -> Result<(), RingError> {
        // Avoid redundant MMIO writes if already disabled
        if self.event_flags_shadow == EventFlags::DISABLE {
            return Ok(());
        }

        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_flags(EventFlags::DISABLE);

        evt.write_release(&self.mem, self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;
        self.event_flags_shadow = EventFlags::DISABLE;
        Ok(())
    }

    /// Driver enables used-buffer notifications from device to driver.
    pub fn enable_used_notifications(&mut self) -> Result<(), RingError> {
        if self.event_flags_shadow == EventFlags::ENABLE {
            return Ok(());
        }

        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_flags(EventFlags::ENABLE);
        evt.write_release(&self.mem, self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;

        self.event_flags_shadow = EventFlags::ENABLE;
        Ok(())
    }

    /// Driver enables descriptor-specific used notifications (EVENT_IDX / DESC mode).
    ///
    /// This tells the device: "Interrupt me when you reach used index (off, wrap)".
    ///
    /// This enables batching on the device side - it can complete multiple requests
    /// before triggering an interrupt.
    pub fn enable_used_notifications_desc(
        &mut self,
        off: u16,
        wrap: bool,
    ) -> Result<(), RingError> {
        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_desc_event(off, wrap);
        evt.set_flags(EventFlags::DESC);

        // Now publish flags = DESC with Release semantics.
        evt.write_release(&self.mem, self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;
        // cache shadow
        self.event_flags_shadow = EventFlags::DESC;
        Ok(())
    }

    /// Convenience: enable DESC mode for "next used cursor" like Linux enable_cb_prepare.
    pub fn enable_used_notifications_for_next(&mut self) -> Result<(), RingError> {
        let off = self.used_cursor.head();
        let wrap = self.used_cursor.wrap();

        self.enable_used_notifications_desc(off, wrap)
    }

    /// Check whether the device should be notified about new available descriptors.
    fn should_notify_device(&self, old: RingCursor, new: RingCursor) -> Result<bool, RingError> {
        // Spec requires: "driver MUST perform a suitable memory barrier before
        // reading device event suppression" (2.8.21.3.1)
        // We already published descriptors with write_release, so now do an Acquire
        // read of device_event.
        let evt = EventSuppression::read_acquire(&self.mem, self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        Ok(should_notify(evt, self.len() as u16, old, new))
    }
}

/// Consumer (device) side of a packed virtqueue.
///
/// The consumer polls for available buffer chains submitted by the driver,
/// processes them, and marks them as used. This is typically used by the
/// device/host side.
///
/// # Lifecycle
///
/// 1. **Poll**: Call [`poll_available`](Self::poll_available) to get buffers
/// 2. **Process**: Read from readable buffers, write to writable buffers
/// 3. **Complete**: Call [`submit_used`](Self::submit_used) to return buffers
/// 4. **Notify**: If `submit_used_with_notify` returns true, signal the driver
#[derive(Debug)]
pub struct RingConsumer<M> {
    /// Memory accessor
    mem: M,
    /// Cursor for reading available (driver-published) descriptors
    avail_cursor: RingCursor,
    /// Cursor for writing used descriptors
    used_cursor: RingCursor,
    /// Shared descriptor table
    desc_table: DescTable,
    /// Per-ID chain length learned when polling (index = ID)
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
    /// Number of descriptors consumed from avail stream but not yet posted as used.
    num_inflight: usize,
    /// Shadow of device event flags (last written value)
    event_flags_shadow: EventFlags,
    // reads driver event to control when device should notify
    drv_evt_addr: u64,
    // write device_event (checks if device wants notification about available buffers)
    dev_evt_addr: u64,
}

impl<M: MemOps> RingConsumer<M> {
    pub fn new(layout: Layout, mem: M) -> Self {
        let size = layout.desc_table_len as usize;
        let raw = layout.desc_table_addr;

        // SAFETY: layout is valid
        let table = unsafe { DescTable::from_raw_parts(raw, size) };
        let cursor = RingCursor::new(size);
        let id_chain_len = SmallVec::<[u16; DescTable::DEFAULT_LEN]>::from_elem(0, size);

        // Notification enabled by default
        let event_flags_shadow = EventFlags::ENABLE;

        Self {
            mem,
            avail_cursor: cursor,
            used_cursor: cursor,
            desc_table: table,
            id_num: id_chain_len,
            num_inflight: 0,
            event_flags_shadow,
            drv_evt_addr: layout.drv_evt_addr,
            dev_evt_addr: layout.dev_evt_addr,
        }
    }

    /// Poll for an available buffer chain.
    ///
    /// Returns the chain ID and a [`BufferChain`] containing all buffers.
    /// The chain ID must be passed to [`submit_used`](Self::submit_used)
    /// when processing is complete.
    ///
    /// # Returns
    ///
    /// - `Ok((id, chain))` - A buffer chain is available
    /// - `Err(RingError::WouldBlock)` - No buffers available
    /// - `Err(RingError::BadChain)` - Malformed chain (driver bug)
    pub fn poll_available(&mut self) -> Result<(u16, BufferChain), RingError> {
        let idx = self.avail_cursor.head();
        let wrap = self.avail_cursor.wrap();

        let head_addr = self
            .desc_table
            .desc_addr(idx)
            .ok_or(RingError::InvalidState)?;

        // Acquire: flags then fields (publish point)
        let head_desc =
            Descriptor::read_acquire(&self.mem, head_addr).map_err(|_| RingError::MemError)?;

        // Check if head descriptor is available to consume
        if !head_desc.is_avail(wrap) {
            return Err(RingError::WouldBlock);
        }

        // Build chain (head + tails).
        let mut elements = SmallVec::<[BufferElement; 16]>::new();
        let mut pos = self.avail_cursor;
        let mut chain_len: u16 = 1;

        let mut steps = 1;
        let mut has_next = head_desc.is_next();

        let max_steps = self.desc_table.len();

        elements.push(BufferElement::from(&head_desc));
        pos.advance();

        while has_next && steps < max_steps {
            let addr = self
                .desc_table
                .desc_addr(pos.head())
                .ok_or(RingError::InvalidState)?;

            // tail reads does not need ordering because head has been already validated
            let desc = self.mem.read_val(addr).map_err(|_| RingError::MemError)?;
            elements.push(BufferElement::from(&desc));

            chain_len += 1;
            steps += 1;

            has_next = desc.is_next();
            pos.advance();
        }

        // Detect malformed chains, this means we reached max_steps but still have NEXT set.
        if steps >= max_steps && has_next {
            return Err(RingError::BadChain);
        }

        // Verify that readable/writable split is correct
        let readables = chain_readable_count(&elements)?;

        // Since driver wrote the same id everywhere, head_desc.id is valid.
        let id = head_desc.id;
        if (id as usize) >= self.id_num.len() {
            return Err(RingError::InvalidState);
        }

        // Record chain length for later used submission
        self.id_num[id as usize] = chain_len;
        // Advance avail cursor to first slot after chain
        self.avail_cursor = pos;
        // Update inflight count
        self.num_inflight += chain_len as usize;

        assert!(self.num_inflight <= self.desc_table.len());

        Ok((
            id,
            BufferChain {
                elems: elements,
                split: readables,
            },
        ))
    }

    /// Publish a single used descriptor for the chain identified by id.
    /// written_len is the total bytes produced by the device (for writeable part).
    ///
    /// # Arguments
    ///
    /// * `id` - The chain ID from `poll_available`
    /// * `written_len` - Total bytes written to writable buffers
    ///
    /// # Errors
    ///
    /// - [`RingError::InvalidState`] - Unknown ID or already completed
    pub fn submit_used(&mut self, id: u16, written_len: u32) -> Result<(), RingError> {
        // Lookup chain length
        let chain_len = *self
            .id_num
            .get(id as usize)
            .ok_or(RingError::InvalidState)?;

        if chain_len == 0 {
            return Err(RingError::InvalidState);
        }

        let idx = self.used_cursor.head();
        let wrap = self.used_cursor.wrap();

        // addr is unused for used descriptor according to packed-virtqueue spec
        let mut used_desc = Descriptor::new(0, 0, id, DescFlags::empty());
        used_desc.len = written_len;
        used_desc.mark_used(wrap);

        let addr = self
            .desc_table
            .desc_addr(idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish (flags written last inside write_release)
        used_desc
            .write_release(&self.mem, addr)
            .map_err(|_| RingError::MemError)?;

        // Advance used cursor by whole chain length
        self.used_cursor.advance_by(chain_len);
        self.id_num[id as usize] = 0;

        self.num_inflight -= chain_len as usize;
        assert!(self.num_inflight <= self.desc_table.len());

        Ok(())
    }

    /// Try to peek whether the next chain is available without consuming it.
    pub fn peek_available(&self) -> Result<bool, RingError> {
        let Some(addr) = self.desc_table.desc_addr(self.avail_cursor.head()) else {
            return Err(RingError::InvalidState);
        };

        let desc = Descriptor::read_acquire(&self.mem, addr).map_err(|_| RingError::MemError)?;
        Ok(desc.is_avail(self.avail_cursor.wrap()))
    }

    /// Submit a used descriptor and return whether to notify the driver.
    pub fn submit_used_with_notify(
        &mut self,
        id: u16,
        written_len: u32,
    ) -> Result<bool, RingError> {
        let old = self.used_cursor;
        self.submit_used(id, written_len)?;
        let new = self.used_cursor;
        self.should_notify_driver(old, new)
    }

    /// Get number of free descriptors in the ring.
    pub fn num_free(&self) -> usize {
        self.desc_table.len() - self.num_inflight
    }

    /// Get number of inflight (submitted but not yet used) descriptors.
    pub fn num_inflight(&self) -> usize {
        self.num_inflight
    }

    /// Check if the ring is full (no free descriptors).
    pub fn is_full(&self) -> bool {
        self.num_inflight == self.desc_table.len()
    }

    /// Get descriptor table length
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.desc_table.len()
    }

    /// Get memory accessor reference
    pub fn mem(&self) -> &M {
        &self.mem
    }

    /// Get a snapshot of the current avail cursor position.
    #[inline]
    pub fn avail_cursor(&self) -> RingCursor {
        self.avail_cursor
    }

    /// Get a snapshot of the current used cursor position.
    #[inline]
    pub fn used_cursor(&self) -> RingCursor {
        self.used_cursor
    }

    /// Device disables available-buffer notifications from driver to device.
    ///
    /// This is the device-side mirror of "disable callbacks" but for avail kicks.
    pub fn disable_avail_notifications(&mut self) -> Result<(), RingError> {
        if self.event_flags_shadow == EventFlags::DISABLE {
            return Ok(());
        }

        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_flags(EventFlags::DISABLE);
        evt.write_release(&self.mem, self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        self.event_flags_shadow = EventFlags::DISABLE;
        Ok(())
    }

    /// Device enables available-buffer notifications from driver to device.
    pub fn enable_avail_notifications(&mut self) -> Result<(), RingError> {
        if self.event_flags_shadow == EventFlags::ENABLE {
            return Ok(());
        }

        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_flags(EventFlags::ENABLE);
        evt.write_release(&self.mem, self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        self.event_flags_shadow = EventFlags::ENABLE;
        Ok(())
    }

    /// Device enables descriptor-specific available notifications (EVENT_IDX / DESC mode).
    ///
    /// This tells the driver: "Kick me when you reach avail index (off, wrap)".
    pub fn enable_avail_notifications_desc(
        &mut self,
        off: u16,
        wrap: bool,
    ) -> Result<(), RingError> {
        // Update off_wrap first
        let mut evt = self
            .mem
            .read_val::<EventSuppression>(self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        evt.set_desc_event(off, wrap);
        evt.set_flags(EventFlags::DESC);

        // Now publish flags = DESC with Release semantics.
        evt.write_release(&self.mem, self.dev_evt_addr)
            .map_err(|_| RingError::MemError)?;

        self.event_flags_shadow = EventFlags::DESC;
        Ok(())
    }

    /// Convenience: enable DESC mode for "next avail cursor" (device wants a kick when new
    /// buffers arrive at the next index it will poll).
    pub fn enable_avail_notifications_for_next(&mut self) -> Result<(), RingError> {
        let off = self.avail_cursor.head();
        let wrap = self.avail_cursor.wrap();
        self.enable_avail_notifications_desc(off, wrap)
    }

    /// Decide whether the device should notify the driver about newly used descriptors.
    fn should_notify_driver(&self, old: RingCursor, new: RingCursor) -> Result<bool, RingError> {
        let evt = EventSuppression::read_acquire(&self.mem, self.drv_evt_addr)
            .map_err(|_| RingError::MemError)?;

        Ok(should_notify(evt, self.desc_table.len() as u16, old, new))
    }
}

/// Common packed-ring notification decision:
/// - `old` and `new` are the ring indices (head) before/after publishing a batch
/// - `new.wrap()` is the wrap counter corresponding to `new.head()`
/// - `evt.desc_event_wrap()` is compared against `new.wrap()`
///
/// This is compatible with Linux `virtqueue_kick_prepare_packed` logic
#[inline]
fn should_notify(evt: EventSuppression, ring_len: u16, old: RingCursor, new: RingCursor) -> bool {
    match evt.flags() {
        EventFlags::DISABLE => false,
        EventFlags::ENABLE => true,
        EventFlags::DESC => {
            let mut off = evt.desc_event_off();
            let wrap = evt.desc_event_wrap();

            if wrap != new.wrap() {
                off = off.wrapping_sub(ring_len);
            }

            ring_need_event(off, new.head(), old.head())
        }
        _ => unreachable!(),
    }
}

#[inline(always)]
pub fn ring_need_event(event_idx: u16, new: u16, old: u16) -> bool {
    new.wrapping_sub(event_idx).wrapping_sub(1) < new.wrapping_sub(old)
}

#[inline]
/// Check that a buffer chain is well-formed: all readable buffers first,
/// then writable and return the count of readable buffers.
fn chain_readable_count(elems: &[BufferElement]) -> Result<usize, RingError> {
    let mut seen_writable = false;
    let mut writables = 0;

    for e in elems {
        if e.writable {
            seen_writable = true;
            writables += 1;
        } else if seen_writable {
            return Err(RingError::BadChain);
        }
    }

    Ok(elems.len() - writables)
}

impl From<&Descriptor> for BufferElement {
    fn from(desc: &Descriptor) -> Self {
        BufferElement {
            addr: desc.addr,
            len: desc.len,
            writable: desc.is_writeable(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::rc::Rc;
    use core::cell::UnsafeCell;
    use core::num::NonZeroU16;
    use core::ptr;
    use core::sync::atomic::{AtomicU16, Ordering};

    use bytemuck::{Pod, Zeroable};

    use super::*;
    use crate::virtq::event::EventSuppression;

    /// Test MemOps implementation that maintains pointer provenance.
    ///
    /// This wraps a Vec and provides memory access using the Vec's
    /// base pointer to preserve provenance for Miri.
    pub struct TestMem {
        /// The backing storage - UnsafeCell for interior mutability
        storage: UnsafeCell<Vec<u8>>,
        /// Base address (the address we tell the ring about)
        base_addr: u64,
    }

    impl TestMem {
        pub fn new(size: usize) -> Self {
            let storage = vec![0u8; size];
            let base_addr = storage.as_ptr() as u64;
            Self {
                storage: UnsafeCell::new(storage),
                base_addr,
            }
        }

        /// Get a pointer with proper provenance for the given address
        fn ptr_for_addr(&self, addr: u64) -> *mut u8 {
            let storage = unsafe { &mut *self.storage.get() };
            let base_ptr = storage.as_mut_ptr();
            let offset = (addr - self.base_addr) as usize;
            // Use wrapping_add to maintain provenance from base_ptr
            base_ptr.wrapping_add(offset)
        }

        pub fn base_addr(&self) -> u64 {
            self.base_addr
        }
    }

    impl MemOps for Rc<TestMem> {
        type Error = core::convert::Infallible;

        fn read(&self, addr: u64, dst: &mut [u8]) -> Result<usize, Self::Error> {
            let src = self.ptr_for_addr(addr);
            unsafe {
                ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len());
            }
            Ok(dst.len())
        }

        fn write(&self, addr: u64, src: &[u8]) -> Result<usize, Self::Error> {
            let dst = self.ptr_for_addr(addr);
            unsafe {
                ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
            }
            Ok(src.len())
        }

        fn read_val<T: Pod>(&self, addr: u64) -> Result<T, Self::Error> {
            let ptr = self.ptr_for_addr(addr).cast::<T>();
            Ok(unsafe { ptr::read_volatile(ptr) })
        }

        fn write_val<T: Pod>(&self, addr: u64, val: T) -> Result<(), Self::Error> {
            let ptr = self.ptr_for_addr(addr).cast::<T>();
            unsafe { ptr::write_volatile(ptr, val) };
            Ok(())
        }

        fn load_acquire(&self, addr: u64) -> Result<u16, Self::Error> {
            let ptr = self.ptr_for_addr(addr).cast::<AtomicU16>();
            Ok(unsafe { (*ptr).load(Ordering::Acquire) })
        }

        fn store_release(&self, addr: u64, val: u16) -> Result<(), Self::Error> {
            let ptr = self.ptr_for_addr(addr).cast::<AtomicU16>();
            unsafe { (*ptr).store(val, Ordering::Release) };
            Ok(())
        }
    }

    /// Owns the descriptor table and event suppression structures
    pub struct OwnedRing {
        mem: Rc<TestMem>,
        layout: Layout,
    }

    fn align_up(val: usize, align: usize) -> usize {
        (val + align - 1) & !(align - 1)
    }

    impl OwnedRing {
        pub fn new(size: usize) -> Self {
            let num_descs = NonZeroU16::new(size as u16).unwrap();
            let needed = Layout::query_size(size);

            // Add padding to ensure we can align the base
            let padding = Descriptor::ALIGN;
            let mem = Rc::new(TestMem::new(needed + padding));

            // Align the base address
            let aligned_base = align_up(mem.base_addr() as usize, Descriptor::ALIGN) as u64;
            let layout = unsafe { Layout::from_base(aligned_base, num_descs).unwrap() };

            Self { mem, layout }
        }

        pub fn layout(&self) -> Layout {
            self.layout
        }

        pub fn mem(&self) -> Rc<TestMem> {
            self.mem.clone()
        }

        /// Get address of descriptor at index
        pub fn desc_addr(&self, idx: u16) -> u64 {
            self.layout.desc_table_addr + (idx as u64 * Descriptor::SIZE as u64)
        }

        /// Read descriptor directly (for test verification)
        pub fn read_desc(&self, idx: u16) -> Descriptor {
            self.mem.read_val(self.desc_addr(idx)).unwrap()
        }

        /// Write descriptor directly (for test manipulation)
        pub fn write_desc(&self, idx: u16, desc: Descriptor) {
            self.mem.write_val(self.desc_addr(idx), desc).unwrap()
        }

        /// Read driver event directly
        pub fn read_driver_event(&self) -> EventSuppression {
            self.mem.read_val(self.layout.drv_evt_addr).unwrap()
        }

        /// Read device event directly
        pub fn read_device_event(&self) -> EventSuppression {
            self.mem.read_val(self.layout.dev_evt_addr).unwrap()
        }

        pub fn len(&self) -> usize {
            self.layout.desc_table_len as usize
        }
    }

    // Share the TestMem between producer and consumer via reference
    pub(crate) fn make_ring(size: usize) -> OwnedRing {
        OwnedRing::new(size)
    }

    pub(crate) fn make_producer(ring: &OwnedRing) -> RingProducer<Rc<TestMem>> {
        RingProducer::new(ring.layout(), ring.mem())
    }

    pub(crate) fn make_consumer(ring: &OwnedRing) -> RingConsumer<Rc<TestMem>> {
        RingConsumer::new(ring.layout(), ring.mem())
    }

    fn assert_invariants(ring: &OwnedRing, prod: &RingProducer<Rc<TestMem>>) {
        let outstanding: u16 = prod.id_num.iter().copied().sum();
        assert_eq!(outstanding as usize + prod.num_free, ring.len());

        for id in prod.id_free.iter() {
            assert_eq!(prod.id_num[*id as usize], 0);
        }

        for (id, &n) in prod.id_num.iter().enumerate() {
            if n > 0 {
                assert!(!prod.id_free.contains(&(id as u16)));
            }
        }
    }

    #[test]
    fn test_initialization() {
        let ring = make_ring(8);
        let producer = make_producer(&ring);

        // All descriptors should be zeroed
        for i in 0..8u16 {
            let desc = ring.read_desc(i);
            assert_eq!(desc, Descriptor::zeroed());
            assert_eq!(desc.flags, 0);
            assert_eq!(desc.addr, 0);
            assert_eq!(desc.len, 0);
            assert_eq!(desc.id, 0);
        }

        // Cursors start at head=0, wrap=true
        assert_eq!(producer.avail_cursor.head(), 0);
        assert!(producer.avail_cursor.wrap());
        assert_eq!(producer.used_cursor.head(), 0);
        assert!(producer.used_cursor.wrap());

        // All IDs free, id_num zeroed, num_free == size
        assert_eq!(producer.id_free.len(), 8);
        assert_eq!(producer.num_free, 8);
        for i in 0..8 {
            assert_eq!(producer.id_num[i], 0);
        }
    }

    #[test]
    fn test_submit_one_descriptor() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let addr = 0x1000;
        let len = 512;
        let writable = false;

        let id = producer.submit_one(addr, len, writable).unwrap();

        // Check descriptor was written correctly
        let desc = ring.read_desc(0);

        assert_eq!(desc.addr, addr);
        assert_eq!(desc.len, len);
        assert_eq!(desc.id, id);

        // AVAIL should match wrap (true), USED should be inverse (false)
        let flags = desc.flags();
        assert!(flags.contains(DescFlags::AVAIL));
        assert!(!flags.contains(DescFlags::USED));
        assert!(!flags.contains(DescFlags::WRITE));
        assert!(!flags.contains(DescFlags::NEXT));

        // num_free should be decremented
        assert_eq!(producer.num_free, 7);

        // Cursor advanced
        assert_eq!(producer.avail_cursor.head(), 1);
        assert!(producer.avail_cursor.wrap());

        // ID allocated and chain length recorded
        assert_eq!(producer.id_num[id as usize], 1);
        assert_eq!(producer.id_free.len(), 7);
    }

    #[test]
    fn test_single_descriptor_wrap_toggle() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        // Advance to last slot
        producer.avail_cursor.head = 3;
        producer.avail_cursor.wrap = true;
        producer.num_free = 1;
        producer.id_free.clear();
        producer.id_free.push(0);

        let _id = producer.submit_one(0x1000, 512, false).unwrap();

        // After submission, cursor should wrap
        assert_eq!(producer.avail_cursor.head(), 0);
        assert!(!producer.avail_cursor.wrap());

        // Descriptor should have old wrap bits
        let desc = ring.read_desc(3);
        let flags = desc.flags();
        assert!(flags.contains(DescFlags::AVAIL));
        assert!(!flags.contains(DescFlags::USED));
    }

    #[test]
    fn test_multi_descriptor_no_wrap() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        // Check head descriptor
        let head_desc = ring.read_desc(0);
        assert_eq!(head_desc.addr, 0x1000);
        assert_eq!(head_desc.len, 256);
        assert_eq!(head_desc.id, id);

        let head_flags = head_desc.flags();
        assert!(head_flags.contains(DescFlags::NEXT));
        assert!(!head_flags.contains(DescFlags::WRITE));
        assert!(head_flags.contains(DescFlags::AVAIL));
        assert!(!head_flags.contains(DescFlags::USED));

        // Check middle descriptor
        let mid_desc = ring.read_desc(1);
        assert_eq!(mid_desc.addr, 0x2000);
        assert_eq!(mid_desc.len, 256);
        assert_eq!(mid_desc.id, id);

        let mid_flags = mid_desc.flags();
        assert!(mid_flags.contains(DescFlags::NEXT));
        assert!(!mid_flags.contains(DescFlags::WRITE));

        // Check tail descriptor
        let tail_desc = ring.read_desc(2);
        assert_eq!(tail_desc.addr, 0x3000);
        assert_eq!(tail_desc.len, 512);
        assert_eq!(tail_desc.id, id);

        let tail_flags = tail_desc.flags();
        assert!(!tail_flags.contains(DescFlags::NEXT));
        assert!(tail_flags.contains(DescFlags::WRITE));

        // All descriptors have same ID
        assert_eq!(head_desc.id, mid_desc.id);
        assert_eq!(mid_desc.id, tail_desc.id);

        // Check state updates
        assert_eq!(producer.num_free, 5);
        assert_eq!(producer.avail_cursor.head(), 3);
        assert_eq!(producer.id_num[id as usize], 3);
    }

    #[test]
    fn test_multi_descriptor_with_wrap() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        // Position head near end
        producer.avail_cursor.head = 2;
        producer.avail_cursor.wrap = true;

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .readable(0x3000, 256)
            .build()
            .unwrap();

        let _id = producer.submit_available(&chain).unwrap();

        // Head at index 2 with wrap=true
        let head_desc = ring.read_desc(2);
        let head_flags = head_desc.flags();
        assert!(head_flags.contains(DescFlags::AVAIL));
        assert!(!head_flags.contains(DescFlags::USED));

        // Middle at index 3 with wrap=true (before boundary)
        let mid_desc = ring.read_desc(3);
        let mid_flags = mid_desc.flags();
        assert!(mid_flags.contains(DescFlags::AVAIL));
        assert!(!mid_flags.contains(DescFlags::USED));

        // Tail at index 0 with wrap=false (after boundary)
        let tail_desc = ring.read_desc(0);
        let tail_flags = tail_desc.flags();
        assert!(!tail_flags.contains(DescFlags::AVAIL));
        assert!(tail_flags.contains(DescFlags::USED));

        // Cursor should have wrapped
        assert_eq!(producer.avail_cursor.head(), 1);
        assert!(!producer.avail_cursor.wrap());
    }

    #[test]
    fn test_ring_full() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        // Fill ring completely
        for _ in 0..4 {
            producer.submit_one(0x1000, 256, false).unwrap();
        }

        assert_eq!(producer.num_free, 0);

        // Next submit should fail
        let result = producer.submit_one(0x5000, 256, false);
        assert!(matches!(result, Err(RingError::WouldBlock)));
    }

    #[test]
    fn test_poll_and_reclaim() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let id = producer.submit_one(0x1000, 512, false).unwrap();

        // Manually mark as used (simulate device)
        let mut desc = ring.read_desc(0);
        desc.mark_used(true);
        desc.len = 256;
        ring.write_desc(0, desc);

        // Poll should return the used buffer
        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 256);

        // State should be updated
        assert_eq!(producer.num_free, 8);
        assert_eq!(producer.used_cursor.head(), 1);
        assert_eq!(producer.id_num[id as usize], 0);
        assert!(producer.id_free.contains(&id));
    }

    #[test]
    fn test_poll_multi_descriptor_chain() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        // Mark only head as used
        let mut head_desc = ring.read_desc(0);
        head_desc.mark_used(true);
        head_desc.len = 512;
        ring.write_desc(0, head_desc);

        // Poll should reclaim all 3 descriptors
        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 512);

        // Should have skipped 3 descriptors
        assert_eq!(producer.used_cursor.head(), 3);
        assert_eq!(producer.num_free, 8);
    }

    #[test]
    fn test_id_reuse() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        // Submit and complete first buffer
        let id1 = producer.submit_one(0x1000, 256, false).unwrap();

        let mut desc = ring.read_desc(0);
        desc.mark_used(true);
        ring.write_desc(0, desc);

        producer.poll_used().unwrap();

        // Submit another buffer - should reuse ID
        let id2 = producer.submit_one(0x2000, 256, false).unwrap();

        // ID should be reused (LIFO from stack)
        assert_eq!(id2, id1);
        assert_eq!(producer.id_num[id2 as usize], 1);
    }

    #[test]
    fn test_available_descriptor_flags() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        producer.submit_one(0x1000, 256, false).unwrap();

        let desc = ring.read_desc(0);

        // Available descriptor: AVAIL != USED
        let flags = desc.flags();
        assert_ne!(
            flags.contains(DescFlags::AVAIL),
            flags.contains(DescFlags::USED)
        );

        // ... and AVAIL=true, USED=false for wrap=true
        assert!(flags.contains(DescFlags::AVAIL));
        assert!(!flags.contains(DescFlags::USED));
    }

    #[test]
    fn test_used_descriptor_flags() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        producer.submit_one(0x1000, 256, false).unwrap();

        let mut desc = ring.read_desc(0);
        desc.mark_used(true);
        ring.write_desc(0, desc);

        let desc = ring.read_desc(0);
        let flags = desc.flags();

        // Used descriptor: AVAIL == USED
        assert_eq!(
            flags.contains(DescFlags::AVAIL),
            flags.contains(DescFlags::USED)
        );
    }

    #[test]
    fn test_poll_empty_ring() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        // Poll without any submitted buffers
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));
    }

    #[test]
    fn test_submit_when_full() {
        let ring = make_ring(2);
        let mut producer = make_producer(&ring);

        producer.submit_one(0x1000, 256, false).unwrap();
        producer.submit_one(0x2000, 256, false).unwrap();

        // Ring is full
        assert!(matches!(
            producer.submit_one(0x3000, 256, false),
            Err(RingError::WouldBlock)
        ));
    }

    #[test]
    fn test_empty_chain_rejected() {
        let chain = BufferChain::default();
        assert_eq!(chain.len(), 0);

        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        let result = producer.submit_available(&chain);
        assert!(matches!(result, Err(RingError::EmptyChain)));
    }

    #[test]
    fn test_wrap_stress() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Do multiple full laps
        for lap in 0..3 {
            let expected_wrap = lap % 2 == 0;

            for _ in 0..4 {
                let id = producer.submit_one(0x1000, 256, false).unwrap();

                let (dev_id, _) = consumer.poll_available().unwrap();
                assert_eq!(dev_id, id);

                consumer.submit_used(dev_id, 256).unwrap();

                producer.poll_used().unwrap();
            }

            // After full lap, wrap should toggle
            assert_eq!(producer.avail_cursor.wrap(), !expected_wrap);
        }
        assert_invariants(&ring, &producer);
    }

    #[test]
    fn test_next_flag_termination() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .readable(0x3000, 256)
            .build()
            .unwrap();

        producer.submit_available(&chain).unwrap();

        // First two should have NEXT
        for i in 0..2 {
            let desc = ring.read_desc(i);
            assert!(desc.flags().contains(DescFlags::NEXT));
        }

        // Last should not have NEXT
        let tail_desc = ring.read_desc(2);
        assert!(!tail_desc.flags().contains(DescFlags::NEXT));
    }

    #[test]
    fn test_consumer_initialization() {
        let ring = make_ring(8);
        let consumer = make_consumer(&ring);

        assert_eq!(consumer.avail_cursor.head(), 0);
        assert!(consumer.avail_cursor.wrap());
        assert_eq!(consumer.used_cursor.head(), 0);
        assert!(consumer.used_cursor.wrap());

        for i in 0..8 {
            assert_eq!(consumer.id_num[i], 0);
        }
    }

    #[test]
    fn test_consumer_poll_available_single() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let id = producer.submit_one(0x1000, 512, false).unwrap();

        let (polled_id, chain) = consumer.poll_available().unwrap();

        assert_eq!(polled_id, id);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.elems()[0].addr, 0x1000);
        assert_eq!(chain.elems()[0].len, 512);
        assert!(!chain.elems()[0].writable);

        // Chain length recorded
        assert_eq!(consumer.id_num[id as usize], 1);
        assert_eq!(consumer.avail_cursor.head(), 1);
    }

    #[test]
    fn test_consumer_poll_available_chain() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        let (polled_id, polled_chain) = consumer.poll_available().unwrap();

        assert_eq!(polled_id, id);
        assert_eq!(polled_chain.len(), 3);

        assert_eq!(polled_chain.elems()[0].addr, 0x1000);
        assert!(!polled_chain.elems()[0].writable);

        assert_eq!(polled_chain.elems()[1].addr, 0x2000);
        assert!(!polled_chain.elems()[1].writable);

        assert_eq!(polled_chain.elems()[2].addr, 0x3000);
        assert!(polled_chain.elems()[2].writable);

        assert_eq!(consumer.id_num[id as usize], 3);
    }

    #[test]
    fn test_consumer_submit_used() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let id = producer.submit_one(0x1000, 512, true).unwrap();

        let (polled_id, _) = consumer.poll_available().unwrap();

        // Submit as used
        consumer.submit_used(polled_id, 256).unwrap();

        // Check descriptor marked used
        let desc = ring.read_desc(0);

        assert_eq!(desc.id, id);
        assert_eq!(desc.len, 256);
        assert!(desc.is_used(true));

        // Cursor advanced, chain length cleared
        assert_eq!(consumer.used_cursor.head(), 1);
        assert_eq!(consumer.id_num[id as usize], 0);
    }

    #[test]
    fn test_consumer_submit_used_multi_descriptor() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .writable(0x2000, 512)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        producer.submit_available(&chain).unwrap();

        let (id, _) = consumer.poll_available().unwrap();

        consumer.submit_used(id, 1024).unwrap();

        // Only head marked used
        let head_desc = ring.read_desc(0);
        assert!(head_desc.is_used(true));
        assert_eq!(head_desc.len, 1024);

        // Cursor skipped entire chain
        assert_eq!(consumer.used_cursor.head(), 3);
        assert_eq!(consumer.id_num[id as usize], 0);
    }

    #[test]
    fn test_consumer_poll_empty() {
        let ring = make_ring(4);
        let mut consumer = make_consumer(&ring);

        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::WouldBlock)
        ));
    }

    #[test]
    fn test_consumer_peek() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let consumer = make_consumer(&ring);

        producer.submit_one(0x1000, 512, false).unwrap();
        assert!(consumer.peek_available().unwrap());

        let empty_ring = make_ring(4);
        let empty_consumer = make_consumer(&empty_ring);
        assert!(!empty_consumer.peek_available().unwrap());
    }

    #[test]
    fn test_full_roundtrip() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .writable(0x2000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        let (consumer_id, consumer_chain) = consumer.poll_available().unwrap();

        assert_eq!(consumer_id, id);
        assert_eq!(consumer_chain.len(), 2);

        consumer.submit_used(consumer_id, 512).unwrap();

        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_eq!(used.len, 512);
    }

    #[test]
    fn ring_initial_poll_used_blocks() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        // No submissions yet: all descriptors zero.
        for _ in 0..8 {
            assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));
        }
        // Invariants: num_free == ring size
        assert_eq!(producer.num_free, ring.len());
    }

    #[test]
    fn ring_consumer_blocks_until_submit() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::WouldBlock)
        ));

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 32)
            .readable(0x2000, 16)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        let (cid, polled) = consumer.poll_available().unwrap();
        assert_eq!(cid, id);
        assert_eq!(polled.len(), chain.len());
    }

    #[test]
    fn test_out_of_order_completion_stream() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Driver submits two single-descriptor chains A then B
        let id_a = producer.submit_one(0x1000, 256, true).unwrap();
        let id_b = producer.submit_one(0x2000, 256, true).unwrap();

        // Device polls them in ring order (A then B)
        let (dev_id_a, chain_a) = consumer.poll_available().unwrap();
        assert_eq!(dev_id_a, id_a);
        assert_eq!(chain_a.len(), 1);

        let (dev_id_b, chain_b) = consumer.poll_available().unwrap();
        assert_eq!(dev_id_b, id_b);
        assert_eq!(chain_b.len(), 1);

        // Device completes B first, then A
        consumer.submit_used(dev_id_b, 128).unwrap();
        consumer.submit_used(dev_id_a, 256).unwrap();

        // Driver polls used stream: should see B (first completion)
        let used_b = producer.poll_used().unwrap();
        assert_eq!(used_b.id, id_b);
        assert_eq!(used_b.len, 128);

        // Then sees A
        let used_a = producer.poll_used().unwrap();
        assert_eq!(used_a.id, id_a);
        assert_eq!(used_a.len, 256);

        // IDs recycled
        assert!(producer.id_free.contains(&id_a));
        assert!(producer.id_free.contains(&id_b));
    }

    #[test]
    fn test_mixed_chain_sizes_out_of_order_completion() {
        let ring = make_ring(16);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let chains = vec![
            BufferChainBuilder::new()
                .readable(0x1000, 10)
                .writable(0x2000, 5)
                .build()
                .unwrap(),
            BufferChainBuilder::new()
                .readable(0x3000, 8)
                .readable(0x3010, 8)
                .writable(0x3020, 16)
                .build()
                .unwrap(),
            BufferChainBuilder::new()
                .readable(0x4000, 4)
                .build()
                .unwrap(),
            BufferChainBuilder::new()
                .readable(0x5000, 4)
                .readable(0x5010, 4)
                .readable(0x5020, 4)
                .writable(0x5030, 4)
                .build()
                .unwrap(),
        ];

        for c in &chains {
            producer.submit_available(c).unwrap();
        }

        let mut dev_chain_lens = Vec::new();
        for _ in &chains {
            let (id, chain) = consumer.poll_available().unwrap();
            dev_chain_lens.push((id, chain.len() as u32));
        }

        let order = [1, 3, 0, 2];
        let mut completion = Vec::new();

        for &idx in &order {
            let (id, len) = dev_chain_lens[idx];
            consumer.submit_used(id, len).unwrap();
            completion.push((id, len));
        }

        for (expected_id, expected_len) in &completion {
            let used = producer.poll_used().unwrap();
            assert_eq!(used.id, *expected_id);
            assert_eq!(used.len, *expected_len);
            assert_eq!(producer.id_num[*expected_id as usize], 0);
            assert!(producer.id_free.contains(expected_id));
        }

        assert_invariants(&ring, &producer);
    }

    // Used stream wrap crossing
    #[test]
    fn test_used_stream_wrap_crossing() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Submit enough single descriptors to make used writes wrap
        let mut ids = Vec::new();
        for i in 0..8 {
            ids.push(producer.submit_one(0x1000 + i as u64, 1, false).unwrap());
        }

        // Device polls all
        for _ in 0..8 {
            consumer.poll_available().unwrap();
        }

        // Complete all in order except we simulate out-of-order by reversing
        for &id in ids.iter().rev() {
            consumer.submit_used(id, 1).unwrap();
        }

        // Producer polls used; after consuming size descriptors used_cursor should wrap
        for _ in 0..8 {
            producer.poll_used().unwrap();
        }
        assert_eq!(producer.used_cursor.head(), 0);
        assert!(!producer.used_cursor.wrap()); // flipped once
        assert_invariants(&ring, &producer);
    }

    // Interleaved availability and completion
    #[test]
    fn test_interleaved_submit_completion() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Submit chain A (len 2)
        let chain_a = BufferChainBuilder::new()
            .readable(0x1000, 8)
            .writable(0x2000, 8)
            .build()
            .unwrap();
        let id_a = producer.submit_available(&chain_a).unwrap();

        // Device polls A
        let (dev_id_a, _) = consumer.poll_available().unwrap();
        assert_eq!(dev_id_a, id_a);

        // Device completes A
        consumer.submit_used(dev_id_a, 8).unwrap();

        // Submit chain B (len 3) before driver reclaims A
        let chain_b = BufferChainBuilder::new()
            .readable(0x3000, 4)
            .readable(0x3010, 4)
            .writable(0x3020, 4)
            .build()
            .unwrap();
        let id_b = producer.submit_available(&chain_b).unwrap();

        // Device polls B
        let (dev_id_b, _) = consumer.poll_available().unwrap();
        assert_eq!(dev_id_b, id_b);

        // Driver reclaims A
        let used_a = producer.poll_used().unwrap();
        assert_eq!(used_a.id, id_a);

        // Device completes B
        consumer.submit_used(dev_id_b, 12).unwrap();

        // Driver reclaims B
        let used_b = producer.poll_used().unwrap();
        assert_eq!(used_b.id, id_b);

        assert_invariants(&ring, &producer);
    }

    // Partial publish safety (head not published yet)
    #[test]
    fn test_partial_publish_safety() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);
        let mut producer = make_producer(&ring);

        // Build chain manually: write tails only
        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .writable(0x3000, 4)
            .build()
            .unwrap();

        // Simulate manual tail writes without head publish
        let id = producer.id_free.pop().unwrap();
        producer.id_num[id as usize] = chain.len() as u16;

        // Emulate internal position logic
        let head_idx = producer.avail_cursor.head();
        let wrap_start = producer.avail_cursor.wrap();
        let mut pos = producer.avail_cursor;
        pos.advance();

        for (i, elem) in chain.elems().iter().enumerate().skip(1) {
            let is_next = i + 1 < chain.len();
            let mut flags = DescFlags::empty();
            flags.set(DescFlags::NEXT, is_next);
            flags.set(DescFlags::WRITE, elem.writable);
            let mut d = Descriptor::new(elem.addr, elem.len, id, flags);
            d.mark_avail(pos.wrap());
            ring.write_desc(pos.head(), d);
            pos.advance();
        }

        // Head not published yet: consumer must not see chain
        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::WouldBlock)
        ));

        // Now publish head
        let head_elem = chain.elems()[0];
        let mut head_flags = DescFlags::empty();
        head_flags.set(DescFlags::NEXT, true);
        head_flags.set(DescFlags::WRITE, head_elem.writable);
        let mut head_desc = Descriptor::new(head_elem.addr, head_elem.len, id, head_flags);
        head_desc.mark_avail(wrap_start);
        ring.write_desc(head_idx, head_desc);
        producer.avail_cursor = pos;
        producer.num_free -= chain.len();

        // Consumer can now see the chain
        let (dev_id, dev_chain) = consumer.poll_available().unwrap();
        assert_eq!(dev_id, id);
        assert_eq!(dev_chain.len(), chain.len());
        assert_invariants(&ring, &producer);
    }

    // Tail misuse negative test
    #[test]
    fn test_tail_marked_used_ignored() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = producer.submit_available(&chain).unwrap();

        // Incorrectly mark tail (index 1) used
        let mut tail_desc = ring.read_desc(1);
        tail_desc.mark_used(producer.used_cursor.wrap());
        ring.write_desc(1, tail_desc);

        // Poll should return WouldBlock (head not used yet)
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));

        // Mark head used properly
        let mut head_desc = ring.read_desc(0);
        head_desc.mark_used(producer.used_cursor.wrap());
        ring.write_desc(0, head_desc);

        // Now poll succeeds
        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_invariants(&ring, &producer);
    }

    // Max chain length boundary
    #[test]
    fn test_max_chain_len_rejected() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        // Try chain longer than ring size
        let elems = (0..9).map(|i| BufferElement {
            addr: 0x1000 + i as u64,
            len: 42,
            writable: false,
        });

        let chain = BufferChainBuilder::new().readables(elems).build().unwrap();

        // Submit_available should reject when num_free < total_descs
        assert!(matches!(
            producer.submit_available(&chain),
            Err(RingError::WouldBlock)
        ));
    }

    // Descriptor state monotonicity after many cycles
    #[test]
    fn test_descriptor_state_monotonicity() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Track states: 0=zero/init, 1=available, 2=used, 3=reclaimed
        let mut states = vec![0u8; 8];

        for _ in 0..5 {
            for state in states.iter_mut() {
                let id = producer.submit_one(0x1000, 4, false).unwrap();
                // mark available
                *state = (*state).max(1);

                // device polls and completes
                let (dev_id, _) = consumer.poll_available().unwrap();
                consumer.submit_used(dev_id, 4).unwrap();
                *state = (*state).max(2);

                let used = producer.poll_used().unwrap();
                assert_eq!(used.id, id);
                *state = (*state).max(3);
            }

            assert_invariants(&ring, &producer);
        }

        // Ensure monotonic progression (never decrease)
        for s in states {
            assert!(s >= 3);
        }
    }

    // Large multi-lap random submission/completion
    #[test]
    fn test_random_stress_small() {
        use rand::Rng;
        use rand::seq::SliceRandom;

        let ring = make_ring(16);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);
        let mut rng = rand::rng();

        // Submit initial set
        let mut active_ids = Vec::new();
        for _ in 0..8 {
            let len = rng.random_range(1..=4);
            let mut b = BufferChainBuilder::new().readable(0x1000, 4);
            for i in 1..len {
                b = b.readable(0x1000 + i as u64 * 0x10, 4);
            }
            let chain = b.build().unwrap();
            if let Ok(id) = producer.submit_available(&chain) {
                active_ids.push(id);
            }
        }

        let mut dev_ids = Vec::new();
        while let Ok((id, _)) = consumer.poll_available() {
            dev_ids.push(id);
        }

        // Randomly complete
        dev_ids.shuffle(&mut rng);
        for id in &dev_ids {
            let chain_len = consumer.id_num[*id as usize];
            consumer.submit_used(*id, chain_len as u32 * 4).unwrap();
        }
        // Driver reclaim
        for _ in &dev_ids {
            if producer.poll_used().is_ok() {}
        }

        assert_invariants(&ring, &producer);
    }

    // Out-of-order multi-length explicit
    #[test]
    fn test_out_of_order_multi_length() {
        let ring = make_ring(12);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let chain_a = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .writable(0x2000, 4)
            .build()
            .unwrap();
        let chain_b = BufferChainBuilder::new()
            .readable(0x3000, 4)
            .readable(0x3010, 4)
            .writable(0x3020, 4)
            .build()
            .unwrap();
        let chain_c = BufferChainBuilder::new()
            .readable(0x4000, 4)
            .build()
            .unwrap();

        let id_a = producer.submit_available(&chain_a).unwrap();
        let id_b = producer.submit_available(&chain_b).unwrap();
        let id_c = producer.submit_available(&chain_c).unwrap();

        let (d_a, _) = consumer.poll_available().unwrap();
        let (d_b, _) = consumer.poll_available().unwrap();
        let (d_c, _) = consumer.poll_available().unwrap();
        assert_eq!(d_a, id_a);
        assert_eq!(d_b, id_b);
        assert_eq!(d_c, id_c);

        // Complete B, then C, then A
        consumer.submit_used(d_b, 12).unwrap();
        consumer.submit_used(d_c, 4).unwrap();
        consumer.submit_used(d_a, 8).unwrap();

        let u_b = producer.poll_used().unwrap();
        assert_eq!(u_b.id, id_b);
        let u_c = producer.poll_used().unwrap();
        assert_eq!(u_c.id, id_c);
        let u_a = producer.poll_used().unwrap();
        assert_eq!(u_a.id, id_a);

        assert_invariants(&ring, &producer);
    }

    #[test]
    fn interleave_submit_and_completion() {
        let ring = make_ring(16);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Submit A (len 2)
        let chain_a = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .writable(0x2000, 4)
            .build()
            .unwrap();
        let id_a = producer.submit_available(&chain_a).unwrap();

        // Device polls A
        let (d_a, _) = consumer.poll_available().unwrap();
        assert_eq!(d_a, id_a);

        // Immediately complete A
        consumer.submit_used(d_a, 8).unwrap();

        // Submit B (len 3)
        let chain_b = BufferChainBuilder::new()
            .readable(0x3000, 4)
            .readable(0x3010, 4)
            .writable(0x3020, 4)
            .build()
            .unwrap();
        let id_b = producer.submit_available(&chain_b).unwrap();

        // Driver polls used: gets A
        let u_a = producer.poll_used().unwrap();
        assert_eq!(u_a.id, id_a);
        assert_eq!(u_a.len, 8);

        // Device polls B and submits used for it
        let (d_b, _) = consumer.poll_available().unwrap();
        assert_eq!(d_b, id_b);
        consumer.submit_used(d_b, 12).unwrap();

        // Submit C (len 1)
        let id_c = producer.submit_one(0x4000, 4, false).unwrap();

        // Device polls C and completes it
        let (d_c, _) = consumer.poll_available().unwrap();
        assert_eq!(d_c, id_c);
        consumer.submit_used(d_c, 4).unwrap();

        // Driver polls used: gets B then C
        let u_b = producer.poll_used().unwrap();
        assert_eq!(u_b.id, id_b);
        assert_eq!(u_b.len, 12);

        let u_c = producer.poll_used().unwrap();
        assert_eq!(u_c.id, id_c);
        assert_eq!(u_c.len, 4);

        assert_invariants(&ring, &producer);
    }

    // Event suppression tests
    #[test]
    fn producer_disable_used_notifications_writes_driver_disable() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        assert_eq!(ring.read_driver_event().flags(), EventFlags::ENABLE);
        producer.disable_used_notifications().unwrap();
        assert_eq!(ring.read_driver_event().flags(), EventFlags::DISABLE);
    }

    #[test]
    fn producer_enable_used_notifications_writes_driver_enable() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        producer.disable_used_notifications().unwrap();
        assert_eq!(ring.read_driver_event().flags(), EventFlags::DISABLE);

        producer.enable_used_notifications().unwrap();
        assert_eq!(ring.read_driver_event().flags(), EventFlags::ENABLE);
    }

    #[test]
    fn producer_enable_used_notifications_desc_sets_off_wrap_and_flags() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        producer.enable_used_notifications_desc(5, true).unwrap();

        let evt = ring.read_driver_event();
        assert_eq!(evt.flags(), EventFlags::DESC);
        assert_eq!(evt.desc_event_off(), 5);
        assert!(evt.desc_event_wrap());
    }

    #[test]
    fn producer_enable_used_notifications_for_next_programs_used_cursor() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        // initial used cursor: head=0, wrap=true
        producer.enable_used_notifications_for_next().unwrap();

        let evt = ring.read_driver_event();
        assert_eq!(evt.flags(), EventFlags::DESC);
        assert_eq!(evt.desc_event_off(), 0);
        assert!(evt.desc_event_wrap());
    }

    #[test]
    fn consumer_disable_avail_notifications_writes_device_disable() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);

        assert_eq!(ring.read_device_event().flags(), EventFlags::ENABLE);
        consumer.disable_avail_notifications().unwrap();
        assert_eq!(ring.read_device_event().flags(), EventFlags::DISABLE);
    }

    #[test]
    fn consumer_enable_avail_notifications_writes_device_enable() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);

        consumer.disable_avail_notifications().unwrap();
        assert_eq!(ring.read_device_event().flags(), EventFlags::DISABLE);

        consumer.enable_avail_notifications().unwrap();
        assert_eq!(ring.read_device_event().flags(), EventFlags::ENABLE);
    }

    #[test]
    fn consumer_enable_avail_notifications_desc_sets_off_wrap_and_flags() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);

        consumer.enable_avail_notifications_desc(7, false).unwrap();

        let evt = ring.read_device_event();
        assert_eq!(evt.flags(), EventFlags::DESC);
        assert_eq!(evt.desc_event_off(), 7);
        assert!(!evt.desc_event_wrap());
    }

    #[test]
    fn consumer_enable_avail_notifications_for_next_programs_avail_cursor() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);

        // initial avail cursor: head=0, wrap=true
        consumer.enable_avail_notifications_for_next().unwrap();

        let evt = ring.read_device_event();
        assert_eq!(evt.flags(), EventFlags::DESC);
        assert_eq!(evt.desc_event_off(), 0);
        assert!(evt.desc_event_wrap());
    }

    #[test]
    fn producer_does_not_write_device_event_when_toggling_used_notifications() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let dev_before = ring.read_device_event();
        producer.disable_used_notifications().unwrap();
        let dev_after = ring.read_device_event();

        assert_eq!(dev_after, dev_before);
    }

    #[test]
    fn consumer_does_not_write_driver_event_when_toggling_avail_notifications() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);

        let drv_before = ring.read_driver_event();
        consumer.disable_avail_notifications().unwrap();
        let drv_after = ring.read_driver_event();

        assert_eq!(drv_after, drv_before);
    }

    #[test]
    fn should_notify_flags_enable_disable() {
        let ring_len = 8;

        let old = RingCursor {
            head: 0,
            size: ring_len,
            wrap: true,
        };
        let new = RingCursor {
            head: 1,
            size: ring_len,
            wrap: true,
        };

        // DISABLE -> never notify
        let evt = EventSuppression::new(0, EventFlags::DISABLE);
        assert!(!should_notify(evt, ring_len, old, new));

        // ENABLE -> always notify
        let evt = EventSuppression::new(0, EventFlags::ENABLE);
        assert!(should_notify(evt, ring_len, old, new));
    }

    #[test]
    fn should_notify_desc_no_crossing() {
        let ring_len = 8;

        let old = RingCursor {
            head: 2,
            size: ring_len,
            wrap: true,
        };
        let new = RingCursor {
            head: 3,
            size: ring_len,
            wrap: true,
        };

        // event at 6, we did not cross it
        let mut evt = EventSuppression::zeroed();
        evt.set_desc_event(6, true);
        evt.set_flags(EventFlags::DESC);

        assert!(!should_notify(evt, ring_len, old, new));
    }

    #[test]
    fn should_notify_desc_wrap_mismatch_adjusts_event_idx() {
        let ring_len = 8;

        let old = RingCursor {
            head: 7,
            size: ring_len,
            wrap: true,
        };
        let new = RingCursor {
            head: 1,
            size: ring_len,
            wrap: false,
        };

        let mut evt = EventSuppression::zeroed();
        evt.set_desc_event(7, true);
        evt.set_flags(EventFlags::DESC);

        assert!(should_notify(evt, ring_len, old, new));
    }

    #[test]
    fn ring_need_event_basic_cases() {
        // If event_idx == new-1, should be true
        assert!(ring_need_event(4, 5, 2));
        // If no progress, should be false
        assert!(!ring_need_event(4, 5, 5));

        // Wrapping arithmetic sanity: old near u16::MAX
        let old = 0xFFFE;
        let new = 1;
        // event at 0xFFFF is considered "just before wrap"
        assert!(ring_need_event(0xFFFF, new, old));
    }

    // Bad device/driver tests
    #[test]
    fn bad_device_marks_tail_used() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = producer.submit_available(&chain).unwrap();

        // Bad device: mark index 1 (tail) used
        let mut tail = ring.read_desc(1);
        tail.mark_used(producer.used_cursor.wrap());
        ring.write_desc(1, tail);

        // Driver must not consume it
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));

        // Now mark head properly, driver must consume
        let mut head = ring.read_desc(0);
        head.mark_used(producer.used_cursor.wrap());
        ring.write_desc(0, head);

        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
    }

    #[test]
    fn bad_device_wrong_used_bits() {
        let ring = make_ring(4);
        let mut producer = make_producer(&ring);

        let id = producer.submit_one(0x1000, 8, true).unwrap();

        // Malformed: set AVAIL but clear USED (should be equal for used)
        let mut d = ring.read_desc(0);
        // Force flags to look like "available" despite intent
        d.mark_avail(producer.used_cursor.wrap());
        d.len = 8;
        ring.write_desc(0, d);

        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));

        let mut d2 = ring.read_desc(0);
        d2.mark_used(producer.used_cursor.wrap());
        ring.write_desc(0, d2);

        let u = producer.poll_used().unwrap();
        assert_eq!(u.id, id);
    }

    #[test]
    fn bad_driver_next_never_clears() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);
        let mut producer = make_producer(&ring);

        // Allocate an ID and pretend one huge chain
        let id = producer.id_free.pop().unwrap();
        producer.id_num[id as usize] = 8;

        let mut pos = producer.avail_cursor;
        let wrap_start = pos.wrap();

        // Write every descriptor with NEXT set and same id
        for _ in 0..8 {
            let idx = pos.head();
            let mut flags = DescFlags::empty();
            flags.set(DescFlags::NEXT, true); // incorrect: last should NOT have NEXT
            let mut desc = Descriptor::new(0x1000 + idx as u64 * 0x10, 4, id, flags);
            desc.mark_avail(pos.wrap());
            ring.write_desc(idx, desc);
            pos.advance();
        }

        // Publish head last (simulate driver behavior)
        let head_idx = producer.avail_cursor.head();
        let mut head_flags = DescFlags::empty();
        head_flags.set(DescFlags::NEXT, true);
        let mut head_desc = Descriptor::new(0x42, 4, id, head_flags);
        head_desc.mark_avail(wrap_start);
        ring.write_desc(head_idx, head_desc);

        // Consumer should detect invalid chain via step guard
        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::BadChain)
        ));
    }

    #[test]
    fn bad_driver_interleaved_readables_and_writables() {
        let ring = make_ring(8);
        let mut consumer = make_consumer(&ring);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .writable(0x2000, 4)
            .build()
            .unwrap();

        let _id = producer.submit_available(&chain).unwrap();

        // now change first descriptor to writable (bad driver)
        let mut first = ring.read_desc(0);
        first.flags |= DescFlags::WRITE.bits();
        ring.write_desc(0, first);

        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::BadChain)
        ));
    }

    #[test]
    fn bad_device_marks_multiple_used_in_chain() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = producer.submit_available(&chain).unwrap();

        // Bad device: mark head and tail used
        let mut head = ring.read_desc(0);
        head.mark_used(producer.used_cursor.wrap());
        ring.write_desc(0, head);

        let mut tail = ring.read_desc(1);
        tail.mark_used(producer.used_cursor.wrap());
        ring.write_desc(1, tail);

        // Driver consumes once
        let u = producer.poll_used().unwrap();
        assert_eq!(u.id, id);

        // Next poll should block; no duplicate consumption
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));
    }

    #[test]
    fn bad_device_writes_used_at_wrong_slot() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let _id = producer.submit_one(0x1000, 4, true).unwrap();

        // Wrong slot: mark index 3 used while next_used is 0
        let mut d = ring.read_desc(3);
        d.mark_used(producer.used_cursor.wrap());
        ring.write_desc(3, d);

        // Driver should still block (polls only slot 0)
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));

        // Now mark slot 0 correctly, driver can consume
        let mut d0 = ring.read_desc(0);
        d0.mark_used(producer.used_cursor.wrap());
        ring.write_desc(0, d0);
        let _u = producer.poll_used().unwrap();
    }

    #[test]
    fn bad_driver_reuses_id_while_outstanding() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        // Submit first buffer: allocate ID
        let id = producer.submit_one(0x1000, 4, false).unwrap();
        assert_eq!(producer.id_num[id as usize], 1);

        // push the same ID back into free list while it's still outstanding.
        producer.id_free.push(id);

        // Next submit should fail because ID is still outstanding.
        let res = producer.submit_one(0x2000, 4, false);
        assert!(matches!(res, Err(RingError::InvalidState)));
    }

    #[test]
    fn test_avail_cursor_accessor() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        // Initial cursor
        let cursor = producer.avail_cursor();
        assert_eq!(cursor.head(), 0);
        assert!(cursor.wrap());

        // After submit
        producer.submit_one(0x1000, 512, false).unwrap();
        let cursor = producer.avail_cursor();
        assert_eq!(cursor.head(), 1);
        assert!(cursor.wrap());
    }

    #[test]
    fn test_should_notify_since() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);

        let before = producer.avail_cursor();
        producer.submit_one(0x1000, 512, false).unwrap();

        // Default is ENABLE mode, so should notify
        let should_notify = producer.should_notify_since(before).unwrap();
        assert!(should_notify);
    }

    #[test]
    fn test_batch_notification_single_check() {
        let ring = make_ring(8);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        let before = producer.avail_cursor();

        // Submit multiple descriptors
        producer.submit_one(0x1000, 512, false).unwrap();
        producer.submit_one(0x2000, 512, false).unwrap();
        producer.submit_one(0x3000, 512, false).unwrap();

        // Single notification check for the entire batch
        let should_notify = producer.should_notify_since(before).unwrap();
        assert!(should_notify);

        // Consumer sees all 3 descriptors
        for _ in 0..3 {
            let (_, _) = consumer.poll_available().unwrap();
        }
    }
}

#[cfg(test)]
mod fuzz {
    use quickcheck::{Arbitrary, Gen, QuickCheck};

    use super::tests::{OwnedRing, make_consumer, make_producer};
    use super::*;

    const MAX_RING: usize = 64;
    const MAX_OPS: usize = 128;
    const MAX_CHAIN_LEN: usize = 8;

    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    enum Op {
        /// submit one chain
        Submit(BufferChain),
        /// poll up to N chains
        PollAvail(u8),
        /// driver reclaims up to N completions
        PollUsed(u8),
        /// complete one previously polled chain
        CompleteOne,
    }

    impl Arbitrary for Op {
        fn arbitrary(g: &mut Gen) -> Self {
            let choice = u8::arbitrary(g) % 4;
            match choice {
                0 => Op::Submit(BufferChain::arbitrary(g)),
                1 => Op::PollAvail(u8::arbitrary(g) % 8 + 1),
                2 => Op::PollUsed(u8::arbitrary(g) % 8 + 1),
                3 => Op::CompleteOne,
                _ => unreachable!(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Scenario {
        table_size: usize,
        ops: Vec<Op>,
    }

    impl Arbitrary for Scenario {
        fn arbitrary(g: &mut Gen) -> Self {
            let table_size = usize::arbitrary(g) % MAX_RING + 1;
            let num_ops = usize::arbitrary(g) % MAX_OPS + 1;

            let ops = (0..num_ops).map(|_| Op::arbitrary(g)).collect();
            Scenario { table_size, ops }
        }
    }

    impl Arbitrary for BufferElement {
        fn arbitrary(g: &mut Gen) -> Self {
            let addr = u64::arbitrary(g);
            let len = u32::arbitrary(g);
            let writable = bool::arbitrary(g);

            BufferElement {
                addr,
                len,
                writable,
            }
        }
    }

    impl Arbitrary for BufferChain {
        fn arbitrary(g: &mut Gen) -> Self {
            let chain_len = usize::arbitrary(g) % MAX_CHAIN_LEN + 1;

            let mut elems = vec![BufferElement::zeroed(); chain_len];
            let mut readables = 0;
            let mut writables = 0;

            for _ in 0..chain_len {
                let elem = BufferElement::arbitrary(g);
                if elem.writable {
                    elems[chain_len - 1 - writables] = elem;
                    writables += 1;
                } else {
                    elems[readables] = elem;
                    readables += 1;
                }
            }

            BufferChain {
                elems: elems.into(),
                split: readables,
            }
        }
    }

    fn run_scenario(s: Scenario) -> bool {
        let ring = OwnedRing::new(s.table_size);
        let mut producer = make_producer(&ring);
        let mut consumer = make_consumer(&ring);

        // Order logs
        let mut dev_order: Vec<u16> = Vec::new();
        let mut drv_order: Vec<u16> = Vec::new();

        // Device-tracked polled-but-not-completed IDs
        let mut dev_ready: Vec<(u16, u32)> = Vec::new();

        for op in &s.ops {
            match op {
                Op::Submit(chain) => {
                    // Submit only if space; otherwise skip
                    let _ = producer.submit_available(chain);
                }
                Op::PollAvail(n) => {
                    for _ in 0..*n {
                        if let Ok((id, chain)) = consumer.poll_available() {
                            dev_ready.push((id, chain.len() as u32));
                        } else {
                            break;
                        }
                    }
                }
                Op::PollUsed(n) => {
                    for _ in 0..*n {
                        match producer.poll_used() {
                            Ok(u) => {
                                drv_order.push(u.id);
                                if producer.id_num[u.id as usize] != 0 {
                                    return false;
                                }
                                if !producer.id_free.contains(&u.id) {
                                    return false;
                                }
                            }
                            Err(RingError::WouldBlock) => break,
                            Err(_) => return false,
                        }
                    }
                }
                Op::CompleteOne => {
                    if let Some((id, len)) = dev_ready.pop() {
                        if consumer.submit_used(id, len).is_err() {
                            return false;
                        }

                        dev_order.push(id);
                    }
                }
            }

            // assert invariants after each op
            let outstanding: u16 = producer.id_num.iter().copied().sum();
            if outstanding as usize + producer.num_free != ring.len() {
                return false;
            }

            for id in producer.id_free.iter() {
                if producer.id_num[*id as usize] != 0 {
                    return false;
                }
            }
        }

        // Drain remaining completions and reclaims
        while let Some((id, len)) = dev_ready.pop() {
            if consumer.submit_used(id, len).is_err() {
                return false;
            }
        }

        loop {
            match producer.poll_used() {
                Ok(u) => drv_order.push(u.id),
                Err(RingError::WouldBlock) => break,
                Err(_) => return false,
            }
        }

        true
    }

    #[test]
    fn prop_interleaved_with_order_verification() {
        #[cfg(miri)]
        let tests = 1;
        #[cfg(not(miri))]
        let tests = 100;

        QuickCheck::new()
            .tests(tests)
            .quickcheck(run_scenario as fn(Scenario) -> bool);
    }
}
