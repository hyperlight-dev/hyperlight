use core::marker::PhantomData;

use bytemuck::Zeroable;
use smallvec::SmallVec;

use super::desc::DescTable;
use super::{EventFlags, EventSuppression, MmioView, MmioViewMut};
use crate::ring::desc::{DescFlags, Descriptor};

/// A buffer element (part of a scatter-gather list).
#[derive(Debug, Copy, Clone, Zeroable)]
pub struct BufferElement {
    /// Physical address of buffer
    pub addr: u64,
    /// Length in bytes
    pub len: u32,
    /// Is this buffer writable
    pub writable: bool,
}

/// A buffer returned from the ring after being used by the device.
#[derive(Debug, Copy, Clone)]
pub struct UsedBuffer {
    /// Descriptor ID associated with this used buffer
    pub id: u16,
    /// Length in bytes of data written by device
    pub len: u32,
}

#[derive(Debug, Copy, Clone)]
pub struct SubmitResult {
    /// Descriptor ID assigned to the submitted buffer chain
    pub id: u16,
    /// Whether the device should be notified immediately
    pub notify: bool,
}

#[derive(Debug)]
pub enum RingError {
    EmptyChain,
    WouldBlock,
    OutOfMemory,
    InvalidState,
}

impl core::fmt::Display for RingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RingError::WouldBlock => write!(f, "Operation would block"),
            RingError::OutOfMemory => write!(f, "Out of memory"),
            RingError::InvalidState => write!(f, "Invalid state"),
            RingError::EmptyChain => write!(f, "Buffer chain is empty"),
        }
    }
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
    /// Create a new builder starting in Readable state.
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

#[derive(Debug, Default, Clone)]
pub struct BufferChain {
    /// Readable and writable buffer elements
    elems: SmallVec<[BufferElement; 16]>,
    /// Split index between readable and writable buffers
    split: usize,
}

// buffer chain cannot be empty
#[allow(clippy::len_without_is_empty)]
impl BufferChain {
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
    pub fn len(&self) -> usize {
        self.elems.len()
    }
}

/// Helper for tracking position in a wrapped ring buffer
#[derive(Debug, Copy, Clone)]
struct RingCursor {
    head: u16,
    size: u16,
    wrap: bool,
}

impl RingCursor {
    fn new(size: usize) -> Self {
        Self {
            head: 0,
            size: size as u16,
            wrap: true,
        }
    }

    /// Advance to next position, wrapping around and toggling wrap counter if needed
    #[inline]
    fn advance(&mut self) {
        self.head += 1;
        if self.head >= self.size {
            self.head = 0;
            self.wrap = !self.wrap;
        }
    }

    /// Advance by n positions
    #[inline]
    fn advance_by(&mut self, n: u16) {
        for _ in 0..n {
            self.advance();
        }
    }

    /// Get current head index
    #[inline]
    fn head(&self) -> u16 {
        self.head
    }

    /// Get current wrap counter
    #[inline]
    fn wrap(&self) -> bool {
        self.wrap
    }
}

/// The producer side of a packed ring.
#[derive(Debug)]
pub struct RingProducer<'q> {
    /// Next available descriptor position
    avail_cursor: RingCursor,
    /// Next used descriptor position
    used_cursor: RingCursor,
    /// Free slots in the ring
    num_free: usize,
    /// Descriptor table in shared memory
    desc_table: DescTable<'q>,
    /// Shadow of driver event flags (last written value)
    event_flags_shadow: EventFlags,
    // controls when device notifies about used buffers
    driver_event: Option<MmioViewMut<'q, EventSuppression>>,
    // reads device event to check if device wants notification
    device_event: Option<MmioView<'q, EventSuppression>>,
    /// stack of free IDs, allows out-of-order completion
    id_free: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
    // chain length per ID, index = ID,
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
}

impl<'q> RingProducer<'q> {
    pub fn new(table: DescTable<'q>) -> Self {
        let size = table.len();
        let cursor = RingCursor::new(size);

        const DEFAULT_LEN: usize = DescTable::default_len();
        let id_free = (0..size as u16).collect::<SmallVec<[_; DEFAULT_LEN]>>();
        let id_num = SmallVec::<[_; DEFAULT_LEN]>::from_elem(0, size);

        // Notification enabled by default
        let event_flags_shadow = EventFlags::ENABLE;

        Self {
            avail_cursor: cursor,
            used_cursor: cursor,
            num_free: size,
            desc_table: table,
            id_free,
            id_num,
            event_flags_shadow,
            driver_event: None,
            device_event: None,
        }
    }

    /// Create a new RingProducer with event suppression.
    pub fn new_with_events(
        table: DescTable<'q>,
        driver_event: MmioViewMut<'q, EventSuppression>,
        device_event: MmioView<'q, EventSuppression>,
    ) -> Self {
        let mut ring = Self::new(table);
        ring.driver_event = Some(driver_event);
        ring.device_event = Some(device_event);
        ring
    }

    // Fast path: submit exactly one descriptor
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

        let mut view = self
            .desc_table
            .get_mut(head_idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish
        view.write_release(desc);

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
        let notify = self.should_notify_device(old, new);

        Ok(SubmitResult { id, notify })
    }

    /// Fast path: submit exactly one descriptor, returning whether to notify the device.
    pub fn submit_one_with_notify(
        &mut self,
        addr: u64,
        len: u32,
        writable: bool,
    ) -> Result<SubmitResult, RingError> {
        let old = self.avail_cursor;
        let id = self.submit_one(addr, len, writable)?;
        let new = self.avail_cursor;
        let notify = self.should_notify_device(old, new);
        Ok(SubmitResult { id, notify })
    }

    /// Submit a buffer chain to the ring.
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

            let mut view = self
                .desc_table
                .get_mut(pos.head())
                .ok_or(RingError::InvalidState)?;

            view.write_volatile(desc);
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

        let mut head_view = self
            .desc_table
            .get_mut(head_idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish
        head_view.write_release(head_desc);

        self.num_free -= total_descs;
        self.avail_cursor = pos;

        Ok(id)
    }

    /// Poll the ring for a used buffer.
    pub fn poll_used(&mut self) -> Result<UsedBuffer, RingError> {
        let idx = self.used_cursor.head();
        let wrap = self.used_cursor.wrap();

        // Read the descriptor at next_used position with ordering
        let view = self.desc_table.get(idx).ok_or(RingError::InvalidState)?;
        // Acquire flags then fields (publish point)
        let desc = view.read_acquire();

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

    /// Driver disables used-buffer notifications from device to driver.
    pub fn disable_used_notifications(&mut self) {
        let Some(drv_evt) = self.driver_event.as_mut() else {
            self.event_flags_shadow = EventFlags::DISABLE;
            return;
        };

        // Avoid redundant MMIO writes if already disabled
        if self.event_flags_shadow == EventFlags::DISABLE {
            return;
        }

        let mut evt = drv_evt.read_volatile();
        evt.set_flags(EventFlags::DISABLE);
        drv_evt.write_release(evt);

        self.event_flags_shadow = EventFlags::DISABLE;
    }

    /// Driver enables used-buffer notifications from device to driver.
    pub fn enable_used_notifications(&mut self) {
        let Some(drv_evt) = self.driver_event.as_mut() else {
            self.event_flags_shadow = EventFlags::ENABLE;
            return;
        };

        if self.event_flags_shadow == EventFlags::ENABLE {
            return;
        }

        let mut evt = drv_evt.read_volatile();
        evt.set_flags(EventFlags::ENABLE);
        drv_evt.write_release(evt);
        // cache shadow
        self.event_flags_shadow = EventFlags::ENABLE;
    }

    /// Driver enables descriptor-specific used notifications (EVENT_IDX / DESC mode).
    ///
    /// This tells the device: "Interrupt me when you reach used index (off, wrap)".
    pub fn enable_used_notifications_desc(&mut self, off: u16, wrap: bool) {
        let Some(drv_evt) = self.driver_event.as_mut() else {
            self.event_flags_shadow = EventFlags::DESC;
            return;
        };

        let mut evt = drv_evt.read_volatile();
        evt.set_desc_event(off, wrap);
        evt.set_flags(EventFlags::DESC);

        // Now publish flags = DESC with Release semantics.
        drv_evt.write_release(evt);
        // cache shadow
        self.event_flags_shadow = EventFlags::DESC;
    }

    /// Convenience: enable DESC mode for "next used cursor" like Linux enable_cb_prepare.
    pub fn enable_used_notifications_for_next(&mut self) {
        let off = self.used_cursor.head();
        let wrap = self.used_cursor.wrap();

        self.enable_used_notifications_desc(off, wrap)
    }

    /// Check whether the device should be notified about new available descriptors.
    fn should_notify_device(&self, old: RingCursor, new: RingCursor) -> bool {
        let Some(device_evt) = &self.device_event else {
            // no event suppression structure wired so always notify
            return true;
        };

        // Spec requires: "driver MUST perform a suitable memory barrier before
        // reading device event suppression" (2.8.21.3.1)
        // We already published descriptors with write_release, so now do an Acquire
        // read of device_event.
        let evt = device_evt.read_acquire();
        should_notify(evt, self.desc_table.len() as u16, old, new)
    }
}

/// The consumer side of a packed ring.
#[derive(Debug)]
pub struct RingConsumer<'q> {
    /// Cursor for reading available (driver-published) descriptors
    avail_cursor: RingCursor,
    /// Cursor for writing used descriptors
    used_cursor: RingCursor,
    /// Shared descriptor table
    desc_table: DescTable<'q>,
    /// Per-ID chain length learned when polling (index = ID)
    id_num: SmallVec<[u16; DescTable::DEFAULT_LEN]>,
    /// Shadow of device event flags (last written value)
    event_flags_shadow: EventFlags,
    // reads driver event to control when device should notify
    driver_event: Option<MmioView<'q, EventSuppression>>,
    // write device_event (checks if device wants notification about available buffers)
    device_event: Option<MmioViewMut<'q, EventSuppression>>,
}

impl<'q> RingConsumer<'q> {
    pub fn new(table: DescTable<'q>) -> Self {
        let size = table.len();
        let cursor = RingCursor::new(size);
        let id_chain_len = SmallVec::<[u16; DescTable::DEFAULT_LEN]>::from_elem(0, size);

        // Notification enabled by default
        let event_flags_shadow = EventFlags::ENABLE;

        Self {
            avail_cursor: cursor,
            used_cursor: cursor,
            desc_table: table,
            id_num: id_chain_len,
            event_flags_shadow,
            driver_event: None,
            device_event: None,
        }
    }

    /// Create a new RingConsumer with event suppression.
    pub fn new_with_events(
        table: DescTable<'q>,
        driver_event: MmioView<'q, EventSuppression>,
        device_event: MmioViewMut<'q, EventSuppression>,
    ) -> Self {
        let mut ring = Self::new(table);
        ring.driver_event = Some(driver_event);
        ring.device_event = Some(device_event);
        ring
    }

    /// Poll one available chain. Returns (id, BufferChain).
    ///
    /// returns `WouldBlock` if head descriptor not yet available.
    pub fn poll_available(&mut self) -> Result<(u16, BufferChain), RingError> {
        let idx = self.avail_cursor.head();
        let wrap = self.avail_cursor.wrap();

        let head_view = self
            .desc_table
            .get_mut(idx)
            .ok_or(RingError::InvalidState)?;

        // Acquire: flags then fields (publish point)
        let head_desc = head_view.read_acquire();
        if !head_desc.is_avail(wrap) {
            return Err(RingError::WouldBlock);
        }

        // Build chain (head + tails).
        let mut elements = SmallVec::<[BufferElement; 16]>::new();
        let mut pos = self.avail_cursor;
        let mut chain_len: u16 = 0;

        let mut steps = 0;
        let mut readables = 0;
        let max_steps = self.desc_table.len();

        loop {
            if steps >= max_steps {
                return Err(RingError::InvalidState);
            }

            let view = self
                .desc_table
                .get(pos.head())
                .ok_or(RingError::InvalidState)?;

            // tail reads does not need ordering because head has been already validated
            let desc = view.read_volatile();
            let writable = desc.is_writeable();

            elements.push(BufferElement {
                addr: desc.addr,
                len: desc.len,
                writable,
            });

            readables += !writable as usize;
            chain_len += 1;
            steps += 1;

            let has_next = desc.is_next();

            pos.advance();
            if !has_next {
                break;
            }
        }

        // since driver wrote the same id everywhere, head_desc.id is valid.
        let id = head_desc.id;
        if (id as usize) >= self.id_num.len() {
            return Err(RingError::InvalidState);
        }

        // Record chain length for later used submission
        self.id_num[id as usize] = chain_len;
        // Advance avail cursor to first slot after chain
        self.avail_cursor = pos;

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

        let mut view = self
            .desc_table
            .get_mut(idx)
            .ok_or(RingError::InvalidState)?;

        // Release publish (flags written last inside write())
        view.write_release(used_desc);

        // Advance used cursor by whole chain length
        self.used_cursor.advance_by(chain_len);
        self.id_num[id as usize] = 0;

        Ok(())
    }

    /// Try to peek whether the next chain is available without consuming it.
    pub fn peek_available(&self) -> bool {
        if let Some(view) = self.desc_table.get(self.avail_cursor.head()) {
            let desc = view.read_acquire();
            desc.is_avail(self.avail_cursor.wrap())
        } else {
            false
        }
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
        Ok(self.should_notify_driver(old, new))
    }

    /// Device disables available-buffer notifications from driver to device.
    ///
    /// This is the device-side mirror of "disable callbacks" but for avail kicks.
    pub fn disable_avail_notifications(&mut self) -> Result<(), RingError> {
        let Some(dev_evt) = self.device_event.as_mut() else {
            self.event_flags_shadow = EventFlags::DISABLE;
            return Ok(());
        };

        if self.event_flags_shadow == EventFlags::DISABLE {
            return Ok(());
        }

        let mut evt = dev_evt.read_volatile();
        evt.set_flags(EventFlags::DISABLE);
        dev_evt.write_release(evt);

        self.event_flags_shadow = EventFlags::DISABLE;
        Ok(())
    }

    /// Device enables available-buffer notifications from driver to device.
    pub fn enable_avail_notifications(&mut self) -> Result<(), RingError> {
        let Some(dev_evt) = self.device_event.as_mut() else {
            self.event_flags_shadow = EventFlags::ENABLE;
            return Ok(());
        };

        if self.event_flags_shadow == EventFlags::ENABLE {
            return Ok(());
        }

        let mut evt = dev_evt.read_volatile();
        evt.set_flags(EventFlags::ENABLE);
        dev_evt.write_release(evt);

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
        let Some(dev_evt) = self.device_event.as_mut() else {
            self.event_flags_shadow = EventFlags::DESC;
            return Ok(());
        };

        // Update off_wrap first
        let mut evt = dev_evt.read_volatile();
        evt.set_desc_event(off, wrap);
        evt.set_flags(EventFlags::DESC);
        dev_evt.write_release(evt);

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
    fn should_notify_driver(&self, old: RingCursor, new: RingCursor) -> bool {
        let Some(driver_evt) = &self.driver_event else {
            // no suppression wired: always notify
            return true;
        };

        let evt = driver_evt.read_acquire();
        should_notify(evt, self.desc_table.len() as u16, old, new)
    }
}

/// Common packed-ring notification decision (Linux `virtqueue_kick_prepare_packed` logic),
/// parameterized by the event suppression struct and the cursor progression.
///
/// - `old` and `new` are the ring indices (head) before/after publishing a batch
/// - `new.wrap()` is the wrap counter corresponding to `new.head()`
/// - `evt.desc_event_wrap()` is compared against `new.wrap()`
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

#[cfg(test)]
mod tests {
    use core::cell::UnsafeCell;
    use core::ptr::NonNull;

    use bytemuck::Zeroable;

    use super::*;

    pub struct OwnedTable {
        buf: UnsafeCell<Vec<Descriptor>>,
    }

    impl OwnedTable {
        pub fn new(size: usize) -> Self {
            let buf = vec![Descriptor::zeroed(); size];
            let buf = UnsafeCell::new(buf);

            Self { buf }
        }

        pub fn table(&self) -> DescTable<'_> {
            let v = self.buf.get();
            let ptr = unsafe { (*v).as_mut_ptr() };
            let len = unsafe { (*v).len() };
            unsafe { DescTable::from_mem(NonNull::new_unchecked(ptr), len) }
        }
    }

    pub fn make_table(size: usize) -> OwnedTable {
        OwnedTable::new(size)
    }

    fn assert_invariants(prod: &RingProducer) {
        // num_free + outstanding == ring size
        let outstanding: u16 = prod.id_num.iter().copied().sum();
        assert_eq!(outstanding as usize + prod.num_free, prod.desc_table.len());

        // IDs in id_free must have id_num == 0
        for id in prod.id_free.iter() {
            assert_eq!(prod.id_num[*id as usize], 0);
        }

        // For each id with id_num > 0 it must not appear in free list
        for (id, &n) in prod.id_num.iter().enumerate() {
            if n > 0 {
                assert!(!prod.id_free.contains(&(id as u16)));
            }
        }
    }

    pub struct OwnedEvents {
        // [0]=driver, [1]=device
        buf: UnsafeCell<[EventSuppression; 2]>,
    }

    impl OwnedEvents {
        pub fn new() -> Self {
            Self {
                buf: UnsafeCell::new([EventSuppression::zeroed(); 2]),
            }
        }

        fn ptr(&self) -> *mut EventSuppression {
            self.buf.get().cast::<EventSuppression>()
        }

        pub fn driver_view(&self) -> MmioView<'_, EventSuppression> {
            unsafe { MmioView::new(NonNull::new_unchecked(self.ptr().add(0))) }
        }

        pub fn device_view(&self) -> MmioView<'_, EventSuppression> {
            unsafe { MmioView::new(NonNull::new_unchecked(self.ptr().add(1))) }
        }

        pub fn driver_view_mut(&self) -> MmioViewMut<'_, EventSuppression> {
            unsafe { MmioViewMut::new(NonNull::new_unchecked(self.ptr().add(0))) }
        }

        pub fn device_view_mut(&self) -> MmioViewMut<'_, EventSuppression> {
            unsafe { MmioViewMut::new(NonNull::new_unchecked(self.ptr().add(1))) }
        }
    }

    #[test]
    fn test_initialization() {
        let size = 8;
        let owned = make_table(size);
        let producer = RingProducer::new(owned.table());

        // All descriptors should be zeroed
        for i in 0..size as u16 {
            let view = producer.desc_table.get(i).unwrap();
            let desc = view.read_acquire();
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
        assert_eq!(producer.id_free.len(), size);
        assert_eq!(producer.num_free, size);
        assert_eq!(producer.id_free.len(), size);
        for i in 0..size {
            assert_eq!(producer.id_num[i], 0);
        }
    }

    #[test]
    fn test_submit_one_descriptor() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let addr = 0x1000;
        let len = 512;
        let writable = false;

        let id = producer.submit_one(addr, len, writable).unwrap();

        // Check descriptor was written correctly
        let view = producer.desc_table.get(0).unwrap();
        let desc = view.read_acquire();

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
        let size = 4;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

        // Advance to last slot
        producer.avail_cursor.head = (size - 1) as u16;
        producer.avail_cursor.wrap = true;
        producer.num_free = 1;
        producer.id_free.clear();
        producer.id_free.push(0);

        let _id = producer.submit_one(0x1000, 512, false).unwrap();

        // After submission, cursor should wrap
        assert_eq!(producer.avail_cursor.head(), 0);
        assert!(!producer.avail_cursor.wrap());

        // Descriptor should have old wrap bits
        let view = producer.desc_table.get((size - 1) as u16).unwrap();
        let desc = view.read_acquire();
        let flags = desc.flags();
        assert!(flags.contains(DescFlags::AVAIL));
        assert!(!flags.contains(DescFlags::USED));
    }

    #[test]
    fn test_multi_descriptor_no_wrap() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        // Check head descriptor
        let head_view = producer.desc_table.get(0).unwrap();
        let head_desc = head_view.read_acquire();
        assert_eq!(head_desc.addr, 0x1000);
        assert_eq!(head_desc.len, 256);
        assert_eq!(head_desc.id, id);

        let head_flags = head_desc.flags();
        assert!(head_flags.contains(DescFlags::NEXT));
        assert!(!head_flags.contains(DescFlags::WRITE));
        assert!(head_flags.contains(DescFlags::AVAIL));
        assert!(!head_flags.contains(DescFlags::USED));

        // Check middle descriptor
        let mid_view = producer.desc_table.get(1).unwrap();
        let mid_desc = mid_view.read_acquire();
        assert_eq!(mid_desc.addr, 0x2000);
        assert_eq!(mid_desc.len, 256);
        assert_eq!(mid_desc.id, id);

        let mid_flags = mid_desc.flags();
        assert!(mid_flags.contains(DescFlags::NEXT));
        assert!(!mid_flags.contains(DescFlags::WRITE));

        // Check tail descriptor
        let tail_view = producer.desc_table.get(2).unwrap();
        let tail_desc = tail_view.read_acquire();
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
        let size = 4;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

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
        let head_view = producer.desc_table.get(2).unwrap();
        let head_desc = head_view.read_acquire();
        let head_flags = head_desc.flags();
        assert!(head_flags.contains(DescFlags::AVAIL));
        assert!(!head_flags.contains(DescFlags::USED));

        // Middle at index 3 with wrap=true (before boundary)
        let mid_view = producer.desc_table.get(3).unwrap();
        let mid_desc = mid_view.read_acquire();
        let mid_flags = mid_desc.flags();
        assert!(mid_flags.contains(DescFlags::AVAIL));
        assert!(!mid_flags.contains(DescFlags::USED));

        // Tail at index 0 with wrap=false (after boundary)
        let tail_view = producer.desc_table.get(0).unwrap();
        let tail_desc = tail_view.read_acquire();
        let tail_flags = tail_desc.flags();
        assert!(!tail_flags.contains(DescFlags::AVAIL));
        assert!(tail_flags.contains(DescFlags::USED));

        // Cursor should have wrapped
        assert_eq!(producer.avail_cursor.head(), 1);
        assert!(!producer.avail_cursor.wrap());
    }

    #[test]
    fn test_ring_full() {
        let size = 4;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

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
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let id = producer.submit_one(0x1000, 512, false).unwrap();

        // Manually mark as used (simulate device)
        let mut view = producer.desc_table.get_mut(0).unwrap();
        let mut desc = view.read_acquire();
        desc.mark_used(true);
        desc.len = 256;
        view.write_release(desc);

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
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        // Mark only head as used
        let mut head_view = producer.desc_table.get_mut(0).unwrap();
        let mut head_desc = head_view.read_acquire();
        head_desc.mark_used(true);
        head_desc.len = 512;
        head_view.write_release(head_desc);

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
        let owned = make_table(4);
        let mut producer = RingProducer::new(owned.table());

        // Submit and complete first buffer
        let id1 = producer.submit_one(0x1000, 256, false).unwrap();

        let mut view = producer.desc_table.get_mut(0).unwrap();
        let mut desc = view.read_acquire();
        desc.mark_used(true);
        view.write_release(desc);

        producer.poll_used().unwrap();

        // Submit another buffer - should reuse ID
        let id2 = producer.submit_one(0x2000, 256, false).unwrap();

        // ID should be reused (LIFO from stack)
        assert_eq!(id2, id1);
        assert_eq!(producer.id_num[id2 as usize], 1);
    }

    #[test]
    fn test_available_descriptor_flags() {
        let owned = make_table(4);
        let mut producer = RingProducer::new(owned.table());

        producer.submit_one(0x1000, 256, false).unwrap();

        let view = producer.desc_table.get(0).unwrap();
        let desc = view.read_acquire();

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
        let owned = make_table(4);
        let mut producer = RingProducer::new(owned.table());

        producer.submit_one(0x1000, 256, false).unwrap();

        let mut view = producer.desc_table.get_mut(0).unwrap();
        let mut desc = view.read_acquire();
        desc.mark_used(true);
        view.write_release(desc);

        let desc = view.read_acquire();
        let flags = desc.flags();

        // Used descriptor: AVAIL == USED
        assert_eq!(
            flags.contains(DescFlags::AVAIL),
            flags.contains(DescFlags::USED)
        );
    }

    #[test]
    fn test_poll_empty_ring() {
        let owned = make_table(4);
        let mut producer = RingProducer::new(owned.table());

        // Poll without any submitted buffers
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));
    }

    #[test]
    fn test_submit_when_full() {
        let size = 2;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

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

        let owned = make_table(4);
        let mut producer = RingProducer::new(owned.table());

        let result = producer.submit_available(&chain);
        assert!(matches!(result, Err(RingError::EmptyChain)));
    }

    #[test]
    fn test_wrap_stress() {
        let size = 4;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

        // Do multiple full laps
        for lap in 0..3 {
            let expected_wrap = lap % 2 == 0;

            for i in 0..size {
                producer
                    .submit_one(0x1000 + i as u64 * 0x1000, 256, false)
                    .unwrap();

                // Mark as used immediately
                let mut view = producer.desc_table.get_mut(i as u16).unwrap();
                let mut desc = view.read_acquire();
                desc.mark_used(expected_wrap);
                view.write_release(desc);

                producer.poll_used().unwrap();
            }

            // After full lap, wrap should toggle
            assert_eq!(producer.avail_cursor.wrap(), !expected_wrap);
        }
        assert_invariants(&producer);
    }

    #[test]
    fn test_next_flag_termination() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .readable(0x3000, 256)
            .build()
            .unwrap();

        producer.submit_available(&chain).unwrap();

        // First two should have NEXT
        for i in 0..2 {
            let view = producer.desc_table.get(i).unwrap();
            let desc = view.read_acquire();
            assert!(desc.flags().contains(DescFlags::NEXT));
        }

        // Last should not have NEXT
        let tail_view = producer.desc_table.get(2).unwrap();
        let tail_desc = tail_view.read_acquire();
        assert!(!tail_desc.flags().contains(DescFlags::NEXT));
    }

    #[test]
    fn test_consumer_initialization() {
        let size = 8;
        let owned = make_table(size);
        let consumer = RingConsumer::new(owned.table());

        assert_eq!(consumer.avail_cursor.head(), 0);
        assert!(consumer.avail_cursor.wrap());
        assert_eq!(consumer.used_cursor.head(), 0);
        assert!(consumer.used_cursor.wrap());

        for i in 0..size {
            assert_eq!(consumer.id_num[i], 0);
        }
    }

    #[test]
    fn test_consumer_poll_available_single() {
        let owned = make_table(8);

        // Producer submits
        let mut producer = RingProducer::new(owned.table());
        let id = producer.submit_one(0x1000, 512, false).unwrap();

        // Consumer polls
        let mut consumer = RingConsumer::new(owned.table());
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
        let owned = make_table(8);

        let mut producer = RingProducer::new(owned.table());
        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .readable(0x2000, 256)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        let mut consumer = RingConsumer::new(owned.table());
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
        let owned = make_table(8);

        let mut producer = RingProducer::new(owned.table());
        let id = producer.submit_one(0x1000, 512, true).unwrap();

        let mut consumer = RingConsumer::new(owned.table());
        let (polled_id, _) = consumer.poll_available().unwrap();

        // Submit as used
        consumer.submit_used(polled_id, 256).unwrap();

        // Check descriptor marked used
        let view = consumer.desc_table.get(0).unwrap();
        let desc = view.read_acquire();

        assert_eq!(desc.id, id);
        assert_eq!(desc.len, 256);
        assert!(desc.is_used(true));

        // Cursor advanced, chain length cleared
        assert_eq!(consumer.used_cursor.head(), 1);
        assert_eq!(consumer.id_num[id as usize], 0);
    }

    #[test]
    fn test_consumer_submit_used_multi_descriptor() {
        let owned = make_table(8);

        let mut producer = RingProducer::new(owned.table());
        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .writable(0x2000, 512)
            .writable(0x3000, 512)
            .build()
            .unwrap();

        producer.submit_available(&chain).unwrap();

        let mut consumer = RingConsumer::new(owned.table());
        let (id, _) = consumer.poll_available().unwrap();

        consumer.submit_used(id, 1024).unwrap();

        // Only head marked used
        let head_view = consumer.desc_table.get(0).unwrap();
        let head_desc = head_view.read_acquire();
        assert!(head_desc.is_used(true));
        assert_eq!(head_desc.len, 1024);

        // Cursor skipped entire chain
        assert_eq!(consumer.used_cursor.head(), 3);
        assert_eq!(consumer.id_num[id as usize], 0);
    }

    #[test]
    fn test_consumer_poll_empty() {
        let owned = make_table(4);
        let mut consumer = RingConsumer::new(owned.table());

        assert!(matches!(
            consumer.poll_available(),
            Err(RingError::WouldBlock)
        ));
    }

    #[test]
    fn test_consumer_peek() {
        let owned = make_table(8);

        let mut producer = RingProducer::new(owned.table());
        producer.submit_one(0x1000, 512, false).unwrap();

        let consumer = RingConsumer::new(owned.table());
        assert!(consumer.peek_available());

        let empty_owned = make_table(4);
        let empty_consumer = RingConsumer::new(empty_owned.table());
        assert!(!empty_consumer.peek_available());
    }

    #[test]
    fn test_full_roundtrip() {
        let owned = make_table(8);

        let mut producer = RingProducer::new(owned.table());
        let chain = BufferChainBuilder::new()
            .readable(0x1000, 256)
            .writable(0x2000, 512)
            .build()
            .unwrap();

        let id = producer.submit_available(&chain).unwrap();

        let mut consumer = RingConsumer::new(owned.table());
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
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());
        // No submissions yet: all descriptors zero.
        for _ in 0..8 {
            assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));
        }
        // Invariants: num_free == ring size
        assert_eq!(producer.num_free, producer.desc_table.len());
    }

    #[test]
    fn ring_consumer_blocks_until_submit() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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
        let owned = make_table(16);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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

        assert_invariants(&producer);
    }

    // Used stream wrap crossing
    #[test]
    fn test_used_stream_wrap_crossing() {
        let size = 8;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

        // Submit enough single descriptors to make used writes wrap
        let mut ids = Vec::new();
        for i in 0..size {
            ids.push(producer.submit_one(0x1000 + i as u64, 1, false).unwrap());
        }

        // Device polls all
        for _ in 0..size {
            consumer.poll_available().unwrap();
        }

        // Complete all in order except we simulate out-of-order by reversing
        for &id in ids.iter().rev() {
            consumer.submit_used(id, 1).unwrap();
        }

        // Producer polls used; after consuming size descriptors used_cursor should wrap
        for _ in 0..size {
            producer.poll_used().unwrap();
        }
        assert_eq!(producer.used_cursor.head(), 0);
        assert!(!producer.used_cursor.wrap()); // flipped once
        assert_invariants(&producer);
    }

    // Interleaved availability and completion
    #[test]
    fn test_interleaved_submit_completion() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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

        assert_invariants(&producer);
    }

    // Partial publish safety (head not published yet)
    #[test]
    fn test_partial_publish_safety() {
        let size = 8;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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
        let head_wrap = producer.avail_cursor.wrap();
        let mut pos = producer.avail_cursor;
        pos.advance();

        for (i, elem) in chain.elems().iter().enumerate().skip(1) {
            let is_next = i + 1 < chain.len();
            let mut flags = DescFlags::empty();
            flags.set(DescFlags::NEXT, is_next);
            flags.set(DescFlags::WRITE, elem.writable);
            let mut d = Descriptor::new(elem.addr, elem.len, id, flags);
            d.mark_avail(pos.wrap());
            producer
                .desc_table
                .get_mut(pos.head())
                .unwrap()
                .write_volatile(d);
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
        head_desc.mark_avail(head_wrap);
        producer
            .desc_table
            .get_mut(head_idx)
            .unwrap()
            .write_release(head_desc);
        producer.avail_cursor = pos;
        producer.num_free -= chain.len();

        // Consumer can now see the chain
        let (dev_id, dev_chain) = consumer.poll_available().unwrap();
        assert_eq!(dev_id, id);
        assert_eq!(dev_chain.len(), chain.len());
        assert_invariants(&producer);
    }

    // Tail misuse negative test
    #[test]
    fn test_tail_marked_used_ignored() {
        let owned = make_table(8);
        let mut producer = RingProducer::new(owned.table());

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = producer.submit_available(&chain).unwrap();

        // Incorrectly mark tail (index 1) used
        let mut tail_view = producer.desc_table.get_mut(1).unwrap();
        let mut tail_desc = tail_view.read_acquire();
        tail_desc.mark_used(producer.used_cursor.wrap());
        tail_view.write_release(tail_desc);

        // Poll should return WouldBlock (head not used yet)
        assert!(matches!(producer.poll_used(), Err(RingError::WouldBlock)));

        // Mark head used properly
        let mut head_view = producer.desc_table.get_mut(0).unwrap();
        let mut head_desc = head_view.read_acquire();
        head_desc.mark_used(producer.used_cursor.wrap());
        head_view.write_release(head_desc);

        // Now poll succeeds
        let used = producer.poll_used().unwrap();
        assert_eq!(used.id, id);
        assert_invariants(&producer);
    }

    // Max chain length boundary
    #[test]
    fn test_max_chain_len_rejected() {
        let size = 8;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

        // Try chain longer than ring size
        let elems = (0..size + 1).map(|i| BufferElement {
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
        let size = 8;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());

        // Track states: 0=zero/init, 1=available, 2=used, 3=reclaimed
        let mut states = vec![0u8; size];

        for _ in 0..5 {
            for _ in 0..size {
                let id = producer.submit_one(0x1000, 4, false).unwrap();
                // mark available
                let idx = producer.avail_cursor.head().wrapping_sub(1) % size as u16;
                states[idx as usize] = states[idx as usize].max(1);
                // simulate device used
                let mut view = producer.desc_table.get_mut(idx).unwrap();
                let mut d = view.read_acquire();
                d.mark_used(producer.used_cursor.wrap());
                view.write_release(d);
                states[idx as usize] = states[idx as usize].max(2);
                let used = producer.poll_used().unwrap();
                assert_eq!(used.id, id);
                states[idx as usize] = states[idx as usize].max(3);
            }
            assert_invariants(&producer);
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
        let size = 16;
        let owned = make_table(size);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());
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

        assert_invariants(&producer);
    }

    // Out-of-order multi-length explicit
    #[test]
    fn test_out_of_order_multi_length() {
        let owned = make_table(12);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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

        assert_invariants(&producer);
    }

    #[test]
    fn interleave_submit_and_completion() {
        let owned = make_table(16);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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

        assert_invariants(&producer);
    }

    #[test]
    fn producer_disable_used_notifications_writes_driver_disable() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut prod =
            RingProducer::new_with_events(owned.table(), ev.driver_view_mut(), ev.device_view());

        assert_eq!(ev.driver_view().read_acquire().flags(), EventFlags::ENABLE);
        prod.disable_used_notifications();
        assert_eq!(ev.driver_view().read_acquire().flags(), EventFlags::DISABLE);
    }

    #[test]
    fn producer_enable_used_notifications_writes_driver_enable() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut prod =
            RingProducer::new_with_events(owned.table(), ev.driver_view_mut(), ev.device_view());

        prod.disable_used_notifications();
        assert_eq!(ev.driver_view().read_acquire().flags(), EventFlags::DISABLE);

        prod.enable_used_notifications();
        assert_eq!(ev.driver_view().read_acquire().flags(), EventFlags::ENABLE);
    }

    #[test]
    fn producer_enable_used_notifications_desc_sets_off_wrap_and_flags() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut prod =
            RingProducer::new_with_events(owned.table(), ev.driver_view_mut(), ev.device_view());

        prod.enable_used_notifications_desc(5, true);

        let st = ev.driver_view().read_acquire();
        assert_eq!(st.flags(), EventFlags::DESC);
        assert_eq!(st.desc_event_off(), 5);
        assert!(st.desc_event_wrap());
    }

    #[test]
    fn producer_enable_used_notifications_for_next_programs_used_cursor() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut prod =
            RingProducer::new_with_events(owned.table(), ev.driver_view_mut(), ev.device_view());

        // initial used cursor: head=0, wrap=true
        prod.enable_used_notifications_for_next();

        let st = ev.driver_view().read_acquire();
        assert_eq!(st.flags(), EventFlags::DESC);
        assert_eq!(st.desc_event_off(), 0);
        assert!(st.desc_event_wrap());
    }

    #[test]
    fn consumer_disable_avail_notifications_writes_device_disable() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut cons = RingConsumer::new_with_events(
            owned.table(),
            ev.driver_view(),     // consumer reads driver_event
            ev.device_view_mut(), // consumer writes device_event
        );

        assert_eq!(ev.device_view().read_acquire().flags(), EventFlags::ENABLE);

        cons.disable_avail_notifications().unwrap();
        assert_eq!(ev.device_view().read_acquire().flags(), EventFlags::DISABLE);
    }

    #[test]
    fn consumer_enable_avail_notifications_writes_device_enable() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut cons =
            RingConsumer::new_with_events(owned.table(), ev.driver_view(), ev.device_view_mut());

        cons.disable_avail_notifications().unwrap();
        assert_eq!(ev.device_view().read_acquire().flags(), EventFlags::DISABLE);

        cons.enable_avail_notifications().unwrap();
        assert_eq!(ev.device_view().read_acquire().flags(), EventFlags::ENABLE);
    }

    #[test]
    fn consumer_enable_avail_notifications_desc_sets_off_wrap_and_flags() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut cons =
            RingConsumer::new_with_events(owned.table(), ev.driver_view(), ev.device_view_mut());

        cons.enable_avail_notifications_desc(7, false).unwrap();

        let st = ev.device_view().read_acquire();
        assert_eq!(st.flags(), EventFlags::DESC);
        assert_eq!(st.desc_event_off(), 7);
        assert!(!st.desc_event_wrap());
    }

    #[test]
    fn consumer_enable_avail_notifications_for_next_programs_avail_cursor() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut cons =
            RingConsumer::new_with_events(owned.table(), ev.driver_view(), ev.device_view_mut());

        // initial avail cursor: head=0, wrap=true
        cons.enable_avail_notifications_for_next().unwrap();

        let st = ev.device_view().read_acquire();
        assert_eq!(st.flags(), EventFlags::DESC);
        assert_eq!(st.desc_event_off(), 0);
        assert!(st.desc_event_wrap());
    }

    #[test]
    fn producer_does_not_write_device_event_when_toggling_used_notifications() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut prod =
            RingProducer::new_with_events(owned.table(), ev.driver_view_mut(), ev.device_view());

        let dev_before = ev.device_view().read_acquire();
        prod.disable_used_notifications();
        let dev_after = ev.device_view().read_acquire();

        assert_eq!(dev_after, dev_before);
    }

    #[test]
    fn consumer_does_not_write_driver_event_when_toggling_avail_notifications() {
        let owned = make_table(8);
        let ev = OwnedEvents::new();

        let mut cons =
            RingConsumer::new_with_events(owned.table(), ev.driver_view(), ev.device_view_mut());

        let drv_before = ev.driver_view().read_acquire();
        cons.disable_avail_notifications().unwrap();
        let drv_after = ev.driver_view().read_acquire();

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

    // Device marks a tail descriptor used instead of the head
    // - Expect producer.poll_used returns WouldBlock (driver only polls next_used head) and ring state remains consistent.
    #[test]
    fn bad_device_marks_tail_used() {
        let owned = make_table(8);
        let mut prod = RingProducer::new(owned.table());
        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = prod.submit_available(&chain).unwrap();

        // Bad device: mark index 1 (tail) used
        let mut tail = prod.desc_table.get_mut(1).unwrap();
        let mut d = tail.read_acquire();
        d.mark_used(prod.used_cursor.wrap());
        tail.write_release(d);

        // Driver must not consume it
        assert!(matches!(prod.poll_used(), Err(RingError::WouldBlock)));

        // Now mark head properly, driver must consume
        let mut head = prod.desc_table.get_mut(0).unwrap();
        let mut hd = head.read_acquire();
        hd.mark_used(prod.used_cursor.wrap());
        head.write_release(hd);
        let used = prod.poll_used().unwrap();
        assert_eq!(used.id, id);
    }

    // Device writes used descriptor with wrong AVAIL/USED bits (AVAIL != USED)
    // - Expect driver treats it as not used and returns WouldBlock.
    #[test]
    fn bad_device_wrong_used_bits() {
        let owned = make_table(4);
        let mut prod = RingProducer::new(owned.table());
        let id = prod.submit_one(0x1000, 8, true).unwrap();

        // Malformed: set AVAIL but clear USED (should be equal for used)
        let mut v = prod.desc_table.get_mut(0).unwrap();
        let mut d = v.read_acquire();
        // Force flags to look like "available" despite intent
        d.mark_avail(prod.used_cursor.wrap());
        d.len = 8;
        v.write_release(d);

        assert!(matches!(prod.poll_used(), Err(RingError::WouldBlock)));

        let mut v2 = prod.desc_table.get_mut(0).unwrap();
        let mut d2 = v2.read_acquire();
        d2.mark_used(prod.used_cursor.wrap());
        v2.write_release(d2);
        let u = prod.poll_used().unwrap();
        assert_eq!(u.id, id);
    }

    // Driver sets NEXT on last descriptor (chain never terminates)
    // - Expect device.poll_available returns InvalidState
    #[test]
    fn bad_driver_next_never_clears() {
        let size = 8;
        let owned = make_table(size);
        let mut cons = RingConsumer::new(owned.table());
        let mut prod = RingProducer::new(owned.table());

        // Allocate an ID and pretend one huge chain
        let id = prod.id_free.pop().unwrap();
        prod.id_num[id as usize] = size as u16;

        let mut pos = prod.avail_cursor;
        let wrap_start = pos.wrap();

        // Write every descriptor with NEXT set and same id
        for _ in 0..size {
            let idx = pos.head();
            let mut flags = DescFlags::empty();
            flags.set(DescFlags::NEXT, true); // incorrect: last should NOT have NEXT
            let mut desc = Descriptor::new(0x1000 + idx as u64 * 0x10, 4, id, flags);
            desc.mark_avail(pos.wrap());
            prod.desc_table.get_mut(idx).unwrap().write_volatile(desc);
            pos.advance();
        }

        // Publish head last (simulate driver behavior)
        let head_idx = prod.avail_cursor.head();
        let mut head_flags = DescFlags::empty();
        head_flags.set(DescFlags::NEXT, true);
        let mut head_desc = Descriptor::new(0x42, 4, id, head_flags);
        head_desc.mark_avail(wrap_start);
        prod.desc_table
            .get_mut(head_idx)
            .unwrap()
            .write_release(head_desc);

        // Consumer should detect invalid chain via step guard
        assert!(matches!(
            cons.poll_available(),
            Err(RingError::InvalidState)
        ));
    }

    // Device writes more than one used descriptor for a single chain (marks both head and tail used)
    //
    // Expect driver consumes the head once; tail still used flags must be ignored logically. After
    // consumption, id_num[id] becomes 0; a second poll should return WouldBlock.
    #[test]
    fn bad_device_marks_multiple_used_in_chain() {
        let owned = make_table(8);
        let mut prod = RingProducer::new(owned.table());

        let chain = BufferChainBuilder::new()
            .readable(0x1000, 4)
            .readable(0x2000, 4)
            .build()
            .unwrap();
        let id = prod.submit_available(&chain).unwrap();

        // Bad device: mark head and tail used
        let mut head = prod.desc_table.get_mut(0).unwrap();

        let mut hd = head.read_acquire();
        hd.mark_used(prod.used_cursor.wrap());
        head.write_release(hd);

        let mut tail = prod.desc_table.get_mut(1).unwrap();
        let mut td = tail.read_acquire();
        td.mark_used(prod.used_cursor.wrap());
        tail.write_release(td);

        // Driver consumes once
        let u = prod.poll_used().unwrap();
        assert_eq!(u.id, id);

        // Next poll should block; no duplicate consumption
        assert!(matches!(prod.poll_used(), Err(RingError::WouldBlock)));
    }

    // Device writes used descriptor in wrong slot (not at device used cursor)
    //
    // Spec says device writes used descriptors in the order they complete, at its used write position;
    // driver polls only next_used. If device writes used into a random ring slot not equal to next_used,
    // driver should not see it until that slot becomes next_used after advances; to detect “wrong slot”,
    // simulate writing used far ahead and assert driver still blocks.
    #[test]
    fn bad_device_writes_used_at_wrong_slot() {
        let owned = make_table(8);
        let mut prod = RingProducer::new(owned.table());

        let _id = prod.submit_one(0x1000, 4, true).unwrap();

        // Wrong slot: mark index 3 used while next_used is 0
        let mut v = prod.desc_table.get_mut(3).unwrap();
        let mut d = v.read_acquire();
        d.mark_used(prod.used_cursor.wrap());
        v.write_release(d);

        // Driver should still block (polls only slot 0)
        assert!(matches!(prod.poll_used(), Err(RingError::WouldBlock)));

        // Now mark slot 0 correctly, driver can consume
        let mut v0 = prod.desc_table.get_mut(0).unwrap();
        let mut d0 = v0.read_acquire();
        d0.mark_used(prod.used_cursor.wrap());
        v0.write_release(d0);
        let _u = prod.poll_used().unwrap();
    }

    // Driver reuses an ID while still outstanding
    // Simulate bug: force id_num[id] > 0 and push id back to id_free then submit should pop the same ID while outstanding.
    #[test]
    fn bad_driver_reuses_id_while_outstanding() {
        let owned = make_table(8);
        let mut prod = RingProducer::new(owned.table());

        // Submit first buffer: allocate ID
        let id = prod.submit_one(0x1000, 4, false).unwrap();
        assert_eq!(prod.id_num[id as usize], 1);

        // push the same ID back into free list while it's still outstanding.
        prod.id_free.push(id);

        // Next submit should fail because ID is still outstanding.
        let res = prod.submit_one(0x2000, 4, false);
        assert!(matches!(res, Err(RingError::InvalidState)));
    }
}

// let's fuzz!
#[cfg(test)]
mod quick {
    use quickcheck::{Arbitrary, Gen, QuickCheck};

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
        let owned = super::tests::make_table(s.table_size);
        let mut producer = RingProducer::new(owned.table());
        let mut consumer = RingConsumer::new(owned.table());

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
            if outstanding as usize + producer.num_free != producer.desc_table.len() {
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
