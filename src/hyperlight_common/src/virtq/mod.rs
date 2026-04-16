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

//! Packed Virtqueue - Ring Primitives
//!
//! This module provides low-level ring primitives for virtio packed virtqueues,
//! implementing the VIRTIO 1.1+ packed ring format with proper memory ordering
//! and event suppression support.
//!
//! # Architecture
//!
//! - **Ring primitives** ([`RingProducer`], [`RingConsumer`]): Low-level descriptor ring
//!   operations with explicit buffer chain management. Use this when you need full control
//!   over buffer layouts or custom allocation strategies.
//!
//! - **Descriptor and event types** ([`Descriptor`], [`EventSuppression`]): Raw virtio
//!   data structures for direct memory manipulation.
//!
//! - **Memory access** ([`MemOps`]): Trait abstracting memory read/write operations,
//!   allowing the ring to work with different memory backends (host vs guest).
//!
//! # Low-Level API
//!
//! ```ignore
//! let chain = BufferChainBuilder::new()
//!     .readable(header_addr, header_len)
//!     .readable(data_addr, data_len)
//!     .writable(response_addr, response_len)
//!     .build()?;
//!
//! let result = ring_producer.submit_available_with_notify(&chain)?;
//! if result.notify {
//!     kick_device();
//! }
//! ```

mod access;
mod desc;
mod event;
mod ring;

use core::num::NonZeroU16;

pub use access::*;
pub use desc::*;
pub use event::*;
pub use ring::*;

/// Layout of a packed virtqueue ring in shared memory.
///
/// Describes the memory addresses for the descriptor table and event suppression
/// structures. Use [`from_base`](Self::from_base) to compute the layout from a
/// base address, or [`query_size`](Self::query_size) to determine memory requirements.
///
/// # Memory Layout
///
/// The packed ring consists of:
/// 1. Descriptor table: `num_descs` × 16 bytes, aligned to 16 bytes
/// 2. Driver event suppression: 4 bytes, aligned to 4 bytes
/// 3. Device event suppression: 4 bytes, aligned to 4 bytes
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Packed ring descriptor table base in shared memory.
    pub desc_table_addr: u64,
    /// Number of descriptors (ring size, must be power of 2).
    pub desc_table_len: u16,
    /// Driver-written event suppression area in shared memory.
    pub drv_evt_addr: u64,
    /// Device-written event suppression area in shared memory.
    pub dev_evt_addr: u64,
}

#[inline]
const fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

impl Layout {
    /// Create a Layout from a base address and number of descriptors.
    ///
    /// The base address must be aligned to `Descriptor::ALIGN`.
    /// The memory region starting at `base` must be at least `Layout::query_size(num_descs)` bytes.
    ///
    /// # Safety
    /// - `base` must be valid for `Layout::query_size(num_descs)` bytes.
    /// - `base` must be aligned to `Descriptor::ALIGN`.
    /// - Memory must remain valid for the lifetime of the ring.
    pub const unsafe fn from_base(base: u64, num_descs: NonZeroU16) -> Result<Self, RingError> {
        if !base.is_multiple_of(Descriptor::ALIGN as u64) {
            return Err(RingError::InvalidLayout);
        }

        let desc_size = num_descs.get() as usize * Descriptor::SIZE;
        let event_size = EventSuppression::SIZE;
        let event_align = EventSuppression::ALIGN;

        let drv_evt_offset = align_up(desc_size, event_align);
        let dev_evt_offset = align_up(drv_evt_offset + event_size, event_align);

        Ok(Self {
            desc_table_addr: base,
            desc_table_len: num_descs.get(),
            drv_evt_addr: base + drv_evt_offset as u64,
            dev_evt_addr: base + dev_evt_offset as u64,
        })
    }

    /// Calculate the memory size needed for a ring with `num_descs` descriptors,
    /// accounting for alignment requirements.
    pub const fn query_size(num_descs: usize) -> usize {
        let desc_size = num_descs * Descriptor::SIZE;
        let event_size = EventSuppression::SIZE;
        let event_align = EventSuppression::ALIGN;

        // desc table at offset 0, then aligned events
        let drv_evt_offset = align_up(desc_size, event_align);
        let dev_evt_offset = align_up(drv_evt_offset + event_size, event_align);

        dev_evt_offset + event_size
    }
}

const _: () = {
    #[allow(clippy::unwrap_used)]
    const fn verify_layout(num_descs: usize) {
        let base = 0x1000u64;

        // Safety: base is aligned and we're only checking layout math
        let layout =
            match unsafe { Layout::from_base(base, NonZeroU16::new(num_descs as u16).unwrap()) } {
                Ok(l) => l,
                Err(_) => panic!("from_base failed"),
            };

        let expected_size = Layout::query_size(num_descs);

        assert!(layout.desc_table_addr == base);
        assert!(layout.desc_table_len as usize == num_descs);
        assert!(
            layout
                .drv_evt_addr
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );
        assert!(
            layout
                .dev_evt_addr
                .is_multiple_of(EventSuppression::ALIGN as u64)
        );

        // Events don't overlap with descriptor table
        let desc_end = base + (num_descs * Descriptor::SIZE) as u64;
        assert!(layout.drv_evt_addr >= desc_end);
        assert!(layout.dev_evt_addr >= layout.drv_evt_addr + EventSuppression::SIZE as u64);

        // Total size from query_size covers entire layout
        let layout_end = layout.dev_evt_addr + EventSuppression::SIZE as u64;
        assert!(base + expected_size as u64 == layout_end);
    }

    verify_layout(1);
    verify_layout(2);
    verify_layout(4);
    verify_layout(8);
    verify_layout(16);
    verify_layout(32);
    verify_layout(64);
    verify_layout(128);
    verify_layout(256);
    verify_layout(512);
    verify_layout(1024);
};
