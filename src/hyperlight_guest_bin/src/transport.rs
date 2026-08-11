// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Guest virtqueue initialization.

use hyperlight_common::layout::{QueueDims, TransportArena};
use hyperlight_common::virtq::Layout;
use hyperlight_guest::transport::{GuestContext, QueueConfig};
use hyperlight_guest::{layout, transport as guest_transport};

use crate::paging::phys_to_virt;

/// Initialize the guest transport queues in host-assigned scratch regions.
pub(crate) fn initialize() {
    // The host writes normalized transport dimensions and the arena base before entry.
    // SAFETY: Generic initialization has mapped writable scratch metadata.
    let transport_arena_gpa = unsafe { layout::transport_arena_gpa_gva().read_volatile() };

    let (size, pages, g2h_bufsz) = read_published_g2h();
    let g2h = QueueDims::new(size, pages).expect("invalid G2H queue dimensions");

    let (size, pages, h2g_bufsz) = read_published_h2g();
    let h2g = QueueDims::new(size, pages).expect("invalid H2G queue dimensions");

    assert!(g2h_bufsz > 0 && h2g_bufsz > 0);

    let arena = TransportArena::new(transport_arena_gpa, g2h, h2g).expect("invalid virtq arena");
    let g2h_pages = g2h.pool_pages().get();
    let h2g_pages = h2g.pool_pages().get();

    let g2h_ring_gva = scratch_gva(arena.g2h_ring_addr());
    let h2g_ring_gva = scratch_gva(arena.h2g_ring_addr());
    let g2h_pool_gva = scratch_gva(arena.g2h_pool_addr());
    let h2g_pool_gva = scratch_gva(arena.h2g_pool_addr());
    let mbx_gva = scratch_gva(arena.mbx_addr());

    let g2h_layout =
        unsafe { Layout::from_base(g2h_ring_gva, g2h.size()) }.expect("G2H layout is invalid");
    let h2g_layout =
        unsafe { Layout::from_base(h2g_ring_gva, h2g.size()) }.expect("H2G layout is invalid");

    // Build the queues and prefill H2G before exposing either queue to the host.
    let context = GuestContext::new(
        QueueConfig {
            layout: g2h_layout,
            pool_gva: g2h_pool_gva,
            pool_pages: g2h_pages,
            buffer_size: g2h_bufsz,
        },
        QueueConfig {
            layout: h2g_layout,
            pool_gva: h2g_pool_gva,
            pool_pages: h2g_pages,
            buffer_size: h2g_bufsz,
        },
        mbx_gva,
    )
    .expect("failed to create guest context");

    guest_transport::set_global_context(context);
}

fn scratch_gva(gpa: u64) -> u64 {
    let ptr = phys_to_virt(gpa).expect("transport GPA is outside scratch");
    u64::try_from(ptr as usize).expect("transport GVA exceeds u64")
}

fn read_published_g2h() -> (usize, usize, usize) {
    // SAFETY: Generic initialization has mapped writable scratch metadata.
    let size_raw = unsafe { layout::g2h_queue_size_gva().read_volatile() };
    let pages_raw = unsafe { layout::g2h_pool_pages_gva().read_volatile() };
    let bufsz_raw = unsafe { layout::g2h_buffer_size_gva().read_volatile() };

    let size = usize::try_from(size_raw).expect("G2H queue size exceeds usize");
    let pages = usize::try_from(pages_raw).expect("G2H pool page count exceeds usize");
    let bufsz = usize::try_from(bufsz_raw).expect("G2H buffer size exceeds usize");

    (size, pages, bufsz)
}

fn read_published_h2g() -> (usize, usize, usize) {
    // SAFETY: Generic initialization has mapped writable scratch metadata.
    let size_raw = unsafe { layout::h2g_queue_size_gva().read_volatile() };
    let pages_raw = unsafe { layout::h2g_pool_pages_gva().read_volatile() };
    let bufsz_raw = unsafe { layout::h2g_buffer_size_gva().read_volatile() };

    let size = usize::try_from(size_raw).expect("H2G queue size exceeds usize");
    let pages = usize::try_from(pages_raw).expect("H2G pool page count exceeds usize");
    let bufsz = usize::try_from(bufsz_raw).expect("H2G buffer size exceeds usize");

    (size, pages, bufsz)
}
