// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Kani proofs for one packed-ring batch containing at most one ring of descriptors.
//! These proofs cover cursor advancement and descriptor-event notification arithmetic,
//! not shared-memory access, atomic ordering, or concurrent peer behaviour.

use bytemuck::Zeroable;

use super::{EventFlags, EventSuppression, RingCursor, should_notify};

fn arbitrary_ring_size() -> u16 {
    let size = kani::any::<u16>();
    kani::assume(size.is_power_of_two());
    size
}

fn arbitrary_cursor(size: u16) -> RingCursor {
    let head = kani::any::<u16>();
    kani::assume(head < size);

    RingCursor {
        head,
        size,
        wrap: kani::any(),
    }
}

#[kani::proof]
fn ring_cursor_advance_by_matches_wide_model() {
    let size = arbitrary_ring_size();
    let mut cursor = arbitrary_cursor(size);
    let original = cursor;
    let count = kani::any::<u16>();
    kani::assume(count <= size);

    let total = u32::from(original.head) + u32::from(count);
    let expected_head = (total % u32::from(size)) as u16;
    let expected_wrap = original.wrap ^ !(total / u32::from(size)).is_multiple_of(2);

    cursor.advance_by(count);

    assert_eq!(cursor.head, expected_head);
    assert_eq!(cursor.wrap, expected_wrap);
    assert_eq!(cursor.size, size);

    kani::cover!(count == 0, "zero advance");
    kani::cover!(total < u32::from(size), "advance without wrap");
    kani::cover!(total >= u32::from(size), "advance across wrap");
    kani::cover!(count == size, "advance by a full ring");
}

#[kani::proof]
fn descriptor_notification_matches_cursor_interval() {
    let size = arbitrary_ring_size();
    let old = arbitrary_cursor(size);
    let count = kani::any::<u16>();
    kani::assume(count <= size);

    let mut new = old;
    new.advance_by(count);

    let event_off = kani::any::<u16>();
    kani::assume(event_off < size);
    let event_wrap = kani::any::<bool>();

    let mut event = EventSuppression::zeroed();
    event.set_desc_event(event_off, event_wrap);
    event.set_flags(EventFlags::DESC);

    let ring_span = u32::from(size) * 2;
    let cursor_position = u32::from(old.head) + u32::from(!old.wrap) * u32::from(size);
    let event_position = u32::from(event_off) + u32::from(!event_wrap) * u32::from(size);
    let event_distance = (event_position + ring_span - cursor_position) % ring_span;
    let expected = event_distance < u32::from(count);

    assert_eq!(should_notify(event, size, old, new), expected);

    kani::cover!(count == 0 && !expected, "zero advance does not notify");
    kani::cover!(
        old.wrap == new.wrap && expected,
        "event crossed without wrap"
    );
    kani::cover!(
        old.wrap != new.wrap && expected,
        "event crossed across wrap"
    );
    kani::cover!(
        count == size && expected,
        "event crossed by a full-ring advance"
    );
    kani::cover!(
        event_distance == u32::from(count) && !expected,
        "new cursor is excluded"
    );
}
