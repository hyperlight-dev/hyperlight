// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

/// Dispatch has no tasks to poll without streams.
#[inline]
pub fn run_ready() {}

pub(crate) fn status() -> hyperlight_common::stream::StatusFlags {
    hyperlight_common::stream::StatusFlags::empty()
}
