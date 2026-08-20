// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use hyperlight_common::mem::HyperlightPEB;

/// A guest handle holds the `HyperlightPEB` and enables the guest to perform
/// operations like:
/// - calling host functions,
/// - accessing shared input and output buffers,
/// - writing errors,
/// - etc.
///
/// Guests are expected to initialize this and store it. For example, you
/// could store it in a global variable.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestHandle {
    peb: Option<*mut HyperlightPEB>,
}

impl GuestHandle {
    /// Creates a new uninitialized guest state.
    pub const fn new() -> Self {
        Self { peb: None }
    }

    /// Initializes the guest state with a given PEB pointer.
    pub fn init(peb: *mut HyperlightPEB) -> Self {
        Self { peb: Some(peb) }
    }

    /// Returns the PEB pointer
    pub fn peb(&self) -> Option<*mut HyperlightPEB> {
        self.peb
    }
}
