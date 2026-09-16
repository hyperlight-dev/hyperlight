// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::format;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::HyperlightPEB;
use tracing::instrument;

use crate::error::{HyperlightGuestError, Result};

/// Access to memory regions described by the guest's `HyperlightPEB`.
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

    /// Get user memory region as bytes.
    #[instrument(skip_all, level = "Trace")]
    pub fn read_n_bytes_from_user_memory(&self, num: u64) -> Result<Vec<u8>> {
        let peb_ptr = self.peb().unwrap();
        // SAFETY: GuestHandle is initialized with the PEB provided by the host,
        // which remains valid for the guest lifetime.
        let init_data = unsafe { (*peb_ptr).init_data };

        if num > init_data.size {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Requested {} bytes from user memory, but only {} bytes are available",
                    num, init_data.size
                ),
            ));
        }

        // SAFETY: The PEB describes a valid user memory region and num was
        // checked against its size.
        let bytes =
            unsafe { core::slice::from_raw_parts(init_data.ptr as *const u8, num as usize) };
        Ok(bytes.to_vec())
    }
}
