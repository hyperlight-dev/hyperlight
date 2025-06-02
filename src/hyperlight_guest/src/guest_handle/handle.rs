/*
Copyright 2025  The Hyperlight Authors.

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
#[derive(Debug, Clone, Copy)]
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
