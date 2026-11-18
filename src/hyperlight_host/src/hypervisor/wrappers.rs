// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use windows::Win32::Foundation::{HANDLE, HMODULE};

/// Wrapper for HANDLE, required since HANDLE is no longer Send.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HandleWrapper(HANDLE);

impl From<HANDLE> for HandleWrapper {
    fn from(value: HANDLE) -> Self {
        Self(value)
    }
}

impl From<HandleWrapper> for HANDLE {
    fn from(wrapper: HandleWrapper) -> Self {
        wrapper.0
    }
}

unsafe impl Send for HandleWrapper {}
unsafe impl Sync for HandleWrapper {}

/// Wrapper for HMODULE, required since HMODULE is no longer Send.
#[derive(Debug, Copy, Clone)]
pub(crate) struct HModuleWrapper(HMODULE);

impl From<HMODULE> for HModuleWrapper {
    fn from(value: HMODULE) -> Self {
        Self(value)
    }
}

impl From<HModuleWrapper> for HMODULE {
    fn from(wrapper: HModuleWrapper) -> Self {
        wrapper.0
    }
}

unsafe impl Send for HModuleWrapper {}
unsafe impl Sync for HModuleWrapper {}
