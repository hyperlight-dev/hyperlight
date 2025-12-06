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

use std::ffi::CString;

use tracing::{Span, instrument};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::core::PSTR;

use crate::{HyperlightError, Result};

/// A wrapper for `windows::core::PSTR` values that ensures memory for the
/// underlying string is properly dropped.
#[derive(Debug)]
pub(super) struct PSTRWrapper(*mut i8);

impl TryFrom<&str> for PSTRWrapper {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(value: &str) -> Result<Self> {
        let c_str = CString::new(value)?;
        Ok(Self(c_str.into_raw()))
    }
}

impl Drop for PSTRWrapper {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn drop(&mut self) {
        let cstr = unsafe { CString::from_raw(self.0) };
        drop(cstr);
    }
}

/// Convert a `WindowsStringWrapper` into a `PSTR`.
///
/// # Safety
/// The returned `PSTR` must not outlive the origin `WindowsStringWrapper`
impl From<&PSTRWrapper> for PSTR {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(value: &PSTRWrapper) -> Self {
        let raw = value.0;
        PSTR::from_raw(raw as *mut u8)
    }
}

/// Wrapper for HANDLE, required since HANDLE is no longer Send.
#[derive(Debug, Copy, Clone)]
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
