/*
Copyright 2024 The Hyperlight Authors.

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

use tracing::{instrument, Span};
use windows::core::PSTR;
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::Hypervisor::WHV_REGISTER_VALUE;

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

// only used on windows. mshv and kvm already has this implemented
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(super) struct WHvGeneralRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(super) struct WHvFPURegisters {
    pub xmm0: u128,
    pub xmm1: u128,
    pub xmm2: u128,
    pub xmm3: u128,
    pub xmm4: u128,
    pub xmm5: u128,
    pub xmm6: u128,
    pub xmm7: u128,
    pub xmm8: u128,
    pub xmm9: u128,
    pub xmm10: u128,
    pub xmm11: u128,
    pub xmm12: u128,
    pub xmm13: u128,
    pub xmm14: u128,
    pub xmm15: u128,

    pub mmx0: u64,
    pub mmx1: u64,
    pub mmx2: u64,
    pub mmx3: u64,
    pub mmx4: u64,
    pub mmx5: u64,
    pub mmx6: u64,
    pub mmx7: u64,

    pub fp_control_word: u16,
    pub fp_tag_word: u8,

    pub mxcsr: u32,
}

#[derive(Default, Copy, Clone)]
pub(super) struct WHvSpecialRegisters {
    pub cr0: WHV_REGISTER_VALUE,
    pub cr2: WHV_REGISTER_VALUE,
    pub cr3: WHV_REGISTER_VALUE,
    pub cr4: WHV_REGISTER_VALUE,
    pub cr8: WHV_REGISTER_VALUE,
    pub efer: WHV_REGISTER_VALUE,
    pub apic_base: WHV_REGISTER_VALUE,
    pub cs: WHV_REGISTER_VALUE,
    pub ds: WHV_REGISTER_VALUE,
    pub es: WHV_REGISTER_VALUE,
    pub fs: WHV_REGISTER_VALUE,
    pub gs: WHV_REGISTER_VALUE,
    pub ss: WHV_REGISTER_VALUE,
    pub tr: WHV_REGISTER_VALUE,
    pub ldtr: WHV_REGISTER_VALUE,
    pub gdtr: WHV_REGISTER_VALUE,
    pub idtr: WHV_REGISTER_VALUE,
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
