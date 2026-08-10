/*
Copyright 2026 The Hyperlight Authors.

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

use alloc::borrow::ToOwned;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};
use core::mem::ManuallyDrop;

use hyperlight_common::flatbuffer_wrappers::function_types::{ReturnType, ReturnValue};
use hyperlight_common::flatbuffer_wrappers::util::byte_chunks_from_vec;

use super::FfiVec;

/// The value held by an [`FfiReturnValue`].
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types, non_snake_case)]
pub union FfiReturnValueUnion {
    pub Int: i32,
    pub UInt: u32,
    pub Long: i64,
    pub ULong: u64,
    pub Float: f32,
    pub Double: f64,
    pub Bool: bool,
    pub String: *mut c_char,
    pub VecBytes: FfiVec,
    pub ByteChunks: FfiVec,
}

/// An owned FFI return value.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct FfiReturnValue {
    tag: ReturnType,
    value: FfiReturnValueUnion,
}

impl FfiReturnValue {
    pub fn int(value: i32) -> Self {
        Self {
            tag: ReturnType::Int,
            value: FfiReturnValueUnion { Int: value },
        }
    }

    pub fn uint(value: u32) -> Self {
        Self {
            tag: ReturnType::UInt,
            value: FfiReturnValueUnion { UInt: value },
        }
    }

    pub fn long(value: i64) -> Self {
        Self {
            tag: ReturnType::Long,
            value: FfiReturnValueUnion { Long: value },
        }
    }

    pub fn ulong(value: u64) -> Self {
        Self {
            tag: ReturnType::ULong,
            value: FfiReturnValueUnion { ULong: value },
        }
    }

    pub fn float(value: f32) -> Self {
        Self {
            tag: ReturnType::Float,
            value: FfiReturnValueUnion { Float: value },
        }
    }

    pub fn double(value: f64) -> Self {
        Self {
            tag: ReturnType::Double,
            value: FfiReturnValueUnion { Double: value },
        }
    }

    pub fn boolean(value: bool) -> Self {
        Self {
            tag: ReturnType::Bool,
            value: FfiReturnValueUnion { Bool: value },
        }
    }

    pub fn void() -> Self {
        Self {
            tag: ReturnType::Void,
            value: FfiReturnValueUnion { Int: 0 },
        }
    }

    pub fn string(value: &CStr) -> Self {
        Self {
            tag: ReturnType::String,
            value: FfiReturnValueUnion {
                String: value.to_owned().into_raw(),
            },
        }
    }

    pub fn vec_bytes(value: Vec<u8>) -> Self {
        Self {
            tag: ReturnType::VecBytes,
            // SAFETY: `FfiReturnValue` reclaims the allocation when consumed or dropped.
            value: FfiReturnValueUnion {
                VecBytes: unsafe { FfiVec::from_vec(value) },
            },
        }
    }

    pub fn byte_chunks(value: Vec<u8>) -> Self {
        Self {
            tag: ReturnType::ByteChunks,
            // SAFETY: `FfiReturnValue` reclaims the allocation when consumed or dropped.
            value: FfiReturnValueUnion {
                ByteChunks: unsafe { FfiVec::from_vec(value) },
            },
        }
    }

    /// Consume this value and transfer its payload into a Rust return value.
    ///
    /// # Safety
    ///
    /// The tag and union value must be unchanged from a value created by this
    /// type's constructors.
    pub unsafe fn into_return_value(self) -> ReturnValue {
        let value = ManuallyDrop::new(self);
        // SAFETY: the contract requires the tag to identify the initialized union field.
        unsafe {
            match value.tag {
                ReturnType::Int => ReturnValue::Int(value.value.Int),
                ReturnType::UInt => ReturnValue::UInt(value.value.UInt),
                ReturnType::Long => ReturnValue::Long(value.value.Long),
                ReturnType::ULong => ReturnValue::ULong(value.value.ULong),
                ReturnType::Float => ReturnValue::Float(value.value.Float),
                ReturnType::Double => ReturnValue::Double(value.value.Double),
                ReturnType::Bool => ReturnValue::Bool(value.value.Bool),
                ReturnType::Void => ReturnValue::Void(()),
                ReturnType::String => {
                    let value = CString::from_raw(value.value.String);
                    ReturnValue::String(value.to_string_lossy().into_owned())
                }
                ReturnType::VecBytes => ReturnValue::VecBytes(value.value.VecBytes.into_vec()),
                ReturnType::ByteChunks => {
                    ReturnValue::ByteChunks(byte_chunks_from_vec(value.value.ByteChunks.into_vec()))
                }
            }
        }
    }
}

impl Drop for FfiReturnValue {
    fn drop(&mut self) {
        // SAFETY: constructors initialize the owned field selected by the tag.
        unsafe {
            match self.tag {
                ReturnType::String => drop(CString::from_raw(self.value.String)),
                ReturnType::VecBytes => drop(self.value.VecBytes.into_vec()),
                ReturnType::ByteChunks => drop(self.value.ByteChunks.into_vec()),
                _ => {}
            }
        }
    }
}
