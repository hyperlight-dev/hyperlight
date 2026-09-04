// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ParameterValue};
use hyperlight_guest::error::Result;

use crate::types::{FfiByteChunks, FfiByteChunksOwner, FfiVec};

/// A union of the value stored in a ParameterValue, used for FFI.
/// On it's own, this union has no way to know which value type is stored
/// which is why it's used in conjunction with `ParameterType` in `FfiParameter`.
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types, non_snake_case)]
pub union FfiParameterValue {
    pub Int: i32,
    pub UInt: u32,
    pub Long: i64,
    pub ULong: u64,
    pub Float: f32,
    pub Double: f64,
    pub Bool: bool,
    pub String: *mut c_char,
    pub VecBytes: FfiVec,
    pub ByteChunks: FfiByteChunks,
}

/// An FFI view of a [`ParameterValue`].
#[repr(C)]
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct FfiParameter {
    tag: ParameterType,
    value: FfiParameterValue,
}

enum FfiParameterOwner {
    None,
    String { _value: CString },
    VecBytes { _value: Vec<u8> },
    ByteChunks { _value: FfiByteChunksOwner },
}

pub(crate) struct OwnedFfiParameter {
    ffi: FfiParameter,
    _owner: FfiParameterOwner,
}

impl OwnedFfiParameter {
    pub(crate) fn from_parameter_value(value: ParameterValue) -> Result<Self> {
        let (tag, union, owner) = match value {
            ParameterValue::Int(v) => (
                ParameterType::Int,
                FfiParameterValue { Int: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::UInt(v) => (
                ParameterType::UInt,
                FfiParameterValue { UInt: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::Long(v) => (
                ParameterType::Long,
                FfiParameterValue { Long: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::ULong(v) => (
                ParameterType::ULong,
                FfiParameterValue { ULong: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::Float(v) => (
                ParameterType::Float,
                FfiParameterValue { Float: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::Double(v) => (
                ParameterType::Double,
                FfiParameterValue { Double: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::Bool(v) => (
                ParameterType::Bool,
                FfiParameterValue { Bool: v },
                FfiParameterOwner::None,
            ),
            ParameterValue::String(v) => {
                let value = CString::new(v.as_str()).expect("Unable to make CString from String");
                let ptr = value.as_ptr().cast_mut();
                (
                    ParameterType::String,
                    FfiParameterValue { String: ptr },
                    FfiParameterOwner::String { _value: value },
                )
            }
            ParameterValue::VecBytes(v) => {
    ParameterValue::VecBytes(mut v) => {
        let view = FfiVec::from_mut_slice(&mut v);
        (
            ParameterType::VecBytes,
            FfiParameterValue { VecBytes: view },
            FfiParameterOwner::VecBytes { _value: v },
        )
    }
                let view = FfiVec::from_mut_slice(&mut value);
                (
                    ParameterType::VecBytes,
                    FfiParameterValue { VecBytes: view },
                    FfiParameterOwner::VecBytes { _value: value },
                )
            }
            ParameterValue::ByteChunks(v) => {
                let owner = FfiByteChunksOwner::new(v);
                (
                    ParameterType::ByteChunks,
                    FfiParameterValue {
                        ByteChunks: owner.view(),
                    },
                    FfiParameterOwner::ByteChunks { _value: owner },
                )
            }
        };
        Ok(Self {
            ffi: FfiParameter { tag, value: union },
            _owner: owner,
        })
    }

    pub(crate) fn ffi(&self) -> FfiParameter {
        self.ffi.clone()
    }
}

impl FfiParameter {
    /// Copies self into a new `ParameterValue`.
    /// # Safety
    /// Every pointer selected by `tag` must reference a live value of the
    /// declared length.
    pub unsafe fn copy_to_parameter_value(&self) -> ParameterValue {
        match self.tag {
            ParameterType::Int => ParameterValue::Int(unsafe { self.value.Int }),
            ParameterType::UInt => ParameterValue::UInt(unsafe { self.value.UInt }),
            ParameterType::Long => ParameterValue::Long(unsafe { self.value.Long }),
            ParameterType::ULong => ParameterValue::ULong(unsafe { self.value.ULong }),
            ParameterType::Float => ParameterValue::Float(unsafe { self.value.Float }),
            ParameterType::Double => ParameterValue::Double(unsafe { self.value.Double }),
            ParameterType::Bool => ParameterValue::Bool(unsafe { self.value.Bool }),
            ParameterType::String => ParameterValue::String(
                unsafe { CStr::from_ptr(self.value.String) }
                    .to_string_lossy()
                    .into_owned(),
            ),
            ParameterType::VecBytes => {
                ParameterValue::VecBytes(unsafe { self.value.VecBytes.copy_to_vec() })
            }
            ParameterType::ByteChunks => {
                // SAFETY: required by the caller.
                ParameterValue::ByteChunks(unsafe { self.value.ByteChunks.copy_to_bytes() })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use hyperlight_common::flatbuffer_wrappers::function_types::Bytes;

    use super::*;

    #[test]
    fn byte_chunks_parameter_is_borrowed_without_copying() {
        let chunks = vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")];
        let addresses = chunks.iter().map(Bytes::as_ptr).collect::<Vec<_>>();
        let parameter =
            OwnedFfiParameter::from_parameter_value(ParameterValue::ByteChunks(chunks)).unwrap();
        let ffi = parameter.ffi();

        // SAFETY: `parameter` keeps its descriptor array and chunks alive.
        let descriptors = unsafe { ffi.value.ByteChunks.as_slice() };
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].data(), addresses[0]);
        assert_eq!(descriptors[1].data(), addresses[1]);

        // SAFETY: `parameter` keeps every pointer in `ffi` alive.
        let copied = unsafe { ffi.copy_to_parameter_value() };
        assert_eq!(
            copied,
            ParameterValue::ByteChunks(vec![
                Bytes::from_static(b"first"),
                Bytes::from_static(b"second")
            ])
        );
    }
}
