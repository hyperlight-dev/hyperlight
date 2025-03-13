use alloc::ffi::CString;
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ParameterValue};
use hyperlight_guest::error::Result;

use crate::types::FfiVec;

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
}

/// An owned FFI version Of `ParameterValue`
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct FfiParameter {
    tag: ParameterType,
    value: FfiParameterValue,
}

impl FfiParameter {
    /// Returns a new `FfiParameter` by consuming a `ParameterValue`
    pub fn from_parameter_value(value: ParameterValue) -> Result<Self> {
        let (tag, union) = match value {
            ParameterValue::Int(v) => (ParameterType::Int, FfiParameterValue { Int: v }),
            ParameterValue::UInt(v) => (ParameterType::UInt, FfiParameterValue { UInt: v }),
            ParameterValue::Long(v) => (ParameterType::Long, FfiParameterValue { Long: v }),
            ParameterValue::ULong(v) => (ParameterType::ULong, FfiParameterValue { ULong: v }),
            ParameterValue::Float(v) => (ParameterType::Float, FfiParameterValue { Float: v }),
            ParameterValue::Double(v) => (ParameterType::Double, FfiParameterValue { Double: v }),
            ParameterValue::Bool(v) => (ParameterType::Bool, FfiParameterValue { Bool: v }),
            ParameterValue::String(v) => {
                let c_str = CString::new(v.as_str()).expect("Unable to make CString from String");
                let leaked = c_str.into_raw();
                (ParameterType::String, FfiParameterValue { String: leaked })
            }
            ParameterValue::VecBytes(v) => {
                let leaked = unsafe { FfiVec::from_vec(v) };
                (
                    ParameterType::VecBytes,
                    FfiParameterValue { VecBytes: leaked },
                )
            }
        };
        Ok(FfiParameter { tag, value: union })
    }

    /// Copies self into a new `ParameterValue`.
    /// # Safety
    /// `self` must be an unmodified version of what `from_parameter_value` returned.
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
        }
    }
}

impl Drop for FfiParameter {
    fn drop(&mut self) {
        match self.tag {
            ParameterType::String => unsafe {
                drop(CString::from_raw(self.value.String));
            },
            ParameterType::VecBytes => unsafe {
                drop(self.value.VecBytes.into_vec());
            },
            _ => {}
        }
    }
}
