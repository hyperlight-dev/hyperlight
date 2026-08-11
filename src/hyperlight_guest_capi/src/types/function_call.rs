/*
Copyright 2025 The Hyperlight Authors.

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

use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::slice;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_guest::error::Result;

use crate::types::{FfiParameter, OwnedFfiParameter};

/// An FFI version of `FunctionCall`
#[repr(C)]
pub struct FfiFunctionCall {
    function_name: *const c_char,
    parameters: *const FfiParameter,
    parameters_len: usize,
    return_type: ReturnType,
}

pub(crate) struct OwnedFfiFunctionCall {
    ffi: FfiFunctionCall,
    _function_name: CString,
    _parameters: Box<[FfiParameter]>,
    _parameter_owners: Vec<OwnedFfiParameter>,
}

impl OwnedFfiFunctionCall {
    pub(crate) fn from_function_call(value: FunctionCall) -> Result<Self> {
        let function_name = CString::new(value.function_name.as_str())
            .expect("Failed to convert function name to CString");
        let parameter_owners = value
            .parameters
            .unwrap_or_default()
            .into_iter()
            .map(OwnedFfiParameter::from_parameter_value)
            .collect::<Result<Vec<_>>>()?;
        let parameters = parameter_owners
            .iter()
            .map(OwnedFfiParameter::ffi)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let parameters_len = parameters.len();
        let parameters_ptr = if parameters.is_empty() {
            core::ptr::null()
        } else {
            parameters.as_ptr()
        };
        let ffi = FfiFunctionCall {
            function_name: function_name.as_ptr(),
            parameters: parameters_ptr,
            parameters_len,
            return_type: value.expected_return_type,
        };

        Ok(Self {
            ffi,
            _function_name: function_name,
            _parameters: parameters,
            _parameter_owners: parameter_owners,
        })
    }

    pub(crate) fn as_ffi(&self) -> &FfiFunctionCall {
        &self.ffi
    }
}

impl FfiFunctionCall {
    /// Copies the parameters of `self` into a new `Vec<ParameterValue>`.
    /// # Safety
    /// Every pointer in `self` must reference a live value of the declared
    /// length.
    pub unsafe fn copy_parameters(&self) -> Vec<ParameterValue> {
        let slice = if self.parameters_len == 0 {
            &[]
        } else {
            // SAFETY: required by the caller.
            unsafe { slice::from_raw_parts(self.parameters, self.parameters_len) }
        };
        slice
            .iter()
            .map(|param| unsafe { param.copy_to_parameter_value() })
            .collect()
    }

    /// Copies the function name of `self` into a new `String`.
    /// # Safety
    /// `function_name` must point to a live NUL-terminated string.
    pub unsafe fn copy_function_name(&self) -> String {
        unsafe {
            CStr::from_ptr(self.function_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Copies the return type of `self` into a new `ReturnType`.
    /// # Safety
    /// `return_type` must contain a valid [`ReturnType`] discriminant.
    pub unsafe fn copy_return_type(&self) -> ReturnType {
        self.return_type
    }
}
