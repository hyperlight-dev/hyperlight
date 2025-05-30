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
use core::ffi::{c_char, CStr};

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_guest::error::Result;

use crate::types::FfiParameter;

/// An FFI version of `FunctionCall`
#[repr(C)]
pub struct FfiFunctionCall {
    function_name: *const c_char,
    parameters: *const FfiParameter,
    parameters_len: usize,
    return_type: ReturnType,
}

impl FfiFunctionCall {
    /// Create a new `FfiFunctionCall` by consuming a FunctionCall.
    pub fn from_function_call(value: FunctionCall) -> Result<Self> {
        let leaked_function_name = CString::new(value.function_name.as_str())
            .expect("Failed to convert function name to CString")
            .into_raw();

        let (parameters, parameter_len) = match value.parameters {
            Some(p) => {
                let parameters: Vec<FfiParameter> = p
                    .into_iter()
                    .map(|param| FfiParameter::from_parameter_value(param).unwrap())
                    .collect();
                let boxed = parameters.into_boxed_slice();
                let parameters_len = boxed.len();
                let leaked_param_vec = Box::into_raw(boxed);
                (leaked_param_vec as *const FfiParameter, parameters_len)
            }
            None => (core::ptr::null(), 0),
        };

        Ok(Self {
            function_name: leaked_function_name,
            parameters,
            parameters_len: parameter_len,
            return_type: value.expected_return_type,
        })
    }

    /// Copies the parameters of `self` into a new `Vec<ParameterValue>`.
    /// # Safety
    /// `self` must be an unmodified version of what `from_function_call` returned.
    pub unsafe fn copy_parameters(&self) -> Vec<ParameterValue> {
        let slice = unsafe { slice::from_raw_parts(self.parameters, self.parameters_len) };
        slice
            .iter()
            .map(|param| unsafe { param.copy_to_parameter_value() })
            .collect()
    }

    /// Copies the function name of `self into a new `String`.
    /// # Safety
    /// `self` must be an unmodified version of what `from_function_call` returned.
    pub unsafe fn copy_function_name(&self) -> String {
        unsafe {
            CStr::from_ptr(self.function_name)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Copies the return type of `self` into a new `ReturnType`.
    /// # Safety
    /// `self` must be an unmodified version of what `from_function_call` returned.
    pub unsafe fn copy_return_type(&self) -> ReturnType {
        self.return_type
    }
}

impl Drop for FfiFunctionCall {
    fn drop(&mut self) {
        unsafe {
            if !self.function_name.is_null() {
                drop(CString::from_raw(self.function_name as *mut c_char));
            }
            if !self.parameters.is_null() {
                let slice = Box::from_raw(slice::from_raw_parts_mut(
                    self.parameters as *mut FfiParameter,
                    self.parameters_len,
                ));
                drop(slice);
            }
        }
    }
}
