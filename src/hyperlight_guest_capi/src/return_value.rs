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
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::function_types::Bytes;
use hyperlight_common::flatbuffer_wrappers::util::byte_chunks_to_vec;

use crate::dispatch::take_last_host_return;
use crate::types::{FfiReturnValue, FfiVec};

// The reason for the capitalized type in the function names below
// is to match the names of the variants in hl_ReturnType,
// which is used in the C macros in macro.h

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Int(value: i32) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::int(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_UInt(value: u32) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::uint(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Long(value: i64) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::long(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_ULong(value: u64) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::ulong(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Float(value: f32) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::float(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Double(value: f64) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::double(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Void() -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::void())
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `value` must point to a live NUL-terminated string.
pub unsafe extern "C" fn hl_result_from_String(value: *const c_char) -> Box<FfiReturnValue> {
    // SAFETY: callers provide a live NUL-terminated string.
    let value = unsafe { CStr::from_ptr(value) };
    Box::new(FfiReturnValue::string(value))
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `data` must reference `len` readable bytes when `len` is nonzero.
pub unsafe extern "C" fn hl_result_from_Bytes(data: *const u8, len: usize) -> Box<FfiReturnValue> {
    let value = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: callers provide `len` readable bytes.
        unsafe { core::slice::from_raw_parts(data, len) }.to_vec()
    };
    Box::new(FfiReturnValue::vec_bytes(value))
}

#[unsafe(no_mangle)]
/// # Safety
///
/// `data` must reference `len` readable bytes when `len` is nonzero.
pub unsafe extern "C" fn hl_result_from_ByteChunks(
    data: *const u8,
    len: usize,
) -> Box<FfiReturnValue> {
    let value = if len == 0 {
        Vec::new()
    } else {
        // SAFETY: callers provide `len` readable bytes.
        unsafe { core::slice::from_raw_parts(data, len) }.to_vec()
    };
    Box::new(FfiReturnValue::byte_chunks(value))
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_result_from_Bool(value: bool) -> Box<FfiReturnValue> {
    Box::new(FfiReturnValue::boolean(value))
}

//--- Functions for getting values returned by host functions calls

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Int() -> i32 {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_UInt() -> u32 {
    take_last_host_return()
}

// the same for long, ulong
#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Long() -> i64 {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_ULong() -> u64 {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Bool() -> bool {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Float() -> f32 {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Double() -> f64 {
    take_last_host_return()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_String() -> *const c_char {
    let string_value: String = take_last_host_return();

    let c_string = CString::new(string_value).expect("Failed to create CString");
    c_string.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_VecBytes() -> Box<FfiVec> {
    let vec_value: Vec<u8> = take_last_host_return();

    Box::new(unsafe { FfiVec::from_vec(vec_value) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_ByteChunks() -> Box<FfiVec> {
    let chunks: Vec<Bytes> = take_last_host_return();

    Box::new(unsafe { FfiVec::from_vec(byte_chunks_to_vec(&chunks)) })
}
