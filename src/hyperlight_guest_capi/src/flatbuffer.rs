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

use alloc::{
        boxed::Box,
        string::String,
        vec::Vec,
        ffi::CString
    };
use core::ffi::{CStr, c_char};

use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_guest_bin::host_comm::get_host_return_value;

use crate::types::FfiVec;

// The reason for the capitalized type in the function names below
// is to match the names of the variants in hl_ReturnType,
// which is used in the C macros in macro.h

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Int(value: i32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_UInt(value: u32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Long(value: i64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_ULong(value: u64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Float(value: f32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Double(value: f64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Void() -> Box<FfiVec> {
    let vec = get_flatbuffer_result(());

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_String(value: *const c_char) -> Box<FfiVec> {
    let str = unsafe { CStr::from_ptr(value) };
    let vec = get_flatbuffer_result(str.to_string_lossy().as_ref());

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_Bytes(data: *const u8, len: usize) -> Box<FfiVec> {
    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    let vec = get_flatbuffer_result(slice);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

//--- Functions for getting values returned by host functions calls

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Int() -> i32 {
    get_host_return_value().expect("Unable to get host return value as int")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_UInt() -> u32 {
    get_host_return_value().expect("Unable to get host return value as uint")
}

// the same for long, ulong
#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Long() -> i64 {
    get_host_return_value().expect("Unable to get host return value as long")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_ULong() -> u64 {
    get_host_return_value().expect("Unable to get host return value as ulong")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_Bool() -> bool {
    get_host_return_value().expect("Unable to get host return value as bool")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_float() -> f32 {
    get_host_return_value().expect("Unable to get host return value as f32")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_get_host_return_value_as_double() -> f64 {
    get_host_return_value().expect("Unable to get host return value as f32")
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_String() -> *const c_char {
    let string_value: String = get_host_return_value()
                                .expect("Unable to get host return value as string");

    let c_string = CString::new(string_value).expect("Failes to create CString");
    c_string.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn hl_flatbuffer_result_from_VecBytes() -> Box<FfiVec> {
    let vec_value: Vec<u8>  = get_host_return_value()
                            .expect("Unable to get host return value as vec bytes");
 
    Box::new(unsafe { FfiVec::from_vec(vec_value) })
}