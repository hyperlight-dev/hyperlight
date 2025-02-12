use alloc::boxed::Box;
use core::ffi::{c_char, CStr};

use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_guest::host_function_call::get_host_return_value;

use crate::types::FfiVec;

// The reason for the capitalized type in the function names below
// is to match the names of the variants in hl_ReturnType,
// which is used in the C macros in macro.h

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Int(value: i32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_UInt(value: u32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Long(value: i64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_ULong(value: u64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Float(value: f32) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Double(value: f64) -> Box<FfiVec> {
    let vec = get_flatbuffer_result(value);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Void() -> Box<FfiVec> {
    let vec = get_flatbuffer_result(());

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_String(value: *const c_char) -> Box<FfiVec> {
    let str = unsafe { CStr::from_ptr(value) };
    let vec = get_flatbuffer_result(str.to_string_lossy().as_ref());

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

#[no_mangle]
pub extern "C" fn hl_flatbuffer_result_from_Bytes(data: *const u8, len: usize) -> Box<FfiVec> {
    let slice = unsafe { core::slice::from_raw_parts(data, len) };

    let vec = get_flatbuffer_result(slice);

    Box::new(unsafe { FfiVec::from_vec(vec) })
}

//--- Functions for getting values returned by host functions calls

#[no_mangle]
pub extern "C" fn hl_get_host_return_value_as_Int() -> i32 {
    get_host_return_value().expect("Unable to get host return value as int")
}

#[no_mangle]
pub extern "C" fn hl_get_host_return_value_as_UInt() -> u32 {
    get_host_return_value().expect("Unable to get host return value as uint")
}

// the same for long, ulong
#[no_mangle]
pub extern "C" fn hl_get_host_return_value_as_Long() -> i64 {
    get_host_return_value().expect("Unable to get host return value as long")
}

#[no_mangle]
pub extern "C" fn hl_get_host_return_value_as_ULong() -> u64 {
    get_host_return_value().expect("Unable to get host return value as ulong")
}

// TODO add bool, float, double, string, vecbytes
