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

#![no_std]
#![no_main]
const DEFAULT_GUEST_STACK_SIZE: i32 = 65536; // default stack size
const MAX_BUFFER_SIZE: usize = 1024;
// ^^^ arbitrary value for max buffer size
// to support allocations when we'd get a
// stack overflow. This can be removed once
// we have proper stack guards in place.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::ffi::c_char;
use core::hint::black_box;
use core::ptr::write_volatile;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::mem::PAGE_SIZE;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::exit::{abort_with_code, abort_with_code_and_message};
use hyperlight_guest_bin::host_comm::{
    call_host, call_host_function, call_host_function_without_returning_result,
    read_n_bytes_from_user_memory,
};
use hyperlight_guest_bin::memory::malloc;
use hyperlight_guest_bin::{MIN_STACK_ADDRESS, guest_function, guest_logger, host_function};
use log::{LevelFilter, error};

extern crate hyperlight_guest;

static mut BIGARRAY: [i32; 1024 * 1024] = [0; 1024 * 1024];

#[host_function("HostPrint")]
fn host_print(message: String) -> Result<i32>;

#[host_function("MakeGetpidSyscall")]
fn make_getpid_syscall() -> Result<u64>;

#[host_function("HostAdd")]
fn host_add(a: i32, b: i32) -> Result<i32>;

#[guest_function("SetStatic")]
#[hyperlight_guest_tracing::trace_function]
fn set_static() -> i32 {
    #[allow(static_mut_refs)]
    unsafe {
        for val in BIGARRAY.iter_mut() {
            *val = 1;
        }
        BIGARRAY.len() as i32
    }
}

#[guest_function("EchoDouble")]
#[hyperlight_guest_tracing::trace_function]
fn echo_double(value: f64) -> f64 {
    value
}

#[guest_function("EchoFloat")]
#[hyperlight_guest_tracing::trace_function]
fn echo_float(value: f32) -> f32 {
    value
}

#[guest_function("PrintUsingPrintf")]
#[hyperlight_guest_tracing::trace_function]
fn simple_print_output(message: String) -> Result<i32> {
    host_print(message)
}

#[guest_function("PrintOutput")]
#[hyperlight_guest_tracing::trace_function]
fn print_output(message: String) -> Result<i32> {
    host_print(message)
}

#[guest_function("SetByteArrayToZero")]
#[hyperlight_guest_tracing::trace_function]
fn set_byte_array_to_zero(mut vec: Vec<u8>) -> Vec<u8> {
    vec.fill(0);
    vec
}

#[guest_function("PrintTwoArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_two_args(arg1: String, arg2: i32) -> Result<i32> {
    let message = format!("Message: arg1:{arg1} arg2:{arg2}.");
    host_print(message)
}

#[guest_function("PrintThreeArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_three_args(arg1: String, arg2: i32, arg3: i64) -> Result<i32> {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3}.");
    host_print(message)
}

#[guest_function("PrintFourArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_four_args(arg1: String, arg2: i32, arg3: i64, arg4: String) -> Result<i32> {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4}.");
    host_print(message)
}

#[guest_function("PrintFiveArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_five_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String) -> Result<i32> {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5}.");
    host_print(message)
}

#[guest_function("PrintSixArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_six_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6}."
    );
    host_print(message)
}

#[guest_function("PrintSevenArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_seven_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
    arg7: bool,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7}."
    );
    host_print(message)
}

#[guest_function("PrintEightArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_eight_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
    arg7: bool,
    arg8: u32,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8}."
    );
    host_print(message)
}

#[guest_function("PrintNineArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_nine_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
    arg7: bool,
    arg8: u32,
    arg9: u64,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9}."
    );
    host_print(message)
}

#[guest_function("PrintTenArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_ten_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
    arg7: bool,
    arg8: u32,
    arg9: u64,
    arg10: i32,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9} arg10:{arg10:.3}."
    );
    host_print(message)
}

#[guest_function("PrintElevenArgs")]
#[hyperlight_guest_tracing::trace_function]
fn print_eleven_args(
    arg1: String,
    arg2: i32,
    arg3: i64,
    arg4: String,
    arg5: String,
    arg6: bool,
    arg7: bool,
    arg8: u32,
    arg9: u64,
    arg10: i32,
    arg11: f32,
) -> Result<i32> {
    let message = format!(
        "Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9} arg10:{arg10} arg11:{arg11:.3}."
    );
    host_print(message)
}

#[guest_function("BufferOverrun")]
#[hyperlight_guest_tracing::trace_function]
fn buffer_overrun(value: String) -> i32 {
    let c_str = value.as_str();

    let mut buffer: [u8; 17] = [0; 17];
    let length = c_str.len();

    let copy_length = length.min(buffer.len());
    buffer[..copy_length].copy_from_slice(&c_str.as_bytes()[..copy_length]);

    (17i32).saturating_sub(length as i32)
}

#[guest_function("InfiniteRecursion")]
#[allow(unconditional_recursion)]
#[hyperlight_guest_tracing::trace_function]
fn infinite_recursion() {
    // blackbox is needed so something
    //is written to the stack in release mode,
    //to trigger guard page violation
    let param = black_box(5);
    black_box(param);
    infinite_recursion();
}

#[guest_function("StackOverflow")]
#[hyperlight_guest_tracing::trace_function]
fn stack_overflow(i: i32) -> i32 {
    loop_stack_overflow(i);
    i
}
// This function will allocate i * (8KiB + 1B) on the stack
#[hyperlight_guest_tracing::trace_function]
fn loop_stack_overflow(i: i32) {
    if i > 0 {
        let _nums = black_box([0u8; 0x2000 + 1]); // chkstk guaranteed to be called for > 8KiB
        loop_stack_overflow(i - 1);
    }
}

#[guest_function("LargeVar")]
#[hyperlight_guest_tracing::trace_function]
fn large_var() -> i32 {
    let _buffer = black_box([0u8; (DEFAULT_GUEST_STACK_SIZE + 1) as usize]);
    DEFAULT_GUEST_STACK_SIZE + 1
}

#[guest_function("SmallVar")]
#[hyperlight_guest_tracing::trace_function]
fn small_var() -> i32 {
    let _buffer = black_box([0u8; 1024]);
    1024
}

#[guest_function("CallMalloc")]
#[hyperlight_guest_tracing::trace_function]
fn call_malloc(size: i32) -> i32 {
    // will panic if OOM, and we need blackbox to avoid optimizing away this test
    let buffer = Vec::<u8>::with_capacity(size as usize);
    black_box(buffer);
    size
}

#[guest_function("MallocAndFree")]
#[hyperlight_guest_tracing::trace_function]
fn malloc_and_free(size: i32) -> i32 {
    let alloc_length = if size < DEFAULT_GUEST_STACK_SIZE {
        size
    } else {
        size.min(MAX_BUFFER_SIZE as i32)
    };
    let allocated_buffer = vec![0; alloc_length as usize];
    drop(allocated_buffer);
    size
}

#[guest_function("Echo")]
#[hyperlight_guest_tracing::trace_function]
fn echo(value: String) -> String {
    value
}

#[guest_function("GetSizePrefixedBuffer")]
#[hyperlight_guest_tracing::trace_function]
fn get_size_prefixed_buffer(data: Vec<u8>) -> Vec<u8> {
    data
}

#[guest_function("Spin")]
#[expect(
    clippy::empty_loop,
    reason = "This function is used to keep the CPU busy"
)]
fn spin() {
    loop {
        // Keep the CPU 100% busy forever
    }
}

#[guest_function("GuestAbortWithCode")]
#[hyperlight_guest_tracing::trace_function]
fn test_abort(code: i32) {
    abort_with_code(&[code as u8]);
}

#[guest_function("GuestAbortWithMessage")]
#[hyperlight_guest_tracing::trace_function]
fn test_abort_with_code_and_message(code: i32, message: String) {
    unsafe {
        abort_with_code_and_message(&[code as u8], message.as_ptr() as *const c_char);
    }
}

#[guest_function("guest_panic")]
#[hyperlight_guest_tracing::trace_function]
fn test_guest_panic(message: String) {
    panic!("{message}");
}

#[guest_function("test_write_raw_ptr")]
#[hyperlight_guest_tracing::trace_function]
fn test_write_raw_ptr(offset: i64) -> String {
    let min_stack_addr = unsafe { MIN_STACK_ADDRESS };
    let page_guard_start = min_stack_addr - PAGE_SIZE;
    let addr = {
        let abs = u64::try_from(offset.abs())
            .map_err(|_| error!("Invalid offset"))
            .unwrap();
        if offset.is_negative() {
            page_guard_start - abs
        } else {
            page_guard_start + abs
        }
    };
    unsafe {
        // print_output(format!("writing to {:#x}\n", addr).as_str()).unwrap();
        write_volatile(addr as *mut u8, 0u8);
    }
    "success".into()
}

#[guest_function("ExecuteOnStack")]
#[hyperlight_guest_tracing::trace_function]
fn execute_on_stack() -> String {
    unsafe {
        let mut noop: u8 = 0x90;
        let stack_fn: fn() = core::mem::transmute(&mut noop as *mut u8);
        stack_fn();
    };
    "fail".into()
}

#[guest_function("ExecuteOnHeap")]
#[hyperlight_guest_tracing::trace_function]
fn execute_on_heap() -> String {
    unsafe {
        // NO-OP followed by RET
        let heap_memory = Box::new([0x90u8, 0xC3]);
        let heap_fn: fn() = core::mem::transmute(Box::into_raw(heap_memory));
        heap_fn();
        black_box(heap_fn); // avoid optimization when running in release mode
    }
    // will only reach this point if heap is executable
    "fail".into()
}

#[guest_function("TestMalloc")]
#[hyperlight_guest_tracing::trace_function]
fn test_rust_malloc(code: i32) -> i32 {
    let ptr = unsafe { malloc(code as usize) };
    ptr as i32
}

#[guest_function("LogMessage")]
#[hyperlight_guest_tracing::trace_function]
fn log_message(message: String, level: i32) {
    let level = LevelFilter::iter().nth(level as usize).unwrap().to_level();

    if let Some(level) = level {
        log::log!(level, "{message}");
    }
}

#[guest_function("TriggerException")]
#[hyperlight_guest_tracing::trace_function]
fn trigger_exception() {
    unsafe {
        core::arch::asm!("ud2");
    } // trigger an undefined instruction exception
}

static mut COUNTER: i32 = 0;

#[guest_function("AddToStatic")]
#[hyperlight_guest_tracing::trace_function]
fn add_to_static(i: i32) -> i32 {
    unsafe {
        COUNTER += i;
        COUNTER
    }
}

#[guest_function("GetStatic")]
#[hyperlight_guest_tracing::trace_function]
fn get_static() -> i32 {
    unsafe { COUNTER }
}

#[guest_function("AddToStaticAndFail")]
#[hyperlight_guest_tracing::trace_function]
fn add_to_static_and_fail() -> Result<i32> {
    unsafe {
        COUNTER += 10;
    };
    Err(HyperlightGuestError::new(
        ErrorCode::GuestError,
        "Crash on purpose".to_string(),
    ))
}

#[guest_function("24K_in_8K_out")]
#[hyperlight_guest_tracing::trace_function]
fn twenty_four_k_in_eight_k_out(input: Vec<u8>) -> Vec<u8> {
    assert!(input.len() == 24 * 1024, "Input must be 24K bytes");
    input[..8 * 1024].to_vec()
}

#[guest_function("ViolateSeccompFilters")]
#[hyperlight_guest_tracing::trace_function]
fn violate_seccomp_filters() -> Result<u64> {
    make_getpid_syscall()
}

#[guest_function("CallGivenParamlessHostFuncThatReturnsI64")]
#[hyperlight_guest_tracing::trace_function]
fn call_given_paramless_hostfunc_that_returns_i64(hostfuncname: String) -> Result<i64> {
    call_host::<i64>(&hostfuncname, ())
}

#[guest_function("Add")]
#[hyperlight_guest_tracing::trace_function]
fn add(a: i32, b: i32) -> Result<i32> {
    host_add(a, b)
}

// Does nothing, but used for testing large parameters
#[guest_function("LargeParameters")]
#[hyperlight_guest_tracing::trace_function]
fn large_parameters(v: Vec<u8>, s: String) {
    black_box((v, s));
}

#[guest_function("ReadFromUserMemory")]
#[hyperlight_guest_tracing::trace_function]
fn read_from_user_memory(num: u64, expected: Vec<u8>) -> Result<Vec<u8>> {
    let bytes = read_n_bytes_from_user_memory(num).expect("Failed to read from user memory");

    // verify that the user memory contains the expected data
    if bytes != expected {
        error!("User memory does not contain the expected data");
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "User memory does not contain the expected data".to_string(),
        ));
    }

    Ok(bytes)
}

#[guest_function("ReadMappedBuffer")]
#[hyperlight_guest_tracing::trace_function]
fn read_mapped_buffer(base: u64, len: u64) -> Vec<u8> {
    let base = base as usize as *const u8;
    let len = len as usize;

    unsafe { hyperlight_guest_bin::paging::map_region(base as _, base as _, len as u64 + 4096) };

    let data = unsafe { core::slice::from_raw_parts(base, len) };

    data.to_vec()
}

#[guest_function("WriteMappedBuffer")]
#[hyperlight_guest_tracing::trace_function]
fn write_mapped_buffer(base: u64, len: u64) -> bool {
    let base = base as usize as *mut u8;
    let len = len as usize;

    unsafe { hyperlight_guest_bin::paging::map_region(base as _, base as _, len as u64 + 4096) };

    let data = unsafe { core::slice::from_raw_parts_mut(base, len) };

    // should fail
    data[0] = 0x42;

    // should never reach this
    true
}

#[hyperlight_guest_tracing::trace_function]
fn exec_mapped_buffer(base: u64, len: u64) -> bool {
    let base = base as usize as *mut u8;
    let len = len as usize;

    unsafe { hyperlight_guest_bin::paging::map_region(base as _, base as _, len as u64 + 4096) };

    let data = unsafe { core::slice::from_raw_parts(base, len) };

    // Should be safe as long as data is something like a NOOP followed by a RET
    let func: fn() = unsafe { core::mem::transmute(data.as_ptr()) };
    func();

    true
}

#[no_mangle]
#[hyperlight_guest_tracing::trace_function]
pub extern "C" fn hyperlight_main() {}

#[no_mangle]
#[hyperlight_guest_tracing::trace_function]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    // This test checks the stack behavior of the input/output buffer
    // by calling the host before serializing the function call.
    // If the stack is not working correctly, the input or output buffer will be
    // overwritten before the function call is serialized, and we will not be able
    // to verify that the function call name is "ThisIsNotARealFunctionButTheNameIsImportant"
    if function_call.function_name == "FuzzHostFunc" {
        return fuzz_host_function(function_call);
    }

    let message = "Hi this is a log message that will overwrite the shared buffer if the stack is not working correctly";

    guest_logger::log_message(
        LogLevel::Information,
        message,
        "source",
        "caller",
        "file",
        1,
    );

    let result = call_host_function::<i32>(
        "HostPrint",
        Some(Vec::from(&[ParameterValue::String(message.to_string())])),
        ReturnType::Int,
    )?;
    let function_name = function_call.function_name.clone();
    let param_len = function_call.parameters.clone().unwrap_or_default().len();
    let call_type = function_call.function_call_type().clone();

    if function_name != "ThisIsNotARealFunctionButTheNameIsImportant"
        || param_len != 0
        || call_type != FunctionCallType::Guest
        || result != 100
    {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionNotFound,
            function_name,
        ));
    }

    Ok(get_flatbuffer_result(99))
}

// Interprets the given guest function call as a host function call and dispatches it to the host.
#[hyperlight_guest_tracing::trace_function]
fn fuzz_host_function(func: FunctionCall) -> Result<Vec<u8>> {
    let mut params = func.parameters.unwrap();
    // first parameter must be string (the name of the host function to call)
    let host_func_name = match params.remove(0) {
        // TODO use `swap_remove` instead of `remove` if performance is an issue, but left out
        // to avoid confusion for replicating failure cases
        ParameterValue::String(name) => name,
        _ => {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionParameterTypeMismatch,
                "Invalid parameters passed to fuzz_host_function".to_string(),
            ));
        }
    };

    // Because we do not know at compile time the actual return type of the host function to be called
    // we cannot use the `call_host_function<T>` generic function.
    // We need to use the `call_host_function_without_returning_result` function that does not retrieve the return
    // value
    call_host_function_without_returning_result(
        &host_func_name,
        Some(params),
        func.expected_return_type,
    )
    .expect("failed to call host function");
    Ok(get_flatbuffer_result(()))
}
