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
use core::alloc::Layout;
use core::ffi::c_char;
use core::hint::black_box;
use core::ptr::write_volatile;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::mem::PAGE_SIZE;
use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest::exit::{abort_with_code, abort_with_code_and_message};
use hyperlight_guest_bin::exceptions::handler::{Context, ExceptionInfo};
use hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition;
use hyperlight_guest_bin::guest_function::register::register_function;
use hyperlight_guest_bin::host_comm::{
    call_host_function, call_host_function_without_returning_result, get_host_return_value_raw,
    print_output_with_host_print, read_n_bytes_from_user_memory,
};
use hyperlight_guest_bin::memory::malloc;
use hyperlight_guest_bin::{MIN_STACK_ADDRESS, guest_function, guest_logger, host_function};
use log::{LevelFilter, error};
use tracing::{Span, instrument};

extern crate hyperlight_guest;

static mut BIGARRAY: [i32; 1024 * 1024] = [0; 1024 * 1024];
// Exception handler test state
static HANDLER_INVOCATION_COUNT: AtomicU64 = AtomicU64::new(0);
const TEST_R9_VALUE: u64 = 0x1234567890ABCDEF;
const TEST_R9_MODIFIED_VALUE: u64 = 0xBADC0FFEE;
const TEST_R10_VALUE: u64 = 0xDEADBEEF;

#[guest_function("SetStatic")]
fn set_static() -> i32 {
    #[allow(static_mut_refs)]
    let bigarray = unsafe { &mut BIGARRAY };
    for val in bigarray.iter_mut() {
        *val = 1;
    }
    bigarray.len() as i32
}

#[guest_function("EchoDouble")]
fn echo_double(value: f64) -> f64 {
    value
}

// Test exception handler that validates stack layout and records invocation
// It is designed to interact with the trigger_int3 breakpoint exception function below
fn test_exception_handler(
    exception_number: u64,
    _exception_info: *mut ExceptionInfo,
    context: *mut Context,
    _page_fault_address: u64,
) -> bool {
    // Record invocation
    HANDLER_INVOCATION_COUNT.fetch_add(1, Ordering::SeqCst);

    // INT3 is exception vector 3
    assert_eq!(exception_number, 3);

    // Validate stack is 16-byte aligned by executing an SSE instruction
    // movaps with a stack memory operand requires 16-byte alignment and will #GP if misaligned
    unsafe {
        core::arch::asm!(
            "sub rsp, 16",        // Allocate space on stack
            "movaps [rsp], xmm0", // This will #GP if stack is not 16-byte aligned
            "add rsp, 16",        // Clean up
            options(nostack)
        );
    }

    // Validate we can read and write to Context registers
    // First, read the original value from R9 register (index 6)
    let original_r9 = unsafe { core::ptr::read_volatile(&(*context).gprs[6]) };
    assert_eq!(
        original_r9, TEST_R9_VALUE,
        "R9 register should contain original test value"
    );

    // Modify R9 register directly and write R10 to context
    unsafe {
        // Modify R9 register directly using inline assembly
        // this should be restored to the original value stored on the stack when the
        // exception completes and is verified in trigger_int3
        core::arch::asm!("mov r9, {0}", in(reg) TEST_R9_MODIFIED_VALUE);

        // Write to R10 via context to verify context modification works
        core::ptr::write_volatile(&mut (*context).gprs[5], TEST_R10_VALUE); // R10
    }

    // Return true to suppress abort and continue execution
    true
}

/// Install handler for a specific vector
#[guest_function("InstallHandler")]
fn install_handler(vector: i32) {
    hyperlight_guest_bin::exceptions::handler::HANDLERS[vector as usize]
        .store(test_exception_handler as usize as u64, Ordering::Release);
}

/// Get how many times the handler was invoked
#[guest_function("GetExceptionHandlerCallCount")]
fn get_exception_handler_call_count() -> i32 {
    let count = HANDLER_INVOCATION_COUNT.load(Ordering::SeqCst);
    count as i32
}

/// Trigger an INT3 breakpoint exception (vector 3)
#[guest_function("TriggerInt3")]
fn trigger_int3() -> i32 {
    // Set up test value in R9 before triggering exception
    let test_value: u64 = TEST_R9_VALUE;

    unsafe {
        // Store test value in R9 register
        core::arch::asm!(
            "mov r9, {0}",
            in(reg) test_value
        );

        // This will trigger exception vector 3 (#BP - Breakpoint)
        core::arch::asm!("int3");

        // After returning from exception handler, verify registers
        let r9_result: u64;
        let r10_result: u64;
        core::arch::asm!(
            "mov {0}, r9",
            "mov {1}, r10",
            out(reg) r9_result,
            out(reg) r10_result
        );

        // R9 should be restored to original value (context restore working)
        assert_eq!(
            r9_result, test_value,
            "R9 register was not properly restored by exception handler"
        );
        // R10 should have the value written to context
        assert_eq!(
            r10_result, TEST_R10_VALUE,
            "R10 register was not modified via context by exception handler"
        );
    }
    0
}

#[guest_function("EchoFloat")]
fn echo_float(value: f32) -> f32 {
    value
}

#[host_function("HostPrint")]
fn host_print(msg: String) -> i32;

#[instrument(skip_all, parent = Span::current(), level= "Trace")]
#[guest_function("PrintOutput")]
fn print_output(msg: String) -> i32 {
    host_print(msg)
}

#[guest_function("PrintUsingPrintf")]
fn print_using_printf(msg: String) -> i32 {
    print_output(msg)
}

#[guest_function("SetByteArrayToZero")]
fn set_byte_array_to_zero(mut vec: Vec<u8>) -> Vec<u8> {
    vec.fill(0);
    vec
}

#[guest_function("PrintTwoArgs")]
fn print_two_args(arg1: String, arg2: i32) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2}.");
    host_print(message)
}

#[guest_function("PrintThreeArgs")]
fn print_three_args(arg1: String, arg2: i32, arg3: i64) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3}.");
    host_print(message)
}

#[guest_function("PrintFourArgs")]
fn print_four_args(arg1: String, arg2: i32, arg3: i64, arg4: String) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4}.");
    host_print(message)
}

#[guest_function("PrintFiveArgs")]
fn print_five_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5}.");
    host_print(message)
}

#[rustfmt::skip]
#[guest_function("PrintSixArgs")]
fn print_six_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6}.");
    host_print(message)
}

#[rustfmt::skip]
#[guest_function("PrintSevenArgs")]
fn print_seven_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool, arg7: bool) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7}.");
    host_print(message)
}

#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
#[guest_function("PrintEightArgs")]
fn print_eight_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool, arg7: bool, arg8: u32) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8}.");
    host_print(message)
}

#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
#[guest_function("PrintNineArgs")]
fn print_nine_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool, arg7: bool, arg8: u32, arg9: u64) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9}.");
    host_print(message)
}

#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
#[guest_function("PrintTenArgs")]
fn print_ten_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool, arg7: bool, arg8: u32, arg9: u64, arg10: i32) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9} arg10:{arg10}.");
    host_print(message)
}

#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
#[guest_function("PrintElevenArgs")]
fn print_eleven_args(arg1: String, arg2: i32, arg3: i64, arg4: String, arg5: String, arg6: bool, arg7: bool, arg8: u32, arg9: u64, arg10: i32, arg11: f32) -> i32 {
    let message = format!("Message: arg1:{arg1} arg2:{arg2} arg3:{arg3} arg4:{arg4} arg5:{arg5} arg6:{arg6} arg7:{arg7} arg8:{arg8} arg9:{arg9} arg10:{arg10} arg11:{arg11:.3}.");
    host_print(message)
}

#[guest_function("BufferOverrun")]
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
fn infinite_recursion() {
    // blackbox is needed so something
    //is written to the stack in release mode,
    //to trigger guard page violation
    let param = black_box(5);
    black_box(param);
    infinite_recursion()
}

#[guest_function("StackOverflow")]
fn stack_overflow(i: i32) -> i32 {
    loop_stack_overflow(i);
    i
}

// This function will allocate i * (8KiB + 1B) on the stack
fn loop_stack_overflow(i: i32) {
    if i > 0 {
        let _nums = black_box([0u8; 0x2000 + 1]); // chkstk guaranteed to be called for > 8KiB
        loop_stack_overflow(i - 1);
    }
}

#[guest_function("LargeVar")]
fn large_var() -> i32 {
    let _buffer = black_box([0u8; (DEFAULT_GUEST_STACK_SIZE + 1) as usize]);
    DEFAULT_GUEST_STACK_SIZE + 1
}

#[guest_function("SmallVar")]
fn small_var() -> i32 {
    let _buffer = black_box([0u8; 1024]);
    1024
}

#[guest_function("CallMalloc")]
fn call_malloc(size: i32) -> i32 {
    // will panic if OOM, and we need blackbox to avoid optimizing away this test
    let buffer = Vec::<u8>::with_capacity(size as usize);
    black_box(buffer);
    size
}

#[guest_function("ExhaustHeap")]
fn exhaust_heap() {
    let layout: Layout = Layout::new::<u8>();
    let mut ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    while !ptr.is_null() {
        black_box(ptr);
        ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    }

    // after alloc::alloc_zeroed failure (null return when called in loop above)
    // allocate a Vec to ensure OOM panic
    let vec = Vec::<i32>::with_capacity(1);
    black_box(vec);

    panic!("function should have panicked before due to OOM")
}

#[guest_function("MallocAndFree")]
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
fn echo(value: String) -> String {
    value
}

#[guest_function("GetSizePrefixedBuffer")]
fn get_size_prefixed_buffer(data: Vec<u8>) -> Vec<u8> {
    data
}

#[expect(
    clippy::empty_loop,
    reason = "This function is used to keep the CPU busy"
)]
#[guest_function("Spin")]
fn spin() {
    loop {
        // Keep the CPU 100% busy forever
    }
}

/// Spins the CPU for approximately the specified number of milliseconds
#[guest_function("SpinForMs")]
fn spin_for_ms(milliseconds: u32) -> u64 {
    // Simple busy-wait loop - not precise but good enough for testing
    // Different iteration counts for debug vs release mode to ensure reasonable CPU usage
    #[cfg(debug_assertions)]
    // Debug mode - less optimized. The value 120,000 for iterations_per_ms was empirically chosen
    // to achieve approximately a 50% "kill rate" in test runs, meaning that about half of the tests
    // using this spin function will hit a timeout or resource limit imposed by the host. This helps
    // stress-test the host's timeout and resource management logic. The value may need adjustment
    // depending on the test environment or hardware.
    let iterations_per_ms = 120_000;

    #[cfg(not(debug_assertions))]
    let iterations_per_ms = 1_000_000; // Release mode - highly optimized

    let total_iterations = milliseconds * iterations_per_ms;

    let mut counter: u64 = 0;
    for _ in 0..total_iterations {
        // Prevent the compiler from optimizing away the loop
        counter = counter.wrapping_add(1);
        core::hint::black_box(counter);
    }

    // Calculate the actual number of milliseconds spun for, based on the counter and iterations per ms
    counter / iterations_per_ms as u64
}

#[guest_function("GuestAbortWithCode")]
fn test_abort(code: i32) {
    abort_with_code(&[code as u8]);
}

#[guest_function("GuestAbortWithMessage")]
fn test_abort_with_code_and_message(code: i32, mut message: String) {
    message.push('\0'); // null-terminate the string
    unsafe {
        abort_with_code_and_message(&[code as u8], message.as_ptr() as *const c_char);
    }
}

#[guest_function("guest_panic")]
fn test_guest_panic(message: String) {
    panic!("{}", message);
}

#[guest_function]
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
        // host_print(format!("writing to {:#x}\n", addr).as_str());
        write_volatile(addr as *mut u8, 0u8);
    }
    String::from("success")
}

#[guest_function("ExecuteOnStack")]
fn execute_on_stack() -> String {
    unsafe {
        let mut noop: u8 = 0x90;
        let stack_fn: fn() = core::mem::transmute(&mut noop as *mut u8);
        stack_fn();
    };
    // will only reach this point if stack is executable
    String::from("fail")
}

#[guest_function("ExecuteOnHeap")]
fn execute_on_heap() -> String {
    unsafe {
        // NO-OP followed by RET
        let heap_memory = Box::new([0x90u8, 0xC3]);
        let heap_fn: fn() = core::mem::transmute(Box::into_raw(heap_memory));
        heap_fn();
        black_box(heap_fn); // avoid optimization when running in release mode
    }
    // will only reach this point if heap is executable
    String::from("fail")
}

#[guest_function("TestMalloc")]
fn test_rust_malloc(code: i32) -> i32 {
    let ptr = unsafe { malloc(code as usize) };
    ptr as i32
}

#[guest_function("LogMessage")]
fn log_message(message: String, level: i32) {
    let level = LevelFilter::iter().nth(level as usize).unwrap().to_level();

    match level {
        Some(level) => log::log!(level, "{}", &message),
        None => {
            // was passed LevelFilter::Off, do nothing
        }
    }
}

#[guest_function("TriggerException")]
fn trigger_exception() {
    // trigger an undefined instruction exception
    unsafe { core::arch::asm!("ud2") };
}

static mut COUNTER: i32 = 0;

#[guest_function("AddToStatic")]
fn add_to_static(i: i32) -> i32 {
    unsafe {
        COUNTER += i;
        COUNTER
    }
}

#[guest_function("GetStatic")]
fn get_static() -> i32 {
    unsafe { COUNTER }
}

#[guest_function("AddToStaticAndFail")]
fn add_to_static_and_fail() -> Result<i32> {
    unsafe { COUNTER += 10 };
    Err(HyperlightGuestError::new(
        ErrorCode::GuestError,
        "Crash on purpose".to_string(),
    ))
}

#[guest_function("24K_in_8K_out")]
fn twenty_four_k_in_eight_k_out(input: Vec<u8>) -> Vec<u8> {
    assert!(input.len() == 24 * 1024, "Input must be 24K bytes");
    input[..8 * 1024].to_vec()
}

#[guest_function("CallGivenParamlessHostFuncThatReturnsI64")]
fn call_given_paramless_hostfunc_that_returns_i64(hostfuncname: String) -> Result<i64> {
    call_host_function::<i64>(&hostfuncname, None, ReturnType::Long)
}

#[guest_function("UseSSE2Registers")]
fn use_sse2_registers() {
    let val: f32 = 1.2f32;
    unsafe { core::arch::asm!("movss xmm1, DWORD PTR [{0}]", in(reg) &val) };
}

#[guest_function("Add")]
fn add(a: i32, b: i32) -> Result<i32> {
    #[host_function("HostAdd")]
    fn host_add(a: i32, b: i32) -> Result<i32>;

    host_add(a, b)
}

// Does nothing, but used for testing large parameters
#[guest_function("LargeParameters")]
fn large_parameters(v: Vec<u8>, s: String) {
    black_box((v, s));
}

#[guest_function("ReadFromUserMemory")]
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
fn read_mapped_buffer(base: u64, len: u64) -> Vec<u8> {
    let base = base as usize as *const u8;
    let len = len as usize;

    unsafe { hyperlight_guest_bin::paging::map_region(base as _, base as _, len as u64 + 4096) };

    let data = unsafe { core::slice::from_raw_parts(base, len) };

    data.to_vec()
}

#[guest_function("WriteMappedBuffer")]
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

#[guest_function("ExecMappedBuffer")]
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

#[guest_function("CallHostExpectError")]
fn call_host_expect_error(hostfuncname: String) -> Result<()> {
    let res = call_host_function::<i32>(&hostfuncname, None, ReturnType::Int);

    let Err(e) = res else {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            "Expected host function to fail, but it succeeded".to_string(),
        ));
    };

    assert_eq!(e.kind, ErrorCode::HostFunctionError);
    assert_eq!(
        e.message,
        format!("HostFunction {hostfuncname} was not found")
    );
    Ok(())
}

#[no_mangle]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
pub extern "C" fn hyperlight_main() {
    let print_output_def = GuestFunctionDefinition::new(
        "PrintOutputWithHostPrint".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        print_output_with_host_print as usize,
    );
    register_function(print_output_def);
}

#[host_function("HostMethod")]
fn host_method(message: String) -> Result<i32>;

#[guest_function("GuestMethod")]
fn guest_function(message: String) -> Result<i32> {
    let message = format!("Hello from GuestFunction, {}", message);
    host_method(message)
}

#[host_function("HostMethod1")]
fn host_method_1(message: String) -> Result<i32>;

#[guest_function("GuestMethod1")]
fn guest_function1(message: String) -> Result<i32> {
    let message = format!("Hello from GuestFunction1, {}", message);
    host_method_1(message)
}

#[guest_function("GuestMethod2")]
fn guest_function2(message: String) -> Result<i32> {
    let message = format!("Hello from GuestFunction2, {}", message);
    host_method_1(message)
}

#[guest_function("GuestMethod3")]
fn guest_function3(message: String) -> Result<i32> {
    let message = format!("Hello from GuestFunction3, {}", message);
    host_method_1(message)
}

#[host_function("HostMethod4")]
fn host_method_4(message: String) -> Result<()>;

#[guest_function("GuestMethod4")]
fn guest_function4() -> Result<()> {
    host_method_4("Hello from GuestFunction4".to_string())
}

#[guest_function("LogMessageWithSource")]
fn guest_log_message(message: String, source: String, level: i32) -> i32 {
    let mut log_level = level;
    if !(0..=6).contains(&log_level) {
        log_level = 0;
    }

    guest_logger::log_message(
        LogLevel::from(log_level as u8),
        &message,
        &source,
        "guest_log_message",
        file!(),
        line!(),
    );

    message.len() as i32
}

#[guest_function("CallErrorMethod")]
fn call_error_method(message: String) -> Result<i32> {
    #[host_function("ErrorMethod")]
    fn error_method(message: String) -> Result<i32>;

    let message = format!("Error From Host: {}", message);
    error_method(message)
}

#[guest_function("CallHostSpin")]
fn call_host_spin() -> Result<()> {
    #[host_function("Spin")]
    fn host_spin() -> Result<()>;

    host_spin()
}

#[guest_function("HostCallLoop")]
fn host_call_loop(host_func_name: String) -> Result<Vec<u8>> {
    loop {
        call_host_function::<()>(&host_func_name, None, ReturnType::Void).unwrap();
    }
}

// Calls the given host function (no param, no return value) and then spins indefinitely.
#[guest_function("CallHostThenSpin")]
fn call_host_then_spin(host_func_name: String) -> Result<()> {
    call_host_function::<()>(&host_func_name, None, ReturnType::Void)?;
    #[expect(
        clippy::empty_loop,
        reason = "This function is used to keep the CPU busy"
    )]
    loop {}
}

#[instrument(skip_all, parent = Span::current(), level= "Trace")]
fn fuzz_traced_function(depth: u32, max_depth: u32, msg: &str) -> u32 {
    if depth < max_depth {
        log::info!("{}", msg);

        fuzz_traced_function(depth + 1, max_depth, msg) + 1
    } else {
        0
    }
}

#[guest_function("FuzzGuestTrace")]
fn fuzz_guest_trace(max_depth: u32, msg: String) -> u32 {
    fuzz_traced_function(0, max_depth, &msg)
}

// Interprets the given guest function call as a host function call and dispatches it to the host.
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

    let host_return = get_host_return_value_raw();
    match host_return {
        Ok(return_value) => match return_value {
            ReturnValue::Int(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::UInt(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::Long(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::ULong(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::Float(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::Double(i) => Ok(get_flatbuffer_result(i)),
            ReturnValue::String(str) => Ok(get_flatbuffer_result(str.as_str())),
            ReturnValue::Bool(bool) => Ok(get_flatbuffer_result(bool)),
            ReturnValue::Void(()) => Ok(get_flatbuffer_result(())),
            ReturnValue::VecBytes(byte) => Ok(get_flatbuffer_result(byte.as_slice())),
        },
        Err(e) => Err(e),
    }
}

#[no_mangle]
#[instrument(skip_all, parent = Span::current(), level= "Trace")]
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
