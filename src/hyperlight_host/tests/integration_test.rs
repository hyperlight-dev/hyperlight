/*
Copyright 2024 The Hyperlight Authors.

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

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::PAGE_SIZE;
use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, HyperlightError, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::{c_simple_guest_as_string, simple_guest_as_string};

pub mod common; // pub to disable dead_code warning
use crate::common::{new_uninit, new_uninit_rust};

#[test]
fn print_four_args_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None, None, None);
    let mut sbox1 = uninit.unwrap().evolve(Noop::default()).unwrap();

    let res = sbox1.call_guest_function_by_name(
        "PrintFourArgs",
        ReturnType::String,
        Some(vec![
            ParameterValue::String("Test4".to_string()),
            ParameterValue::Int(3_i32),
            ParameterValue::Long(4_i64),
            ParameterValue::String("Tested".to_string()),
        ]),
    );
    println!("{:?}", res);
    assert!(matches!(res, Ok(ReturnValue::Int(46))));
}

// Checks that guest can abort with a specific code.
#[test]
fn guest_abort() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();
    let error_code: u8 = 13; // this is arbitrary
    let res = sbox1
        .call_guest_function_by_name(
            "GuestAbortWithCode",
            ReturnType::Void,
            Some(vec![ParameterValue::Int(error_code as i32)]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, message) if (code == error_code && message.is_empty()) )
    );
}

#[test]
fn guest_abort_with_context1() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let res = sbox1
        .call_guest_function_by_name(
            "GuestAbortWithMessage",
            ReturnType::Void,
            Some(vec![
                ParameterValue::Int(25),
                ParameterValue::String("Oh no".to_string()),
            ]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, context) if (code == 25 && context == "Oh no"))
    );
}

#[test]
fn guest_abort_with_context2() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    // The buffer size for the panic context is 1024 bytes.
    // This test will see what happens if the panic message is longer than that
    let abort_message = "Lorem ipsum dolor sit amet, \
                                consectetur adipiscing elit, \
                                sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                                Nec feugiat nisl pretium fusce. \
                                Amet mattis vulputate enim nulla aliquet porttitor lacus. \
                                Nunc congue nisi vitae suscipit tellus. \
                                Erat imperdiet sed euismod nisi porta lorem mollis aliquam ut. \
                                Amet tellus cras adipiscing enim eu turpis egestas. \
                                Blandit volutpat maecenas volutpat blandit aliquam etiam erat velit scelerisque. \
                                Tristique senectus et netus et malesuada. \
                                Eu turpis egestas pretium aenean pharetra magna ac placerat vestibulum. \
                                Adipiscing at in tellus integer feugiat. \
                                Faucibus vitae aliquet nec ullamcorper sit amet risus. \
                                \n\
                                Eros in cursus turpis massa tincidunt dui. \
                                Purus non enim praesent elementum facilisis leo vel fringilla. \
                                Dolor sit amet consectetur adipiscing elit pellentesque habitant morbi. \
                                Id leo in vitae turpis. At lectus urna duis convallis convallis tellus id interdum. \
                                Purus sit amet volutpat consequat. Egestas purus viverra accumsan in. \
                                Sodales ut etiam sit amet nisl. Lacus sed viverra tellus in hac. \
                                Nec ullamcorper sit amet risus nullam eget. \
                                Adipiscing bibendum est ultricies integer quis auctor. \
                                Vitae elementum curabitur vitae nunc sed velit dignissim sodales ut. \
                                Auctor neque vitae tempus quam pellentesque nec. \
                                Non pulvinar neque laoreet suspendisse interdum consectetur libero. \
                                Mollis nunc sed id semper. \
                                Et sollicitudin ac orci phasellus egestas tellus rutrum tellus pellentesque. \
                                Arcu felis bibendum ut tristique et. \
                                Proin sagittis nisl rhoncus mattis rhoncus urna. Magna eget est lorem ipsum.";

    let res = sbox1
        .call_guest_function_by_name(
            "GuestAbortWithMessage",
            ReturnType::Void,
            Some(vec![
                ParameterValue::Int(60),
                ParameterValue::String(abort_message.to_string()),
            ]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(_, context) if context.contains(&abort_message[..400]))
    );
}

// Ensure abort with context works for c guests.
// Just run this manually for now since we only build c guests on Windows and will
// hopefully be removing the c guest library soon.
#[test]
fn guest_abort_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None, None, None);
    let mut sbox1 = uninit.unwrap().evolve(Noop::default()).unwrap();

    let res = sbox1
        .call_guest_function_by_name(
            "GuestAbortWithMessage",
            ReturnType::Void,
            Some(vec![
                ParameterValue::Int(75_i32),
                ParameterValue::String("This is a test error message".to_string()),
            ]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, message) if (code == 75 && message == "This is a test error message"))
    );
}

#[test]
fn guest_panic() {
    // this test is rust-specific
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();

    let res = sbox1
        .call_guest_function_by_name(
            "guest_panic",
            ReturnType::Void,
            Some(vec![ParameterValue::String(
                "Error... error...".to_string(),
            )]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, context) if code == ErrorCode::UnknownError as u8 && context.contains("\nError... error..."))
    )
}

#[test]
fn guest_malloc() {
    // this test is rust-only
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();

    let size_to_allocate = 2000;
    let res = sbox1
        .call_guest_function_by_name(
            "TestMalloc",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(size_to_allocate)]),
        )
        .unwrap();
    assert!(matches!(res, ReturnValue::Int(_)));
}

#[test]
fn guest_allocate_vec() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let size_to_allocate = 2000;

    let res = sbox1
        .call_guest_function_by_name(
            "CallMalloc", // uses the rust allocator to allocate a vector on heap
            ReturnType::Int,
            Some(vec![ParameterValue::Int(size_to_allocate)]),
        )
        .unwrap();

    assert!(matches!(res, ReturnValue::Int(returned_size) if returned_size == size_to_allocate));
}

// checks that malloc failures are captured correctly
#[test]
fn guest_malloc_abort() {
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();

    let size = 20000000; // some big number that should fail when allocated

    let res = sbox1
        .call_guest_function_by_name(
            "TestMalloc",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(size)]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, _) if code == ErrorCode::MallocFailed as u8)
    );

    // allocate a vector (on heap) that is bigger than the heap
    let heap_size = 0x4000;
    let size_to_allocate = 0x10000;
    assert!(size_to_allocate > heap_size);

    let mut cfg = SandboxConfiguration::default();
    cfg.set_heap_size(heap_size);
    let uninit = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(cfg),
        None,
        None,
    )
    .unwrap();
    let mut sbox2 = uninit.evolve(Noop::default()).unwrap();

    let res = sbox2.call_guest_function_by_name(
        "CallMalloc", // uses the rust allocator to allocate a vector on heap
        ReturnType::Int,
        Some(vec![ParameterValue::Int(size_to_allocate as i32)]),
    );
    println!("{:?}", res);
    assert!(matches!(
        res.unwrap_err(),
        // OOM memory errors in rust allocator are panics. Our panic handler returns ErrorCode::UnknownError on panic
        HyperlightError::GuestAborted(code, msg) if code == ErrorCode::UnknownError as u8 && msg.contains("memory allocation of ")
    ));
}

// Tests libc alloca
#[test]
fn dynamic_stack_allocate_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None, None, None);
    let mut sbox1: MultiUseSandbox = uninit.unwrap().evolve(Noop::default()).unwrap();

    let res2 = sbox1
        .call_guest_function_by_name(
            "StackAllocate",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(100)]),
        )
        .unwrap();
    assert!(matches!(res2, ReturnValue::Int(n) if n == 100));

    let res = sbox1
        .call_guest_function_by_name(
            "StackAllocate",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(128 * 1024 * 1024)]),
        )
        .unwrap_err();
    assert!(matches!(res, HyperlightError::StackOverflow()));
}

// checks that a small buffer on stack works
#[test]
fn static_stack_allocate() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let res = sbox1
        .call_guest_function_by_name("SmallVar", ReturnType::Int, Some(Vec::new()))
        .unwrap();
    assert!(matches!(res, ReturnValue::Int(1024)));
}

// checks that a huge buffer on stack fails with stackoverflow
#[test]
fn static_stack_allocate_overflow() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();
    let res = sbox1
        .call_guest_function_by_name("LargeVar", ReturnType::Int, Some(Vec::new()))
        .unwrap_err();
    assert!(matches!(res, HyperlightError::StackOverflow()));
}

// checks that a recursive function with stack allocation works, (that chkstk can be called without overflowing)
#[test]
fn recursive_stack_allocate() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let iterations = 1;

    sbox1
        .call_guest_function_by_name(
            "StackOverflow",
            ReturnType::Int,
            Some(vec![ParameterValue::Int(iterations)]),
        )
        .unwrap();
}

// checks stack guard page (between guest stack and heap)
// is properly set up and cannot be written to
#[test]
fn guard_page_check() {
    // this test is rust-guest only
    let offsets_from_page_guard_start: Vec<i64> = vec![
        -1024,
        -1,
        0,                    // should fail
        1,                    // should fail
        1024,                 // should fail
        PAGE_SIZE as i64 - 1, // should fail
        PAGE_SIZE as i64,
        PAGE_SIZE as i64 + 1024,
    ];

    let guard_range = 0..PAGE_SIZE as i64;

    for offset in offsets_from_page_guard_start {
        // we have to create a sandbox each iteration because can't reuse after MMIO error in release mode

        let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();
        let result = sbox1.call_guest_function_by_name(
            "test_write_raw_ptr",
            ReturnType::String,
            Some(vec![ParameterValue::Long(offset)]),
        );
        if guard_range.contains(&offset) {
            // should have failed
            assert!(matches!(
                result.unwrap_err(),
                HyperlightError::StackOverflow()
            ));
        } else {
            assert!(result.is_ok(), "offset {} should pass", offset)
        }
    }
}

#[test]
fn guard_page_check_2() {
    // this test is rust-guest only
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();

    let result = sbox1
        .call_guest_function_by_name("InfiniteRecursion", ReturnType::Void, Some(vec![]))
        .unwrap_err();
    assert!(matches!(result, HyperlightError::StackOverflow()));
}

#[test]
fn execute_on_stack() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let result = sbox1
        .call_guest_function_by_name("ExecuteOnStack", ReturnType::String, Some(vec![]))
        .unwrap_err();

    #[cfg(inprocess)]
    if let HyperlightError::Error(message) = result {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                assert!(message.starts_with("Unexpected VM Exit") || message.starts_with("unknown Hyper-V run message type"));
            } else if #[cfg(target_os = "windows")] {
                assert!(message.starts_with("Unexpected VM Exit \"Did not receive a halt from Hypervisor as expected - Received WHV_RUN_VP_EXIT_REASON(4)"));
            } else {
                panic!("Unexpected");
            }
        }
    }

    #[cfg(not(inprocess))]
    {
        let err = result.to_string();
        assert!(
            // exception that indicates a page fault
            err.contains("EXCEPTION: 0xe")
        );
    }
}

#[test]
#[ignore] // ran from Justfile because requires feature "executable_heap"
fn execute_on_heap() {
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();
    let result =
        sbox1.call_guest_function_by_name("ExecuteOnHeap", ReturnType::String, Some(vec![]));

    println!("{:#?}", result);
    #[cfg(feature = "executable_heap")]
    assert!(result.is_ok());

    #[cfg(not(feature = "executable_heap"))]
    {
        assert!(result.is_err());
        let err = result.unwrap_err();

        assert!(err.to_string().contains("EXCEPTION: 0xe"));
    }
}

#[test]
fn memory_resets_after_failed_guestcall() {
    let mut sbox1 = new_uninit_rust().unwrap().evolve(Noop::default()).unwrap();
    sbox1
        .call_guest_function_by_name("AddToStaticAndFail", ReturnType::String, None)
        .unwrap_err();
    let res = sbox1
        .call_guest_function_by_name("GetStatic", ReturnType::Int, None)
        .unwrap();
    assert!(
        matches!(res, ReturnValue::Int(0)),
        "Expected 0, got {:?}",
        res
    );
}

// checks that a recursive function with stack allocation eventually fails with stackoverflow
#[test]
fn recursive_stack_allocate_overflow() {
    let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

    let iterations = 10;

    let res = sbox1
        .call_guest_function_by_name(
            "StackOverflow",
            ReturnType::Void,
            Some(vec![ParameterValue::Int(iterations)]),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(matches!(res, HyperlightError::StackOverflow()));
}

// Check that log messages are emitted correctly from the guest
// This test is ignored as it sets a logger and therefore maybe impacted by other tests running concurrently
// or it may impact other tests.
// It will run from the command just test-rust as it is included in that target
// It can also be run explicitly with `cargo test --test integration_test log_message -- --ignored`
#[test]
#[ignore]
fn log_message() {
    use hyperlight_testing::simplelogger::{SimpleLogger, LOGGER};
    // init
    SimpleLogger::initialize_test_logger();

    // internal_dispatch_function does a log::trace! in debug mode, and we call it 6 times in `log_test_messages`
    let num_fixed_trace_log = if cfg!(debug_assertions) { 6 } else { 0 };

    // test trace level
    log::set_max_level(log::LevelFilter::Trace);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(5 + num_fixed_trace_log, LOGGER.num_log_calls());
    // The number of enabled calls is the number of times that the enabled function is called
    // with a target of "hyperlight-guest"
    // This should be the same as the number of log calls as all the log calls for the "hyperlight-guest" target should be filtered in
    // the guest
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());

    // test debug level
    log::set_max_level(log::LevelFilter::Debug);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(4, LOGGER.num_log_calls());
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());

    // test info level
    log::set_max_level(log::LevelFilter::Info);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(3, LOGGER.num_log_calls());
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());

    // test warn level
    log::set_max_level(log::LevelFilter::Warn);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(2, LOGGER.num_log_calls());
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());

    // test error level
    log::set_max_level(log::LevelFilter::Error);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(1, LOGGER.num_log_calls());
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());

    // test off level
    log::set_max_level(log::LevelFilter::Off);
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    log_test_messages();
    assert_eq!(0, LOGGER.num_log_calls());
    assert_eq!(LOGGER.num_log_calls(), LOGGER.num_enabled_calls());
}

fn log_test_messages() {
    for level in log::LevelFilter::iter() {
        let mut sbox1 = new_uninit().unwrap().evolve(Noop::default()).unwrap();

        let message = format!("Hello from log_message level {}", level as i32);
        sbox1
            .call_guest_function_by_name(
                "LogMessage",
                ReturnType::Void,
                Some(vec![
                    ParameterValue::String(message.to_string()),
                    ParameterValue::Int(level as i32),
                ]),
            )
            .unwrap();
    }
}
