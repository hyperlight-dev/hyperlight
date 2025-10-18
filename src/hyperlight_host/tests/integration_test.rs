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
#![allow(clippy::disallowed_macros)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::mem::PAGE_SIZE;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, HyperlightError, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simplelogger::{LOGGER, SimpleLogger};
use hyperlight_testing::{c_simple_guest_as_string, simple_guest_as_string};
use log::LevelFilter;

pub mod common; // pub to disable dead_code warning
use crate::common::{new_uninit, new_uninit_c, new_uninit_rust};

// A host function cannot be interrupted, but we can at least make sure after requesting to interrupt a host call,
// we don't re-enter the guest again once the host call is done
#[test]
fn interrupt_host_call() {
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();

    let mut usbox = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
        None,
    )
    .unwrap();

    let spin = move || {
        barrier2.wait();
        thread::sleep(std::time::Duration::from_secs(1));
        Ok(())
    };

    #[cfg(any(target_os = "windows", not(seccomp)))]
    usbox.register("Spin", spin).unwrap();

    #[cfg(seccomp)]
    usbox
        .register_with_extra_allowed_syscalls("Spin", spin, vec![libc::SYS_clock_nanosleep])
        .unwrap();

    let mut sandbox: MultiUseSandbox = usbox.evolve().unwrap();
    let interrupt_handle = sandbox.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    let thread = thread::spawn({
        move || {
            barrier.wait(); // wait for the host function to be entered
            interrupt_handle.kill(); // send kill once host call is in progress
        }
    });

    let result = sandbox.call::<i32>("CallHostSpin", ());
    println!("Result: {:?}", result);
    let result = result.unwrap_err();
    assert!(matches!(result, HyperlightError::ExecutionCanceledByHost()));

    thread.join().unwrap();
}

/// Makes sure a running guest call can be interrupted by the host
#[test]
fn interrupt_in_progress_guest_call() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let interrupt_handle = sbox1.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    // kill vm after 1 second
    let thread = thread::spawn(move || {
        thread::sleep(Duration::from_secs(1));
        assert!(interrupt_handle.kill());
        barrier2.wait(); // wait here until main thread has returned from the interrupted guest call
        barrier2.wait(); // wait here until main thread has dropped the sandbox
        assert!(interrupt_handle.dropped());
    });

    let res = sbox1.call::<i32>("Spin", ()).unwrap_err();
    assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));

    barrier.wait();
    // Make sure we can still call guest functions after the VM was interrupted
    sbox1.call::<String>("Echo", "hello".to_string()).unwrap();

    // drop vm to make sure other thread can detect it
    drop(sbox1);
    barrier.wait();
    thread.join().expect("Thread should finish");
}

/// Makes sure interrupting a vm before the guest call has started has no effect,
/// but a second kill after the call starts will interrupt it
#[test]
fn interrupt_guest_call_in_advance() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let interrupt_handle = sbox1.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    // First kill before the guest call has started - should have no effect
    // Then kill again after a delay to interrupt the actual call
    let thread = thread::spawn(move || {
        assert!(!interrupt_handle.kill()); // should return false since no call is active
        barrier2.wait();
        // Wait a bit for the Spin call to actually start
        thread::sleep(Duration::from_millis(100));
        assert!(interrupt_handle.kill()); // this should succeed and interrupt the Spin call
        barrier2.wait(); // wait here until main thread has dropped the sandbox
        assert!(interrupt_handle.dropped());
    });

    barrier.wait(); // wait until first `kill()` is called before starting the guest call
    // The Spin call should be interrupted by the second kill()
    let res = sbox1.call::<i32>("Spin", ()).unwrap_err();
    assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));

    // Make sure we can still call guest functions after the VM was interrupted
    sbox1.call::<String>("Echo", "hello".to_string()).unwrap();

    // drop vm to make sure other thread can detect it
    drop(sbox1);
    barrier.wait();
    thread.join().expect("Thread should finish");
}

/// Verifies that only the intended sandbox (`sbox2`) is interruptible,
/// even when multiple sandboxes share the same thread.
/// This test runs several interleaved iterations where `sbox2` is interrupted,
/// and ensures that:
/// - `sbox1` and `sbox3` are never affected by the interrupt.
/// - `sbox2` either completes normally or fails with `ExecutionCanceledByHost`.
///
/// This test is not foolproof and may not catch
/// all possible interleavings, but can hopefully increases confidence somewhat.
#[test]
fn interrupt_same_thread() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let mut sbox2: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let mut sbox3: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();

    let interrupt_handle = sbox2.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    const NUM_ITERS: usize = 500;

    // kill vm after 1 second
    let thread = thread::spawn(move || {
        for _ in 0..NUM_ITERS {
            barrier2.wait();
            interrupt_handle.kill();
        }
    });

    for _ in 0..NUM_ITERS {
        barrier.wait();
        sbox1
            .call::<String>("Echo", "hello".to_string())
            .expect("Only sandbox 2 is allowed to be interrupted");
        match sbox2.call::<String>("Echo", "hello".to_string()) {
            Ok(_) | Err(HyperlightError::ExecutionCanceledByHost()) => {
                // Only allow successful calls or interrupted.
                // The call can be successful in case the call is finished before kill() is called.
            }
            _ => panic!("Unexpected return"),
        };
        sbox3
            .call::<String>("Echo", "hello".to_string())
            .expect("Only sandbox 2 is allowed to be interrupted");
    }
    thread.join().expect("Thread should finish");
}

/// Same test as above but with no per-iteration barrier, to get more possible interleavings.
#[test]
fn interrupt_same_thread_no_barrier() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let mut sbox2: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let mut sbox3: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let workload_done = Arc::new(AtomicBool::new(false));
    let workload_done2 = workload_done.clone();

    let interrupt_handle = sbox2.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    const NUM_ITERS: usize = 500;

    // kill vm after 1 second
    let thread = thread::spawn(move || {
        barrier2.wait();
        while !workload_done2.load(Ordering::Relaxed) {
            interrupt_handle.kill();
        }
    });

    barrier.wait();
    for _ in 0..NUM_ITERS {
        sbox1
            .call::<String>("Echo", "hello".to_string())
            .expect("Only sandbox 2 is allowed to be interrupted");
        match sbox2.call::<String>("Echo", "hello".to_string()) {
            Ok(_) | Err(HyperlightError::ExecutionCanceledByHost()) => {
                // Only allow successful calls or interrupted.
                // The call can be successful in case the call is finished before kill() is called.
            }
            _ => panic!("Unexpected return"),
        };
        sbox3
            .call::<String>("Echo", "hello".to_string())
            .expect("Only sandbox 2 is allowed to be interrupted");
    }
    workload_done.store(true, Ordering::Relaxed);
    thread.join().expect("Thread should finish");
}

// Verify that a sandbox moved to a different thread after initialization can still be killed,
// and that anther sandbox on the original thread does not get incorrectly killed
#[test]
fn interrupt_moved_sandbox() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let mut sbox2: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();

    let interrupt_handle = sbox1.interrupt_handle();
    let interrupt_handle2 = sbox2.interrupt_handle();

    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();

    let thread = thread::spawn(move || {
        barrier2.wait();
        let res = sbox1.call::<i32>("Spin", ()).unwrap_err();
        assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));
    });

    let thread2 = thread::spawn(move || {
        barrier.wait();
        thread::sleep(Duration::from_secs(1));
        assert!(interrupt_handle.kill());

        // make sure this returns true, which means the sandbox wasn't killed incorrectly before
        assert!(interrupt_handle2.kill());
    });

    let res = sbox2.call::<i32>("Spin", ()).unwrap_err();
    assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));

    thread.join().expect("Thread should finish");
    thread2.join().expect("Thread should finish");
}

/// This tests exercises the behavior of killing vcpu with a long retry delay.
/// This will exercise the ABA-problem, where the vcpu could be successfully interrupted,
/// but restarted, before the interruptor-thread has a chance to see that the vcpu was killed.
///
/// The ABA-problem is solved by introducing run-generation on the vcpu.
#[test]
#[cfg(target_os = "linux")]
fn interrupt_custom_signal_no_and_retry_delay() {
    let mut config = SandboxConfiguration::default();
    config.set_interrupt_vcpu_sigrtmin_offset(0).unwrap();
    config.set_interrupt_retry_delay(Duration::from_secs(1));

    let mut sbox1: MultiUseSandbox = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(config),
    )
    .unwrap()
    .evolve()
    .unwrap();

    let interrupt_handle = sbox1.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    const NUM_ITERS: usize = 3;

    let thread = thread::spawn(move || {
        for _ in 0..NUM_ITERS {
            // wait for the guest call to start
            thread::sleep(Duration::from_millis(1000));
            interrupt_handle.kill();
        }
    });

    for _ in 0..NUM_ITERS {
        let res = sbox1.call::<i32>("Spin", ()).unwrap_err();
        assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));
        // immediately reenter another guest function call after having being cancelled,
        // so that the vcpu is running again before the interruptor-thread has a chance to see that the vcpu is not running
    }
    thread.join().expect("Thread should finish");
}

#[test]
fn interrupt_spamming_host_call() {
    let mut uninit = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        None,
    )
    .unwrap();

    uninit
        .register("HostFunc1", || {
            // do nothing
        })
        .unwrap();
    let mut sbox1: MultiUseSandbox = uninit.evolve().unwrap();

    let interrupt_handle = sbox1.interrupt_handle();

    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();

    let thread = thread::spawn(move || {
        barrier2.wait();
        thread::sleep(Duration::from_secs(1));
        interrupt_handle.kill();
    });

    barrier.wait();
    // This guest call calls "HostFunc1" in a loop
    let res = sbox1
        .call::<i32>("HostCallLoop", "HostFunc1".to_string())
        .unwrap_err();

    assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));

    thread.join().expect("Thread should finish");
}

#[test]
fn print_four_args_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None);
    let mut sbox1 = uninit.unwrap().evolve().unwrap();

    let res = sbox1.call::<i32>(
        "PrintFourArgs",
        ("Test4".to_string(), 3_i32, 4_i64, "Tested".to_string()),
    );
    println!("{:?}", res);
    assert!(matches!(res, Ok(46)));
}

// Checks that guest can abort with a specific code.
#[test]
fn guest_abort() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();
    let error_code: u8 = 13; // this is arbitrary
    let res = sbox1
        .call::<()>("GuestAbortWithCode", error_code as i32)
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, message) if (code == error_code && message.is_empty()))
    );
}

#[test]
fn guest_abort_with_context1() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let res = sbox1
        .call::<()>("GuestAbortWithMessage", (25_i32, "Oh no".to_string()))
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, context) if (code == 25 && context == "Oh no"))
    );
}

#[test]
fn guest_abort_with_context2() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

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
        .call::<()>("GuestAbortWithMessage", (60_i32, abort_message.to_string()))
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(_, context) if context.contains("Guest abort buffer overflowed"))
    );
}

// Ensure abort with context works for c guests.
// Just run this manually for now since we only build c guests on Windows and will
// hopefully be removing the c guest library soon.
#[test]
fn guest_abort_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None);
    let mut sbox1 = uninit.unwrap().evolve().unwrap();

    let res = sbox1
        .call::<()>(
            "GuestAbortWithMessage",
            (75_i32, "This is a test error message".to_string()),
        )
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, message) if (code == 75 && message == "This is a test error message") )
    );
}

#[test]
fn guest_panic() {
    // this test is rust-specific
    let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();

    let res = sbox1
        .call::<()>("guest_panic", "Error... error...".to_string())
        .unwrap_err();
    println!("{:?}", res);
    assert!(
        matches!(res, HyperlightError::GuestAborted(code, context) if code == ErrorCode::UnknownError as u8 && context.contains("\nError... error..."))
    )
}

#[test]
fn guest_malloc() {
    // this test is rust-only
    let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();

    let size_to_allocate = 2000_i32;
    sbox1.call::<i32>("TestMalloc", size_to_allocate).unwrap();
}

#[test]
fn guest_allocate_vec() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let size_to_allocate = 2000_i32;

    let res = sbox1
        .call::<i32>(
            "CallMalloc", // uses the rust allocator to allocate a vector on heap
            size_to_allocate,
        )
        .unwrap();

    assert_eq!(res, size_to_allocate);
}

// checks that malloc failures are captured correctly
#[test]
fn guest_malloc_abort() {
    let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();

    let size = 20000000_i32; // some big number that should fail when allocated

    let res = sbox1.call::<i32>("TestMalloc", size).unwrap_err();
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
    )
    .unwrap();
    let mut sbox2 = uninit.evolve().unwrap();

    let res = sbox2.call::<i32>(
        "CallMalloc", // uses the rust allocator to allocate a vector on heap
        size_to_allocate as i32,
    );
    println!("{:?}", res);
    assert!(matches!(
        res.unwrap_err(),
        // OOM memory errors in rust allocator are panics. Our panic handler returns ErrorCode::UnknownError on panic
        HyperlightError::GuestAborted(code, msg) if code == ErrorCode::UnknownError as u8 && msg.contains("memory allocation of ")
    ));
}

#[test]
fn guest_panic_no_alloc() {
    let heap_size = 0x4000;

    let mut cfg = SandboxConfiguration::default();
    cfg.set_heap_size(heap_size);
    let uninit = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(cfg),
    )
    .unwrap();
    let mut sbox: MultiUseSandbox = uninit.evolve().unwrap();

    let res = sbox
        .call::<i32>(
            "ExhaustHeap", // uses the rust allocator to allocate small blocks on the heap until OOM
            (),
        )
        .unwrap_err();

    if let HyperlightError::StackOverflow() = res {
        panic!("panic on OOM caused stack overflow, this implies allocation in panic handler");
    }

    assert!(matches!(
        res,
        HyperlightError::GuestAborted(code, msg) if code == ErrorCode::UnknownError as u8 && msg.contains("memory allocation of ") && msg.contains("bytes failed")
    ));
}

// Tests libc alloca
#[test]
fn dynamic_stack_allocate_c_guest() {
    let path = c_simple_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None);
    let mut sbox1: MultiUseSandbox = uninit.unwrap().evolve().unwrap();

    let res: i32 = sbox1.call("StackAllocate", 100_i32).unwrap();
    assert_eq!(res, 100);

    let res = sbox1
        .call::<i32>("StackAllocate", 0x800_0000_i32)
        .unwrap_err();
    assert!(matches!(res, HyperlightError::StackOverflow()));
}

// checks that a small buffer on stack works
#[test]
fn static_stack_allocate() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let res: i32 = sbox1.call("SmallVar", ()).unwrap();
    assert_eq!(res, 1024);
}

// checks that a huge buffer on stack fails with stackoverflow
#[test]
fn static_stack_allocate_overflow() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();
    let res = sbox1.call::<i32>("LargeVar", ()).unwrap_err();
    assert!(matches!(res, HyperlightError::StackOverflow()));
}

// checks that a recursive function with stack allocation works, (that chkstk can be called without overflowing)
#[test]
fn recursive_stack_allocate() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let iterations = 1_i32;

    sbox1.call::<i32>("StackOverflow", iterations).unwrap();
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

        let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();
        let result = sbox1.call::<String>("test_write_raw_ptr", offset);
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
    let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();

    let result = sbox1.call::<()>("InfiniteRecursion", ()).unwrap_err();
    assert!(matches!(result, HyperlightError::StackOverflow()));
}

#[test]
fn execute_on_stack() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let result = sbox1.call::<String>("ExecuteOnStack", ()).unwrap_err();

    let err = result.to_string();
    assert!(
        // exception that indicates a page fault
        err.contains("PageFault")
    );
}

#[test]
#[ignore] // ran from Justfile because requires feature "executable_heap"
fn execute_on_heap() {
    let mut sbox1 = new_uninit_rust().unwrap().evolve().unwrap();
    let result = sbox1.call::<String>("ExecuteOnHeap", ());

    println!("{:#?}", result);
    #[cfg(feature = "executable_heap")]
    assert!(result.is_ok());

    #[cfg(not(feature = "executable_heap"))]
    {
        assert!(result.is_err());
        let err = result.unwrap_err();

        assert!(err.to_string().contains("PageFault"));
    }
}

// checks that a recursive function with stack allocation eventually fails with stackoverflow
#[test]
fn recursive_stack_allocate_overflow() {
    let mut sbox1 = new_uninit().unwrap().evolve().unwrap();

    let iterations = 10_i32;

    let res = sbox1.call::<()>("StackOverflow", iterations).unwrap_err();
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
    // internal_dispatch_function does a log::trace! in debug mode, and we call it 6 times in `log_test_messages`
    let num_fixed_trace_log = if cfg!(debug_assertions) { 6 } else { 0 };

    let tests = vec![
        (LevelFilter::Trace, 5 + num_fixed_trace_log),
        (LevelFilter::Debug, 4),
        (LevelFilter::Info, 3),
        (LevelFilter::Warn, 2),
        (LevelFilter::Error, 1),
        (LevelFilter::Off, 0),
    ];

    // init
    SimpleLogger::initialize_test_logger();

    for test in tests {
        let (level, expected) = test;

        // Test setting max log level via method on uninit sandbox
        log_test_messages(Some(level));
        assert_eq!(expected, LOGGER.num_log_calls());

        // Set the log level via env var
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("RUST_LOG", format!("hyperlight_guest={}", level)) };
        log_test_messages(None);
        assert_eq!(expected, LOGGER.num_log_calls());

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("RUST_LOG", format!("hyperlight_host={}", level)) };
        log_test_messages(None);
        assert_eq!(expected, LOGGER.num_log_calls());

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("RUST_LOG", format!("{}", level)) };
        log_test_messages(None);
        assert_eq!(expected, LOGGER.num_log_calls());

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::remove_var("RUST_LOG") };
    }

    // Test that if no log level is set, the default is error
    log_test_messages(None);
    assert_eq!(1, LOGGER.num_log_calls());
}

fn log_test_messages(levelfilter: Option<log::LevelFilter>) {
    LOGGER.clear_log_calls();
    assert_eq!(0, LOGGER.num_log_calls());
    for level in log::LevelFilter::iter() {
        let mut sbox = new_uninit().unwrap();
        if let Some(levelfilter) = levelfilter {
            sbox.set_max_guest_log_level(levelfilter);
        }

        let mut sbox1 = sbox.evolve().unwrap();

        let message = format!("Hello from log_message level {}", level as i32);
        sbox1
            .call::<()>("LogMessage", (message.to_string(), level as i32))
            .unwrap();
    }
}

/// Tests whether host is able to return Bool as return type
/// or not
#[test]
fn test_if_guest_is_able_to_get_bool_return_values_from_host() {
    let mut sbox1 = new_uninit_c().unwrap();

    sbox1
        .register("HostBool", |a: i32, b: i32| a + b > 10)
        .unwrap();
    let mut sbox3 = sbox1.evolve().unwrap();

    for i in 1..10 {
        if i < 6 {
            let res = sbox3
                .call::<bool>("GuestRetrievesBoolValue", (i, i))
                .unwrap();
            println!("{:?}", res);
            assert!(!res);
        } else {
            let res = sbox3
                .call::<bool>("GuestRetrievesBoolValue", (i, i))
                .unwrap();
            println!("{:?}", res);
            assert!(res);
        }
    }
}

/// Tests whether host is able to return Float/f32 as return type
/// or not
/// Adding Ignore attribute, due known issues with float and double
/// calculations - see Github issue #179. Once it is fixed we can
/// remove ignore attribute
#[ignore]
#[test]
fn test_if_guest_is_able_to_get_float_return_values_from_host() {
    let mut sbox1 = new_uninit_c().unwrap();

    sbox1
        .register("HostAddFloat", |a: f32, b: f32| a + b)
        .unwrap();
    let mut sbox3 = sbox1.evolve().unwrap();
    let res = sbox3
        .call::<f32>("GuestRetrievesFloatValue", (1.34_f32, 1.34_f32))
        .unwrap();
    println!("{:?}", res);
    assert_eq!(res, 2.68_f32);
}

/// Tests whether host is able to return Double/f64 as return type
/// or not
/// Adding Ignore attribute, due known issues with float and double
/// calculations - see Github issue #179. Once it is fixed we can
/// remove ignore attribute
#[ignore]
#[test]
fn test_if_guest_is_able_to_get_double_return_values_from_host() {
    let mut sbox1 = new_uninit_c().unwrap();

    sbox1
        .register("HostAddDouble", |a: f64, b: f64| a + b)
        .unwrap();
    let mut sbox3 = sbox1.evolve().unwrap();
    let res = sbox3
        .call::<f64>("GuestRetrievesDoubleValue", (1.34_f64, 1.34_f64))
        .unwrap();
    println!("{:?}", res);
    assert_eq!(res, 2.68_f64);
}

/// Tests whether host is able to return String as return type
/// or not
#[test]
fn test_if_guest_is_able_to_get_string_return_values_from_host() {
    let mut sbox1 = new_uninit_c().unwrap();

    sbox1
        .register("HostAddStrings", |a: String| {
            a + ", string added by Host Function"
        })
        .unwrap();
    let mut sbox3 = sbox1.evolve().unwrap();
    let res = sbox3
        .call::<String>("GuestRetrievesStringValue", ())
        .unwrap();
    println!("{:?}", res);
    assert_eq!(
        res,
        "Guest Function, string added by Host Function".to_string()
    );
}

/// Test that monitors CPU time usage and can interrupt a guest based on CPU time limits
/// Uses a pool of 100 sandboxes, 100 threads, and 500 iterations per thread
/// Some sandboxes are expected to complete normally, some are expected to be killed
/// This test makes sure that a reused sandbox is not killed in the case where the previous
/// execution was killed due to CPU time limit but the invocation completed normally before the cancel was processed.
#[test]
fn test_cpu_time_interrupt() {
    use std::collections::VecDeque;
    use std::mem::MaybeUninit;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::channel;

    const POOL_SIZE: usize = 100;
    const NUM_THREADS: usize = 100;
    const ITERATIONS_PER_THREAD: usize = 500;

    // Create a pool of 100 sandboxes
    println!("Creating pool of {} sandboxes...", POOL_SIZE);
    let mut sandbox_pool: Vec<MultiUseSandbox> = Vec::with_capacity(POOL_SIZE);
    for i in 0..POOL_SIZE {
        let sandbox = new_uninit_rust().unwrap().evolve().unwrap();
        if (i + 1) % 10 == 0 {
            println!("Created {}/{} sandboxes", i + 1, POOL_SIZE);
        }
        sandbox_pool.push(sandbox);
    }

    // Wrap the pool in Arc<Mutex<VecDeque>> for thread-safe access
    let pool = Arc::new(Mutex::new(VecDeque::from(sandbox_pool)));

    // Counters for statistics
    let total_iterations = Arc::new(AtomicUsize::new(0));
    let killed_count = Arc::new(AtomicUsize::new(0));
    let completed_count = Arc::new(AtomicUsize::new(0));
    let errors_count = Arc::new(AtomicUsize::new(0));

    println!(
        "Starting {} threads with {} iterations each...",
        NUM_THREADS, ITERATIONS_PER_THREAD
    );

    // Spawn worker threads
    let mut thread_handles = vec![];
    for thread_id in 0..NUM_THREADS {
        let pool_clone = Arc::clone(&pool);
        let total_iterations_clone = Arc::clone(&total_iterations);
        let killed_count_clone = Arc::clone(&killed_count);
        let completed_count_clone = Arc::clone(&completed_count);
        let errors_count_clone = Arc::clone(&errors_count);

        let handle = thread::spawn(move || {
            for iteration in 0..ITERATIONS_PER_THREAD {
                // === START OF ITERATION ===
                // Get a fresh sandbox from the pool for this iteration
                let mut sandbox = {
                    let mut pool_guard = pool_clone.lock().unwrap();
                    // Wait if pool is empty (shouldn't happen with proper design)
                    while pool_guard.is_empty() {
                        drop(pool_guard);
                        thread::sleep(Duration::from_micros(100));
                        pool_guard = pool_clone.lock().unwrap();
                    }
                    pool_guard.pop_front().unwrap()
                };

                // Vary CPU time between 3ms and 7ms to ensure some get killed and some complete
                // The CPU limit is 5ms, so:
                // - 3-4ms should complete normally
                // - 6-7ms should be killed
                // - 5ms is borderline and could go either way
                let cpu_time_ms =
                    3 + (((thread_id * ITERATIONS_PER_THREAD + iteration) % 5) as u32);

                let interrupt_handle = sandbox.interrupt_handle();

                // Channel to send the thread ID
                let (tx, rx) = channel();

                // Flag to signal monitoring start
                let should_monitor = Arc::new(AtomicBool::new(false));
                let should_monitor_clone = should_monitor.clone();

                // Flag to signal monitoring stop (when guest execution completes)
                let stop_monitoring = Arc::new(AtomicBool::new(false));
                let stop_monitoring_clone = stop_monitoring.clone();

                // Flag to track if we actually sent a kill signal
                let was_killed = Arc::new(AtomicBool::new(false));
                let was_killed_clone = was_killed.clone();

                // Spawn CPU time monitor thread
                let monitor_thread = thread::spawn(move || {
                    let main_thread_id = match rx.recv() {
                        Ok(tid) => tid,
                        Err(_) => return,
                    };

                    while !should_monitor_clone.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_micros(50));
                    }

                    #[cfg(target_os = "linux")]
                    unsafe {
                        let mut clock_id: libc::clockid_t = 0;
                        if libc::pthread_getcpuclockid(main_thread_id, &mut clock_id) != 0 {
                            return;
                        }

                        let cpu_limit_ns = 5_000_000; // 5ms CPU time limit
                        let mut start_time = MaybeUninit::<libc::timespec>::uninit();

                        if libc::clock_gettime(clock_id, start_time.as_mut_ptr()) != 0 {
                            return;
                        }
                        let start_time = start_time.assume_init();

                        loop {
                            // Check if we should stop monitoring (guest completed)
                            if stop_monitoring_clone.load(Ordering::Acquire) {
                                break;
                            }

                            let mut current_time = MaybeUninit::<libc::timespec>::uninit();
                            if libc::clock_gettime(clock_id, current_time.as_mut_ptr()) != 0 {
                                break;
                            }
                            let current_time = current_time.assume_init();

                            let elapsed_ns = (current_time.tv_sec - start_time.tv_sec)
                                * 1_000_000_000
                                + (current_time.tv_nsec - start_time.tv_nsec);

                            if elapsed_ns > cpu_limit_ns {
                                // Double-check that monitoring should still continue before killing
                                // The guest might have completed between our last check and now
                                if stop_monitoring_clone.load(Ordering::Acquire) {
                                    break;
                                }

                                // Mark that we sent a kill signal BEFORE calling kill
                                // to avoid race conditions
                                was_killed_clone.store(true, Ordering::Release);
                                interrupt_handle.kill();
                                break;
                            }

                            thread::sleep(Duration::from_micros(50));
                        }
                    }

                    #[cfg(target_os = "windows")]
                    unsafe {
                        use std::ffi::c_void;

                        // On Windows, we use GetThreadTimes to get CPU time
                        // main_thread_id is a HANDLE on Windows
                        let thread_handle = main_thread_id as *mut c_void;

                        let cpu_limit_ns: i64 = 5_000_000; // 5ms CPU time limit (in nanoseconds)

                        let mut creation_time =
                            MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
                        let mut exit_time =
                            MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
                        let mut kernel_time_start =
                            MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
                        let mut user_time_start =
                            MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();

                        // Get initial CPU times
                        if windows_sys::Win32::System::Threading::GetThreadTimes(
                            thread_handle,
                            creation_time.as_mut_ptr(),
                            exit_time.as_mut_ptr(),
                            kernel_time_start.as_mut_ptr(),
                            user_time_start.as_mut_ptr(),
                        ) == 0
                        {
                            return;
                        }

                        let kernel_time_start = kernel_time_start.assume_init();
                        let user_time_start = user_time_start.assume_init();

                        // Convert FILETIME to u64 (100-nanosecond intervals)
                        let start_cpu_time = ((kernel_time_start.dwHighDateTime as u64) << 32
                            | kernel_time_start.dwLowDateTime as u64)
                            + ((user_time_start.dwHighDateTime as u64) << 32
                                | user_time_start.dwLowDateTime as u64);

                        loop {
                            // Check if we should stop monitoring (guest completed)
                            if stop_monitoring_clone.load(Ordering::Acquire) {
                                break;
                            }

                            let mut kernel_time_current =
                                MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();
                            let mut user_time_current =
                                MaybeUninit::<windows_sys::Win32::Foundation::FILETIME>::uninit();

                            if windows_sys::Win32::System::Threading::GetThreadTimes(
                                thread_handle,
                                creation_time.as_mut_ptr(),
                                exit_time.as_mut_ptr(),
                                kernel_time_current.as_mut_ptr(),
                                user_time_current.as_mut_ptr(),
                            ) == 0
                            {
                                break;
                            }

                            let kernel_time_current = kernel_time_current.assume_init();
                            let user_time_current = user_time_current.assume_init();

                            // Convert FILETIME to u64
                            let current_cpu_time = ((kernel_time_current.dwHighDateTime as u64)
                                << 32
                                | kernel_time_current.dwLowDateTime as u64)
                                + ((user_time_current.dwHighDateTime as u64) << 32
                                    | user_time_current.dwLowDateTime as u64);

                            // FILETIME is in 100-nanosecond intervals, convert to nanoseconds
                            let elapsed_ns = ((current_cpu_time - start_cpu_time) * 100) as i64;

                            if elapsed_ns > cpu_limit_ns {
                                // Double-check that monitoring should still continue before killing
                                // The guest might have completed between our last check and now
                                if stop_monitoring_clone.load(Ordering::Acquire) {
                                    break;
                                }

                                // Mark that we sent a kill signal BEFORE calling kill
                                // to avoid race conditions
                                println!("Thread {} iteration {}: CPU time exceeded, sending kill signal", thread_id, iteration);
                                was_killed_clone.store(true, Ordering::Release);
                                interrupt_handle.kill();
                                break;
                            }

                            thread::sleep(Duration::from_micros(50));
                        }
                    }
                });

                // Send thread ID and start monitoring
                #[cfg(target_os = "linux")]
                unsafe {
                    let thread_id = libc::pthread_self();
                    let _ = tx.send(thread_id);
                }

                #[cfg(target_os = "windows")]
                unsafe {
                    // On Windows, get the current thread's pseudo-handle
                    let thread_handle = windows_sys::Win32::System::Threading::GetCurrentThread();
                    let _ = tx.send(thread_handle as usize);
                }

                should_monitor.store(true, Ordering::Release);

                // Call the guest function
                let result = sandbox.call::<u64>("SpinForMs", cpu_time_ms);

                // Signal the monitor to stop
                stop_monitoring.store(true, Ordering::Release);

                // Wait for monitor thread to complete to ensure was_killed flag is set
                let _ = monitor_thread.join();

                // NOW check if we sent a kill signal (after monitor thread has completed)
                let kill_was_sent = was_killed.load(Ordering::Acquire);

                // Process the result and validate correctness
                match result {
                    Err(HyperlightError::ExecutionCanceledByHost()) => {
                        // We received a cancellation error
                        if !kill_was_sent {
                            // ERROR: We got a cancellation but never sent a kill!
                            panic!(
                                "Thread {} iteration {}: Got ExecutionCanceledByHost but no kill signal was sent!",
                                thread_id, iteration
                            );
                        }
                        // This is correct - we sent kill and got the error
                        killed_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(_) => {
                        // Execution completed normally
                        // This is OK whether or not we sent a kill - the guest might have
                        // finished just before the kill signal arrived
                        completed_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        // Unexpected error
                        eprintln!(
                            "Thread {} iteration {}: Unexpected error: {:?}, kill_sent: {}",
                            thread_id, iteration, e, kill_was_sent
                        );
                        errors_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }

                total_iterations_clone.fetch_add(1, Ordering::Relaxed);

                // Progress reporting
                let current_total = total_iterations_clone.load(Ordering::Relaxed);
                if current_total % 500 == 0 {
                    println!(
                        "Progress: {}/{} iterations completed",
                        current_total,
                        NUM_THREADS * ITERATIONS_PER_THREAD
                    );
                }

                // === END OF ITERATION ===
                // Return sandbox to pool for reuse by other threads/iterations
                {
                    let mut pool_guard = pool_clone.lock().unwrap();
                    pool_guard.push_back(sandbox);
                }
            }
        });

        thread_handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in thread_handles {
        handle.join().unwrap();
    }

    // Print statistics
    let total = total_iterations.load(Ordering::Relaxed);
    let killed = killed_count.load(Ordering::Relaxed);
    let completed = completed_count.load(Ordering::Relaxed);
    let errors = errors_count.load(Ordering::Relaxed);

    println!("\n=== Test Statistics ===");
    println!("Total iterations: {}", total);
    println!("Killed (CPU limit exceeded): {}", killed);
    println!("Completed normally: {}", completed);
    println!("Errors: {}", errors);
    println!("Kill rate: {:.1}%", (killed as f64 / total as f64) * 100.0);

    // Verify we had both kills and completions
    assert!(
        killed > 0,
        "Expected some executions to be killed, but none were"
    );
    assert!(
        completed > 0,
        "Expected some executions to complete, but none did"
    );
    assert_eq!(errors, 0, "Expected no errors, but got {}", errors);
    assert_eq!(
        total,
        NUM_THREADS * ITERATIONS_PER_THREAD,
        "Not all iterations completed"
    );
}
