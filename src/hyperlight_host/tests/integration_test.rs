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

    usbox.register("Spin", spin).unwrap();

    let mut sandbox: MultiUseSandbox = usbox.evolve().unwrap();
    let snapshot = sandbox.snapshot().unwrap();
    let interrupt_handle = sandbox.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    let thread = thread::spawn({
        move || {
            barrier.wait(); // wait for the host function to be entered
            interrupt_handle.kill(); // send kill once host call is in progress
        }
    });

    let result = sandbox.call::<i32>("CallHostSpin", ()).unwrap_err();
    assert!(matches!(result, HyperlightError::ExecutionCanceledByHost()));
    assert!(sandbox.poisoned());

    // Restore from snapshot to clear poison
    sandbox.restore(snapshot.clone()).unwrap();
    assert!(!sandbox.poisoned());

    thread.join().unwrap();
}

/// Makes sure a running guest call can be interrupted by the host
#[test]
fn interrupt_in_progress_guest_call() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let snapshot = sbox1.snapshot().unwrap();
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
    assert!(sbox1.poisoned());

    // Restore from snapshot to clear poison
    sbox1.restore(snapshot.clone()).unwrap();
    assert!(!sbox1.poisoned());

    barrier.wait();
    // Make sure we can still call guest functions after the VM was interrupted
    sbox1.call::<String>("Echo", "hello".to_string()).unwrap();

    // drop vm to make sure other thread can detect it
    drop(sbox1);
    barrier.wait();
    thread.join().expect("Thread should finish");
}

/// Makes sure interrupting a vm before the guest call has started does not prevent the guest call from running
#[test]
fn interrupt_guest_call_in_advance() {
    let mut sbox1: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();
    let interrupt_handle = sbox1.interrupt_handle();
    assert!(!interrupt_handle.dropped()); // not yet dropped

    // kill vm before the guest call has started
    let thread = thread::spawn(move || {
        assert!(!interrupt_handle.kill()); // should return false since vcpu is not running yet
        barrier2.wait();
        barrier2.wait(); // wait here until main thread has dropped the sandbox
        assert!(interrupt_handle.dropped());
    });

    barrier.wait(); // wait until `kill()` is called before starting the guest call
    match sbox1.call::<String>("Echo", "hello".to_string()) {
        Ok(_) => {}
        Err(HyperlightError::ExecutionCanceledByHost()) => {
            panic!("Unexpected Cancellation Error");
        }
        Err(_) => {}
    }

    // Make sure we can still call guest functions after the VM was interrupted early
    // i.e. make sure we dont kill the next iteration.
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
    let snapshot2 = sbox2.snapshot().unwrap();
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
            // Only allow successful calls or interrupted.
            // The call can be successful in case the call is finished before kill() is called.
            Ok(_) | Err(HyperlightError::ExecutionCanceledByHost()) => {}
            _ => panic!("Unexpected return"),
        };
        if sbox2.poisoned() {
            sbox2.restore(snapshot2.clone()).unwrap();
        }
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
    let snapshot2 = sbox2.snapshot().unwrap();
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
            // Only allow successful calls or interrupted.
            // The call can be successful in case the call is finished before kill() is called.
            Ok(_) | Err(HyperlightError::ExecutionCanceledByHost()) => {}
            _ => panic!("Unexpected return"),
        };
        if sbox2.poisoned() {
            sbox2.restore(snapshot2.clone()).unwrap();
        }
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
    let snapshot1 = sbox1.snapshot().unwrap();
    let mut sbox2: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();

    let interrupt_handle = sbox1.interrupt_handle();
    let interrupt_handle2 = sbox2.interrupt_handle();

    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = barrier.clone();

    let thread = thread::spawn(move || {
        barrier2.wait();
        let res = sbox1.call::<i32>("Spin", ()).unwrap_err();
        assert!(matches!(res, HyperlightError::ExecutionCanceledByHost()));
        assert!(sbox1.poisoned());
        sbox1.restore(snapshot1.clone()).unwrap();
        assert!(!sbox1.poisoned());
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
/// The ABA-problem is solved by clearing CANCEL bit at the start of each VirtualCPU::run() call.
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

    let snapshot1 = sbox1.snapshot().unwrap();
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
        assert!(sbox1.poisoned());
        // immediately reenter another guest function call after having being cancelled,
        // so that the vcpu is running again before the interruptor-thread has a chance to see that the vcpu is not running
        sbox1.restore(snapshot1.clone()).unwrap();
        assert!(!sbox1.poisoned());
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

/// Test that executing an OUT instruction with an invalid port causes an error and poisons the sandbox.
#[test]
fn guest_outb_with_invalid_port_poisons_sandbox() {
    let mut sbox = new_uninit_rust().unwrap().evolve().unwrap();

    // Port 0x1234 is not a valid hyperlight port
    let res = sbox.call::<()>("OutbWithPort", (0x1234_u32, 0_u32));
    assert!(res.is_err(), "Expected error from invalid OUT port");

    // The sandbox should be poisoned because the guest didn't complete normally
    assert!(
        sbox.poisoned(),
        "Sandbox should be poisoned after invalid OUT"
    );
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
    // The magic numbers below represent the number of fixed log messages that are emitted as
    // follows:
    //  - internal_dispatch_function does a log::trace! in debug mode
    //  - logs from trace level tracing spans created as logs because of the tracing `log` feature
    //    - 6 from evolve call (hyperlight_main + halt)
    //    - 16 from guest call (internal_dispatch_function + others)
    // and are multiplied because we make 6 calls to `log_test_messages`
    // NOTE: These numbers need to be updated if log messages or spans are added/removed
    let num_fixed_trace_log = if cfg!(debug_assertions) {
        (1 + 22) * 6
    } else {
        22 * 6
    };

    // Calculate fixed info logs
    // - 10 logs per iteration from infrastructure at Info level (halt, dispatch_function, call_guest_function)
    //   (halt x 3 calls + dispatch x 1 + call_guest x 1) * 2 logs (Enter/Exit) = 10 logs
    // - 6 iterations
    let num_fixed_info_log = 10 * 6;

    let tests = vec![
        (LevelFilter::Trace, 5 + num_fixed_trace_log),
        (LevelFilter::Debug, 4 + num_fixed_info_log),
        (LevelFilter::Info, 3 + num_fixed_info_log),
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
/// Test that validates interrupt behavior with random kill timing under concurrent load
/// Uses a pool of 100 sandboxes, 100 threads, and 500 iterations per thread.
/// Randomly decides to kill some calls at random times during execution.
/// Validates that:
/// - Calls we chose to kill can end in any state (including some cancelled)
/// - Calls we did NOT choose to kill NEVER return ExecutionCanceledByHost
/// - We get a mix of killed and non-killed outcomes (not 100% or 0%)
#[test]
fn interrupt_random_kill_stress_test() {
    // Wrapper to hold a sandbox and its snapshot together
    struct SandboxWithSnapshot {
        sandbox: MultiUseSandbox,
        snapshot: Arc<Snapshot>,
    }

    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use hyperlight_host::sandbox::snapshot::Snapshot;
    use log::{error, trace};

    const POOL_SIZE: usize = 100;
    const NUM_THREADS: usize = 100;
    const ITERATIONS_PER_THREAD: usize = 500;
    const KILL_PROBABILITY: f64 = 0.5; // 50% chance to attempt kill
    const GUEST_CALL_DURATION_MS: u32 = 10; // SpinForMs duration

    // Create a pool of 50 sandboxes
    println!("Creating pool of {} sandboxes...", POOL_SIZE);
    let mut sandbox_pool: Vec<SandboxWithSnapshot> = Vec::with_capacity(POOL_SIZE);
    for i in 0..POOL_SIZE {
        let mut sandbox = new_uninit_rust().unwrap().evolve().unwrap();
        // Create a snapshot for this sandbox
        let snapshot = sandbox.snapshot().unwrap();
        if (i + 1) % 10 == 0 {
            println!("Created {}/{} sandboxes", i + 1, POOL_SIZE);
        }
        sandbox_pool.push(SandboxWithSnapshot { sandbox, snapshot });
    }

    // Wrap the pool in Arc<Mutex<VecDeque>> for thread-safe access
    let pool = Arc::new(Mutex::new(VecDeque::from(sandbox_pool)));

    // Counters for statistics
    let total_iterations = Arc::new(AtomicUsize::new(0));
    let kill_attempted_count = Arc::new(AtomicUsize::new(0)); // We chose to kill
    let actually_killed_count = Arc::new(AtomicUsize::new(0)); // Got ExecutionCanceledByHost
    let not_killed_completed_ok = Arc::new(AtomicUsize::new(0));
    let not_killed_error = Arc::new(AtomicUsize::new(0)); // Non-cancelled errors
    let killed_but_completed_ok = Arc::new(AtomicUsize::new(0));
    let killed_but_error = Arc::new(AtomicUsize::new(0)); // Non-cancelled errors
    let unexpected_cancelled = Arc::new(AtomicUsize::new(0)); // CRITICAL: non-killed calls that got cancelled
    let sandbox_replaced_count = Arc::new(AtomicUsize::new(0)); // Sandboxes replaced due to restore failure

    println!(
        "Starting {} threads with {} iterations each...",
        NUM_THREADS, ITERATIONS_PER_THREAD
    );

    // Spawn worker threads
    let mut thread_handles = vec![];
    for thread_id in 0..NUM_THREADS {
        let pool_clone = Arc::clone(&pool);
        let total_iterations_clone = Arc::clone(&total_iterations);
        let kill_attempted_count_clone = Arc::clone(&kill_attempted_count);
        let actually_killed_count_clone = Arc::clone(&actually_killed_count);
        let not_killed_completed_ok_clone = Arc::clone(&not_killed_completed_ok);
        let not_killed_error_clone = Arc::clone(&not_killed_error);
        let killed_but_completed_ok_clone = Arc::clone(&killed_but_completed_ok);
        let killed_but_error_clone = Arc::clone(&killed_but_error);
        let unexpected_cancelled_clone = Arc::clone(&unexpected_cancelled);
        let sandbox_replaced_count_clone = Arc::clone(&sandbox_replaced_count);

        let handle = thread::spawn(move || {
            // Use thread_id as seed for reproducible randomness per thread
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hash};

            let mut hasher = RandomState::new().build_hasher();
            thread_id.hash(&mut hasher);
            let mut rng_state = RandomState::new().hash_one(thread_id);

            // Simple random number generator for reproducible randomness
            let mut next_random = || -> u64 {
                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                rng_state
            };

            for iteration in 0..ITERATIONS_PER_THREAD {
                // === START OF ITERATION ===
                // Get a sandbox from the pool for this iteration
                let sandbox_with_snapshot = loop {
                    let mut pool_guard = pool_clone.lock().unwrap();
                    if let Some(sb) = pool_guard.pop_front() {
                        break sb;
                    }
                    // Pool is empty, release lock and wait
                    drop(pool_guard);
                    trace!(
                        "[THREAD-{}] Iteration {}: Pool empty, waiting for sandbox...",
                        thread_id, iteration
                    );
                    thread::sleep(Duration::from_millis(1));
                };

                // Use a guard struct to ensure sandbox is always returned to pool
                struct SandboxGuard<'a> {
                    sandbox_with_snapshot: Option<SandboxWithSnapshot>,
                    pool: &'a Arc<Mutex<VecDeque<SandboxWithSnapshot>>>,
                }

                impl<'a> Drop for SandboxGuard<'a> {
                    fn drop(&mut self) {
                        if let Some(sb) = self.sandbox_with_snapshot.take() {
                            let mut pool_guard = self.pool.lock().unwrap();
                            pool_guard.push_back(sb);
                            trace!(
                                "[GUARD] Returned sandbox to pool, pool size now: {}",
                                pool_guard.len()
                            );
                        }
                    }
                }

                let mut guard = SandboxGuard {
                    sandbox_with_snapshot: Some(sandbox_with_snapshot),
                    pool: &pool_clone,
                };

                // Decide randomly: should we attempt to kill this call?
                let should_kill = (next_random() as f64 / u64::MAX as f64) < KILL_PROBABILITY;

                if should_kill {
                    kill_attempted_count_clone.fetch_add(1, Ordering::Relaxed);
                }

                let sandbox_wrapper = guard.sandbox_with_snapshot.as_mut().unwrap();
                let sandbox = &mut sandbox_wrapper.sandbox;
                let interrupt_handle = sandbox.interrupt_handle();

                // If we decided to kill, spawn a thread that will kill at a random time
                // Use a barrier to ensure the killer thread waits until we're about to call the guest
                let killer_thread = if should_kill {
                    use std::sync::{Arc, Barrier};

                    let barrier = Arc::new(Barrier::new(2));
                    let barrier_clone = Arc::clone(&barrier);

                    // Generate random delay here before moving into thread
                    let kill_delay_ms = next_random() % 16;
                    let thread_id_clone = thread_id;
                    let iteration_clone = iteration;
                    let handle = thread::spawn(move || {
                        trace!(
                            "[KILLER-{}-{}] Waiting at barrier...",
                            thread_id_clone, iteration_clone
                        );
                        // Wait at the barrier until the main thread is ready to call the guest
                        barrier_clone.wait();
                        trace!(
                            "[KILLER-{}-{}] Passed barrier, sleeping for {}ms...",
                            thread_id_clone, iteration_clone, kill_delay_ms
                        );
                        // Random delay between 0 and 15ms (guest runs for ~10ms)
                        thread::sleep(Duration::from_millis(kill_delay_ms));
                        trace!(
                            "[KILLER-{}-{}] Calling kill()...",
                            thread_id_clone, iteration_clone
                        );
                        interrupt_handle.kill();
                        trace!(
                            "[KILLER-{}-{}] kill() returned, exiting thread",
                            thread_id_clone, iteration_clone
                        );
                    });
                    Some((handle, barrier))
                } else {
                    None
                };

                // Call the guest function
                trace!(
                    "[THREAD-{}] Iteration {}: Calling guest function (should_kill={})...",
                    thread_id, iteration, should_kill
                );

                // Release the barrier just before calling the guest function
                if let Some((_, ref barrier)) = killer_thread {
                    trace!(
                        "[THREAD-{}] Iteration {}: Main thread waiting at barrier...",
                        thread_id, iteration
                    );
                    barrier.wait();
                    trace!(
                        "[THREAD-{}] Iteration {}: Main thread passed barrier, calling guest...",
                        thread_id, iteration
                    );
                }

                let result = sandbox.call::<u64>("SpinForMs", GUEST_CALL_DURATION_MS);
                trace!(
                    "[THREAD-{}] Iteration {}: Guest call returned: {:?}",
                    thread_id,
                    iteration,
                    result
                        .as_ref()
                        .map(|_| "Ok")
                        .map_err(|e| format!("{:?}", e))
                );

                // Wait for killer thread to finish if it was spawned
                if let Some((kt, _)) = killer_thread {
                    trace!(
                        "[THREAD-{}] Iteration {}: Waiting for killer thread to join...",
                        thread_id, iteration
                    );
                    let _ = kt.join();
                }

                // Process the result based on whether we attempted to kill
                match result {
                    Err(HyperlightError::ExecutionCanceledByHost()) => {
                        // Restore the sandbox from the snapshot
                        trace!(
                            "[THREAD-{}] Iteration {}: Restoring sandbox from snapshot after ExecutionCanceledByHost...",
                            thread_id, iteration
                        );
                        let sandbox_wrapper = guard.sandbox_with_snapshot.as_mut().unwrap();

                        // Make sure the sandbox is poisoned
                        assert!(sandbox_wrapper.sandbox.poisoned());

                        // Try to restore the snapshot
                        if let Err(e) = sandbox_wrapper
                            .sandbox
                            .restore(sandbox_wrapper.snapshot.clone())
                        {
                            error!(
                                "CRITICAL: Thread {} iteration {}: Failed to restore snapshot: {:?}",
                                thread_id, iteration, e
                            );
                            trace!(
                                "[THREAD-{}] Iteration {}: Creating new sandbox to replace failed one...",
                                thread_id, iteration
                            );

                            // Create a new sandbox with snapshot
                            match new_uninit_rust().and_then(|uninit| uninit.evolve()) {
                                Ok(mut new_sandbox) => {
                                    match new_sandbox.snapshot() {
                                        Ok(new_snapshot) => {
                                            // Replace the failed sandbox with the new one
                                            sandbox_wrapper.sandbox = new_sandbox;
                                            sandbox_wrapper.snapshot = new_snapshot;
                                            sandbox_replaced_count_clone
                                                .fetch_add(1, Ordering::Relaxed);
                                            trace!(
                                                "[THREAD-{}] Iteration {}: Successfully replaced sandbox",
                                                thread_id, iteration
                                            );
                                        }
                                        Err(snapshot_err) => {
                                            error!(
                                                "CRITICAL: Thread {} iteration {}: Failed to create snapshot for new sandbox: {:?}",
                                                thread_id, iteration, snapshot_err
                                            );
                                            // Still use the new sandbox even without snapshot
                                            sandbox_wrapper.sandbox = new_sandbox;
                                            sandbox_replaced_count_clone
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                                Err(create_err) => {
                                    error!(
                                        "CRITICAL: Thread {} iteration {}: Failed to create new sandbox: {:?}",
                                        thread_id, iteration, create_err
                                    );
                                    // Continue with the broken sandbox - it will be removed from pool eventually
                                }
                            }
                        }

                        if should_kill {
                            // We attempted to kill and it was cancelled - SUCCESS
                            actually_killed_count_clone.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // We did NOT attempt to kill but got cancelled - CRITICAL FAILURE
                            unexpected_cancelled_clone.fetch_add(1, Ordering::Relaxed);
                            error!(
                                "CRITICAL: Thread {} iteration {}: Got ExecutionCanceledByHost but did NOT attempt kill!",
                                thread_id, iteration
                            );
                        }
                    }
                    Ok(_) => {
                        if should_kill {
                            // We attempted to kill but it completed OK - acceptable race condition
                            killed_but_completed_ok_clone.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // We did NOT attempt to kill and it completed OK - EXPECTED
                            not_killed_completed_ok_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_other_error) => {
                        // Log the other error so we can see what it is
                        error!(
                            "Thread {} iteration {}: Got non-cancellation error: {:?}",
                            thread_id, iteration, _other_error
                        );
                        if should_kill {
                            // We attempted to kill and got some other error - acceptable
                            killed_but_error_clone.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // We did NOT attempt to kill and got some other error - acceptable
                            not_killed_error_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                total_iterations_clone.fetch_add(1, Ordering::Relaxed);

                // Progress reporting
                let current_total = total_iterations_clone.load(Ordering::Relaxed);
                if current_total.is_multiple_of(5000) {
                    println!(
                        "Progress: {}/{} iterations completed",
                        current_total,
                        NUM_THREADS * ITERATIONS_PER_THREAD
                    );
                }

                // === END OF ITERATION ===
                // SandboxGuard will automatically return sandbox to pool when it goes out of scope
            }

            trace!(
                "[THREAD-{}] Completed all {} iterations!",
                thread_id, ITERATIONS_PER_THREAD
            );
        });

        thread_handles.push(handle);
    }

    trace!(
        "All {} worker threads spawned, waiting for completion...",
        NUM_THREADS
    );

    // Wait for all threads to complete
    for (idx, handle) in thread_handles.into_iter().enumerate() {
        trace!("Waiting for thread {} to join...", idx);
        handle.join().unwrap();
        trace!("Thread {} joined successfully", idx);
    }

    trace!("All threads joined successfully!");

    // Collect final statistics
    let total = total_iterations.load(Ordering::Relaxed);
    let kill_attempted = kill_attempted_count.load(Ordering::Relaxed);
    let actually_killed = actually_killed_count.load(Ordering::Relaxed);
    let not_killed_ok = not_killed_completed_ok.load(Ordering::Relaxed);
    let not_killed_err = not_killed_error.load(Ordering::Relaxed);
    let killed_but_ok = killed_but_completed_ok.load(Ordering::Relaxed);
    let killed_but_err = killed_but_error.load(Ordering::Relaxed);
    let unexpected_cancel = unexpected_cancelled.load(Ordering::Relaxed);
    let sandbox_replaced = sandbox_replaced_count.load(Ordering::Relaxed);

    let no_kill_attempted = total - kill_attempted;

    // Print detailed statistics
    println!("\n=== Interrupt Random Kill Stress Test Statistics ===");
    println!("Total iterations: {}", total);
    println!();
    println!(
        "Kill Attempts: {} ({:.1}%)",
        kill_attempted,
        (kill_attempted as f64 / total as f64) * 100.0
    );
    println!(
        "  - Actually killed (ExecutionCanceledByHost): {}",
        actually_killed
    );
    println!("  - Completed OK despite kill attempt: {}", killed_but_ok);
    println!(
        "  - Error (non-cancelled) despite kill attempt: {}",
        killed_but_err
    );
    if kill_attempted > 0 {
        println!(
            "  - Kill success rate: {:.1}%",
            (actually_killed as f64 / kill_attempted as f64) * 100.0
        );
    }
    println!();
    println!(
        "No Kill Attempts: {} ({:.1}%)",
        no_kill_attempted,
        (no_kill_attempted as f64 / total as f64) * 100.0
    );
    println!("  - Completed OK: {}", not_killed_ok);
    println!("  - Error (non-cancelled): {}", not_killed_err);
    println!(
        "  - Cancelled (SHOULD BE 0): {} {}",
        unexpected_cancel,
        if unexpected_cancel == 0 {
            "✅"
        } else {
            "❌ FAILURE"
        }
    );
    println!();
    println!("Sandbox Management:");
    println!(
        "  - Sandboxes replaced due to restore failure: {}",
        sandbox_replaced
    );

    // CRITICAL VALIDATIONS
    assert_eq!(
        unexpected_cancel, 0,
        "FAILURE: {} non-killed calls returned ExecutionCanceledByHost! This indicates false kills.",
        unexpected_cancel
    );

    assert!(
        actually_killed > 0,
        "FAILURE: No calls were actually killed despite {} kill attempts!",
        kill_attempted
    );

    assert!(
        kill_attempted > 0,
        "FAILURE: No kill attempts were made (expected ~50% of {} iterations)!",
        total
    );

    assert!(
        kill_attempted < total,
        "FAILURE: All {} iterations were kill attempts (expected ~50%)!",
        total
    );

    // Verify total accounting
    assert_eq!(
        total,
        actually_killed
            + not_killed_ok
            + not_killed_err
            + killed_but_ok
            + killed_but_err
            + unexpected_cancel,
        "Iteration accounting mismatch!"
    );

    assert_eq!(
        total,
        NUM_THREADS * ITERATIONS_PER_THREAD,
        "Not all iterations completed"
    );

    println!("\n✅ All validations passed!");
}

/// Ensures that `kill()` reliably interrupts a running guest
///
/// The test works by:
/// 1. Guest calls a host function which waits on a barrier, ensuring the guest is "in-progress" and that `kill()` is not called prematurely to be ignored.
/// 2. Once the guest has passed that host function barrier, the host calls `kill()`. The `kill()` could be delivered at any time after this point, for example while guest is still in the host func, or returning into guest vm.
/// 3. The guest enters an infinite loop, so `kill()` is the only way to stop it.
///
/// This is repeated across multiple threads and iterations to stress test the cancellation mechanism.
///
/// **Failure Condition:** If this test hangs, it means `kill()` failed to stop the guest, leaving it spinning forever.
#[test]
fn interrupt_infinite_loop_stress_test() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NUM_THREADS: usize = 50;
    const ITERATIONS_PER_THREAD: usize = 500;

    let mut handles = vec![];

    for i in 0..NUM_THREADS {
        handles.push(thread::spawn(move || {
            // Create a barrier for 2 threads:
            // 1. The guest (executing a host function)
            // 2. The killer thread
            let barrier = Arc::new(Barrier::new(2));
            let barrier_for_host = barrier.clone();

            let mut uninit = new_uninit_rust().unwrap();

            // Register a host function that waits on the barrier
            uninit
                .register("WaitForKill", move || {
                    barrier_for_host.wait();
                    Ok(())
                })
                .unwrap();

            let mut sandbox = uninit.evolve().unwrap();
            // Take a snapshot to restore after each kill
            let snapshot = sandbox.snapshot().unwrap();

            for j in 0..ITERATIONS_PER_THREAD {
                let barrier_for_killer = barrier.clone();
                let interrupt_handle = sandbox.interrupt_handle();

                // Spawn the killer thread
                let killer_thread = std::thread::spawn(move || {
                    // Wait for the guest to call WaitForKill
                    barrier_for_killer.wait();

                    // The guest is now waiting on the barrier (or just finished waiting).
                    // We kill it immediately.
                    interrupt_handle.kill();
                });

                // Call the guest function "CallHostThenSpin" which calls "WaitForKill" once then spins
                // NOTE: If this test hangs, it means the guest was not successfully killed and is spinning forever.
                // This indicates a bug in the cancellation mechanism.
                let res = sandbox.call::<()>("CallHostThenSpin", "WaitForKill".to_string());

                // Wait for killer thread to finish
                killer_thread.join().unwrap();

                // We expect the execution to be canceled
                match res {
                    Err(HyperlightError::ExecutionCanceledByHost()) => {
                        // Success!
                    }
                    Ok(_) => {
                        panic!(
                            "Thread {} Iteration {}: Guest finished successfully but should have been killed!",
                            i, j
                        );
                    }
                    Err(e) => {
                        panic!(
                            "Thread {} Iteration {}: Guest failed with unexpected error: {:?}",
                            i, j, e
                        );
                    }
                }

                // Restore the sandbox for the next iteration
                sandbox.restore(snapshot.clone()).unwrap();
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// Validates that kill delivery stays accurate when a sandbox hops between threads
// mid-call and shares a thread ID with another sandbox, ensuring only the intended
// VM is interrupted while bait sandboxes keep running.
#[test]
fn interrupt_infinite_moving_loop_stress_test() {
    use std::sync::Arc;
    use std::thread;

    // We have a high thread count to stress test and to have interesting interleavings
    const NUM_THREADS: usize = 200;

    let mut handles = vec![];

    for _ in 0..NUM_THREADS {
        handles.push(thread::spawn(move || {
            let entered_guest = Arc::new(AtomicBool::new(false));
            let entered_guest_clone = entered_guest.clone();

            let mut uninit = new_uninit_rust().unwrap();
            // Register a host function that waits on the barrier
            uninit
                .register("WaitForKill", move || {
                    entered_guest.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .unwrap();
            let uninit2 = new_uninit_rust().unwrap();

            // These 2 sandboxes will have the same TID
            let sandbox = uninit.evolve().unwrap();
            let bait = uninit2.evolve().unwrap();

            let interrupt = sandbox.interrupt_handle();

            let kill_handle = thread::spawn(move || {
                let entered_before_kill = entered_guest_clone.load(Ordering::Relaxed);
                interrupt.kill();
                entered_before_kill
            });

            let mut sandbox_slot = Some(sandbox);
            let mut bait_slot = Some(bait);

            // bait-sandbox should NEVER be interrupted which is why we can unwrap()
            // sandbox may or may not be interrupted depending on whether `kill()` was called prematurely or not
            let sandbox_res = match rand::random_range(..8u8) {
                // sandbox on main thread, then bait on main thread
                0 => {
                    let res = sandbox_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Real".to_string());
                    bait_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Bait".to_string())
                        .expect("Bait call should never be interrupted");
                    res
                }
                // bait on main thread, then sandbox on main thread
                1 => {
                    bait_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Bait".to_string())
                        .expect("Bait call should never be interrupted");
                    sandbox_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Real".to_string())
                }
                // sandbox on spawned thread, bait on main thread
                2 => {
                    let mut sandbox = sandbox_slot.take().unwrap();
                    let sandbox_handle =
                        thread::spawn(move || sandbox.call::<String>("Echo", "Real".to_string()));
                    bait_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Bait".to_string())
                        .expect("Bait call should never be interrupted");
                    sandbox_handle.join().unwrap()
                }
                // bait on spawned thread, sandbox on main thread
                3 => {
                    let mut bait = bait_slot.take().unwrap();
                    let bait_handle = thread::spawn(move || {
                        bait.call::<String>("Echo", "Bait".to_string())
                            .expect("Bait call should never be interrupted");
                    });
                    let res = sandbox_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Real".to_string());
                    bait_handle.join().unwrap();
                    res
                }
                // sandbox on main thread, bait on spawned thread
                4 => {
                    let res = sandbox_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Real".to_string());
                    let mut bait = bait_slot.take().unwrap();
                    let bait_handle = thread::spawn(move || {
                        bait.call::<String>("Echo", "Bait".to_string())
                            .expect("Bait call should never be interrupted");
                    });
                    bait_handle.join().unwrap();
                    res
                }
                // bait on main thread, sandbox on spawned thread
                5 => {
                    bait_slot
                        .as_mut()
                        .unwrap()
                        .call::<String>("Echo", "Bait".to_string())
                        .expect("Bait call should never be interrupted");
                    let mut sandbox = sandbox_slot.take().unwrap();
                    let sandbox_handle =
                        thread::spawn(move || sandbox.call::<String>("Echo", "Real".to_string()));
                    sandbox_handle.join().unwrap()
                }
                // sandbox on spawned thread, bait on spawned thread
                6 => {
                    let mut sandbox = sandbox_slot.take().unwrap();
                    let sandbox_handle =
                        thread::spawn(move || sandbox.call::<String>("Echo", "Real".to_string()));
                    let mut bait = bait_slot.take().unwrap();
                    let bait_handle = thread::spawn(move || {
                        bait.call::<String>("Echo", "Bait".to_string())
                            .expect("Bait call should never be interrupted");
                    });
                    bait_handle.join().unwrap();
                    sandbox_handle.join().unwrap()
                }
                // bait on spawned thread, sandbox on spawned thread (spawn bait first)
                7 => {
                    let mut bait = bait_slot.take().unwrap();
                    let bait_handle = thread::spawn(move || {
                        bait.call::<String>("Echo", "Bait".to_string())
                            .expect("Bait call should never be interrupted");
                    });
                    let mut sandbox = sandbox_slot.take().unwrap();
                    let sandbox_handle =
                        thread::spawn(move || sandbox.call::<String>("Echo", "Real".to_string()));
                    bait_handle.join().unwrap();
                    sandbox_handle.join().unwrap()
                }
                _ => unreachable!(),
            };

            let entered_before_kill = kill_handle.join().unwrap();

            // If the guest entered before calling kill, then we know for a fact the call should have been canceled since kill() was NOT premature.
            if entered_before_kill {
                assert!(matches!(
                    sandbox_res,
                    Err(HyperlightError::ExecutionCanceledByHost())
                ));
            }

            // If we did NOT enter the guest before calling kill, then the call may or may not have been canceled depending on timing.
            match sandbox_res {
                Err(HyperlightError::ExecutionCanceledByHost()) => {
                    // OK!
                }
                Ok(_) => {
                    // OK!
                }
                Err(e) => {
                    panic!("Got unexpected error: {:?}", e);
                }
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn exception_handler_installation_and_validation() {
    let mut sandbox: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();

    // Verify handler count starts at 0
    let count: i32 = sandbox.call("GetExceptionHandlerCallCount", ()).unwrap();
    assert_eq!(count, 0, "Handler should not have been called yet");

    // Install handler for vector
    sandbox.call::<()>("InstallHandler", 3i32).unwrap();

    // Try to install again - should be able to overwrite
    sandbox.call::<()>("InstallHandler", 3i32).unwrap();

    // Trigger int3 exception
    let trigger_result: i32 = sandbox.call("TriggerInt3", ()).unwrap();
    assert_eq!(trigger_result, 0, "Exception should be handled gracefully");

    // Verify handler was invoked
    let count: i32 = sandbox.call("GetExceptionHandlerCallCount", ()).unwrap();
    assert_eq!(count, 1, "Handler should have been called once");

    // Trigger int3 exception
    let trigger_result: i32 = sandbox.call("TriggerInt3", ()).unwrap();
    assert_eq!(trigger_result, 0, "Exception should be handled gracefully");

    // Verify handler was invoked a second time
    let count: i32 = sandbox.call("GetExceptionHandlerCallCount", ()).unwrap();
    assert_eq!(count, 2, "Handler should have been called twice");
}

/// Tests that an exception can be properly handled even when the heap is exhausted.
/// The guest function fills the heap completely, then triggers a ud2 exception.
/// This validates that the exception handling path does not require heap allocations.
#[test]
fn fill_heap_and_cause_exception() {
    let mut sandbox: MultiUseSandbox = new_uninit_rust().unwrap().evolve().unwrap();
    let result = sandbox.call::<()>("FillHeapAndCauseException", ());

    // The call should fail with an exception error since there's no handler installed
    assert!(result.is_err(), "Expected an error from ud2 exception");

    let err = result.unwrap_err();
    match &err {
        HyperlightError::GuestAborted(code, message) => {
            assert_eq!(*code, ErrorCode::GuestError as u8, "Full error: {:?}", err);

            // Verify the message was properly formatted (proves no-allocation path worked)
            // Exception vector 6 is #UD (Invalid Opcode from ud2 instruction)
            assert!(
                message.contains("Exception vector: 6"),
                "Message should contain 'Exception vector: 6'\nFull error: {:?}",
                err
            );
            assert!(
                message.contains("Faulting Instruction:"),
                "Message should contain 'Faulting Instruction:'\nFull error: {:?}",
                err
            );
            assert!(
                message.contains("Stack Pointer:"),
                "Message should contain 'Stack Pointer:'\nFull error: {:?}",
                err
            );
        }
        _ => panic!("Expected GuestAborted error, got: {:?}", err),
    }
}

/// This test is "likely" to catch a race condition where WHvCancelRunVirtualProcessor runs halfway, then the partition is deleted (by drop calling WHvDeletePartition),
/// and WHvCancelRunVirtualProcessor continues, and tries to access freed memory.
///
/// Based on local observations, "likely" means that if the bug exist, running this test 5 times will catch it at least once.
#[test]
#[cfg(target_os = "windows")]
fn interrupt_cancel_delete_race() {
    const NUM_THREADS: usize = 8;
    const NUM_KILL_THREADS: usize = 4;
    const ITERATIONS_PER_THREAD: usize = 1000;

    let mut handles = vec![];

    for _ in 0..NUM_THREADS {
        handles.push(thread::spawn(move || {
            for _ in 0..ITERATIONS_PER_THREAD {
                let mut sandbox: MultiUseSandbox = new_uninit().unwrap().evolve().unwrap();
                let interrupt_handle = sandbox.interrupt_handle();

                let stop_flag = Arc::new(AtomicBool::new(false));

                let kill_handles: Vec<_> = (0..NUM_KILL_THREADS)
                    .map(|_| {
                        let handle = interrupt_handle.clone();
                        let stop = stop_flag.clone();
                        thread::spawn(move || {
                            while !stop.load(Ordering::Relaxed) {
                                handle.kill();
                            }
                        })
                    })
                    .collect();

                // Makes sure RUNNING_BIT is set when kill() is called
                let _ = sandbox.call::<String>("Echo", "test".to_string());

                // Drop the sandbox while kill threads are spamming
                drop(sandbox);

                // Signal kill threads to stop
                stop_flag.store(true, Ordering::Relaxed);

                // Wait for kill threads
                for kill_handle in kill_handles {
                    kill_handle.join().expect("Kill thread panicked!");
                }
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
