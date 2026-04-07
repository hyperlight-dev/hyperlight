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
use core::f64;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{
    GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox, new_error,
};
use hyperlight_testing::simple_guest_as_string;

pub mod common; // pub to disable dead_code warning
use crate::common::{
    with_all_sandboxes, with_all_sandboxes_cfg, with_all_sandboxes_with_writer,
    with_all_uninit_sandboxes, with_rust_sandbox_cfg, with_rust_uninit_sandbox,
    with_rust_uninit_sandbox_cfg,
};

#[test]
fn pass_byte_array() {
    with_all_sandboxes(|mut sandbox| {
        const LEN: usize = 10;
        let bytes = vec![1u8; LEN];
        let res: Vec<u8> = sandbox
            .call("SetByteArrayToZero", bytes.clone())
            .expect("Expected VecBytes");
        assert_eq!(res, [0; LEN]);

        sandbox
            .call::<i32>("SetByteArrayToZeroNoLength", bytes.clone())
            .unwrap_err(); // missing length param
    });
}

#[test]
fn float_roundtrip() {
    let doubles = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        std::f64::consts::PI,
        -std::f64::consts::PI,
        -1231.43821,
        f64::MAX,
        f64::MIN,
        f64::EPSILON,
        f64::INFINITY,
        -f64::INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    let floats = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        std::f32::consts::PI,
        -std::f32::consts::PI,
        -1231.4382,
        f32::MAX,
        f32::MIN,
        f32::EPSILON,
        f32::INFINITY,
        -f32::INFINITY,
        f32::NAN,
        -f32::NAN,
    ];
    with_all_sandboxes(|mut sandbox| {
        for f in doubles.iter() {
            let res: f64 = sandbox.call("EchoDouble", *f).unwrap();

            // Use == for comparison (handles -0.0 == 0.0) with special case for NaN.
            // Note: FlatBuffers doesn't preserve -0.0 (-0.0 round-trips to 0.0) because FlatBuffers skips
            // storing values equal to the default (as an optimization), and -0.0 == 0.0 in IEEE 754.
            assert!(
                (res.is_nan() && f.is_nan()) || res == *f,
                "Expected {:?} but got {:?}",
                f,
                res
            );
        }
        for f in floats.iter() {
            let res: f32 = sandbox.call("EchoFloat", *f).unwrap();

            // Use == for comparison (handles -0.0 == 0.0) with special case for NaN.
            // Note: FlatBuffers doesn't preserve -0.0 (-0.0 round-trips to 0.0) because FlatBuffers skips
            // storing values equal to the default (as an optimization), and -0.0 == 0.0 in IEEE 754.
            assert!(
                (res.is_nan() && f.is_nan()) || res == *f,
                "Expected {:?} but got {:?}",
                f,
                res
            );
        }
    });
}

#[test]
fn invalid_guest_function_name() {
    with_all_sandboxes(|mut sandbox| {
        let fn_name = "FunctionDoesntExist";
        let res = sandbox.call::<i32>(fn_name, ());
        assert!(
            matches!(res.unwrap_err(), HyperlightError::GuestError(hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionNotFound, error_name) if error_name == fn_name)
        );
    });
}

#[test]
fn set_static() {
    let mut cfg: SandboxConfiguration = Default::default();
    cfg.set_scratch_size(0x100A000);
    with_all_sandboxes_cfg(Some(cfg), |mut sandbox| {
        let fn_name = "SetStatic";
        let res = sandbox.call::<i32>(fn_name, ());
        assert!(res.is_ok());
        // the result is the size of the static array in the guest
        assert_eq!(res.unwrap(), 1024 * 1024);
    });
}

#[test]
fn multiple_parameters() {
    let (tx, rx) = channel();
    let writer = move |msg: String| {
        tx.send(msg).unwrap();
        0
    };

    let args = (
        ("1".to_string(), "arg1:1"),
        (2_i32, "arg2:2"),
        (3_i64, "arg3:3"),
        ("4".to_string(), "arg4:4"),
        ("5".to_string(), "arg5:5"),
        (true, "arg6:true"),
        (false, "arg7:false"),
        (8_u32, "arg8:8"),
        (9_u64, "arg9:9"),
        (10_i32, "arg10:10"),
        (3.123_f32, "arg11:3.123"),
    );

    macro_rules! test_case {
        ($sandbox:ident, $rx:ident, $name:literal, ($($p:ident),+)) => {{
            let ($($p),+, ..) = args.clone();
            let _res: i32 = $sandbox.call($name, ($($p.0,)+)).unwrap();
            let output = $rx.try_recv().unwrap();
            assert_eq!(output, format!("Message: {}.", [$($p.1),+].join(" ")));
        }};
    }

    with_all_sandboxes_with_writer(writer.into(), |mut sb| {
        test_case!(sb, rx, "PrintTwoArgs", (a, b));
        test_case!(sb, rx, "PrintThreeArgs", (a, b, c));
        test_case!(sb, rx, "PrintFourArgs", (a, b, c, d));
        test_case!(sb, rx, "PrintFiveArgs", (a, b, c, d, e));
        test_case!(sb, rx, "PrintSixArgs", (a, b, c, d, e, f));
        test_case!(sb, rx, "PrintSevenArgs", (a, b, c, d, e, f, g));
        test_case!(sb, rx, "PrintEightArgs", (a, b, c, d, e, f, g, h));
        test_case!(sb, rx, "PrintNineArgs", (a, b, c, d, e, f, g, h, i));
        test_case!(sb, rx, "PrintTenArgs", (a, b, c, d, e, f, g, h, i, j));
        test_case!(sb, rx, "PrintElevenArgs", (a, b, c, d, e, f, g, h, i, j, k));
    });
}

#[test]
fn incorrect_parameter_type() {
    with_all_sandboxes(|mut sandbox| {
        let res = sandbox.call::<i32>(
            "Echo", 2_i32, // should be string
        );

        assert!(matches!(
            res.unwrap_err(),
            HyperlightError::GuestError(
                hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionParameterTypeMismatch,
                msg
            ) if msg == "Expected parameter type String for parameter index 0 of function Echo but got Int."
        ));
    });
}

#[test]
fn incorrect_parameter_num() {
    with_all_sandboxes(|mut sandbox| {
        let res = sandbox.call::<i32>("Echo", ("1".to_string(), 2_i32));
        assert!(matches!(
            res.unwrap_err(),
            HyperlightError::GuestError(
                hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionIncorrecNoOfParameters,
                msg
            ) if msg == "Called function Echo with 2 parameters but it takes 1."
        ));
    });
}

#[test]
fn small_scratch_sandbox() {
    let mut cfg = SandboxConfiguration::default();
    cfg.set_scratch_size(0x48000);
    cfg.set_input_data_size(0x24000);
    cfg.set_output_data_size(0x24000);
    let a = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(cfg),
    );

    assert!(matches!(
        a.unwrap_err(),
        HyperlightError::MemoryRequestTooSmall(..)
    ));
}

#[test]
fn iostack_is_working() {
    with_all_sandboxes(|mut sandbox| {
        let res: i32 = sandbox
            .call::<i32>("ThisIsNotARealFunctionButTheNameIsImportant", ())
            .unwrap();
        assert_eq!(res, 99);
    });
}

fn simple_test_helper() {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let messages_clone = messages.clone();
    let writer = move |msg: String| {
        let len = msg.len();
        let mut lock = messages_clone
            .try_lock()
            .map_err(|_| new_error!("Error locking"))
            .unwrap();
        lock.push(msg);
        len as i32
    };

    let message = "hello";
    let message2 = "world";

    with_all_sandboxes_with_writer(writer.into(), |mut sandbox| {
        let res: i32 = sandbox.call("PrintOutput", message.to_string()).unwrap();
        assert_eq!(res, 5);

        let res: String = sandbox.call("Echo", message2.to_string()).unwrap();
        assert_eq!(res, "world");

        let buffer = [1u8, 2, 3, 4, 5, 6];
        let res: Vec<u8> = sandbox
            .call("GetSizePrefixedBuffer", buffer.to_vec())
            .unwrap();
        assert_eq!(res, buffer);
    });

    let expected_calls = 2; // Once per guest (rust + c)

    assert_eq!(messages.try_lock().unwrap().len(), expected_calls);

    assert!(
        messages
            .try_lock()
            .unwrap()
            .iter()
            .all(|msg| msg == message)
    );
}

#[test]
fn simple_test() {
    simple_test_helper();
}

#[test]
fn simple_test_parallel() {
    let handles: Vec<_> = (0..50)
        .map(|_| {
            std::thread::spawn(|| {
                simple_test_helper();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

fn callback_test_helper() {
    with_all_uninit_sandboxes(|mut sandbox| {
        // create host function
        let (tx, rx) = channel();
        sandbox
            .register("HostMethod1", move |msg: String| {
                let len = msg.len();
                tx.send(msg).unwrap();
                Ok(len as i32)
            })
            .unwrap();

        // call guest function that calls host function
        let mut init_sandbox: MultiUseSandbox = sandbox.evolve().unwrap();
        let msg = "Hello world";
        init_sandbox
            .call::<i32>("GuestMethod1", msg.to_string())
            .unwrap();

        let messages = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(messages, [format!("Hello from GuestFunction1, {msg}")]);
    });
}

#[test]
fn callback_test() {
    callback_test_helper();
}

#[test]
fn callback_test_parallel() {
    let handles: Vec<_> = (0..100)
        .map(|_| {
            std::thread::spawn(|| {
                callback_test_helper();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn host_function_error() {
    with_all_uninit_sandboxes(|mut sandbox| {
        // create host function
        sandbox
            .register("HostMethod1", |_: String| -> Result<String> {
                Err(new_error!("Host function error!"))
            })
            .unwrap();

        // call guest function that calls host function
        let mut init_sandbox: MultiUseSandbox = sandbox.evolve().unwrap();
        let msg = "Hello world";
        let snapshot = init_sandbox.snapshot().unwrap();

        for _ in 0..1000 {
            let res = init_sandbox
                .call::<i32>("GuestMethod1", msg.to_string())
                .unwrap_err();
            assert!(
                matches!(&res, HyperlightError::GuestError(_, msg) if msg == "Host function error!") // rust guest
                || matches!(&res, HyperlightError::GuestAborted(_, msg) if msg.contains("Host function error!")), // c guest
                "expected something but got {}",
                res
            );
            // C guest panics in rust guest lib when host function returns error, which will poison the sandbox
            if init_sandbox.poisoned() {
                init_sandbox.restore(snapshot.clone()).unwrap();
            }
        }
    });
}

#[test]
fn virtq_log_delivery() {
    use hyperlight_testing::simplelogger::{LOGGER, SimpleLogger};

    SimpleLogger::initialize_test_logger();
    LOGGER.clear_log_calls();

    with_rust_uninit_sandbox(|mut sbox| {
        sbox.set_max_guest_log_level(tracing_core::LevelFilter::TRACE);
        let mut sandbox = sbox.evolve().unwrap();

        sandbox
            .call::<()>("LogMessage", ("virtq log test message".to_string(), 3_i32))
            .unwrap();

        // Verify the guest log arrived via virtqueue
        let count = LOGGER.num_log_calls();
        assert!(count > 0, "expected at least one guest log, got 0");

        let mut found = false;
        for i in 0..count {
            if let Some(call) = LOGGER.get_log_call(i)
                && call.target == "hyperlight_guest"
                && call.args.contains("virtq log test")
            {
                found = true;
                break;
            }
        }
        assert!(found, "expected 'virtq log test' message from guest");
        LOGGER.clear_log_calls();
    });
}

#[test]
fn virtq_log_with_callback() {
    // Verify that log messages interleaved with host callbacks work
    with_all_uninit_sandboxes(|mut sandbox| {
        let (tx, _rx) = channel();
        sandbox
            .register("HostMethod1", move |msg: String| {
                let len = msg.len();
                tx.send(msg).unwrap();
                len as i32
            })
            .unwrap();
        let mut sandbox = sandbox.evolve().unwrap();

        // Echo triggers guest-side logging infrastructure, then returns.
        // This validates that log ReadOnly entries interleaved with
        // function call ReadWrite entries don't corrupt the G2H queue.
        let res: String = sandbox.call("Echo", "test".to_string()).unwrap();
        assert_eq!(res, "test");
    });
}

#[test]
fn virtq_log_backpressure() {
    use hyperlight_testing::simplelogger::{LOGGER, SimpleLogger};

    SimpleLogger::initialize_test_logger();
    LOGGER.clear_log_calls();

    let mut cfg = SandboxConfiguration::default();
    cfg.set_g2h_pool_pages(2);

    with_rust_uninit_sandbox_cfg(cfg, |mut sbox| {
        sbox.set_max_guest_log_level(tracing_core::LevelFilter::INFO);
        let mut sandbox = sbox.evolve().unwrap();

        // 50 logs with a 2-page pool should trigger backpressure
        sandbox.call::<()>("LogMessageN", 50_i32).unwrap();

        // Verify sandbox is still functional after backpressure
        let res: i32 = sandbox
            .call("ThisIsNotARealFunctionButTheNameIsImportant", ())
            .unwrap();
        assert_eq!(res, 99);

        // Verify all 50 log entries were delivered
        let guest_count = (0..LOGGER.num_log_calls())
            .filter_map(|i| LOGGER.get_log_call(i))
            .filter(|c| c.target == "hyperlight_guest" && c.args.contains("log entry"))
            .count();
        assert_eq!(guest_count, 50, "expected 50 guest logs, got {guest_count}");
        LOGGER.clear_log_calls();
    });
}

#[test]
fn virtq_log_backpressure_repeated() {
    // Multiple calls that each trigger backpressure, verifying the
    // pool recovers correctly each time.
    let mut cfg = SandboxConfiguration::default();
    cfg.set_g2h_pool_pages(2);

    with_rust_sandbox_cfg(cfg, |mut sandbox| {
        for _ in 0..5 {
            sandbox.call::<()>("LogMessageN", 30_i32).unwrap();
        }
    });
}

#[test]
fn virtq_backpressure_small_ring() {
    // Small descriptor table forces ring-level backpressure.
    use hyperlight_testing::simplelogger::{LOGGER, SimpleLogger};

    SimpleLogger::initialize_test_logger();
    LOGGER.clear_log_calls();

    let mut cfg = SandboxConfiguration::default();
    cfg.set_g2h_queue_depth(4);

    with_rust_uninit_sandbox_cfg(cfg, |mut sbox| {
        sbox.set_max_guest_log_level(tracing_core::LevelFilter::INFO);
        let mut sandbox = sbox.evolve().unwrap();

        sandbox.call::<()>("LogMessageN", 20_i32).unwrap();

        let guest_count = (0..LOGGER.num_log_calls())
            .filter_map(|i| LOGGER.get_log_call(i))
            .filter(|c| c.target == "hyperlight_guest" && c.args.contains("log entry"))
            .count();
        assert_eq!(guest_count, 20, "expected 20 guest logs, got {guest_count}");
        LOGGER.clear_log_calls();
    });
}

#[test]
fn virtq_backpressure_log_then_callback() {
    // Logs fill the G2H ring, then a host callback needs ring space.
    // call_host_function handles backpressure by notify + reclaim + retry.
    let mut cfg = SandboxConfiguration::default();
    cfg.set_g2h_queue_depth(4);
    cfg.set_g2h_pool_pages(2);

    with_rust_uninit_sandbox_cfg(cfg, |mut sbox| {
        sbox.set_max_guest_log_level(tracing_core::LevelFilter::INFO);
        sbox.register_print(|msg: String| msg.len() as i32).unwrap();
        let mut sandbox = sbox.evolve().unwrap();

        // PrintOutput logs and calls HostPrint callback.
        // With depth=4 the logs may fill the ring, requiring
        // call_host_function to handle backpressure before
        // submitting the callback entry.
        let res: i32 = sandbox.call("PrintOutput", "bp-test".to_string()).unwrap();
        assert_eq!(res, 7);
    });
}

#[test]
fn virtq_backpressure_no_data_loss() {
    // After backpressure recovery, verify multiple function calls
    // return correct results (completion data wasn't lost by reclaim).
    let mut cfg = SandboxConfiguration::default();
    cfg.set_g2h_pool_pages(2);
    cfg.set_g2h_queue_depth(4);

    with_rust_uninit_sandbox_cfg(cfg, |mut sbox| {
        sbox.set_max_guest_log_level(tracing_core::LevelFilter::INFO);
        let mut sandbox = sbox.evolve().unwrap();

        // Trigger backpressure with logs
        sandbox.call::<()>("LogMessageN", 20_i32).unwrap();

        // Now verify multiple function calls with return values
        let res: String = sandbox.call("Echo", "first".to_string()).unwrap();
        assert_eq!(res, "first");

        let res: String = sandbox.call("Echo", "second".to_string()).unwrap();
        assert_eq!(res, "second");

        let res: f64 = sandbox.call("EchoDouble", 1.234_f64).unwrap();
        assert!((res - 1.234).abs() < f64::EPSILON);
    });
}

#[test]
fn virtq_log_tracing_delivery() {
    // Verify guest logs are emitted as tracing events when a tracing
    // subscriber is active, matching the behavior of the old outb_log.
    use hyperlight_testing::tracing_subscriber::TracingSubscriber;

    let subscriber = TracingSubscriber::new(tracing::Level::TRACE);

    tracing::subscriber::with_default(subscriber.clone(), || {
        with_rust_uninit_sandbox(|mut sbox| {
            sbox.set_max_guest_log_level(tracing_core::LevelFilter::INFO);
            let mut sandbox = sbox.evolve().unwrap();

            subscriber.clear();

            sandbox
                .call::<()>("LogMessage", ("tracing delivery test".to_string(), 3_i32))
                .unwrap();

            // Guest log goes through format_trace which creates tracing
            // events with log.target = "hyperlight_guest" as a field.
            let events = subscriber.get_events();
            assert!(
                !events.is_empty(),
                "expected tracing events after guest log call, got none"
            );
        });
    });
}

#[test]
fn virtq_log_tracing_levels() {
    // Verify each guest log level produces tracing events.
    use hyperlight_testing::tracing_subscriber::TracingSubscriber;

    let subscriber = TracingSubscriber::new(tracing::Level::TRACE);

    tracing::subscriber::with_default(subscriber.clone(), || {
        with_rust_uninit_sandbox(|mut sbox| {
            sbox.set_max_guest_log_level(tracing_core::LevelFilter::TRACE);
            let mut sandbox = sbox.evolve().unwrap();

            // Test each level: 1=Trace, 2=Debug, 3=Info, 4=Warn, 5=Error
            for level in [1_i32, 2, 3, 4, 5] {
                subscriber.clear();
                let msg = format!("level-test-{}", level);
                sandbox.call::<()>("LogMessage", (msg, level)).unwrap();

                let events = subscriber.get_events();
                assert!(
                    !events.is_empty(),
                    "expected tracing events for guest log level {}",
                    level
                );
            }
        });
    });
}

#[test]
fn virtq_invalid_guest_function_returns_error() {
    // Calling a non-existent guest function should return a proper
    // GuestError, not corrupt data or a hang. This validates that
    // the virtq error path (MsgKind::Response with GuestError payload)
    // works end-to-end.
    with_rust_sandbox_cfg(SandboxConfiguration::default(), |mut sandbox| {
        let res = sandbox.call::<()>("ThisFunctionDoesNotExist", ());
        assert!(res.is_err(), "expected error for non-existent function");
        let err = res.unwrap_err();
        assert!(
            matches!(
                err,
                HyperlightError::GuestError(
                    hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionNotFound,
                    _
                )
            ),
            "expected GuestFunctionNotFound, got {:?}",
            err
        );
    });
}

#[test]
fn virtq_large_payload_roundtrip() {
    // Verify that larger payloads survive the virtq roundtrip without corruption.
    with_rust_sandbox_cfg(SandboxConfiguration::default(), |mut sandbox| {
        // 1KB string
        let large_msg: String = "X".repeat(1024);
        let res: String = sandbox.call("Echo", large_msg.clone()).unwrap();
        assert_eq!(res, large_msg);

        // 1KB byte array
        let large_bytes = vec![0xABu8; 1024];
        let res: Vec<u8> = sandbox
            .call("SetByteArrayToZero", large_bytes.clone())
            .unwrap();
        assert_eq!(res.len(), 1024);
        assert!(res.iter().all(|&b| b == 0));
    });
}
