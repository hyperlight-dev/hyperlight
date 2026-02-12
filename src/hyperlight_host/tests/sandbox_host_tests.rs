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
use core::f64;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use hyperlight_host::{HyperlightError, MultiUseSandbox, Result, new_error};

pub mod common; // pub to disable dead_code warning
use crate::common::{
    with_all_sandboxes, with_all_sandboxes_with_writer, with_all_uninit_sandboxes,
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
    with_all_sandboxes(|mut sandbox| {
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
