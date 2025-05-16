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
#![allow(clippy::disallowed_macros)]
use core::f64;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use common::new_uninit;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{
    new_error, GuestBinary, HyperlightError, MultiUseSandbox, Result, UninitializedSandbox,
};
use hyperlight_testing::simple_guest_as_string;
#[cfg(target_os = "windows")]
use serial_test::serial; // using LoadLibrary requires serial tests

pub mod common; // pub to disable dead_code warning
use crate::common::{get_callbackguest_uninit_sandboxes, get_simpleguest_sandboxes};

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn pass_byte_array() {
    for sandbox in get_simpleguest_sandboxes(None).into_iter() {
        let mut ctx = sandbox.new_call_context();
        const LEN: usize = 10;
        let bytes = vec![1u8; LEN];
        let res: Vec<u8> = ctx
            .call("SetByteArrayToZero", bytes.clone())
            .expect("Expected VecBytes");
        assert_eq!(res, [0; LEN]);

        ctx.call::<i32>("SetByteArrayToZeroNoLength", bytes.clone())
            .unwrap_err(); // missing length param
    }
}

#[test]
#[ignore = "Fails with mismatched float only when c .exe guest?!"]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
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
    let mut sandbox: MultiUseSandbox = new_uninit().unwrap().evolve(Noop::default()).unwrap();
    for f in doubles.iter() {
        let res: f64 = sandbox
            .call_guest_function_by_name("EchoDouble", *f)
            .unwrap();

        assert!(
            res.total_cmp(f).is_eq(),
            "Expected {:?} but got {:?}",
            f,
            res
        );
    }
    for f in floats.iter() {
        let res: f32 = sandbox
            .call_guest_function_by_name("EchoFloat", *f)
            .unwrap();

        assert!(
            res.total_cmp(f).is_eq(),
            "Expected {:?} but got {:?}",
            f,
            res
        );
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn invalid_guest_function_name() {
    for mut sandbox in get_simpleguest_sandboxes(None).into_iter() {
        let fn_name = "FunctionDoesntExist";
        let res = sandbox.call_guest_function_by_name::<i32>(fn_name, ());
        println!("{:?}", res);
        assert!(
            matches!(res.unwrap_err(), HyperlightError::GuestError(hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionNotFound, error_name) if error_name == fn_name)
        );
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn set_static() {
    for mut sandbox in get_simpleguest_sandboxes(None).into_iter() {
        let fn_name = "SetStatic";
        let res = sandbox.call_guest_function_by_name::<i32>(fn_name, ());
        println!("{:?}", res);
        assert!(res.is_ok());
        // the result is the size of the static array in the guest
        assert_eq!(res.unwrap(), 1024 * 1024);
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
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
            let res: i32 = $sandbox.call_guest_function_by_name($name, ($($p.0,)+)).unwrap();
            println!("{res:?}");
            let output = $rx.try_recv().unwrap();
            println!("{output:?}");
            assert_eq!(output, format!("Message: {}.", [$($p.1),+].join(" ")));
        }};
    }

    for mut sb in get_simpleguest_sandboxes(Some(writer.into())).into_iter() {
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
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn incorrect_parameter_type() {
    for mut sandbox in get_simpleguest_sandboxes(None) {
        let res = sandbox.call_guest_function_by_name::<i32>(
            "Echo", 2_i32, // should be string
        );

        assert!(matches!(
            res.unwrap_err(),
            HyperlightError::GuestError(
                hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionParameterTypeMismatch,
                msg
            ) if msg == "Expected parameter type String for parameter index 0 of function Echo but got Int."
        ));
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn incorrect_parameter_num() {
    for mut sandbox in get_simpleguest_sandboxes(None).into_iter() {
        let res = sandbox.call_guest_function_by_name::<i32>("Echo", ("1".to_string(), 2_i32));
        assert!(matches!(
            res.unwrap_err(),
            HyperlightError::GuestError(
                hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode::GuestFunctionIncorrecNoOfParameters,
                msg
            ) if msg == "Called function Echo with 2 parameters but it takes 1."
        ));
    }
}

#[test]
fn max_memory_sandbox() {
    let mut cfg = SandboxConfiguration::default();
    cfg.set_input_data_size(0x40000000);
    let a = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        Some(cfg),
    );

    assert!(matches!(
        a.unwrap_err(),
        HyperlightError::MemoryRequestTooBig(..)
    ));
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn iostack_is_working() {
    for mut sandbox in get_simpleguest_sandboxes(None).into_iter() {
        let res: i32 = sandbox
            .call_guest_function_by_name::<i32>("ThisIsNotARealFunctionButTheNameIsImportant", ())
            .unwrap();
        assert_eq!(res, 99);
    }
}

fn simple_test_helper() -> Result<()> {
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

    for mut sandbox in get_simpleguest_sandboxes(Some(writer.into())).into_iter() {
        let res: i32 = sandbox
            .call_guest_function_by_name("PrintOutput", message.to_string())
            .unwrap();
        assert_eq!(res, 5);

        let res: String = sandbox
            .call_guest_function_by_name("Echo", message2.to_string())
            .unwrap();
        assert_eq!(res, "world");

        let buffer = [1u8, 2, 3, 4, 5, 6];
        let res: Vec<u8> = sandbox
            .call_guest_function_by_name("GetSizePrefixedBuffer", buffer.to_vec())
            .unwrap();
        assert_eq!(res, buffer);
    }

    let expected_calls = 1;

    assert_eq!(
        messages
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .len(),
        expected_calls
    );

    assert!(messages
        .try_lock()
        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
        .iter()
        .all(|msg| msg == message));
    Ok(())
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn simple_test() {
    simple_test_helper().unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn simple_test_parallel() {
    let handles: Vec<_> = (0..50)
        .map(|_| {
            std::thread::spawn(|| {
                simple_test_helper().unwrap();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

fn callback_test_helper() -> Result<()> {
    for mut sandbox in get_callbackguest_uninit_sandboxes(None).into_iter() {
        // create host function
        let (tx, rx) = channel();
        sandbox.register("HostMethod1", move |msg: String| {
            let len = msg.len();
            tx.send(msg).unwrap();
            Ok(len as i32)
        })?;

        // call guest function that calls host function
        let mut init_sandbox: MultiUseSandbox = sandbox.evolve(Noop::default())?;
        let msg = "Hello world";
        init_sandbox.call_guest_function_by_name::<i32>("GuestMethod1", msg.to_string())?;

        let messages = rx.try_iter().collect::<Vec<_>>();
        assert_eq!(messages, [format!("Hello from GuestFunction1, {msg}")]);
    }
    Ok(())
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn callback_test() {
    callback_test_helper().unwrap();
}

#[test]
#[cfg(target_os = "linux")] // windows can't run parallel with LoadLibrary
fn callback_test_parallel() {
    let handles: Vec<_> = (0..100)
        .map(|_| {
            std::thread::spawn(|| {
                callback_test_helper().unwrap();
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn host_function_error() -> Result<()> {
    for mut sandbox in get_callbackguest_uninit_sandboxes(None).into_iter() {
        // create host function
        sandbox.register("HostMethod1", |_: String| -> Result<String> {
            Err(new_error!("Host function error!"))
        })?;

        // call guest function that calls host function
        let mut init_sandbox: MultiUseSandbox = sandbox.evolve(Noop::default())?;
        let msg = "Hello world";
        let res = init_sandbox
            .call_guest_function_by_name::<i32>("GuestMethod1", msg.to_string())
            .unwrap_err();
        assert!(matches!(res, HyperlightError::Error(msg) if msg == "Host function error!"));
    }
    Ok(())
}
