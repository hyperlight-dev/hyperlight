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
use std::sync::{Arc, Mutex};

use common::new_uninit;
use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
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
        let res = ctx.call(
            "SetByteArrayToZero",
            ReturnType::VecBytes,
            Some(vec![ParameterValue::VecBytes(bytes.clone())]),
        );

        match res.unwrap() {
            ReturnValue::VecBytes(res_bytes) => {
                assert_eq!(res_bytes.len(), LEN);
                assert!(res_bytes.iter().all(|&b| b == 0));
            }
            _ => panic!("Expected VecBytes"),
        }

        let res = ctx.call(
            "SetByteArrayToZeroNoLength",
            ReturnType::Int,
            Some(vec![ParameterValue::VecBytes(bytes.clone())]),
        );
        assert!(res.is_err()); // missing length param
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
        let res = sandbox.call_guest_function_by_name(
            "EchoDouble",
            ReturnType::Double,
            Some(vec![ParameterValue::Double(*f)]),
        );

        assert!(
            matches!(res, Ok(ReturnValue::Double(f2)) if f2 == *f || f2.is_nan() && f.is_nan()),
            "Expected {:?} but got {:?}",
            f,
            res
        );
    }
    for f in floats.iter() {
        let res = sandbox.call_guest_function_by_name(
            "EchoFloat",
            ReturnType::Float,
            Some(vec![ParameterValue::Float(*f)]),
        );

        assert!(
            matches!(res, Ok(ReturnValue::Float(f2)) if f2 == *f || f2.is_nan() && f.is_nan()),
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
        let res = sandbox.call_guest_function_by_name(fn_name, ReturnType::Int, None);
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
        let res = sandbox.call_guest_function_by_name(fn_name, ReturnType::Int, None);
        println!("{:?}", res);
        assert!(res.is_ok());
        // the result is the size of the static array in the guest
        assert_eq!(res.unwrap(), ReturnValue::Int(1024 * 1024));
    }
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn multiple_parameters() {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let messages_clone = messages.clone();
    let writer = move |msg: String| {
        let mut lock = messages_clone
            .try_lock()
            .map_err(|_| new_error!("Error locking"))
            .unwrap();
        lock.push(msg);
        0
    };

    let test_cases = vec![
        (
            "PrintTwoArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
            ],
            format!("Message: arg1:{} arg2:{}.", "1", 2),
        ),
        (
            "PrintThreeArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
            ],
            format!("Message: arg1:{} arg2:{} arg3:{}.", "1", 2, 3),
        ),
        (
            "PrintFourArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
            ],
            format!("Message: arg1:{} arg2:{} arg3:{} arg4:{}.", "1", 2, 3, "4"),
        ),
        (
            "PrintFiveArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{}.",
                "1", 2, 3, "4", "5"
            ),
        ),
        (
            "PrintSixArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{}.",
                "1", 2, 3, "4", "5", true
            ),
        ),
        (
            "PrintSevenArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{} arg7:{}.",
                "1", 2, 3, "4", "5", true, false
            ),
        ),
        (
            "PrintEightArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{} arg7:{} arg8:{}.",
                "1", 2, 3, "4", "5", true, false, 8
            ),
        ),
        (
            "PrintNineArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
                ParameterValue::ULong(9),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{} arg7:{} arg8:{} arg9:{}.",
                "1", 2, 3, "4", "5", true, false, 8, 9
            ),
        ),
        (
            "PrintTenArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
                ParameterValue::ULong(9),
                ParameterValue::Int(10),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{} arg7:{} arg8:{} arg9:{} arg10:{}.",
                "1", 2, 3, "4", "5", true, false, 8, 9, 10
            ),
        ),
        (
            "PrintElevenArgs",
            vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
                ParameterValue::Long(3),
                ParameterValue::String("4".to_string()),
                ParameterValue::String("5".to_string()),
                ParameterValue::Bool(true),
                ParameterValue::Bool(false),
                ParameterValue::UInt(8),
                ParameterValue::ULong(9),
                ParameterValue::Int(10),
                ParameterValue::Float(3.123),
            ],
            format!(
                "Message: arg1:{} arg2:{} arg3:{} arg4:{} arg5:{} arg6:{} arg7:{} arg8:{} arg9:{} arg10:{} arg11:{}.",
                "1", 2, 3, "4", "5", true, false, 8, 9, 10, 3.123
            ),
        )
    ];

    for mut sandbox in get_simpleguest_sandboxes(Some(writer.into())).into_iter() {
        for (fn_name, args, _expected) in test_cases.clone().into_iter() {
            let res = sandbox.call_guest_function_by_name(fn_name, ReturnType::Int, Some(args));
            println!("{:?}", res);
            assert!(res.is_ok());
        }
    }

    let lock = messages
        .try_lock()
        .map_err(|_| new_error!("Error locking"))
        .unwrap();
    lock.clone()
        .into_iter()
        .zip(test_cases)
        .for_each(|(printed_msg, expected)| {
            println!("{:?}", printed_msg);
            assert_eq!(printed_msg, expected.2);
        });
}

#[test]
#[cfg_attr(target_os = "windows", serial)] // using LoadLibrary requires serial tests
fn incorrect_parameter_type() {
    for mut sandbox in get_simpleguest_sandboxes(None) {
        let res = sandbox.call_guest_function_by_name(
            "Echo",
            ReturnType::Int,
            Some(vec![
                ParameterValue::Int(2), // should be string
            ]),
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
        let res = sandbox.call_guest_function_by_name(
            "Echo",
            ReturnType::Int,
            Some(vec![
                ParameterValue::String("1".to_string()),
                ParameterValue::Int(2),
            ]),
        );
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
        let res = sandbox.call_guest_function_by_name(
            "ThisIsNotARealFunctionButTheNameIsImportant",
            ReturnType::Int,
            None,
        );
        println!("{:?}", res);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), ReturnValue::Int(99));
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
        let res = sandbox.call_guest_function_by_name(
            "PrintOutput",
            ReturnType::Int,
            Some(vec![ParameterValue::String(message.to_string())]),
        );
        println!("res: {:?}", res);
        assert!(matches!(res, Ok(ReturnValue::Int(5))));

        let res2 = sandbox.call_guest_function_by_name(
            "Echo",
            ReturnType::String,
            Some(vec![ParameterValue::String(message2.to_string())]),
        );
        println!("res2: {:?}", res2);
        assert!(matches!(res2, Ok(ReturnValue::String(s)) if s == "world"));

        let buffer = vec![1u8, 2, 3, 4, 5, 6];
        let res3 = sandbox.call_guest_function_by_name(
            "GetSizePrefixedBuffer",
            ReturnType::Int,
            Some(vec![ParameterValue::VecBytes(buffer.clone())]),
        );
        println!("res3: {:?}", res3);
        assert!(matches!(res3, Ok(ReturnValue::VecBytes(v)) if v == buffer));
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
        let vec = Arc::new(Mutex::new(vec![]));
        let vec_cloned = vec.clone();

        sandbox.register("HostMethod1", move |msg: String| {
            let len = msg.len();
            vec_cloned
                .try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .push(msg);
            Ok(len as i32)
        })?;

        // call guest function that calls host function
        let mut init_sandbox: MultiUseSandbox = sandbox.evolve(Noop::default())?;
        let msg = "Hello world";
        init_sandbox.call_guest_function_by_name(
            "GuestMethod1",
            ReturnType::Int,
            Some(vec![ParameterValue::String(msg.to_string())]),
        )?;

        assert_eq!(
            vec.try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .len(),
            1
        );
        assert_eq!(
            vec.try_lock()
                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                .remove(0),
            format!("Hello from GuestFunction1, {}", msg)
        );
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
        let res = init_sandbox.call_guest_function_by_name(
            "GuestMethod1",
            ReturnType::Int,
            Some(vec![ParameterValue::String(msg.to_string())]),
        );
        println!("res {:?}", res);
        assert!(matches!(res, Err(HyperlightError::Error(msg)) if msg == "Host function error!"));
    }
    Ok(())
}
