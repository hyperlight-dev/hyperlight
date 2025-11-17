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

#![no_main]

#[cfg(not(feature = "trace"))]
compile_error!("feature `trace` must be enabled to correctly fuzz guest trace functionality");

use std::sync::{Mutex, OnceLock};

use hyperlight_host::func::{ParameterValue, ReturnType, ReturnValue};
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox::uninitialized::GuestBinary;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_for_fuzzing_as_string;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::{Corpus, fuzz_target};

static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

#[derive(Debug)]
struct FuzzInput {
    max_depth: u8,
    message: String,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(
        u: &mut libfuzzer_sys::arbitrary::Unstructured<'_>,
    ) -> libfuzzer_sys::arbitrary::Result<Self> {
        let max_depth = u.arbitrary::<u8>()?;
        // Limit message length to 1024 characters
        let message_length = u.arbitrary_len::<u16>()? as usize % 1024;

        let message = u
            .arbitrary::<String>()?
            .chars()
            .take(message_length)
            .collect();
        Ok(FuzzInput { max_depth, message })
    }
}

// This fuzz target exercises the guest function `FuzzGuestTrace` in the simple Rust guest.
// The function takes two parameters: a `u32` max depth and a `String` message.
// The function recursively traces calls up to the specified depth, logging the message at each level.
// The fuzzer provides various depths and messages to test the tracing functionality.
//
// The fuzzer uses a `u8` for max depth (0-255) and a `String` for the message.
// This is to avoid `SandboxOverflow` errors from excessively deep recursion.
//
// The goal is to ensure that the tracing and logging mechanisms in the sandbox
// can handle a variety of inputs without crashing or misbehaving.
// The sandbox shall correctly handle any number of spans and logs without crashing.
// Any unexpected errors from the guest should be reported.
fuzz_target!(
    init: {
        let mut cfg = SandboxConfiguration::default();
        // In local tests, 256 KiB seemed sufficient for deep recursion
        cfg.set_stack_size(256 * 1024);
        let path = simple_guest_for_fuzzing_as_string().expect("Guest Binary Missing");
        let u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(path),
            Some(cfg),
        )
        .unwrap();

        let mu_sbox: MultiUseSandbox = u_sbox.evolve().unwrap();

        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: FuzzInput| -> Corpus {
        let (max_depth, msg_len) = (data.max_depth as u32, data.message.len());
        let msg = data.message;

        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();

        let func_params = vec![ParameterValue::UInt(max_depth), ParameterValue::String(msg)];
        let result = sandbox.call_type_erased_guest_function_by_name("FuzzGuestTrace", ReturnType::UInt, func_params);

        match result {
            Ok(ret_val) => {
                if let ReturnValue::UInt(depth_reached) = ret_val {
                    assert!(depth_reached == max_depth);
                    Corpus::Keep
                } else {
                panic!(
                    "While fuzzing FuzzGuestTrace with max_depth: {}, msg length: {}, the guest function return unexpected type: {:?}",
                    max_depth,
                    msg_len,
                    ret_val
                );
                }
            }
            Err(e) => {
                panic!(
                    "While fuzzing FuzzGuestTrace with max_depth: {}, msg length: {}, the guest function aborted with error: {:?}",
                    max_depth,
                    msg_len,
                    e);
            }
        }
    }
);
