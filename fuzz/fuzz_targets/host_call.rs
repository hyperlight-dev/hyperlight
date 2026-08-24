// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![no_main]

use std::sync::{Mutex, OnceLock};

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_host::func::{ParameterValue, ReturnType};
use hyperlight_host::{HyperlightError, MultiUseSandbox, SandboxBuilder};
use hyperlight_testing::simple_guest_for_fuzzing_as_pathbuf;
use libfuzzer_sys::fuzz_target;

static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target tests all combinations of ReturnType and Parameters for `call_guest_function_by_name`.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let mu_sbox = SandboxBuilder::from_file(simple_guest_for_fuzzing_as_pathbuf())
            .output_data_size(64 * 1024) // 64 KB output buffer
            .input_data_size(64 * 1024) // 64 KB input buffer
            .scratch_size(512 * 1024) // large scratch region to contain those buffers, any data copies, etc.
            .build()
            .unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: (String, ReturnType, Vec<ParameterValue>)| {
        let (host_func_name, host_func_return, mut host_func_params) = data;
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        host_func_params.insert(0, ParameterValue::String(host_func_name.clone()));
        if let Err(e) = sandbox.call_type_erased_guest_function_by_name("FuzzHostFunc", host_func_return, host_func_params) {
            match e {
                // the following are expected errors and occur frequently since
                // we are randomly generating the function name and parameters
                // to call with.
                HyperlightError::HostFunctionNotFound(_) => {}
                HyperlightError::GuestError(ErrorCode::HostFunctionError, msg) if msg == format!("HostFunction {} was not found", host_func_name) => {}
                HyperlightError::UnexpectedNoOfArguments(_, _) => {},
                HyperlightError::GuestError(ErrorCode::HostFunctionError, msg) if msg.contains("The number of arguments to the function is wrong") => {}
                HyperlightError::ParameterValueConversionFailure(_, _) => {},
                HyperlightError::GuestError(ErrorCode::HostFunctionError, msg) if msg.contains("Failed To Convert Parameter Value") => {}

                // any other error should be reported
                _ => panic!("Guest Aborted with Unexpected Error: {:?}", e),
            }
        }
    }
);
