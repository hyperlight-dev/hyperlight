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

use std::sync::{Mutex, OnceLock};

use hyperlight_host::func::{ParameterValue, ReturnType};
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox::snapshot::Snapshot;
use hyperlight_host::sandbox::uninitialized::GuestBinary;
use hyperlight_host::{HyperlightError, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_for_fuzzing_as_string;
use libfuzzer_sys::fuzz_target;

// TODO: this SNAPSHOT is needed because of the memory leak in: https://github.com/hyperlight-dev/hyperlight/issues/826
// This should be removed once the leak is fixed
static SNAPSHOT: OnceLock<Mutex<Snapshot>> = OnceLock::new();
static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target tests all combinations of ReturnType and Parameters for `call_guest_function_by_name`.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let mut cfg = SandboxConfiguration::default();
        cfg.set_output_data_size(64 * 1024); // 64 KB output buffer
        cfg.set_input_data_size(64 * 1024); // 64 KB input buffer
        let u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_for_fuzzing_as_string().expect("Guest Binary Missing")),
            Some(cfg)
        )
        .unwrap();

        let mut mu_sbox: MultiUseSandbox = u_sbox.evolve().unwrap();
        let snapshot = mu_sbox.snapshot().unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
        SNAPSHOT.set(Mutex::new(snapshot)).map_err(|_| "Snapshot already set").unwrap();
    },

    |data: (String, ReturnType, Vec<ParameterValue>)| {
        let (host_func_name, host_func_return, mut host_func_params) = data;
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        let snapshot = SNAPSHOT.get().unwrap().lock().unwrap();
        sandbox.restore(&snapshot).unwrap();

        host_func_params.insert(0, ParameterValue::String(host_func_name));
        match sandbox.call_type_erased_guest_function_by_name("FuzzHostFunc", host_func_return, host_func_params) {
            Err(e) => {
                match e {
                    // the following are expected errors and occur frequently since
                    // we are randomly generating the function name and parameters
                    // to call with.
                    HyperlightError::HostFunctionNotFound(_) => {}
                    HyperlightError::UnexpectedNoOfArguments(_, _) => {},
                    HyperlightError::ParameterValueConversionFailure(_, _) => {},

                    // any other error should be reported
                    _ => panic!("Guest Aborted with Unexpected Error: {:?}", e),
                }
            }
            _ => {}
        }
    }
);
