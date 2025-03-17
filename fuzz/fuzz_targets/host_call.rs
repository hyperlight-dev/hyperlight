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

#![no_main]

use std::sync::{Mutex, OnceLock};

use hyperlight_host::func::{ParameterValue, ReturnType};
use hyperlight_host::sandbox::uninitialized::GuestBinary;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{HyperlightError, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_for_fuzzing_as_string;
use libfuzzer_sys::fuzz_target;
static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target tests all combinations of ReturnType and Parameters for `call_guest_function_by_name`.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let u_sbox = UninitializedSandbox::new(
            GuestBinary::FilePath(simple_guest_for_fuzzing_as_string().expect("Guest Binary Missing")),
            None,
            None,
            None,
        )
        .unwrap();

        let mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: (String, ReturnType, Vec<ParameterValue>)| {
        let (host_func_name, host_func_return, mut host_func_params) = data;
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        host_func_params.insert(0, ParameterValue::String(host_func_name));
        match sandbox.call_guest_function_by_name("FuzzHostFunc", host_func_return, Some(host_func_params)) {
            Err(HyperlightError::GuestAborted(_, message)) if !message.contains("Host Function Not Found") => {
                // We don't allow GuestAborted errors, except for the "Host Function Not Found" case
                panic!("Guest Aborted: {}", message);
            }
            _ => {}
        }
    }
);
