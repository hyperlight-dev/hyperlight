// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#![no_main]

use std::sync::{Mutex, OnceLock};

use hyperlight_host::func::{ParameterValue, ReturnType};
use hyperlight_host::{MultiUseSandbox, SandboxBuilder};
use hyperlight_testing::simple_guest_for_fuzzing_as_pathbuf;
use libfuzzer_sys::fuzz_target;
static SANDBOX: OnceLock<Mutex<MultiUseSandbox>> = OnceLock::new();

// This fuzz target tests all combinations of ReturnType and Parameters for `call_guest_function_by_name`.
// For fuzzing efficiency, we create one Sandbox and reuse it for all fuzzing iterations.
fuzz_target!(
    init: {
        let mu_sbox = SandboxBuilder::from_file(simple_guest_for_fuzzing_as_pathbuf())
            .build()
            .unwrap();
        SANDBOX.set(Mutex::new(mu_sbox)).unwrap();
    },

    |data: (ReturnType, Vec<ParameterValue>)| {
        let mut sandbox = SANDBOX.get().unwrap().lock().unwrap();
        let _ = sandbox.call_type_erased_guest_function_by_name("PrintOutput", data.0, data.1);
    }
);
