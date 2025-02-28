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

use hyperlight_host::func::{ParameterValue, ReturnType};
use hyperlight_host::sandbox::uninitialized::GuestBinary;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_as_string;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (ReturnType, Option<Vec<ParameterValue>>)| {
    let u_sbox = UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().expect("Guest Binary Missing")),
        None,
        None,
        None,
    )
    .unwrap();

    let mut mu_sbox: MultiUseSandbox = u_sbox.evolve(Noop::default()).unwrap();

    let _ = mu_sbox.call_guest_function_by_name("PrintOutput", data.0, data.1);
});
