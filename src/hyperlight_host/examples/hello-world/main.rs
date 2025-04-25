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

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_host::func::HostFunction2;
use hyperlight_host::sandbox::sandbox_builder::SandboxBuilder;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox};
use hyperlight_testing::simple_guest_as_string;

fn main() -> hyperlight_host::Result<()> {
    // Create an uninitialized sandbox with a guest binary
    let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?;

    let mut uninitialized_sandbox = sandbox_builder.build()?;

    // Register a host function
    fn add(a: i32, b: i32) -> hyperlight_host::Result<i32> {
        Ok(a + b)
    }
    let host_function = Arc::new(Mutex::new(add));
    host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

    let host_function = Arc::new(Mutex::new(add));

    host_function.register(&mut uninitialized_sandbox, "HostAdd")?;

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

    // Call guest function
    let result = multi_use_sandbox.call_guest_function_by_name(
        "Add", // function must be defined in the guest binary
        ReturnType::Int,
        Some(vec![ParameterValue::Int(1), ParameterValue::Int(41)]),
    )?;

    println!("Guest function result: 1 + 41 = {:?}", result);

    Ok(())
}
