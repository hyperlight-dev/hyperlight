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
use std::thread;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_host::func::HostFunction0;
#[cfg(gdb)]
use hyperlight_host::sandbox::config::DebugInfo;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

/// Build a sandbox configuration that enables GDB debugging when the `gdb` feature is enabled.
fn get_sandbox_cfg() -> Option<SandboxConfiguration> {
    #[cfg(gdb)]
    {
        let mut cfg = SandboxConfiguration::default();
        let debug_info = DebugInfo { port: 8080 };
        cfg.set_guest_debug_info(debug_info);

        Some(cfg)
    }

    #[cfg(not(gdb))]
    None
}

fn main() -> hyperlight_host::Result<()> {
    let cfg = get_sandbox_cfg();

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        cfg,  // sandbox configuration
        None, // default run options
        None, // default host print function
    )?;

    // Register a host functions
    fn sleep_5_secs() -> hyperlight_host::Result<()> {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    }

    let host_function = Arc::new(Mutex::new(sleep_5_secs));

    host_function.register(&mut uninitialized_sandbox, "Sleep5Secs")?;
    // Note: This function is unused, it's just here for demonstration purposes

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

    // Call guest function
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    let result = multi_use_sandbox.call_guest_function_by_name(
        "PrintOutput", // function must be defined in the guest binary
        ReturnType::Int,
        Some(vec![ParameterValue::String(message.clone())]),
    );

    assert!(result.is_ok());

    Ok(())
}
