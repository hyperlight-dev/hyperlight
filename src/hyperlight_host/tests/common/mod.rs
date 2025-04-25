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

use hyperlight_host::sandbox::sandbox_builder::SandboxBuilder;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, MultiUseSandbox, Result, UninitializedSandbox};
use hyperlight_testing::{
    c_callback_guest_as_string, c_simple_guest_as_string, callback_guest_as_string,
    simple_guest_as_string,
};

/// Returns a rust/c simpleguest depending on environment variable GUEST.
/// Uses rust guest by default. Run test with environment variable GUEST="c" to use the c version
/// If a test is only applicable to rust, use `new_uninit_rust`` instead
pub fn new_uninit() -> Result<UninitializedSandbox> {
    let sandbox_builder =
        SandboxBuilder::new(GuestBinary::FilePath(get_c_or_rust_simpleguest_path()))?;
    sandbox_builder.build()
}

/// Use this instead of the `new_uninit` if you want your test to only run with the rust guest, not the c guest
pub fn new_uninit_rust() -> Result<UninitializedSandbox> {
    SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string()?))?.build()
}

pub fn get_simpleguest_sandboxes() -> Result<Vec<MultiUseSandbox>> {
    let elf_path = get_c_or_rust_simpleguest_path();
    let exe_path = format!("{elf_path}.exe");

    Ok(vec![
        // in hypervisor elf
        SandboxBuilder::new(GuestBinary::FilePath(elf_path.clone()))?
            .build()?
            .evolve(Noop::default())?,
        // in hypervisor exe
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?
            .build()?
            .evolve(Noop::default())?,
        // in-process elf
        #[cfg(inprocess)]
        SandboxBuilder::new(GuestBinary::FilePath(elf_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(false))?
            .build()?
            .evolve(Noop::default())?,
        //in-process exe
        #[cfg(inprocess)]
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(false))?
            .build()?
            .evolve(Noop::default())?,
        // loadlib in process
        #[cfg(all(target_os = "windows", inprocess))]
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(true))?
            .build()?
            .evolve(Noop::default())?,
    ])
}

pub fn get_callbackguest_uninit_sandboxes() -> Result<Vec<UninitializedSandbox>> {
    let elf_path = get_c_or_rust_callbackguest_path();
    let exe_path = format!("{elf_path}.exe");

    Ok(vec![
        // in hypervisor elf
        SandboxBuilder::new(GuestBinary::FilePath(elf_path.clone()))?.build()?,
        // in hypervisor exe
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?.build()?,
        // in-process elf
        #[cfg(inprocess)]
        SandboxBuilder::new(GuestBinary::FilePath(elf_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(false))?
            .build()?,
        //in-process exe
        #[cfg(inprocess)]
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(false))?
            .build()?,
        // loadlib in process
        #[cfg(all(target_os = "windows", inprocess))]
        SandboxBuilder::new(GuestBinary::FilePath(exe_path.clone()))?
            .set_sandbox_run_options(hyperlight_host::SandboxRunOptions::RunInProcess(true))?
            .build()?,
    ])
}

// returns the path of simpleguest binary. Picks rust/c version depending on environment variable GUEST (or rust by default if unset)
pub(crate) fn get_c_or_rust_simpleguest_path() -> String {
    let guest_type = std::env::var("GUEST").unwrap_or("rust".to_string());
    match guest_type.as_str() {
        "rust" => simple_guest_as_string().unwrap(),
        "c" => c_simple_guest_as_string().unwrap(),
        _ => panic!("Unknown guest type '{guest_type}', use either 'rust' or 'c'"),
    }
}

// returns the path of callbackguest binary. Picks rust/ version depending on environment variable GUEST (or rust by default if unset)
fn get_c_or_rust_callbackguest_path() -> String {
    let guest_type = std::env::var("GUEST").unwrap_or("rust".to_string());
    match guest_type.as_str() {
        "rust" => callback_guest_as_string().unwrap(),
        "c" => c_callback_guest_as_string().unwrap(),
        _ => panic!("Unknown guest type '{guest_type}', use either 'rust' or 'c'"),
    }
}
