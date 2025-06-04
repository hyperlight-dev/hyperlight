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
use hyperlight_host::func::HostFunction;
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
    UninitializedSandbox::new(
        GuestBinary::FilePath(get_c_or_rust_simpleguest_path()),
        None,
    )
}

/// Use this instead of the `new_uninit` if you want your test to only run with the rust guest, not the c guest
pub fn new_uninit_rust() -> Result<UninitializedSandbox> {
    UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().unwrap()),
        None,
    )
}

pub fn get_simpleguest_sandboxes(
    writer: Option<HostFunction<i32, (String,)>>, // An optional writer to make sure correct info is passed to the host printer
) -> Vec<MultiUseSandbox> {
    let elf_path = get_c_or_rust_simpleguest_path();

    let sandboxes = [
        // in hypervisor elf
        UninitializedSandbox::new(GuestBinary::FilePath(elf_path.clone()), None).unwrap(),
    ];

    sandboxes
        .into_iter()
        .map(|mut sandbox| {
            if let Some(writer) = writer.clone() {
                sandbox.register_print(writer).unwrap();
            }
            sandbox.evolve(Noop::default()).unwrap()
        })
        .collect()
}

pub fn get_callbackguest_uninit_sandboxes(
    writer: Option<HostFunction<i32, (String,)>>, // An optional writer to make sure correct info is passed to the host printer
) -> Vec<UninitializedSandbox> {
    let elf_path = get_c_or_rust_callbackguest_path();

    let sandboxes = [
        // in hypervisor elf
        UninitializedSandbox::new(GuestBinary::FilePath(elf_path.clone()), None).unwrap(),
    ];

    sandboxes
        .into_iter()
        .map(|mut sandbox| {
            if let Some(writer) = writer.clone() {
                sandbox.register_print(writer).unwrap();
            }
            sandbox
        })
        .collect()
}

// returns the the path of simpleguest binary. Picks rust/c version depending on environment variable GUEST (or rust by default if unset)
pub(crate) fn get_c_or_rust_simpleguest_path() -> String {
    let guest_type = std::env::var("GUEST").unwrap_or("rust".to_string());
    match guest_type.as_str() {
        "rust" => simple_guest_as_string().unwrap(),
        "c" => c_simple_guest_as_string().unwrap(),
        _ => panic!("Unknown guest type '{guest_type}', use either 'rust' or 'c'"),
    }
}

// returns the the path of callbackguest binary. Picks rust/ version depending on environment variable GUEST (or rust by default if unset)
fn get_c_or_rust_callbackguest_path() -> String {
    let guest_type = std::env::var("GUEST").unwrap_or("rust".to_string());
    match guest_type.as_str() {
        "rust" => callback_guest_as_string().unwrap(),
        "c" => c_callback_guest_as_string().unwrap(),
        _ => panic!("Unknown guest type '{guest_type}', use either 'rust' or 'c'"),
    }
}
