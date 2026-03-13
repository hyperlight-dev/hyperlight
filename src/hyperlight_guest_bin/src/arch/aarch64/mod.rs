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

// TODO(aarch64): implement aarch64 guest runtime

pub mod dispatch {
    /// Dispatch function pointer — set during initialisation and called
    /// by the host for each guest function invocation.
    #[unsafe(no_mangle)]
    pub extern "C" fn dispatch_function() {
        unimplemented!("aarch64 dispatch_function")
    }
}

/// The entrypoint for the guest binary — called by the hypervisor.
///
/// On aarch64 this is a stub that will be implemented when the
/// aarch64 hypervisor backend is ready.
#[unsafe(no_mangle)]
pub extern "C" fn entrypoint() -> ! {
    unimplemented!("aarch64 entrypoint")
}
