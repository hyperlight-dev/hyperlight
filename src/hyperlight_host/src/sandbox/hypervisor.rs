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

use std::fmt::Debug;
use std::sync::OnceLock;

#[cfg(kvm)]
use crate::hypervisor::virtual_machine::kvm;
#[cfg(mshv3)]
use crate::hypervisor::virtual_machine::mshv;
use crate::hypervisor::virtual_machine::HypervisorType;

static AVAILABLE_HYPERVISOR: OnceLock<Option<HypervisorType>> = OnceLock::new();

pub fn get_available_hypervisor() -> &'static Option<HypervisorType> {
    AVAILABLE_HYPERVISOR.get_or_init(|| {
        cfg_if::cfg_if! {
            if #[cfg(all(kvm, mshv3))] {
                // If both features are enabled, we need to determine hypervisor at runtime.
                // Currently /dev/kvm and /dev/mshv cannot exist on the same machine, so the first one
                // that works is guaranteed to be correct.
                if mshv::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(kvm)] {
                if kvm::is_hypervisor_present() {
                    Some(HypervisorType::Kvm)
                } else {
                    None
                }
            } else if #[cfg(mshv3)] {
                if mshv::is_hypervisor_present() {
                    Some(HypervisorType::Mshv)
                } else {
                    None
                }
            } else if #[cfg(target_os = "windows")] {
                use crate::hypervisor::vm::whp;

                if whp::is_hypervisor_present() {
                    Some(HypervisorType::Whp)
                } else {
                    None
                }
            } else {
                None
            }
        }
    })
}

// Compiler error if no hypervisor type is available
#[cfg(not(any(kvm, mshv3, target_os = "windows")))]
compile_error!(
    "No hypervisor type is available for the current platform. Please enable either the `kvm` or `mshv3` cargo feature."
);
