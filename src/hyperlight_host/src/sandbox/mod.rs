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

/// Configuration needed to establish a sandbox.
pub mod config;
/// Functionality for reading, but not modifying host functions
mod host_funcs;
/// Functionality for dealing with `Sandbox`es that contain Hypervisors
pub(crate) mod hypervisor;
/// Functionality for dealing with initialized sandboxes that can
/// call 0 or more guest functions
pub mod initialized_multi_use;
/// Functionality for dealing with memory access from the VM guest
/// executable
pub(crate) mod mem_access;
/// Functionality for interacting with a sandbox's internally-stored
/// `SandboxMemoryManager`
pub(crate) mod mem_mgr;
pub(crate) mod outb;
/// Functionality for creating uninitialized sandboxes, manipulating them,
/// and converting them to initialized sandboxes.
pub mod uninitialized;
/// Functionality for properly converting `UninitializedSandbox`es to
/// initialized `Sandbox`es.
pub(crate) mod uninitialized_evolve;

/// Re-export for `SandboxConfiguration` type
pub use config::SandboxConfiguration;
/// Re-export for the `MultiUseSandbox` type
pub use initialized_multi_use::MultiUseSandbox;
use tracing::{instrument, Span};
/// Re-export for `GuestBinary` type
pub use uninitialized::GuestBinary;
/// Re-export for `UninitializedSandbox` type
pub use uninitialized::UninitializedSandbox;

use self::mem_mgr::MemMgrWrapper;
use crate::hypervisor::hypervisor_handler::HypervisorHandler;
#[cfg(target_os = "windows")]
use crate::hypervisor::windows_hypervisor_platform;
use crate::mem::shared_mem::HostSharedMemory;

// In case its not obvious why there are separate is_supported_platform and is_hypervisor_present functions its because
// Hyperlight is designed to be able to run on a host that doesn't have a hypervisor.
// In that case, the sandbox will be in process, we plan on making this a dev only feature and fixing up Linux support
// so we should review the need for this function at that time.

/// Determine if this is a supported platform for Hyperlight
///
/// Returns a boolean indicating whether this is a supported platform.
#[instrument(skip_all, parent = Span::current())]
pub fn is_supported_platform() -> bool {
    #[cfg(not(target_os = "linux"))]
    #[cfg(not(target_os = "windows"))]
    return false;

    true
}

/// Alias for the type of extra allowed syscalls.
pub type ExtraAllowedSyscall = i64;

/// Determine whether a suitable hypervisor is available to run
/// this sandbox.
///
//  Returns a boolean indicating whether a suitable hypervisor is present.
#[instrument(skip_all, parent = Span::current())]
pub fn is_hypervisor_present() -> bool {
    hypervisor::get_available_hypervisor().is_some()
}

pub(crate) trait WrapperGetter {
    #[allow(dead_code)]
    fn get_mgr_wrapper(&self) -> &MemMgrWrapper<HostSharedMemory>;
    fn get_mgr_wrapper_mut(&mut self) -> &mut MemMgrWrapper<HostSharedMemory>;
    fn get_hv_handler(&self) -> &HypervisorHandler;
    #[allow(dead_code)]
    fn get_hv_handler_mut(&mut self) -> &mut HypervisorHandler;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use crossbeam_queue::ArrayQueue;
    use hyperlight_testing::simple_guest_as_string;

    use crate::sandbox::uninitialized::GuestBinary;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::{new_error, MultiUseSandbox, UninitializedSandbox};

    #[test]
    // TODO: add support for testing on WHP
    #[cfg(target_os = "linux")]
    fn is_hypervisor_present() {
        use std::path::Path;

        cfg_if::cfg_if! {
            if #[cfg(all(kvm, mshv))] {
                assert_eq!(Path::new("/dev/kvm").exists() || Path::new("/dev/mshv").exists(), super::is_hypervisor_present());
            } else if #[cfg(kvm)] {
                assert_eq!(Path::new("/dev/kvm").exists(), super::is_hypervisor_present());
            } else if #[cfg(mshv)] {
                assert_eq!(Path::new("/dev/mshv").exists(), super::is_hypervisor_present());
            } else {
                assert!(!super::is_hypervisor_present());
            }
        }
    }

    #[test]
    fn check_create_and_use_sandbox_on_different_threads() {
        let unintializedsandbox_queue = Arc::new(ArrayQueue::<UninitializedSandbox>::new(10));
        let sandbox_queue = Arc::new(ArrayQueue::<MultiUseSandbox>::new(10));

        for i in 0..10 {
            let simple_guest_path = simple_guest_as_string().expect("Guest Binary Missing");
            let unintializedsandbox =
                UninitializedSandbox::new(GuestBinary::FilePath(simple_guest_path), None)
                    .unwrap_or_else(|_| panic!("Failed to create UninitializedSandbox {}", i));

            unintializedsandbox_queue
                .push(unintializedsandbox)
                .unwrap_or_else(|_| panic!("Failed to push UninitializedSandbox {}", i));
        }

        let thread_handles = (0..10)
            .map(|i| {
                let uq = unintializedsandbox_queue.clone();
                let sq = sandbox_queue.clone();
                thread::spawn(move || {
                    let uninitialized_sandbox = uq.pop().unwrap_or_else(|| {
                        panic!("Failed to pop UninitializedSandbox thread {}", i)
                    });
                    let host_funcs = uninitialized_sandbox
                        .host_funcs
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"));

                    assert!(host_funcs.is_ok());

                    host_funcs
                        .unwrap()
                        .host_print(format!(
                            "Printing from UninitializedSandbox on Thread {}\n",
                            i
                        ))
                        .unwrap();

                    let sandbox = uninitialized_sandbox
                        .evolve(Noop::default())
                        .unwrap_or_else(|_| {
                            panic!("Failed to initialize UninitializedSandbox thread {}", i)
                        });

                    sq.push(sandbox).unwrap_or_else(|_| {
                        panic!("Failed to push UninitializedSandbox thread {}", i)
                    })
                })
            })
            .collect::<Vec<_>>();

        for handle in thread_handles {
            handle.join().unwrap();
        }

        let thread_handles = (0..10)
            .map(|i| {
                let sq = sandbox_queue.clone();
                thread::spawn(move || {
                    let sandbox = sq
                        .pop()
                        .unwrap_or_else(|| panic!("Failed to pop Sandbox thread {}", i));
                    let host_funcs = sandbox
                        ._host_funcs
                        .try_lock()
                        .map_err(|_| new_error!("Error locking"));

                    assert!(host_funcs.is_ok());

                    host_funcs
                        .unwrap()
                        .host_print(format!("Print from Sandbox on Thread {}\n", i))
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for handle in thread_handles {
            handle.join().unwrap();
        }
    }
}
