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

/// Configuration needed to establish a sandbox.
pub mod config;
/// Functionality for reading, but not modifying host functions
pub(crate) mod host_funcs;
/// Functionality for dealing with `Sandbox`es that contain Hypervisors
pub(crate) mod hypervisor;
/// Functionality for dealing with initialized sandboxes that can
/// call 0 or more guest functions
pub mod initialized_multi_use;
pub(crate) mod outb;
/// Functionality for creating uninitialized sandboxes, manipulating them,
/// and converting them to initialized sandboxes.
pub mod uninitialized;
/// Functionality for properly converting `UninitializedSandbox`es to
/// initialized `Sandbox`es.
pub(crate) mod uninitialized_evolve;

/// Representation of a snapshot of a `Sandbox`.
pub mod snapshot;

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
mod callable;

#[cfg(feature = "unwind_guest")]
use std::io::Write;
#[cfg(feature = "trace_guest")]
use std::sync::{Arc, Mutex};

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
pub use callable::Callable;
/// Re-export for `SandboxConfiguration` type
pub use config::SandboxConfiguration;
#[cfg(feature = "unwind_guest")]
use framehop::Unwinder;
/// Re-export for the `MultiUseSandbox` type
pub use initialized_multi_use::MultiUseSandbox;
use tracing::{Span, instrument};
/// Re-export for `GuestBinary` type
pub use uninitialized::GuestBinary;
/// Re-export for `UninitializedSandbox` type
pub use uninitialized::UninitializedSandbox;

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
///  Returns a boolean indicating whether a suitable hypervisor is present.
#[instrument(skip_all, parent = Span::current())]
pub fn is_hypervisor_present() -> bool {
    hypervisor::get_available_hypervisor().is_some()
}

#[cfg(feature = "trace_guest")]
#[derive(Clone)]
/// The information that trace collection requires in order to write
/// an accurate trace.
pub(crate) struct TraceInfo {
    /// The epoch against which trace events are timed; at least as
    /// early as the creation of the sandbox being traced.
    pub epoch: std::time::Instant,
    /// The frequency of the timestamp counter.
    pub tsc_freq: Option<u64>,
    /// The epoch at which the guest started, if it has started.
    /// This is used to calculate the time spent in the guest relative to the
    /// time when the host started.
    pub guest_start_epoch: Option<std::time::Instant>,
    /// The start guest time, in TSC cycles, for the current guest has a double purpose.
    /// This field is used in two ways:
    /// 1. It contains the TSC value recorded on the host when the guest started.
    ///    This is used to calculate the TSC frequency which is the same on the host and guest.
    ///    The TSC frequency is used to convert TSC values to timestamps in the trace.
    ///    **NOTE**: This is only used until the TSC frequency is calculated, when the first
    ///    records are received.
    /// 2. To store the TSC value at recorded on the guest when the guest started (first record
    ///    received)
    ///    This is used to calculate the records timestamps relative to when guest started.
    pub guest_start_tsc: Option<u64>,
    /// The file to which the trace is being written
    #[allow(dead_code)]
    pub file: Arc<Mutex<std::fs::File>>,
    /// The unwind information for the current guest
    #[cfg(feature = "unwind_guest")]
    #[allow(dead_code)]
    pub unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    /// The framehop unwinder for the current guest
    #[cfg(feature = "unwind_guest")]
    pub unwinder: framehop::x86_64::UnwinderX86_64<Vec<u8>>,
    /// The framehop cache
    #[cfg(feature = "unwind_guest")]
    pub unwind_cache: Arc<Mutex<framehop::x86_64::CacheX86_64>>,
}
#[cfg(feature = "trace_guest")]
impl TraceInfo {
    /// Create a new TraceInfo by saving the current time as the epoch
    /// and generating a random filename.
    pub fn new(
        #[cfg(feature = "unwind_guest")] unwind_module: Arc<dyn crate::mem::exe::UnwindInfo>,
    ) -> crate::Result<Self> {
        let mut path = std::env::current_dir()?;
        path.push("trace");

        // create directory if it does not exist
        if !path.exists() {
            std::fs::create_dir(&path)?;
        }
        path.push(uuid::Uuid::new_v4().to_string());
        path.set_extension("trace");

        log::info!("Creating trace file at: {}", path.display());
        println!("Creating trace file at: {}", path.display());

        #[cfg(feature = "unwind_guest")]
        let hash = unwind_module.hash();
        #[cfg(feature = "unwind_guest")]
        let (unwinder, unwind_cache) = {
            let mut unwinder = framehop::x86_64::UnwinderX86_64::new();
            unwinder.add_module(unwind_module.clone().as_module());
            let cache = framehop::x86_64::CacheX86_64::new();
            (unwinder, Arc::new(Mutex::new(cache)))
        };
        if !hyperlight_guest_tracing::invariant_tsc::has_invariant_tsc() {
            // If the platform does not support invariant TSC, warn the user.
            // On Azure nested virtualization, the TSC invariant bit is not correctly reported, this is a known issue.
            log::warn!(
                "Invariant TSC is not supported on this platform, trace timestamps may be inaccurate"
            );
        }

        let ret = Self {
            epoch: std::time::Instant::now(),
            tsc_freq: None,
            guest_start_epoch: None,
            guest_start_tsc: None,
            file: Arc::new(Mutex::new(std::fs::File::create_new(path)?)),
            #[cfg(feature = "unwind_guest")]
            unwind_module,
            #[cfg(feature = "unwind_guest")]
            unwinder,
            #[cfg(feature = "unwind_guest")]
            unwind_cache,
        };
        /* write a frame identifying the binary */
        #[cfg(feature = "unwind_guest")]
        self::outb::record_trace_frame(&ret, 0, |f| {
            let _ = f.write_all(hash.as_bytes());
        })?;
        Ok(ret)
    }

    /// Calculate the TSC frequency based on the RDTSC instruction on the host.
    fn calculate_tsc_freq(&mut self) -> crate::Result<()> {
        let (start, start_time) = match (
            self.guest_start_tsc.as_ref(),
            self.guest_start_epoch.as_ref(),
        ) {
            (Some(start), Some(start_time)) => (*start, *start_time),
            _ => {
                // If the guest start TSC and time are not set, we use the current time and TSC.
                // This is not ideal, but it allows us to calculate the TSC frequency without
                // failing.
                // This is a fallback mechanism to ensure that we can still calculate, however it
                // should be noted that this may lead to inaccuracies in the TSC frequency.
                // The start time should be already set before running the guest for each sandbox.
                log::error!(
                    "Guest start TSC and time are not set. Calculating TSC frequency will use current time and TSC."
                );
                (
                    hyperlight_guest_tracing::invariant_tsc::read_tsc(),
                    std::time::Instant::now(),
                )
            }
        };

        let end_time = std::time::Instant::now();
        let end = hyperlight_guest_tracing::invariant_tsc::read_tsc();

        let elapsed = end_time.duration_since(start_time).as_secs_f64();
        let tsc_freq = ((end - start) as f64 / elapsed) as u64;

        log::info!("Calculated TSC frequency: {} Hz", tsc_freq);
        self.tsc_freq = Some(tsc_freq);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use crossbeam_queue::ArrayQueue;
    use hyperlight_testing::simple_guest_as_string;

    use crate::sandbox::uninitialized::GuestBinary;
    use crate::{MultiUseSandbox, UninitializedSandbox, new_error};

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

                    let sandbox = uninitialized_sandbox.evolve().unwrap_or_else(|_| {
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
