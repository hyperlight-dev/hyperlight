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

use libc::c_int;

use crate::sandbox::SandboxConfiguration;

#[cfg(feature = "seccomp")]
pub mod sigsys_signal_handler;

pub(crate) fn setup_signal_handlers(config: &SandboxConfiguration) -> crate::Result<()> {
    // This is unsafe because signal handlers only allow a very restrictive set of
    // functions (i.e., async-signal-safe functions) to be executed inside them.
    // Anything that performs memory allocations, locks, and others are non-async-signal-safe.
    // Hyperlight signal handlers are all designed to be async-signal-safe, so this function
    // should be safe to call.
    #[cfg(feature = "seccomp")]
    {
        vmm_sys_util::signal::register_signal_handler(
            libc::SIGSYS,
            sigsys_signal_handler::handle_sigsys,
        )?;

        let original_hook = std::panic::take_hook();
        // Set a custom panic hook that checks for "DisallowedSyscall"
        std::panic::set_hook(Box::new(move |panic_info| {
            // Check if the panic payload matches "DisallowedSyscall"
            if let Some(crate::HyperlightError::DisallowedSyscall) = panic_info
                .payload()
                .downcast_ref::<crate::HyperlightError>(
            ) {
                // Do nothing to avoid superfluous syscalls
                return;
            }
            // If not "DisallowedSyscall", use the original hook
            original_hook(panic_info);
        }));
    }
    vmm_sys_util::signal::register_signal_handler(
        libc::SIGRTMIN() + config.get_interrupt_vcpu_sigrtmin_offset() as c_int,
        vm_kill_signal,
    )?;

    // Note: For libraries registering signal handlers, it's important to keep in mind that
    // the user of the library could have their own signal handlers that we don't want to
    // overwrite. The common practice there is to provide signal handling chaining, which
    // means that the signal is handled by all registered handlers from the last registered
    // to the first. **Hyperlight does not provide signal chaining**. For SIGSYS, this is because,
    // currently, Hyperlight handles SIGSYS signals by directly altering the instruction pointer at
    // the time the syscall occurred to call a function that will panic the host function execution.
    // For SIGRTMIN, this is because Hyperlight issues potentially 200 signals back-to-back and its
    // likely that the embedder will not want to handle this.

    Ok(())
}

extern "C" fn vm_kill_signal(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // Do nothing. SIGRTMIN is just used to issue a VM exit to the underlying VM.
}
