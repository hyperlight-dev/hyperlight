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

use std::marker::PhantomData;
use std::sync::Arc;

use hyperlight_common::flatbuffer_wrappers::function_types::ReturnType;

use super::initialized_multi_use::MultiUseSandbox;
use super::snapshot::Snapshot;
use crate::func::SupportedReturnType;
use crate::{HyperlightError, Result};

/// The result of driving a [`PendingCall`] forward via [`poll()`](PendingCall::poll).
#[derive(Debug)]
pub enum CallProgress<T> {
    /// The guest function completed and returned this value.
    Completed(T),
    /// The VM was paused mid-execution. The [`PendingCall`] can be used to
    /// inspect, snapshot, or resume the paused VM.
    Paused,
}

/// Internal state of the pending call.
enum CallState {
    /// The guest call has not been dispatched yet.
    NotStarted {
        function_name: String,
        return_type: ReturnType,
        args: Vec<hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue>,
    },
    /// The VM is paused mid-execution and can be resumed.
    Paused,
    /// The call has completed or been killed — the pending call is consumed.
    Done,
}

/// A handle to an in-progress guest function call that can be paused and resumed.
///
/// Created by [`MultiUseSandbox::call_async()`]. Holds an exclusive borrow of
/// the sandbox, preventing other operations while the call is in flight.
///
/// # Usage
///
/// ```no_run
/// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
/// # use hyperlight_host::sandbox::pending_call::CallProgress;
/// # use std::thread;
/// # use std::time::Duration;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sandbox: MultiUseSandbox = UninitializedSandbox::new(
///     GuestBinary::FilePath("guest.bin".into()),
///     None
/// )?.evolve()?;
///
/// let mut call = sandbox.call_async::<i32>("LongRunning", (42,));
///
/// // Pause from another thread
/// let handle = call.sandbox().interrupt_handle();
/// thread::spawn(move || {
///     thread::sleep(Duration::from_secs(1));
///     handle.pause();
/// });
///
/// loop {
///     match call.poll()? {
///         CallProgress::Completed(result) => {
///             println!("result: {result}");
///             break;
///         }
///         CallProgress::Paused => {
///             println!("VM paused, resuming...");
///             // Calling poll() again resumes execution
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct PendingCall<'a, Output> {
    sandbox: &'a mut MultiUseSandbox,
    state: CallState,
    _phantom: PhantomData<Output>,
}

impl<'a, Output: SupportedReturnType> PendingCall<'a, Output> {
    /// Create a new `PendingCall` for the given guest function call.
    pub(crate) fn new(
        sandbox: &'a mut MultiUseSandbox,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue>,
    ) -> Self {
        Self {
            sandbox,
            state: CallState::NotStarted {
                function_name: function_name.to_string(),
                return_type,
                args,
            },
            _phantom: PhantomData,
        }
    }

    /// Drive execution until completion or pause.
    ///
    /// - On the first call, dispatches the guest function.
    /// - On subsequent calls after a pause, resumes execution from
    ///   exactly where it was interrupted.
    ///
    /// Returns [`CallProgress::Completed`] when the guest function finishes,
    /// or [`CallProgress::Paused`] if the VM was paused mid-execution.
    pub fn poll(&mut self) -> Result<CallProgress<Output>> {
        match std::mem::replace(&mut self.state, CallState::Done) {
            CallState::NotStarted {
                function_name,
                return_type,
                args,
            } => self.dispatch_and_wait(&function_name, return_type, args),
            CallState::Paused => self.resume_and_wait(),
            CallState::Done => Err(HyperlightError::Error(
                "PendingCall has already completed or been killed".to_string(),
            )),
        }
    }

    /// Returns `true` if the VM is currently paused mid-execution.
    pub fn is_paused(&self) -> bool {
        matches!(self.state, CallState::Paused)
    }

    /// Take a snapshot of the VM in its current state.
    ///
    /// If the VM is paused, this captures a mid-execution snapshot
    /// (memory only — full register state snapshot is not yet implemented).
    /// If the VM has not started, this captures the current quiescent state.
    pub fn snapshot(&mut self) -> Result<Arc<Snapshot>> {
        self.sandbox.snapshot()
    }

    /// Cancel the in-progress call. This poisons the sandbox.
    pub fn kill(mut self) {
        self.sandbox.interrupt_handle().kill();
        self.state = CallState::Done;
    }

    /// Read-only access to the underlying sandbox.
    pub fn sandbox(&self) -> &MultiUseSandbox {
        self.sandbox
    }

    /// Dispatch the initial guest function call and wait for completion or pause.
    fn dispatch_and_wait(
        &mut self,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue>,
    ) -> Result<CallProgress<Output>> {
        // Reset snapshot since we are mutating the sandbox state
        self.sandbox.snapshot = None;

        let res = self
            .sandbox
            .call_guest_function_pausable(function_name, return_type, args);

        match res {
            Ok(val) => {
                self.state = CallState::Done;
                let output = Output::from_value(val)?;
                Ok(CallProgress::Completed(output))
            }
            Err(HyperlightError::ExecutionPaused()) => {
                self.state = CallState::Paused;
                Ok(CallProgress::Paused)
            }
            Err(e) => {
                self.state = CallState::Done;
                Err(e)
            }
        }
    }

    /// Resume a paused VM and wait for completion or another pause.
    fn resume_and_wait(&mut self) -> Result<CallProgress<Output>> {
        let res = self.sandbox.resume_paused_call();

        match res {
            Ok(val) => {
                self.state = CallState::Done;
                let output = Output::from_value(val)?;
                Ok(CallProgress::Completed(output))
            }
            Err(HyperlightError::ExecutionPaused()) => {
                self.state = CallState::Paused;
                Ok(CallProgress::Paused)
            }
            Err(e) => {
                self.state = CallState::Done;
                Err(e)
            }
        }
    }
}

impl<Output> Drop for PendingCall<'_, Output> {
    fn drop(&mut self) {
        if matches!(self.state, CallState::Paused) {
            // The guest was mid-execution and there's no way to resume.
            // This is equivalent to kill() during execution — poison the sandbox.
            self.sandbox.poison();
            self.sandbox.clear_pause();
        }
    }
}
