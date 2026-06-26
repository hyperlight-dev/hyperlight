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

/// The result of driving a [`PendingCall`] or [`PendingCallOwned`] forward.
#[derive(Debug)]
pub enum CallProgress<T> {
    /// The guest function completed and returned this value.
    Completed(T),
    /// The VM was paused mid-execution. The call handle can be used to
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
            } => {
                let (result, new_state) =
                    dispatch_and_wait::<Output>(self.sandbox, &function_name, return_type, args);
                self.state = new_state;
                result
            }
            CallState::Paused => {
                let (result, new_state) = resume_and_wait::<Output>(self.sandbox);
                self.state = new_state;
                result
            }
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
    /// including full register state (GPRs + FPU), enabling resume
    /// after restore via [`MultiUseSandbox::restore_paused()`].
    /// If the VM has not started, this captures the current quiescent state.
    pub fn snapshot(&mut self) -> Result<Arc<Snapshot>> {
        if self.is_paused() {
            self.sandbox.snapshot_with_regs()
        } else {
            self.sandbox.snapshot()
        }
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

// ─── Shared dispatch/resume logic ───────────────────────────────────────────

fn dispatch_and_wait<Output: SupportedReturnType>(
    sandbox: &mut MultiUseSandbox,
    function_name: &str,
    return_type: ReturnType,
    args: Vec<hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue>,
) -> (Result<CallProgress<Output>>, CallState) {
    // Reset snapshot since we are mutating the sandbox state
    sandbox.snapshot = None;

    let res = sandbox.call_guest_function_pausable(function_name, return_type, args);

    match res {
        Ok(val) => match Output::from_value(val) {
            Ok(output) => (Ok(CallProgress::Completed(output)), CallState::Done),
            Err(e) => (Err(e.into()), CallState::Done),
        },
        Err(HyperlightError::ExecutionPaused()) => (Ok(CallProgress::Paused), CallState::Paused),
        Err(e) => (Err(e), CallState::Done),
    }
}

fn resume_and_wait<Output: SupportedReturnType>(
    sandbox: &mut MultiUseSandbox,
) -> (Result<CallProgress<Output>>, CallState) {
    let res = sandbox.resume_paused_call();

    match res {
        Ok(val) => match Output::from_value(val) {
            Ok(output) => (Ok(CallProgress::Completed(output)), CallState::Done),
            Err(e) => (Err(e.into()), CallState::Done),
        },
        Err(HyperlightError::ExecutionPaused()) => (Ok(CallProgress::Paused), CallState::Paused),
        Err(e) => (Err(e), CallState::Done),
    }
}

// ─── PendingCallOwned ───────────────────────────────────────────────────────

/// An owned handle to an in-progress guest function call that can be paused
/// and resumed.
///
/// Unlike [`PendingCall`], this takes ownership of the [`MultiUseSandbox`],
/// eliminating lifetime parameters. The sandbox can be recovered via
/// [`into_sandbox()`](Self::into_sandbox) after the call completes or is
/// cancelled.
///
/// Created by [`MultiUseSandbox::call_async_owned()`] or
/// [`MultiUseSandbox::restore_paused()`].
///
/// # Usage
///
/// ```no_run
/// # use hyperlight_host::{MultiUseSandbox, UninitializedSandbox, GuestBinary};
/// # use hyperlight_host::sandbox::pending_call::CallProgress;
/// # use std::thread;
/// # use std::time::Duration;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let sandbox: MultiUseSandbox = UninitializedSandbox::new(
///     GuestBinary::FilePath("guest.bin".into()),
///     None
/// )?.evolve()?;
///
/// let mut call = sandbox.call_async_owned::<i32>("LongRunning", (42,));
///
/// // Pause from another thread
/// let handle = call.sandbox().interrupt_handle();
/// thread::spawn(move || {
///     thread::sleep(Duration::from_secs(1));
///     handle.pause();
/// });
///
/// let sandbox = loop {
///     match call.poll()? {
///         CallProgress::Completed(result) => {
///             println!("result: {result}");
///             break call.into_sandbox();
///         }
///         CallProgress::Paused => {
///             println!("VM paused, resuming...");
///         }
///     }
/// };
/// # Ok(())
/// # }
/// ```
pub struct PendingCallOwned<Output> {
    sandbox: Option<MultiUseSandbox>,
    state: CallState,
    _phantom: PhantomData<Output>,
}

impl<Output: SupportedReturnType> PendingCallOwned<Output> {
    /// Create a new `PendingCallOwned` for the given guest function call.
    pub(crate) fn new(
        sandbox: MultiUseSandbox,
        function_name: &str,
        return_type: ReturnType,
        args: Vec<hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue>,
    ) -> Self {
        Self {
            sandbox: Some(sandbox),
            state: CallState::NotStarted {
                function_name: function_name.to_string(),
                return_type,
                args,
            },
            _phantom: PhantomData,
        }
    }

    /// Create a `PendingCallOwned` in the paused state, for resuming from
    /// a restored snapshot that was taken mid-execution.
    pub(crate) fn new_paused(sandbox: MultiUseSandbox) -> Self {
        Self {
            sandbox: Some(sandbox),
            state: CallState::Paused,
            _phantom: PhantomData,
        }
    }

    /// Restore a sandbox from a mid-execution (paused) snapshot and return
    /// a `PendingCallOwned` ready to resume.
    ///
    /// The snapshot must contain register state (i.e., it must have been
    /// taken while the VM was paused). Use [`MultiUseSandbox::restore()`]
    /// for quiescent snapshots instead.
    ///
    /// This is equivalent to [`MultiUseSandbox::restore_paused()`] but
    /// expressed as an associated function on `PendingCallOwned`.
    pub fn from_paused_snapshot(
        mut sandbox: MultiUseSandbox,
        snapshot: Arc<Snapshot>,
    ) -> Result<Self> {
        if snapshot.regs().is_none() {
            return Err(HyperlightError::Error(
                "snapshot does not contain register state; use restore() for quiescent snapshots"
                    .to_string(),
            ));
        }
        sandbox.restore_impl(snapshot)?;
        Ok(Self::new_paused(sandbox))
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
        let sandbox = self.sandbox.as_mut().expect("sandbox taken after Done");
        match std::mem::replace(&mut self.state, CallState::Done) {
            CallState::NotStarted {
                function_name,
                return_type,
                args,
            } => {
                let (result, new_state) =
                    dispatch_and_wait::<Output>(sandbox, &function_name, return_type, args);
                self.state = new_state;
                result
            }
            CallState::Paused => {
                let (result, new_state) = resume_and_wait::<Output>(sandbox);
                self.state = new_state;
                result
            }
            CallState::Done => Err(HyperlightError::Error(
                "PendingCallOwned has already completed or been killed".to_string(),
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
    /// including full register state, enabling resume after restore.
    pub fn snapshot(&mut self) -> Result<Arc<Snapshot>> {
        let paused = self.is_paused();
        let sandbox = self.sandbox.as_mut().expect("sandbox taken after Done");
        if paused {
            sandbox.snapshot_with_regs()
        } else {
            sandbox.snapshot()
        }
    }

    /// Cancel the in-progress call. This poisons the sandbox.
    ///
    /// Returns the (poisoned) sandbox so you can restore it from a snapshot.
    pub fn kill(mut self) -> MultiUseSandbox {
        let sandbox = self.sandbox.as_mut().expect("sandbox taken after Done");
        sandbox.interrupt_handle().kill();
        self.state = CallState::Done;
        self.sandbox.take().unwrap()
    }

    /// Consume this handle and return the underlying sandbox.
    ///
    /// - If the call has completed (state is `Done`), returns the sandbox
    ///   in a non-poisoned, usable state.
    /// - If the call is still paused, this poisons the sandbox before
    ///   returning it (since the mid-execution state cannot be resumed
    ///   without the `PendingCallOwned`).
    pub fn into_sandbox(mut self) -> MultiUseSandbox {
        if matches!(self.state, CallState::Paused) {
            let sandbox = self.sandbox.as_mut().unwrap();
            sandbox.poison();
            sandbox.clear_pause();
        }
        self.state = CallState::Done;
        self.sandbox.take().unwrap()
    }

    /// Read-only access to the underlying sandbox.
    pub fn sandbox(&self) -> &MultiUseSandbox {
        self.sandbox.as_ref().expect("sandbox taken after Done")
    }
}

impl<Output> Drop for PendingCallOwned<Output> {
    fn drop(&mut self) {
        if matches!(self.state, CallState::Paused) {
            if let Some(sandbox) = self.sandbox.as_mut() {
                sandbox.poison();
                sandbox.clear_pause();
            }
        }
    }
}
