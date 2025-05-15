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

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tracing::{instrument, Span};

use super::ExtraAllowedSyscall;
use crate::func::host_functions::TypeErasedHostFunction;
use crate::HyperlightError::HostFunctionNotFound;
use crate::{new_error, Result};

#[derive(Default)]
/// A Wrapper around details of functions exposed by the Host
pub struct FunctionRegistry {
    functions_map: HashMap<String, FunctionEntry>,
}

pub struct FunctionEntry {
    pub function: TypeErasedHostFunction,
    pub extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
}

impl FunctionRegistry {
    /// Register a host function with the sandbox.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn register_host_function(
        &mut self,
        name: String,
        func: TypeErasedHostFunction,
    ) -> Result<()> {
        self.register_host_function_helper(name, func, None)
    }

    /// Register a host function with the sandbox, with a list of extra syscalls
    /// that the function is allowed to make.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    pub(crate) fn register_host_function_with_syscalls(
        &mut self,
        name: String,
        func: TypeErasedHostFunction,
        extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()> {
        self.register_host_function_helper(name, func, Some(extra_allowed_syscalls))
    }

    /// Assuming a host function called `"HostPrint"` exists, and takes a
    /// single string parameter, call it with the given `msg` parameter.
    ///
    /// Return `Ok` if the function was found and was of the right signature,
    /// and `Err` otherwise.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn host_print(&mut self, msg: String) -> Result<i32> {
        let res = self.call_host_func_impl("HostPrint", vec![ParameterValue::String(msg)])?;
        res.try_into()
            .map_err(|_| HostFunctionNotFound("HostPrint".to_string()))
    }
    /// From the set of registered host functions, attempt to get the one
    /// named `name`. If it exists, call it with the given arguments list
    /// `args` and return its result.
    ///
    /// Return `Err` if no such function exists,
    /// its parameter list doesn't match `args`, or there was another error
    /// getting, configuring or calling the function.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(super) fn call_host_function(
        &self,
        name: &str,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        self.call_host_func_impl(name, args)
    }

    fn register_host_function_helper(
        &mut self,
        name: String,
        function: TypeErasedHostFunction,
        extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
    ) -> Result<()> {
        #[cfg(not(all(feature = "seccomp", target_os = "linux")))]
        if extra_allowed_syscalls.is_some() {
            return Err(new_error!(
                "Extra syscalls are only supported on Linux with seccomp"
            ));
        }

        self.functions_map.insert(
            name,
            FunctionEntry {
                function,
                extra_allowed_syscalls,
            },
        );
        Ok(())
    }

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn call_host_func_impl(&self, name: &str, args: Vec<ParameterValue>) -> Result<ReturnValue> {
        let FunctionEntry {
            function,
            extra_allowed_syscalls,
        } = self
            .functions_map
            .get(name)
            .ok_or_else(|| HostFunctionNotFound(name.to_string()))?;

        // Create a new thread when seccomp is enabled on Linux
        maybe_with_seccomp(name, extra_allowed_syscalls.as_deref(), || {
            crate::metrics::maybe_time_and_emit_host_call(name, || function.call(args))
        })
    }
}

/// The default writer function is to write to stdout with green text.
#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
pub(super) fn default_writer_func(s: String) -> Result<i32> {
    match std::io::stdout().is_terminal() {
        false => {
            print!("{}", s);
            Ok(s.len() as i32)
        }
        true => {
            let mut stdout = StandardStream::stdout(ColorChoice::Auto);
            let mut color_spec = ColorSpec::new();
            color_spec.set_fg(Some(Color::Green));
            stdout.set_color(&color_spec)?;
            stdout.write_all(s.as_bytes())?;
            stdout.reset()?;
            Ok(s.len() as i32)
        }
    }
}

#[cfg(all(feature = "seccomp", target_os = "linux"))]
fn maybe_with_seccomp<T: Send>(
    name: &str,
    syscalls: Option<&[ExtraAllowedSyscall]>,
    f: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    use crate::seccomp::guest::get_seccomp_filter_for_host_function_worker_thread;

    // Use a scoped thread so that we can pass around references without having to clone them.
    crossbeam::thread::scope(|s| {
        s.builder()
            .name(format!("Host Function Worker Thread for: {name:?}"))
            .spawn(move |_| {
                let seccomp_filter = get_seccomp_filter_for_host_function_worker_thread(syscalls)?;
                seccompiler::apply_filter(&seccomp_filter)?;

                // We have a `catch_unwind` here because, if a disallowed syscall is issued,
                // we handle it by panicking. This is to avoid returning execution to the
                // offending host function—for two reasons: (1) if a host function is issuing
                // disallowed syscalls, it could be unsafe to return to, and (2) returning
                // execution after trapping the disallowed syscall can lead to UB (e.g., try
                // running a host function that attempts to sleep without `SYS_clock_nanosleep`,
                // you'll block the syscall but panic in the aftermath).
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
                    Ok(val) => val,
                    Err(err) => {
                        if let Some(crate::HyperlightError::DisallowedSyscall) =
                            err.downcast_ref::<crate::HyperlightError>()
                        {
                            return Err(crate::HyperlightError::DisallowedSyscall);
                        }

                        crate::log_then_return!("Host function {} panicked", name);
                    }
                }
            })?
            .join()
            .map_err(|_| new_error!("Error joining thread executing host function"))?
    })
    .map_err(|_| new_error!("Error joining thread executing host function"))?
}

#[cfg(not(all(feature = "seccomp", target_os = "linux")))]
fn maybe_with_seccomp<T: Send>(
    _name: &str,
    _syscalls: Option<&[ExtraAllowedSyscall]>,
    f: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    // No seccomp, just call the function
    f()
}
