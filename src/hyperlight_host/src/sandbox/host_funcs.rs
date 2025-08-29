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

use std::collections::HashMap;
use std::io::{IsTerminal, Write};

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tracing::{Span, instrument};

use super::ExtraAllowedSyscall;
use crate::HyperlightError::HostFunctionNotFound;
use crate::func::host_functions::TypeErasedHostFunction;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::ExclusiveSharedMemory;
use crate::{Result, new_error};

#[derive(Default)]
/// A Wrapper around details of functions exposed by the Host
pub struct FunctionRegistry {
    functions_map: HashMap<String, FunctionEntry>,
}

impl From<&mut FunctionRegistry> for HostFunctionDetails {
    fn from(registry: &mut FunctionRegistry) -> Self {
        let host_functions = registry
            .functions_map
            .iter()
            .map(|(name, entry)| HostFunctionDefinition {
                function_name: name.clone(),
                parameter_types: Some(entry.parameter_types.to_vec()),
                return_type: entry.return_type,
            })
            .collect();

        HostFunctionDetails {
            host_functions: Some(host_functions),
        }
    }
}

pub struct FunctionEntry {
    pub function: TypeErasedHostFunction,
    pub extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
    pub parameter_types: &'static [ParameterType],
    pub return_type: ReturnType,
}

impl FunctionRegistry {
    /// Register a host function with the sandbox.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn register_host_function(
        &mut self,
        name: String,
        func: FunctionEntry,
        mgr: &mut SandboxMemoryManager<ExclusiveSharedMemory>,
    ) -> Result<()> {
        self.functions_map.insert(name, func);

        let hfd = HostFunctionDetails::from(self);

        let buffer: Vec<u8> = (&hfd).try_into().map_err(|e| {
            new_error!(
                "Error serializing host function details to flatbuffer: {}",
                e
            )
        })?;

        mgr.write_buffer_host_function_details(&buffer)?;
        Ok(())
    }

    /// Assuming a host function called `"HostPrint"` exists, and takes a
    /// single string parameter, call it with the given `msg` parameter.
    ///
    /// Return `Ok` if the function was found and was of the right signature,
    /// and `Err` otherwise.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    #[allow(dead_code)]
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

    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn call_host_func_impl(&self, name: &str, args: Vec<ParameterValue>) -> Result<ReturnValue> {
        let FunctionEntry {
            function,
            extra_allowed_syscalls,
            parameter_types: _,
            return_type: _,
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

#[cfg(seccomp)]
fn maybe_with_seccomp<T: Send>(
    name: &str,
    syscalls: Option<&[ExtraAllowedSyscall]>,
    f: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    use std::thread;

    use crate::seccomp::guest::get_seccomp_filter_for_host_function_worker_thread;

    // Use a scoped thread so that we can pass around references without having to clone them.
    thread::scope(|s| {
        thread::Builder::new()
            .name(format!("Host Function Worker Thread for: {name:?}"))
            .spawn_scoped(s, move || {
                let seccomp_filter = get_seccomp_filter_for_host_function_worker_thread(syscalls)?;
                seccomp_filter
                    .iter()
                    .try_for_each(|filter| seccompiler::apply_filter(filter))?;

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
}

#[cfg(not(seccomp))]
fn maybe_with_seccomp<T: Send>(
    _name: &str,
    _syscalls: Option<&[ExtraAllowedSyscall]>,
    f: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    // No seccomp, just call the function
    f()
}
