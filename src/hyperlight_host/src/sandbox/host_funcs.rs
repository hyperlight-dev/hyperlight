// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

#[cfg(feature = "process-isolation")]
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
#[cfg(feature = "process-isolation")]
use std::sync::Arc;

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::host_function_definition::HostFunctionDefinition;
use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use tracing::{Span, instrument};

use crate::HyperlightError::HostFunctionNotFound;
use crate::Result;
use crate::func::host_functions::TypeErasedHostFunction;

#[derive(Default)]
/// A Wrapper around details of functions exposed by the Host
pub struct FunctionRegistry {
    functions_map: HashMap<String, FunctionEntry>,
    #[cfg(feature = "process-isolation")]
    pub(crate) process_topology: Option<Box<crate::process::program::ProcessTopologyDefinition>>,
    #[cfg(feature = "process-isolation")]
    pub(crate) process_runtime: Option<Arc<crate::process::ProcessRuntime>>,
}

/// A collection of host functions that can be supplied to a sandbox
/// constructor (e.g. [`crate::Sandbox::from_snapshot`]) to
/// expose host-side functionality to the guest.
///
/// Use [`HostFunctions::default`] to start with the standard
/// `HostPrint` function pre-registered (matching the registry a
/// [`crate::SandboxBuilder`] starts with), or
/// [`HostFunctions::empty`] to start with an empty registry.
///
/// Add additional host functions via the
/// [`crate::func::Registerable`] trait.
///
/// ```no_run
/// # use hyperlight_host::{HostFunctions, Result};
/// # use hyperlight_host::func::Registerable;
/// # fn example() -> Result<()> {
/// // Default: HostPrint already registered.
/// let mut funcs = HostFunctions::default();
/// funcs.register_host_function("Add", |a: i32, b: i32| Ok(a + b))?;
/// # Ok(())
/// # }
/// ```
pub struct HostFunctions(FunctionRegistry);

impl HostFunctions {
    /// Create an empty `HostFunctions` with no host functions
    /// registered.
    ///
    /// Most callers want [`HostFunctions::default`] instead, which
    /// pre-registers the standard `HostPrint` function. An empty
    /// registry will fail snapshot validation against any snapshot
    /// that captured `HostPrint`, and any guest code that tries to
    /// `printf` into an empty registry will get an EIO from
    /// `write(2)`.
    pub fn empty() -> Self {
        Self(FunctionRegistry::default())
    }

    pub(crate) fn into_iter(self) -> impl Iterator<Item = (String, FunctionEntry)> {
        self.0.functions_map.into_iter()
    }

    /// Consume this `HostFunctions` and return the inner registry.
    pub(crate) fn into_inner(self) -> FunctionRegistry {
        self.0
    }

    /// Borrow the inner registry mutably.
    pub(crate) fn inner_mut(&mut self) -> &mut FunctionRegistry {
        &mut self.0
    }

    /// Borrow the inner registry immutably.
    pub(crate) fn inner(&self) -> &FunctionRegistry {
        &self.0
    }
}

impl Default for HostFunctions {
    /// Create a `HostFunctions` pre-populated with the standard
    /// `HostPrint` function (writes UTF-8 strings to the host's
    /// stdout in green).
    ///
    /// This matches the default registry installed by the
    /// `SandboxBuilder` constructors, so a snapshot taken from a
    /// regular sandbox can be loaded with
    /// `SandboxBuilder::from_snapshot(snap).build()`
    /// without registering anything else.
    ///
    /// Use [`HostFunctions::empty`] for an empty registry.
    fn default() -> Self {
        Self(FunctionRegistry::with_default_host_print())
    }
}

impl From<&FunctionRegistry> for HostFunctionDetails {
    fn from(registry: &FunctionRegistry) -> Self {
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
    #[cfg(not(feature = "process-isolation"))]
    pub parameter_types: &'static [ParameterType],
    #[cfg(feature = "process-isolation")]
    pub parameter_types: Cow<'static, [ParameterType]>,
    pub return_type: ReturnType,
}

impl FunctionEntry {
    pub(crate) fn new(
        function: TypeErasedHostFunction,
        parameter_types: &'static [ParameterType],
        return_type: ReturnType,
    ) -> Self {
        Self {
            function,
            parameter_types: parameter_types.into(),
            return_type,
        }
    }

    fn parameter_types(&self) -> &[ParameterType] {
        &self.parameter_types
    }
}

impl FunctionRegistry {
    #[cfg(feature = "process-isolation")]
    pub(crate) fn validate_local_registration(&self, name: &str) -> Result<()> {
        if self.process_topology.as_ref().is_some_and(|topology| {
            topology.workers().iter().any(|worker| {
                worker
                    .functions()
                    .iter()
                    .any(|function| function.name() == name)
            })
        }) {
            return Err(crate::new_error!(
                "Host function '{name}' already belongs to a process"
            ));
        }
        Ok(())
    }

    /// Register a host function with the sandbox.
    #[instrument(skip_all, parent = Span::current(), level = "Trace")]
    pub(crate) fn register_host_function(&mut self, name: String, func: FunctionEntry) {
        self.functions_map.insert(name, func);
    }

    /// Return the registered signature for `name`.
    pub(crate) fn function_signature(&self, name: &str) -> Option<(&[ParameterType], ReturnType)> {
        self.functions_map
            .get(name)
            .map(|entry| (entry.parameter_types(), entry.return_type))
    }

    /// Create a `FunctionRegistry` pre-populated with the default
    /// `HostPrint` function (writes to stdout with green text).
    pub(crate) fn with_default_host_print() -> Self {
        use crate::func::host_functions::HostFunction;
        use crate::func::{ParameterTuple, SupportedReturnType};

        let mut registry = Self::default();
        let hf: HostFunction<i32, (String,)> = default_writer_func.into();
        let entry = FunctionEntry::new(
            hf.into(),
            <(String,)>::TYPE,
            <i32 as SupportedReturnType>::TYPE,
        );
        registry.register_host_function("HostPrint".to_string(), entry);
        registry
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
    pub(crate) fn call_host_function(
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
            parameter_types: _,
            return_type: _,
        } = self
            .functions_map
            .get(name)
            .ok_or_else(|| HostFunctionNotFound(name.to_string()))?;

        // Make the host function call
        crate::metrics::maybe_time_and_emit_host_call(name, || function.call(args))
    }
}

/// The default writer function is to write to stdout with green text.
#[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
fn default_writer_func(s: String) -> Result<i32> {
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

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails;

    use super::*;
    use crate::func::{ParameterTuple, Registerable, SupportedReturnType};

    #[test]
    fn local_signature_borrows_static_tuple_types() {
        let parameters = <(i32,)>::TYPE;
        let function: crate::func::HostFunction<i32, (i32,)> = (|value: i32| value).into();
        let entry = FunctionEntry::new(
            function.into(),
            parameters,
            <i32 as SupportedReturnType>::TYPE,
        );
        assert!(std::ptr::eq(entry.parameter_types(), parameters));
        #[cfg(feature = "process-isolation")]
        assert!(matches!(
            entry.parameter_types,
            std::borrow::Cow::Borrowed(_)
        ));
        println!(
            "FunctionEntry={} FunctionRegistry={} HostFunctions={} SandboxBuilder={} MultiUseSandbox={}",
            std::mem::size_of::<FunctionEntry>(),
            std::mem::size_of::<FunctionRegistry>(),
            std::mem::size_of::<HostFunctions>(),
            std::mem::size_of::<crate::SandboxBuilder>(),
            std::mem::size_of::<crate::MultiUseSandbox>(),
        );
    }

    #[test]
    fn registration_replaces_local_implementation() {
        let mut functions = HostFunctions::empty();
        functions
            .register_host_function("Add", |a: i32, b: i32| a + b)
            .unwrap();
        functions
            .register_host_function("Add", |a: i32, b: i32| a + b + 1)
            .unwrap();

        let result = functions
            .inner()
            .call_host_function("Add", (10_i32, 32_i32).into_value())
            .unwrap();

        assert_eq!(
            <i32 as SupportedReturnType>::from_value(result).unwrap(),
            43
        );
        assert_eq!(functions.into_iter().count(), 1);
    }

    #[test]
    fn registration_replaces_local_signature() {
        let mut functions = HostFunctions::empty();
        functions
            .register_host_function("Value", |value: i32| value)
            .unwrap();
        functions
            .register_host_function("Value", |value: String| value.len() as u64)
            .unwrap();

        assert_eq!(
            functions.inner().function_signature("Value"),
            Some((<(String,)>::TYPE, <u64 as SupportedReturnType>::TYPE)),
        );
        let details = HostFunctionDetails::from(functions.inner());
        let entries = details.host_functions.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].function_name, "Value");
        assert_eq!(
            entries[0].parameter_types.as_deref(),
            Some(<(String,)>::TYPE),
        );
        assert_eq!(entries[0].return_type, <u64 as SupportedReturnType>::TYPE);
        let result = functions
            .inner()
            .call_host_function("Value", ("hello".to_owned(),).into_value())
            .unwrap();
        assert_eq!(<u64 as SupportedReturnType>::from_value(result).unwrap(), 5);
    }

    #[test]
    fn default_host_print_can_be_replaced_locally() {
        let mut functions = HostFunctions::default();
        functions
            .register_host_function("HostPrint", |_: String| 42_i32)
            .unwrap();

        assert_eq!(
            functions
                .inner_mut()
                .host_print("handled by replacement".to_owned())
                .unwrap(),
            42,
        );
        assert_eq!(functions.into_iter().count(), 1);
    }
}
