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

#![allow(non_snake_case)]
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType,
};
use tracing::{instrument, Span};

use super::{HyperlightFunction, SupportedParameterType, SupportedReturnType};
use crate::sandbox::{ExtraAllowedSyscall, UninitializedSandbox};
use crate::HyperlightError::UnexpectedNoOfArguments;
use crate::{log_then_return, new_error, Result};

/// The definition of a function exposed from the host to the guest
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostFunctionDefinition {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Option<Vec<ParameterType>>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
}

impl HostFunctionDefinition {
    /// Create a new `HostFunctionDefinition`.
    pub fn new(
        function_name: String,
        parameter_types: Option<Vec<ParameterType>>,
        return_type: ReturnType,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
        }
    }
}

/// Trait for registering a host function
pub trait HostFunction<R, Args> {
    /// Register the host function with the given name in the sandbox.
    fn register(&self, sandbox: &mut UninitializedSandbox, name: &str) -> Result<()>;

    /// Register the host function with the given name in the sandbox, allowing extra syscalls.
    #[cfg(all(feature = "seccomp", target_os = "linux"))]
    fn register_with_extra_allowed_syscalls(
        &self,
        sandbox: &mut UninitializedSandbox,
        name: &str,
        extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
    ) -> Result<()>;
}

macro_rules! impl_host_function {
    (@count) => { 0 };
    (@count $P:ident $(, $R:ident)*) => {
        impl_host_function!(@count $($R),*) + 1
    };
    (@impl $($P:ident),*) => {
        const _: () = {
            impl<R $(, $P)*, F> HostFunction<R, ($($P,)*)> for Arc<Mutex<F>>
            where
                F: FnMut($($P),*) -> Result<R> + Send + 'static,
                $($P: SupportedParameterType<$P> + Clone,)*
                R: SupportedReturnType<R>,
            {
                /// Register the host function with the given name in the sandbox.
                #[instrument(
                    err(Debug), skip(self, sandbox), parent = Span::current(), level = "Trace"
                )]
                fn register(
                    &self,
                    sandbox: &mut UninitializedSandbox,
                    name: &str,
                ) -> Result<()> {
                    register_host_function(self.clone(), sandbox, name, None)
                }

                /// Register the host function with the given name in the sandbox, allowing extra syscalls.
                #[cfg(all(feature = "seccomp", target_os = "linux"))]
                #[instrument(
                    err(Debug), skip(self, sandbox, extra_allowed_syscalls),
                    parent = Span::current(), level = "Trace"
                )]
                fn register_with_extra_allowed_syscalls(
                    &self,
                    sandbox: &mut UninitializedSandbox,
                    name: &str,
                    extra_allowed_syscalls: Vec<ExtraAllowedSyscall>,
                ) -> Result<()> {
                    register_host_function(self.clone(), sandbox, name, Some(extra_allowed_syscalls))
                }
            }

            fn register_host_function<T, $($P,)* R>(
                self_: Arc<Mutex<T>>,
                sandbox: &mut UninitializedSandbox,
                name: &str,
                extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
            ) -> Result<()>
            where
                T: FnMut($($P),*) -> Result<R> + Send + 'static,
                $($P: SupportedParameterType<$P> + Clone,)*
                R: SupportedReturnType<R>,
            {
                const N: usize = impl_host_function!(@count $($P),*);
                let cloned = self_.clone();
                let func = Box::new(move |args: Vec<ParameterValue>| {
                    let ($($P,)*) = match <[ParameterValue; N]>::try_from(args) {
                        Ok([$($P,)*]) => ($($P::get_inner($P)?,)*),
                        Err(args) => { log_then_return!(UnexpectedNoOfArguments(args.len(), N)); }
                    };

                    let result = cloned
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?(
                            $($P),*
                        )?;
                    Ok(result.get_hyperlight_value())
                });

                let parameter_types = Some(vec![$($P::get_hyperlight_type()),*]);

                if let Some(_eas) = extra_allowed_syscalls {
                    if cfg!(all(feature = "seccomp", target_os = "linux")) {
                        // Register with extra allowed syscalls
                        #[cfg(all(feature = "seccomp", target_os = "linux"))]
                        {
                            sandbox
                                .host_funcs
                                .try_lock()
                                .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                                .register_host_function_with_syscalls(
                                    &HostFunctionDefinition::new(
                                        name.to_string(),
                                        parameter_types,
                                        R::get_hyperlight_type(),
                                    ),
                                    HyperlightFunction::new(func),
                                    _eas,
                                )?;
                        }
                    } else {
                        // Log and return an error
                        log_then_return!("Extra allowed syscalls are only supported on Linux with seccomp enabled");
                    }
                } else {
                    // Register without extra allowed syscalls
                    sandbox
                        .host_funcs
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                        .register_host_function(
                            &HostFunctionDefinition::new(
                                name.to_string(),
                                parameter_types,
                                R::get_hyperlight_type(),
                            ),
                            HyperlightFunction::new(func),
                        )?;
                }

                Ok(())
            }
        };
    };
    () => {
        impl_host_function!(@impl);
    };
    ($P:ident $(, $R:ident)*) => {
        impl_host_function!($($R),*);
        impl_host_function!(@impl $P $(, $R)*);
    };
}

impl_host_function!(P1, P2, P3, P4, P5, P6, P7, P8, P9, P10);
