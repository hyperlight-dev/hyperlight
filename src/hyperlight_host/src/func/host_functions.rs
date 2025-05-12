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

use hyperlight_common::flatbuffer_wrappers::function_types::ParameterValue;
use tracing::{instrument, Span};

use super::{HyperlightFunction, SupportedParameterType, SupportedReturnType};
use crate::sandbox::{ExtraAllowedSyscall, UninitializedSandbox};
use crate::HyperlightError::UnexpectedNoOfArguments;
use crate::{log_then_return, new_error, Result};

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

/// Tait for types that can be converted into types implementing `HostFunction`.
pub trait IntoHostFunction<R, Args> {
    /// Concrete type of the returned host function
    type Output: HostFunction<R, Args>;

    /// Convert the type into a host function
    fn into_host_function(self) -> Self::Output;
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
                $($P: SupportedParameterType + Clone,)*
                R: SupportedReturnType,
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

            impl<R $(, $P)*, F> IntoHostFunction<R, ($($P,)*)> for F
            where
                F: FnMut($($P),*) -> Result<R> + Send + 'static,
                Arc<Mutex<F>>: HostFunction<R, ($($P,)*)>,
            {
                type Output = Arc<Mutex<F>>;

                fn into_host_function(self) -> Self::Output {
                    Arc::new(Mutex::new(self))
                }
            }

            impl<R $(, $P)*, F> IntoHostFunction<R, ($($P,)*)> for Arc<Mutex<F>>
            where
                F: FnMut($($P),*) -> Result<R> + Send + 'static,
                Arc<Mutex<F>>: HostFunction<R, ($($P,)*)>,
            {
                type Output = Arc<Mutex<F>>;

                fn into_host_function(self) -> Self::Output {
                    self
                }
            }

            impl<R $(, $P)*, F> IntoHostFunction<R, ($($P,)*)> for &Arc<Mutex<F>>
            where
                F: FnMut($($P),*) -> Result<R> + Send + 'static,
                Arc<Mutex<F>>: HostFunction<R, ($($P,)*)>,
            {
                type Output = Arc<Mutex<F>>;

                fn into_host_function(self) -> Self::Output {
                    self.clone()
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
                $($P: SupportedParameterType + Clone,)*
                R: SupportedReturnType,
            {
                const N: usize = impl_host_function!(@count $($P),*);
                let cloned = self_.clone();
                let func = Box::new(move |args: Vec<ParameterValue>| {
                    let ($($P,)*) = match <[ParameterValue; N]>::try_from(args) {
                        Ok([$($P,)*]) => ($($P::from_value($P)?,)*),
                        Err(args) => { log_then_return!(UnexpectedNoOfArguments(args.len(), N)); }
                    };

                    let result = cloned
                        .try_lock()
                        .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?(
                            $($P),*
                        )?;
                    Ok(result.into_value())
                });

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
                                    name.to_string(),
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
                            name.to_string(),
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
