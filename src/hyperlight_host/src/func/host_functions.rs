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

use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnValue};

use super::utils::for_each_tuple;
use super::{ParameterTuple, ResultType, SupportedReturnType};
use crate::sandbox::{ExtraAllowedSyscall, UninitializedSandbox};
use crate::{log_then_return, new_error, Result};

/// A representation of a host function.
/// This is a thin wrapper around a `Fn(Args) -> Result<Output>`.
#[derive(Clone)]
pub struct HostFunction<Output, Args>
where
    Args: ParameterTuple,
    Output: SupportedReturnType,
{
    // This is a thin wrapper around a `Fn(Args) -> Result<Output>`.
    // But unlike `Fn` which is a trait, this is a concrete type.
    // This allows us to:
    //  1. Impose constraints on the function arguments and return type.
    //  2. Impose a single function signature.
    //
    // This second point is important because the `Fn` trait is generic
    // over the function arguments (with an associated return type).
    // This means that a given type could implement `Fn` for multiple
    // function signatures.
    // This means we can't do something like:
    // ```rust,ignore
    // impl<Args, Output, F> SomeTrait for F
    // where
    //     F: Fn(Args) -> Result<Output>,
    // { ... }
    // ```
    // because the concrete type F might implement `Fn` for multiple times,
    // and that would means implementing `SomeTrait` multiple times for the
    // same type.

    // Use Arc in here instead of Box because it's useful in tests and
    // presumably in other places to be able to clone a HostFunction and
    // use it across different sandboxes.
    func: Arc<dyn Fn(Args) -> Result<Output> + Send + Sync + 'static>,
}

pub(crate) struct TypeErasedHostFunction {
    func: Box<dyn Fn(Vec<ParameterValue>) -> Result<ReturnValue> + Send + Sync + 'static>,
}

impl<Args, Output> HostFunction<Output, Args>
where
    Args: ParameterTuple,
    Output: SupportedReturnType,
{
    /// Call the host function with the given arguments.
    pub fn call(&self, args: Args) -> Result<Output> {
        (self.func)(args)
    }
}

impl TypeErasedHostFunction {
    pub(crate) fn call(&self, args: Vec<ParameterValue>) -> Result<ReturnValue> {
        (self.func)(args)
    }
}

impl<Args, Output> From<HostFunction<Output, Args>> for TypeErasedHostFunction
where
    Args: ParameterTuple,
    Output: SupportedReturnType,
{
    fn from(func: HostFunction<Output, Args>) -> TypeErasedHostFunction {
        TypeErasedHostFunction {
            func: Box::new(move |args: Vec<ParameterValue>| {
                let args = Args::from_value(args)?;
                Ok(func.call(args)?.into_value())
            }),
        }
    }
}

macro_rules! impl_host_function {
    ([$N:expr] ($($p:ident: $P:ident),*)) => {
        /*
        // Normally for a `Fn + Send + Sync` we don't need to use a Mutex
        // like we do in the case of a `FnMut`.
        // However, we can't implement `IntoHostFunction` for `Fn` and `FnMut`
        // because `FnMut` is a supertrait of `Fn`.
        */

        impl<F, R, $($P),*> From<F> for HostFunction<R::ReturnType, ($($P,)*)>
        where
            F: FnMut($($P),*) -> R + Send + 'static,
            ($($P,)*): ParameterTuple,
            R: ResultType,
        {
            fn from(mut func: F) -> HostFunction<R::ReturnType, ($($P,)*)> {
                let func = move |($($p,)*): ($($P,)*)| -> Result<R::ReturnType> {
                    func($($p),*).into_result()
                };
                let func = Mutex::new(func);
                HostFunction {
                    func: Arc::new(move |args: ($($P,)*)| {
                        func.try_lock()
                            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                            (args)
                    })
                }
            }
        }
    };
}

for_each_tuple!(impl_host_function);

pub(crate) fn register_host_function<Args: ParameterTuple, Output: SupportedReturnType>(
    func: impl Into<HostFunction<Output, Args>>,
    sandbox: &mut UninitializedSandbox,
    name: &str,
    extra_allowed_syscalls: Option<Vec<ExtraAllowedSyscall>>,
) -> Result<()> {
    let func = func.into().into();

    if let Some(_eas) = extra_allowed_syscalls {
        if cfg!(all(feature = "seccomp", target_os = "linux")) {
            // Register with extra allowed syscalls
            #[cfg(all(feature = "seccomp", target_os = "linux"))]
            {
                sandbox
                    .host_funcs
                    .try_lock()
                    .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
                    .register_host_function_with_syscalls(name.to_string(), func, _eas)?;
            }
        } else {
            // Log and return an error
            log_then_return!(
                "Extra allowed syscalls are only supported on Linux with seccomp enabled"
            );
        }
    } else {
        // Register without extra allowed syscalls
        sandbox
            .host_funcs
            .try_lock()
            .map_err(|e| new_error!("Error locking at {}:{}: {}", file!(), line!(), e))?
            .register_host_function(name.to_string(), func)?;
    }

    Ok(())
}
