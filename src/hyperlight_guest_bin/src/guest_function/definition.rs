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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result;
use hyperlight_common::for_each_tuple;
use hyperlight_common::func::{
    Function, ParameterTuple, ResultType, ReturnValue, SupportedReturnType,
};
use hyperlight_guest::error::{HyperlightGuestError, Result};

/// The definition of a function exposed from the guest to the host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFunctionDefinition {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Vec<ParameterType>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
    /// The function pointer to the guest function
    pub function_pointer: usize,
}

/// Trait for functions that can be converted to a `fn(&FunctionCall) -> Result<Vec<u8>>`
#[doc(hidden)]
pub trait IntoGuestFunction<Output, Args>
where
    Self: Function<Output, Args, HyperlightGuestError>,
    Self: Copy + 'static,
    Output: SupportedReturnType,
    Args: ParameterTuple,
{
    #[doc(hidden)]
    const ASSERT_ZERO_SIZED: ();

    /// Convert the function into a `fn(&FunctionCall) -> Result<Vec<u8>>`
    fn into_guest_function(self) -> fn(&FunctionCall) -> Result<Vec<u8>>;
}

/// Trait for functions that can be converted to a `GuestFunctionDefinition`
pub trait AsGuestFunctionDefinition<Output, Args>
where
    Self: Function<Output, Args, HyperlightGuestError>,
    Self: IntoGuestFunction<Output, Args>,
    Output: SupportedReturnType,
    Args: ParameterTuple,
{
    /// Get the `GuestFunctionDefinition` for this function
    fn as_guest_function_definition(&self, name: impl Into<String>) -> GuestFunctionDefinition;
}

fn into_flatbuffer_result(value: ReturnValue) -> Vec<u8> {
    match value {
        ReturnValue::Void(()) => get_flatbuffer_result(()),
        ReturnValue::Int(i) => get_flatbuffer_result(i),
        ReturnValue::UInt(u) => get_flatbuffer_result(u),
        ReturnValue::Long(l) => get_flatbuffer_result(l),
        ReturnValue::ULong(ul) => get_flatbuffer_result(ul),
        ReturnValue::Float(f) => get_flatbuffer_result(f),
        ReturnValue::Double(d) => get_flatbuffer_result(d),
        ReturnValue::Bool(b) => get_flatbuffer_result(b),
        ReturnValue::String(s) => get_flatbuffer_result(s.as_str()),
        ReturnValue::VecBytes(v) => get_flatbuffer_result(v.as_slice()),
    }
}

macro_rules! impl_host_function {
    ([$N:expr] ($($p:ident: $P:ident),*)) => {
        impl<F, R, $($P),*> IntoGuestFunction<R::ReturnType, ($($P,)*)> for F
        where
            F: Fn($($P),*) -> R,
            F: Function<R::ReturnType, ($($P,)*), HyperlightGuestError>,
            F: Copy + 'static, // Copy implies that F has no Drop impl
            ($($P,)*): ParameterTuple,
            R: ResultType<HyperlightGuestError>,
        {
            #[doc(hidden)]
            const ASSERT_ZERO_SIZED: () = const {
                assert!(core::mem::size_of::<Self>() == 0)
            };

            fn into_guest_function(self) -> fn(&FunctionCall) -> Result<Vec<u8>> {
                |fc: &FunctionCall| {
                    // SAFETY: This is safe because of the safety comment on the function.
                    let this = unsafe { core::mem::zeroed::<F>() };
                    let params = fc.parameters.clone().unwrap_or_default();
                    let params = <($($P,)*) as ParameterTuple>::from_value(params)?;
                    let result = Function::<R::ReturnType, ($($P,)*), HyperlightGuestError>::call(&this, params)?;
                    Ok(into_flatbuffer_result(result.into_value()))
                }
            }
        }
    };
}

impl<F, Args, Output> AsGuestFunctionDefinition<Output, Args> for F
where
    F: IntoGuestFunction<Output, Args>,
    Args: ParameterTuple,
    Output: SupportedReturnType,
{
    fn as_guest_function_definition(&self, name: impl Into<String>) -> GuestFunctionDefinition {
        let parameter_types = Args::TYPE.to_vec();
        let return_type = Output::TYPE;
        let function_pointer = self.into_guest_function();
        let function_pointer = function_pointer as usize;

        GuestFunctionDefinition {
            function_name: name.into(),
            parameter_types,
            return_type,
            function_pointer,
        }
    }
}

for_each_tuple!(impl_host_function);

impl GuestFunctionDefinition {
    /// Create a new `GuestFunctionDefinition`.
    pub fn new(
        function_name: String,
        parameter_types: Vec<ParameterType>,
        return_type: ReturnType,
        function_pointer: usize,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
            function_pointer,
        }
    }

    /// Create a new `GuestFunctionDefinition` from a function that implements
    /// `AsGuestFunctionDefinition`.
    pub fn from_fn<Output, Args>(
        function_name: String,
        function: impl AsGuestFunctionDefinition<Output, Args>,
    ) -> Self
    where
        Args: ParameterTuple,
        Output: SupportedReturnType,
    {
        function.as_guest_function_definition(function_name)
    }

    /// Verify that `self` has same signature as the provided `parameter_types`.
    pub fn verify_parameters(&self, parameter_types: &[ParameterType]) -> Result<()> {
        // Verify that the function does not have more than `MAX_PARAMETERS` parameters.
        const MAX_PARAMETERS: usize = 11;
        if parameter_types.len() > MAX_PARAMETERS {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestError,
                format!(
                    "Function {} has too many parameters: {} (max allowed is {}).",
                    self.function_name,
                    parameter_types.len(),
                    MAX_PARAMETERS
                ),
            ));
        }

        if self.parameter_types.len() != parameter_types.len() {
            return Err(HyperlightGuestError::new(
                ErrorCode::GuestFunctionIncorrecNoOfParameters,
                format!(
                    "Called function {} with {} parameters but it takes {}.",
                    self.function_name,
                    parameter_types.len(),
                    self.parameter_types.len()
                ),
            ));
        }

        for (i, parameter_type) in self.parameter_types.iter().enumerate() {
            if parameter_type != &parameter_types[i] {
                return Err(HyperlightGuestError::new(
                    ErrorCode::GuestFunctionParameterTypeMismatch,
                    format!(
                        "Expected parameter type {:?} for parameter index {} of function {} but got {:?}.",
                        parameter_type, i, self.function_name, parameter_types[i]
                    ),
                ));
            }
        }

        Ok(())
    }
}
