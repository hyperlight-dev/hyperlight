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

/// The function pointer type for Rust guest functions.
pub type GuestFunc = fn(FunctionCall) -> Result<Vec<u8>>;

/// The definition of a function exposed from the guest to the host.
///
/// The type parameter `F` is the function pointer type. For Rust guests this
/// is [`GuestFunc`]; the C API uses its own `CGuestFunc` type.
#[derive(Debug, Clone)]
pub struct GuestFunctionDefinition<F: Copy> {
    /// The function name
    pub function_name: String,
    /// The type of the parameter values for the host function call.
    pub parameter_types: Vec<ParameterType>,
    /// The type of the return value from the host function call
    pub return_type: ReturnType,
    /// The function pointer to the guest function.
    pub function_pointer: F,
}

/// Trait for functions that can be converted to a `fn(FunctionCall) -> Result<Vec<u8>>`
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

    /// Convert the function into a `fn(FunctionCall) -> Result<Vec<u8>>`
    fn into_guest_function(self) -> fn(FunctionCall) -> Result<Vec<u8>>;
}

/// Trait for functions that can be converted to a `GuestFunctionDefinition<GuestFunc>`
pub trait AsGuestFunctionDefinition<Output, Args>
where
    Self: Function<Output, Args, HyperlightGuestError>,
    Self: IntoGuestFunction<Output, Args>,
    Output: SupportedReturnType,
    Args: ParameterTuple,
{
    /// Get the `GuestFunctionDefinition` for this function
    fn as_guest_function_definition(
        &self,
        name: impl Into<String>,
    ) -> GuestFunctionDefinition<GuestFunc>;
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
            // Only functions that can be coerced into a function pointer (i.e., "fn" types)
            // can be registered as guest functions.
            //
            // Note that the "Fn" trait is different from "fn" types in Rust.
            // "fn" is a type, while "Fn" is a trait.
            // For example, closures that capture environment implement "Fn" but cannot be
            // coerced to function pointers.
            // This means that the closure returned by `into_guest_function` can not capture
            // any environment, not event `self`, and we must only rely on the type system
            // to call the correct function.
            //
            // Ideally we would implement IntoGuestFunction for any F that can be converted
            // into a function pointer, but currently there's no way to express that in Rust's
            // type system.
            // Therefore, to ensure that F is a "fn" type, we enforce that F is zero-sized
            // has no Drop impl (the latter is enforced by the Copy bound), and it doesn't
            // capture any lifetimes (not even through a marker type like PhantomData).
            //
            // Note that implementing IntoGuestFunction for "fn($(P),*) -> R" is not an option
            // either, "fn($(P),*) -> R" is a type that's shared for all function pointers with
            // that signature, e.g., "fn add(a: i32, b: i32) -> i32 { a + b }" and
            // "fn sub(a: i32, b: i32) -> i32 { a - b }" both can be coerced to the same
            // "fn(i32, i32) -> i32" type, so we would need to capture self (a function pointer)
            // to know exactly which function to call.

            #[doc(hidden)]
            const ASSERT_ZERO_SIZED: () = const {
                assert!(core::mem::size_of::<Self>() == 0)
            };

            fn into_guest_function(self) -> fn(FunctionCall) -> Result<Vec<u8>> {
                |fc: FunctionCall| {
                    // SAFETY: This is safe because:
                    //  1. F is zero-sized (enforced by the ASSERT_ZERO_SIZED const).
                    //  2. F has no Drop impl (enforced by the Copy bound).
                    // Therefore, creating an instance of F is safe.
                    let this = unsafe { core::mem::zeroed::<F>() };
                    let params = fc.parameters.unwrap_or_default();
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
    fn as_guest_function_definition(
        &self,
        name: impl Into<String>,
    ) -> GuestFunctionDefinition<GuestFunc> {
        let parameter_types = Args::TYPE.to_vec();
        let return_type = Output::TYPE;
        let function_pointer = self.into_guest_function();

        GuestFunctionDefinition {
            function_name: name.into(),
            parameter_types,
            return_type,
            function_pointer,
        }
    }
}

for_each_tuple!(impl_host_function);

impl<F: Copy> GuestFunctionDefinition<F> {
    /// Create a new `GuestFunctionDefinition`.
    pub fn new(
        function_name: String,
        parameter_types: Vec<ParameterType>,
        return_type: ReturnType,
        function_pointer: F,
    ) -> Self {
        Self {
            function_name,
            parameter_types,
            return_type,
            function_pointer,
        }
    }

    /// Create a new `GuestFunctionDefinition<GuestFunc>` from a function that
    /// implements `AsGuestFunctionDefinition`.
    pub fn from_fn<Output, Args>(
        function_name: String,
        function: impl AsGuestFunctionDefinition<Output, Args>,
    ) -> GuestFunctionDefinition<GuestFunc>
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
