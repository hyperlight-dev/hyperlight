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

use alloc::format;
use alloc::vec::Vec;

use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::ParameterType;
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

use crate::entrypoint::halt;
use crate::error::{HyperlightGuestError, Result};
use crate::guest_error::{reset_error, set_error};
use crate::shared_input_data::try_pop_shared_input_data_into;
use crate::shared_output_data::push_shared_output_data;
use crate::REGISTERED_GUEST_FUNCTIONS;

type GuestFunc = fn(&FunctionCall) -> Result<Vec<u8>>;

pub(crate) fn call_guest_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    // Validate this is a Guest Function Call
    if function_call.function_call_type() != FunctionCallType::Guest {
        return Err(HyperlightGuestError::new(
            ErrorCode::GuestError,
            format!(
                "Invalid function call type: {:#?}, should be Guest.",
                function_call.function_call_type()
            ),
        ));
    }

    // Find the function definition for the function call.
    if let Some(registered_function_definition) =
        unsafe { REGISTERED_GUEST_FUNCTIONS.get(&function_call.function_name) }
    {
        let function_call_parameter_types: Vec<ParameterType> = function_call
            .parameters
            .iter()
            .flatten()
            .map(|p| p.into())
            .collect();

        // Verify that the function call has the correct parameter types and length.
        registered_function_definition.verify_parameters(&function_call_parameter_types)?;

        let p_function = unsafe {
            let function_pointer = registered_function_definition.function_pointer;
            core::mem::transmute::<usize, GuestFunc>(function_pointer)
        };

        p_function(&function_call)
    } else {
        // The given function is not registered. The guest should implement a function called guest_dispatch_function to handle this.

        // TODO: ideally we would define a default implementation of this with weak linkage so the guest is not required
        // to implement the function but its seems that weak linkage is an unstable feature so for now its probably better
        // to not do that.
        extern "Rust" {
            fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>>;
        }

        unsafe { guest_dispatch_function(function_call) }
    }
}

// This function is marked as no_mangle/inline to prevent the compiler from inlining it , if its inlined the epilogue will not be called
// and we will leak memory as the epilogue will not be called as halt() is not going to return.
#[no_mangle]
#[inline(never)]
fn internal_dispatch_function() -> Result<()> {
    reset_error();

    #[cfg(debug_assertions)]
    log::trace!("internal_dispatch_function");

    let function_call = try_pop_shared_input_data_into::<FunctionCall>()
        .expect("Function call deserialization failed");

    let result_vec = call_guest_function(function_call).inspect_err(|e| {
        set_error(e.kind.clone(), e.message.as_str());
    })?;

    push_shared_output_data(result_vec)
}

// This is implemented as a separate function to make sure that epilogue in the internal_dispatch_function is called before the halt()
// which if it were included in the internal_dispatch_function cause the epilogue to not be called because the halt() would not return
// when running in the hypervisor.
pub(crate) extern "win64" fn dispatch_function() {
    let _ = internal_dispatch_function();
    halt();
}
