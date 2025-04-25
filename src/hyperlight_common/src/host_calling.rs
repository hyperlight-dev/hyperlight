use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_char;

use anyhow::Result;

use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use crate::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType, ReturnValue};
use crate::input_output::{InputDataSection, OutputDataSection};
use crate::outb::{outb, OutBAction};
use crate::PEB;

/// Get a return value from a host function call.
/// This usually requires a host function to be called first using `call_host_function`.
pub fn get_host_return_value<T: TryFrom<ReturnValue>>() -> Result<T> {
    let input_data_section: InputDataSection =
        unsafe { (*PEB).clone() }.get_input_data_region()?.into();
    let return_value = input_data_section.try_pop_shared_input_data_into::<ReturnValue>()?;

    T::try_from(return_value).map_err(|_| {
        anyhow::anyhow!(
            "Host return value was not a {} as expected",
            core::any::type_name::<T>()
        )
    })
}

/// Calls a host function.
// TODO: Make this generic, return a Result<T, ErrorCode> this should allow callers to call this function and get the result type they expect
// without having to do the conversion themselves
pub fn call_host_function(
    function_name: &str,
    parameters: Option<Vec<ParameterValue>>,
    return_type: ReturnType,
) -> Result<()> {
    let host_function_call = FunctionCall::new(
        function_name.to_string(),
        parameters,
        FunctionCallType::Host,
        return_type,
    );

    let host_function_call_buffer: Vec<u8> = host_function_call.try_into()?;

    let output_data_section: OutputDataSection =
        unsafe { (*PEB).clone() }.get_output_data_region()?.into();
    output_data_section.push_shared_output_data(host_function_call_buffer)?;

    outb(OutBAction::CallFunction as u16, 0)
}

/// Uses `hloutb` to issue multiple `DebugPrint` `OutBAction`s to print a message.
pub fn print(message: &str) -> Result<()> {
    for byte in message.bytes() {
        outb(OutBAction::DebugPrint as u16, byte)?;
    }

    Ok(())
}

/// Exposes a C API to allow the guest to print a string, byte by byte
///
/// # Safety
/// This function is not thread safe and assumes `outb` is safe to call directly.
#[no_mangle]
pub unsafe extern "C" fn _putchar(c: c_char) {
    #[allow(clippy::expect_used)] // allow `expect` over C API functions
    outb(OutBAction::DebugPrint as u16, c as u8).expect("Failed to print character");
}
