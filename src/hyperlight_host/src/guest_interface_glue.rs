use anyhow::{anyhow, Result};

/// All the types that can be used as parameters or return types for a host function.
enum SupportedParameterAndReturnTypes {
    Int,
    Long,
    ULong,
    Bool,
    String,
    ByteArray,
    IntPtr,
    UInt32,
}

/// Validates that the given type is supported by the host interface.
pub fn validate_type_supported(some_type: &str) -> Result<()> {
    // try to convert from &str to SupportedParameterAndReturnTypes
    match from_csharp_typename(some_type) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn from_csharp_typename(value: &str) -> Result<SupportedParameterAndReturnTypes> {
    match value {
        "System.Int32" => Ok(SupportedParameterAndReturnTypes::Int),
        "System.Int64" => Ok(SupportedParameterAndReturnTypes::Long),
        "System.UInt64" => Ok(SupportedParameterAndReturnTypes::ULong),
        "System.Boolean" => Ok(SupportedParameterAndReturnTypes::Bool),
        "System.String" => Ok(SupportedParameterAndReturnTypes::String),
        "System.Byte[]" => Ok(SupportedParameterAndReturnTypes::ByteArray),
        "System.IntPtr" => Ok(SupportedParameterAndReturnTypes::IntPtr),
        "System.UInt32" => Ok(SupportedParameterAndReturnTypes::UInt32),
        _ => Err(anyhow!("Unsupported type")),
    }
}