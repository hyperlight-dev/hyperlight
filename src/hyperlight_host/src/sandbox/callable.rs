use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterValue, ReturnType, ReturnValue,
};

use crate::Result;

/// Trait used by the macros to paper over the differences between hyperlight and hyperlight-wasm
pub trait Callable {
    /// Call a guest function dynamically
    fn call(
        &mut self,
        func_name: &str,
        func_ret_type: ReturnType,
        args: Option<Vec<ParameterValue>>,
    ) -> Result<ReturnValue>;
}
