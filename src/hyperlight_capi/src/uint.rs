use hyperlight_host::Result;

use super::context::Context;
use super::handle::Handle;
use super::hdl::Hdl;
use crate::{validate_context, validate_context_or_panic};

fn get_u64(ctx: &Context, hdl: Handle) -> Result<&u64> {
    Context::get(hdl, &ctx.uint64s, |h| matches!(h, Hdl::UInt64(_)))
}

fn get_u32(ctx: &Context, hdl: Handle) -> Result<&u32> {
    Context::get(hdl, &ctx.uint32s, |h| matches!(h, Hdl::UInt32(_)))
}

/// Add `val` to `ctx` and return a new `Handle` referencing it
pub(crate) fn register_u64(ctx: &mut Context, val: u64) -> Handle {
    Context::register(val, &mut ctx.uint64s, Hdl::UInt64)
}

/// Create a new `Handle` that contains the given `val`
///
/// Generally, this function should not be called directly.
/// Instead, 64 bit unsigned integers will be returned from various
/// other functions, particularly those that deal with shared
/// memory or other memory management tasks. This function
/// is provided mostly for testing purposes.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn uint_64_new(ctx: *mut Context, val: u64) -> Handle {
    validate_context!(ctx);

    Context::register(val, &mut (*ctx).uint64s, Hdl::UInt64)
}

/// Return `true` if `hdl` references a `u64` inside `ctx`, false
/// otherwise
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_is_uint_64(ctx: *const Context, hdl: Handle) -> bool {
    validate_context_or_panic!(ctx);

    get_u64(&*ctx, hdl).is_ok()
}

/// Create a new `Handle` that contains the given `val`
///
/// Generally, this function should not be called directly.
/// Instead, 32 bit unsigned integers will be returned from various
/// other functions, particularly those that deal with shared
/// memory or other memory management tasks. This function
/// is provided mostly for testing purposes.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn uint_32_new(ctx: *mut Context, val: u32) -> Handle {
    validate_context!(ctx);

    Context::register(val, &mut (*ctx).uint32s, Hdl::UInt32)
}

/// Return `true` if `hdl` references a `u32` inside `ctx`, false
/// otherwise
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_is_uint_32(ctx: *const Context, hdl: Handle) -> bool {
    validate_context_or_panic!(ctx);

    get_u32(&*ctx, hdl).is_ok()
}

/// Fetch the `u64` inside `ctx` referenced by `hdl` and return it,
/// or return `0` if `hdl` does not reference a `u64` inside `ctx`.
///
/// You can determine if `hdl` is a valid `u64` inside `ctx` with
/// `handle_is_uint_64`.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_get_uint_64(ctx: *const Context, hdl: Handle) -> u64 {
    validate_context_or_panic!(ctx);

    match get_u64(&*ctx, hdl) {
        Ok(i) => *i,
        Err(_) => 0,
    }
}

/// Fetch the `u32` inside `ctx` referenced by `hdl` and return it,
/// or return `0` if `hdl` does not reference a `u32` inside `ctx`.
///
/// You can determine if `hdl` is a valid `u32` inside `ctx` with
/// `handle_is_uint_32`.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_get_uint_32(ctx: *const Context, hdl: Handle) -> u32 {
    validate_context_or_panic!(ctx);

    match get_u32(&*ctx, hdl) {
        Ok(i) => *i,
        Err(_) => 0,
    }
}
