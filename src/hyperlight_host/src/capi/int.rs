use crate::{validate_context, validate_context_or_panic};

use super::context::Context;
use super::handle::Handle;
use super::hdl::Hdl;
use anyhow::Result;

fn get_i64(ctx: &Context, hdl: Handle) -> Result<&i64> {
    Context::get(hdl, &ctx.int64s, |h| matches!(h, Hdl::Int64(_)))
}

fn get_i32(ctx: &Context, hdl: Handle) -> Result<&i32> {
    Context::get(hdl, &ctx.int32s, |h| matches!(h, Hdl::Int32(_)))
}

/// Add `val` to `ctx` and return a new `Handle` referencing it
pub fn register_i32(ctx: &mut Context, val: i32) -> Handle {
    Context::register(val, &mut ctx.int32s, Hdl::Int32)
}

/// Create a new `Handle` that contains the given `val`
///
/// Generally, this function should not be called directly.
/// Instead, 64 bit integers will be returned from various
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
pub unsafe extern "C" fn int_64_new(ctx: *mut Context, val: i64) -> Handle {
    validate_context!(ctx);

    Context::register(val, &mut (*ctx).int64s, Hdl::Int64)
}

/// Return `true` if `hdl` references an `i64` inside `ctx`, false
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
pub unsafe extern "C" fn handle_is_int_64(ctx: *const Context, hdl: Handle) -> bool {
    validate_context_or_panic!(ctx);

    get_i64(&*ctx, hdl).is_ok()
}

/// Create a new `Handle` that contains the given `val`
///
///
/// Generally, this function should not be called directly.
/// Instead, 64 bit integers will be returned from various
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
pub unsafe extern "C" fn int_32_new(ctx: *mut Context, val: i32) -> Handle {
    validate_context!(ctx);
    register_i32(&mut *ctx, val)
}

/// Return `true` if `hdl` references an `i32` inside `ctx`, false
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
pub unsafe extern "C" fn handle_is_int_32(ctx: *const Context, hdl: Handle) -> bool {
    validate_context_or_panic!(ctx);

    get_i32(&*ctx, hdl).is_ok()
}

/// Fetch the `i64` inside `ctx` referenced by `hdl` and return it,
/// or return `0` if `hdl` does not reference an `i64` inside `ctx`.
///
/// You can determine if `hdl` is a valid `i64` inside `ctx` with
/// `handle_is_int_64`.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_get_int_64(ctx: *const Context, hdl: Handle) -> i64 {
    validate_context_or_panic!(ctx);

    match get_i64(&*ctx, hdl) {
        Ok(i) => *i,
        Err(_) => 0,
    }
}

/// Fetch the `i32` inside `ctx` referenced by `hdl` and return it,
/// or return `0` if `hdl` does not reference an `i64` inside `ctx`.
///
/// You can determine if `hdl` is a valid `i64` inside `ctx` with
/// `handle_is_int_32`.
///
/// # Safety
///
/// You must call this function with a `Context*` that has been:
///
/// - Created with `context_new`
/// - Not yet freed with `context_free`
/// - Not modified, except by calling functions in the Hyperlight C API
#[no_mangle]
pub unsafe extern "C" fn handle_get_int_32(ctx: *const Context, hdl: Handle) -> i32 {
    validate_context_or_panic!(ctx);

    match get_i32(&*ctx, hdl) {
        Ok(i) => *i,
        Err(_) => 0,
    }
}
