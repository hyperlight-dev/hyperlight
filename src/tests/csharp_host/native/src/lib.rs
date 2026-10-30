// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! A C API over hyperlight-host for the C# binding tests. Guest and host
//! functions take and return byte buffers. Each function returns an error
//! message, or empty [`OwnedBytes`] on success.

use std::ffi::c_void;
use std::fmt::Display;
use std::ptr;

use hyperlight_host::{GuestBinary, HyperlightError, Sandbox, UninitializedSandbox};

/// Bytes the caller owns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    ptr: *const u8,
    len: usize,
}

/// Bytes this library owns. Free them with [`hltest_bytes_free`].
#[repr(C)]
pub struct OwnedBytes {
    ptr: *mut u8,
    len: usize,
}

const OK: OwnedBytes = OwnedBytes {
    ptr: ptr::null_mut(),
    len: 0,
};

/// A sandbox that host functions are registered on, then evolved and
/// called.
pub struct TestSandbox {
    uninit: Option<UninitializedSandbox>,
    sandbox: Option<Sandbox>,
}

/// The result a host function sets with [`hltest_host_result`].
pub struct HostResult(Result<Vec<u8>, String>);

/// A host function. It receives the `context` it was registered with and
/// `count` arguments, and sets its result with [`hltest_host_result`].
pub type HostFunction = unsafe extern "C" fn(
    context: *mut c_void,
    args: *const Bytes,
    count: usize,
    result: *mut HostResult,
);

/// # Safety
///
/// `b.ptr` must point to `b.len` readable bytes for `'a`, or `b.len` must
/// be zero.
unsafe fn slice<'a>(b: Bytes) -> &'a [u8] {
    if b.len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `b.ptr` points to `b.len` bytes.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
    }
}

/// # Safety
///
/// As for [`slice`].
unsafe fn string(b: Bytes) -> Result<String, OwnedBytes> {
    // SAFETY: the caller upholds the preconditions of `slice`.
    let bytes = unsafe { slice(b) };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(report)
}

fn owned(v: Vec<u8>) -> OwnedBytes {
    let b = v.into_boxed_slice();
    let len = b.len();
    OwnedBytes {
        ptr: Box::into_raw(b).cast(),
        len,
    }
}

fn report(e: impl Display) -> OwnedBytes {
    owned(e.to_string().into_bytes())
}

/// Frees bytes this library returned.
///
/// # Safety
///
/// `b` must come from this library and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_bytes_free(b: OwnedBytes) {
    if !b.ptr.is_null() {
        // SAFETY: `b` is a boxed slice from `owned` that the caller has
        // not freed.
        drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(b.ptr, b.len)) });
    }
}

/// Creates a sandbox for the guest binary at the UTF-8 path `path`.
///
/// # Safety
///
/// `path` must be valid for reads and `out` for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_sandbox_new(path: Bytes, out: *mut *mut TestSandbox) -> OwnedBytes {
    // SAFETY: the caller guarantees `path` is valid.
    let path = match unsafe { string(path) } {
        Ok(path) => path,
        Err(e) => return e,
    };
    match UninitializedSandbox::new(GuestBinary::FilePath(path.into()), None) {
        Ok(uninit) => {
            let sandbox = Box::new(TestSandbox {
                uninit: Some(uninit),
                sandbox: None,
            });
            // SAFETY: the caller guarantees `out` is valid for writes.
            unsafe { *out = Box::into_raw(sandbox) };
            OK
        }
        Err(e) => report(e),
    }
}

/// Frees a sandbox.
///
/// # Safety
///
/// `sandbox` must come from [`hltest_sandbox_new`], not have been freed,
/// and not be in use by another call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_sandbox_free(sandbox: *mut TestSandbox) {
    if !sandbox.is_null() {
        // SAFETY: the caller guarantees `sandbox` is a live box from
        // `hltest_sandbox_new` that nothing else uses.
        drop(unsafe { Box::from_raw(sandbox) });
    }
}

/// The host function and context of one registration.
#[derive(Clone, Copy)]
struct Callback {
    function: HostFunction,
    context: usize,
}

impl Callback {
    fn call(self, args: Vec<Vec<u8>>) -> Result<Vec<u8>, HyperlightError> {
        let args = args
            .iter()
            .map(|a| Bytes {
                ptr: a.as_ptr(),
                len: a.len(),
            })
            .collect::<Vec<_>>();
        let mut result = HostResult(Err("the host function set no result".to_string()));
        // SAFETY: `hltest_register` requires `function` to be callable with
        // `context` while the sandbox lives. `args` and `result` outlive the
        // call.
        unsafe {
            (self.function)(
                self.context as *mut c_void,
                args.as_ptr(),
                args.len(),
                &mut result,
            )
        };
        result.0.map_err(HyperlightError::Error)
    }
}

/// Registers a host function named `name` with `count` parameters.
///
/// # Safety
///
/// `sandbox` must be live, not evolved, and not in use by another call.
/// `name` must be valid for reads.
/// `function` must be safe to call with `context` from any thread until
/// the sandbox is freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_register(
    sandbox: *mut TestSandbox,
    name: Bytes,
    count: usize,
    function: HostFunction,
    context: *mut c_void,
) -> OwnedBytes {
    // SAFETY: the caller guarantees `sandbox` is live and not in use
    // elsewhere.
    let sandbox = unsafe { &mut *sandbox };
    let Some(uninit) = sandbox.uninit.as_mut() else {
        return report("the sandbox is already evolved");
    };
    // SAFETY: the caller guarantees `name` is valid.
    let name = match unsafe { string(name) } {
        Ok(name) => name,
        Err(e) => return e,
    };
    let cb = Callback {
        function,
        context: context as usize,
    };
    macro_rules! register {
        ($($n:literal => ($($a:ident),*)),*) => {
            match count {
                $($n => uninit.register(&name, move |$($a: Vec<u8>),*| cb.call(vec![$($a),*])),)*
                n => return report(format!("host functions take at most 2 parameters, not {n}")),
            }
        };
    }
    let result = register!(
        0 => (),
        1 => (a0),
        2 => (a0, a1)
    );
    match result {
        Ok(()) => OK,
        Err(e) => report(e),
    }
}

/// Sets the result of a host function call. `ok` selects whether `bytes`
/// is the encoded result or a UTF-8 error message.
///
/// # Safety
///
/// `result` must be the pointer passed to the host function, and `bytes`
/// valid for reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_host_result(result: *mut HostResult, bytes: Bytes, ok: bool) {
    // SAFETY: the caller guarantees `bytes` is valid.
    let data = unsafe { slice(bytes) }.to_vec();
    let value = if ok {
        Ok(data)
    } else {
        Err(String::from_utf8_lossy(&data).into_owned())
    };
    // SAFETY: the caller guarantees `result` is the live pointer passed to
    // the host function.
    unsafe { (*result).0 = value };
}

/// Initializes the guest. Host functions must be registered before.
///
/// # Safety
///
/// `sandbox` must be live and not in use by another call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_evolve(sandbox: *mut TestSandbox) -> OwnedBytes {
    // SAFETY: the caller guarantees `sandbox` is live and not in use
    // elsewhere.
    let sandbox = unsafe { &mut *sandbox };
    let Some(uninit) = sandbox.uninit.take() else {
        return report("the sandbox is already evolved");
    };
    match uninit.evolve() {
        Ok(s) => {
            sandbox.sandbox = Some(s);
            OK
        }
        Err(e) => report(e),
    }
}

/// Calls the guest function `name` with `count` arguments and writes its
/// result to `out`.
///
/// # Safety
///
/// `sandbox` must be live and not in use by another call. `name` and
/// `count` elements of `args` must be valid for reads, and `out` valid for
/// writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hltest_call(
    sandbox: *mut TestSandbox,
    name: Bytes,
    args: *const Bytes,
    count: usize,
    out: *mut OwnedBytes,
) -> OwnedBytes {
    // SAFETY: the caller guarantees `sandbox` is live and not in use
    // elsewhere.
    let sandbox = unsafe { &mut *sandbox };
    let Some(sb) = sandbox.sandbox.as_mut() else {
        return report("the sandbox is not evolved");
    };
    // SAFETY: the caller guarantees `name` is valid.
    let name = match unsafe { string(name) } {
        Ok(name) => name,
        Err(e) => return e,
    };
    let args = (0..count)
        // SAFETY: the caller guarantees `args` has `count` valid elements.
        .map(|i| unsafe { slice(*args.add(i)) }.to_vec())
        .collect::<Vec<_>>();
    let mut args = args.into_iter();
    macro_rules! call {
        ($($n:literal => ($($a:ident),*)),*) => {
            match count {
                $($n => {
                    $(let $a = args.next().unwrap();)*
                    sb.call::<Vec<u8>>(&name, ($($a,)*))
                })*
                n => return report(format!("guest functions take at most 2 parameters, not {n}")),
            }
        };
    }
    let result = call!(
        0 => (),
        1 => (a0),
        2 => (a0, a1)
    );
    match result {
        Ok(bytes) => {
            // SAFETY: the caller guarantees `out` is valid for writes.
            unsafe { *out = owned(bytes) };
            OK
        }
        Err(e) => report(format!("{e:?}")),
    }
}
