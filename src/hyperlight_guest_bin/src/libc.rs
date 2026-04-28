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

use alloc::string::String;
use alloc::vec;
use core::ffi::*;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_guest::time;

use crate::host_comm::call_host_function;

unsafe extern "C" {
    static mut errno: c_int;
}

fn set_errno(val: c_int) {
    // SAFETY: single-threaded guest, errno is a global int (__GLOBAL_ERRNO)
    unsafe { errno = val };
}

// POSIX errno values (matching picolibc sys/errno.h)
const EINVAL: c_int = 22;
const EIO: c_int = 5;
const EBADF: c_int = 9;
const ENOSYS: c_int = 88;

// picolibc clock IDs (from time.h)
const CLOCK_REALTIME: c_ulong = 1;
const CLOCK_MONOTONIC: c_ulong = 4;

static CURRENT_TIME: AtomicU64 = AtomicU64::new(0);

/// Matches picolibc `struct timespec` layout for x86_64 and aarch64.
#[repr(C)]
pub(crate) struct Timespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

/// Matches picolibc `struct timeval` layout for x86_64 and aarch64.
#[repr(C)]
pub(crate) struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

/// Fallback clock used when the host has not armed a paravirtualized
/// clock. Returns a synthetic `(secs, nsecs)` pair that advances by one
/// second per call, preserving long-standing guest behaviour for hosts
/// built without the `enable_guest_clock` feature.
fn fallback_time() -> (u64, u64) {
    let call_count = CURRENT_TIME.fetch_add(1, Ordering::Relaxed) + 1;
    (call_count, 0)
}

/// Returns `(secs, nsecs)` for `CLOCK_REALTIME` (wall-clock).
fn realtime() -> (u64, u64) {
    match time::wall_clock_time() {
        Some((secs, nsecs)) => (secs, nsecs as u64),
        None => fallback_time(),
    }
}

/// Returns `(secs, nsecs)` for `CLOCK_MONOTONIC` (time since sandbox
/// creation).
fn monotonic() -> (u64, u64) {
    match time::monotonic_time_ns() {
        Some(ns) => (ns / 1_000_000_000, ns % 1_000_000_000),
        None => fallback_time(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        set_errno(EINVAL);
        return -1;
    }

    if fd != 0 {
        set_errno(EBADF);
        return -1;
    }

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    if buf.is_null() && count > 0 {
        set_errno(EINVAL);
        return -1;
    }

    if fd != 1 && fd != 2 {
        set_errno(EBADF);
        return -1;
    }

    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    let s = String::from_utf8_lossy(slice);
    match call_host_function::<i32>(
        "HostPrint",
        Some(vec![ParameterValue::String(s.into_owned())]),
        ReturnType::Int,
    ) {
        Ok(_) => count as isize,
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clock_gettime(clk_id: c_ulong, tp: *mut Timespec) -> c_int {
    if tp.is_null() {
        set_errno(EINVAL);
        return -1;
    }

    match clk_id {
        CLOCK_REALTIME => {
            let (secs, nanos) = realtime();
            unsafe {
                (*tp).tv_sec = secs as c_long;
                (*tp).tv_nsec = nanos as c_long;
            }
            0
        }
        CLOCK_MONOTONIC => {
            let (secs, nanos) = monotonic();
            unsafe {
                (*tp).tv_sec = secs as c_long;
                (*tp).tv_nsec = nanos as c_long;
            }
            0
        }
        _ => {
            set_errno(EINVAL);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gettimeofday(tv: *mut Timeval, _tz: *mut c_void) -> c_int {
    if tv.is_null() {
        set_errno(EINVAL);
        return -1;
    }

    let (secs, nanos) = realtime();
    unsafe {
        (*tv).tv_sec = secs as c_long;
        (*tv).tv_usec = (nanos / 1000) as c_long;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(ec: c_int) -> ! {
    hyperlight_guest::exit::abort_with_code(&[ec as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn lseek(_fd: c_int, _offset: c_long, _whence: c_int) -> c_long {
    set_errno(ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn close(_fd: c_int) -> c_int {
    0
}
