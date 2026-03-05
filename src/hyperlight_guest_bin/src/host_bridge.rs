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
use alloc::vec::Vec;
use core::ffi::*;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

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

/// Matches picolibc `struct timespec` layout for x86_64.
#[repr(C)]
struct Timespec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

/// Matches picolibc `struct timeval` layout for x86_64.
#[repr(C)]
struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

/// Retrieves the current time from the host as (seconds, nanoseconds).
fn current_time() -> (u64, u64) {
    let bytes = call_host_function::<Vec<u8>>("CurrentTime", Some(vec![]), ReturnType::VecBytes)
        .unwrap_or_default();

    if bytes.len() == 16 {
        let secs = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let nanos = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        (secs, nanos)
    } else {
        let secs = 1609459200 + CURRENT_TIME.fetch_add(1, Ordering::Relaxed);
        (secs, 0)
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

    match call_host_function::<Vec<u8>>(
        "HostRead",
        Some(vec![ParameterValue::ULong(count as u64)]),
        ReturnType::VecBytes,
    ) {
        Ok(bytes) => {
            let n = bytes.len().min(count);
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
            }
            n as isize
        }
        Err(_) => {
            set_errno(EIO);
            -1
        }
    }
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
pub extern "C" fn _current_time(ts: *mut u64) -> c_int {
    let (secs, nanos) = current_time();
    let ts = unsafe { core::slice::from_raw_parts_mut(ts, 2) };
    ts[0] = secs;
    ts[1] = nanos;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn clock_gettime(clk_id: c_ulong, tp: *mut Timespec) -> c_int {
    if tp.is_null() {
        set_errno(EINVAL);
        return -1;
    }

    match clk_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC => {
            let (secs, nanos) = current_time();
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

    let (secs, nanos) = current_time();
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
