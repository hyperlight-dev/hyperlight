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

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::OnceCell;
use core::ffi::*;
use core::sync::atomic::{AtomicU64, Ordering};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};

use crate::host_comm::{call_host_function, get_host_function_details};

static CURRENT_TIME: AtomicU64 = AtomicU64::new(0);
static CAPS: Caps = Caps::new();

// Host capability flags
struct Caps {
    host_read: OnceCell<bool>,
    host_clock: OnceCell<bool>,
}

unsafe impl Sync for Caps {}

impl Caps {
    const fn new() -> Self {
        Self {
            host_read: OnceCell::new(),
            host_clock: OnceCell::new(),
        }
    }

    #[inline]
    fn query(name: &str) -> bool {
        get_host_function_details()
            .host_functions
            .unwrap_or_default()
            .iter()
            .any(|f| f.function_name == name)
    }

    #[inline]
    fn host_read(&self) -> bool {
        *self.host_read.get_or_init(|| Self::query("HostRead"))
    }

    #[inline]
    fn host_clock(&self) -> bool {
        *self.host_clock.get_or_init(|| Self::query("CurrentTime"))
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    // Only stdin (fd=0) and only if HostRead is defined
    if fd != 0 || !CAPS.host_read() {
        return 0;
    }

    let bytes = call_host_function::<Vec<u8>>(
        "HostRead",
        Some(vec![ParameterValue::ULong(count as u64)]),
        ReturnType::VecBytes,
    )
    .unwrap_or_default();

    let n = bytes.len();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
    }
    n as isize
}

#[unsafe(no_mangle)]
pub extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    // Only stdout (fd=1) and stderr (fd=2)
    if fd != 1 && fd != 2 {
        return count as isize;
    }

    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    let s = core::str::from_utf8(slice).unwrap_or("<invalid utf8>");
    let _ = call_host_function::<i32>(
        "HostPrint",
        Some(vec![ParameterValue::String(s.to_string())]),
        ReturnType::Int,
    );
    count as isize
}

#[unsafe(no_mangle)]
pub extern "C" fn _current_time(ts: *mut u64) -> c_int {
    let bytes = if !CAPS.host_clock() {
        vec![]
    } else {
        call_host_function::<Vec<u8>>("CurrentTime", Some(vec![]), ReturnType::VecBytes).unwrap()
    };

    let (secs, nanos) = if bytes.len() == 16 {
        let secs = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let nanos = u64::from_ne_bytes(bytes[8..16].try_into().unwrap());
        (secs, nanos)
    } else {
        let secs = 1609459200 + CURRENT_TIME.fetch_add(1, Ordering::Relaxed);
        (secs, 0)
    };

    let ts = unsafe { core::slice::from_raw_parts_mut(ts, 2) };
    ts[0] = secs;
    ts[1] = nanos;
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(ec: c_int) -> ! {
    hyperlight_guest::exit::abort_with_code(&[ec as u8]);
}

#[unsafe(no_mangle)]
pub extern "C" fn lseek(_fd: c_int, _offset: c_long, _whence: c_int) -> c_long {
    0 // NOP
}

#[unsafe(no_mangle)]
pub extern "C" fn close(_fd: c_int) -> c_int {
    0 // NOP
}
