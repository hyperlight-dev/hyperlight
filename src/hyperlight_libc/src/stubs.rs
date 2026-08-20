/*
Copyright 2026  The Hyperlight Authors.

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

use crate::{CLOCK_REALTIME, EINVAL, c_int, c_void, clock_gettime, errno, timespec, timeval};

#[unsafe(no_mangle)]
extern "C" fn gettimeofday(tv: *mut timeval, _tz: *mut c_void) -> c_int {
    if tv.is_null() {
        unsafe { errno = EINVAL as _ };
        return -1;
    }

    let mut ts = timespec::default();
    let res = unsafe { clock_gettime(CLOCK_REALTIME as _, &raw mut ts) };
    if res != 0 {
        return -1;
    }

    unsafe {
        (*tv).tv_sec = ts.tv_sec;
        (*tv).tv_usec = ts.tv_nsec / 1000;
    }

    0
}
