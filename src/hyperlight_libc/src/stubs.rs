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
