#define _POSIX_MONOTONIC_CLOCK 1
#define _POSIX_C_SOURCE 200809L

#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

extern void _current_time(uint64_t *ts);

int gettimeofday(struct timeval *__restrict tv, void *__restrict __tz) {
    uint64_t current_time[2];
    (void)__tz;

    _current_time(current_time);
    tv->tv_sec = current_time[0];
    tv->tv_usec = current_time[1] / 1000;

    return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    uint64_t current_time[2];
    switch (clk_id) {
        case CLOCK_REALTIME:
        case CLOCK_MONOTONIC:
            _current_time(current_time);
            tp->tv_sec = current_time[0];
            tp->tv_nsec = current_time[1];
            break;
        default:
            errno = EINVAL;
            return -1;
    }

    return 0;
}
