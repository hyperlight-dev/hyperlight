/* Bindgen wrapper for picolibc types used by hyperlight guest */

/* Enable POSIX clock definitions that picolibc guards behind __rtems__ */
#define _POSIX_MONOTONIC_CLOCK 200112L

#include <errno.h>
#include <time.h>
#include <sys/time.h>
