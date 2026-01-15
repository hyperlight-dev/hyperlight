# Guest Time API

This document describes how to access time from within a Hyperlight guest. Hyperlight provides a paravirtualized clock that allows guests to read time without expensive VM exits.

## Overview

When a sandbox is created, Hyperlight configures a shared clock page between the host and guest. The guest can read time by accessing this shared page and the CPU's Time Stamp Counter (TSC), without requiring any VM exit or host call.

### Supported Hypervisors

- **KVM**: Uses KVM pvclock (MSR `0x4b564d01`)
- **MSHV**: Uses Hyper-V Reference TSC page
- **WHP** (Windows): Uses Hyper-V Reference TSC page

### Clock Types

- **Monotonic time**: Time since sandbox creation. Guaranteed to never go backwards. Use for measuring elapsed time.
- **Wall-clock time**: UTC time since Unix epoch (1970-01-01 00:00:00 UTC). Can be used for timestamps.
- **Local time**: Wall-clock time adjusted for the host's timezone offset (captured at sandbox creation).

## Feature Flag

The time functionality is controlled by the `guest_time` feature flag, which is enabled by default. To disable:

```toml
[dependencies]
hyperlight-guest = { version = "...", default-features = false }
```

## Rust API

### High-Level API (`hyperlight_guest_bin::time`)

The recommended API for Rust guests mirrors `std::time`:

```rust
use hyperlight_guest_bin::time::{SystemTime, Instant, UNIX_EPOCH};
use core::time::Duration;

// Wall-clock time (like std::time::SystemTime)
let now = SystemTime::now();
let duration = now.duration_since(UNIX_EPOCH).unwrap();
let unix_timestamp = duration.as_secs();

// Monotonic time for measuring elapsed time (like std::time::Instant)
let start = Instant::now();
// ... do work ...
let elapsed = start.elapsed();

// Get timezone offset (seconds east of UTC)
use hyperlight_guest_bin::time::utc_offset_seconds;
if let Some(offset) = utc_offset_seconds() {
    // offset is seconds to add to UTC for local time
    // e.g., +3600 for UTC+1, -18000 for UTC-5
}
```

#### `SystemTime`

Represents wall-clock time (UTC). Methods:

- `SystemTime::now()` - Get current wall-clock time
- `duration_since(earlier)` - Duration between two system times
- `elapsed()` - Duration since this time was captured
- `checked_add(duration)` / `checked_sub(duration)` - Arithmetic operations

#### `Instant`

Represents monotonic time for measuring durations. Methods:

- `Instant::now()` - Get current monotonic time
- `duration_since(earlier)` - Duration between two instants
- `elapsed()` - Duration since this instant was captured
- Supports `+`, `-` operators with `Duration`
- Supports `-` between two `Instant`s to get a `Duration`

#### `DateTime`

For formatting human-readable dates and times:

```rust
use hyperlight_guest_bin::time::DateTime;

// Get current local time
let dt = DateTime::now_local();

// Format: "Thursday 15th January 2026 15:34:56"
let formatted = format!(
    "{} {} {} {} {:02}:{:02}:{:02}",
    dt.weekday().name(),      // "Thursday"
    dt.day_ordinal(),         // "15th"
    dt.month().name(),        // "January"
    dt.year(),                // 2026
    dt.hour(),                // 15
    dt.minute(),              // 34
    dt.second()               // 56
);
```

Available methods on `DateTime`:

| Method | Returns | Description |
|--------|---------|-------------|
| `DateTime::now()` | `DateTime` | Current UTC time |
| `DateTime::now_local()` | `DateTime` | Current local time |
| `year()` | `i32` | Year (e.g., 2026) |
| `month()` | `Month` | Month enum |
| `month_number()` | `u8` | Month (1-12) |
| `day()` | `u8` | Day of month (1-31) |
| `hour()` | `u8` | Hour (0-23) |
| `minute()` | `u8` | Minute (0-59) |
| `second()` | `u8` | Second (0-59) |
| `nanosecond()` | `u32` | Nanosecond |
| `weekday()` | `Weekday` | Day of week enum |
| `day_of_year()` | `u16` | Day of year (1-366) |
| `day_ordinal()` | `&str` | Day with suffix ("15th") |
| `hour12()` | `u8` | 12-hour format (1-12) |
| `is_pm()` | `bool` | True if PM |
| `am_pm()` | `&str` | "AM" or "PM" |

The `Weekday` and `Month` enums provide:
- `name()` - Full name ("Thursday", "January")
- `short_name()` - Abbreviated ("Thu", "Jan")

### Low-Level API (`hyperlight_guest::time`)

For cases where you need direct access or have a custom `GuestHandle`:

```rust
use hyperlight_guest::time::{
    monotonic_time_ns,
    wall_clock_time_ns,
    is_clock_available,
    utc_offset_seconds,
};

// Check availability
if is_clock_available(handle) {
    // Get raw nanoseconds
    let mono_ns = monotonic_time_ns(handle).unwrap();
    let wall_ns = wall_clock_time_ns(handle).unwrap();
    let offset = utc_offset_seconds(handle).unwrap();
}
```

## C API

The C API provides POSIX-compatible functions:

### `gettimeofday`

```c
#include "hyperlight_guest.h"

hl_timeval tv;
hl_timezone tz;

// Get wall-clock time and timezone
if (gettimeofday(&tv, &tz) == 0) {
    // tv.tv_sec is seconds since Unix epoch
    // tv.tv_usec is microseconds
    // tz.tz_minuteswest is minutes west of UTC
}
```

### `clock_gettime`

```c
#include "hyperlight_guest.h"

hl_timespec ts;

// Wall-clock time (UTC)
if (clock_gettime(hl_CLOCK_REALTIME, &ts) == 0) {
    // ts.tv_sec is seconds since Unix epoch
    // ts.tv_nsec is nanoseconds
}

// Monotonic time (since sandbox creation)
if (clock_gettime(hl_CLOCK_MONOTONIC, &ts) == 0) {
    // ts.tv_sec is seconds since sandbox started
    // ts.tv_nsec is nanoseconds
}
```

### `time`

```c
#include "hyperlight_guest.h"

int64_t seconds = time(NULL);  // Returns seconds since Unix epoch
```

### Broken-Down Time (`struct tm`)

Convert timestamps to human-readable components:

```c
#include "hyperlight_guest.h"

int64_t now = time(NULL);
hl_tm tm_utc, tm_local;

// UTC time
gmtime_r(&now, &tm_utc);

// Local time (using timezone captured at sandbox creation)
localtime_r(&now, &tm_local);

// Access components
int year = tm_local.tm_year + 1900;  // Years since 1900
int month = tm_local.tm_mon + 1;     // 0-11, so add 1
int day = tm_local.tm_mday;          // 1-31
int hour = tm_local.tm_hour;         // 0-23
int minute = tm_local.tm_min;        // 0-59
int second = tm_local.tm_sec;        // 0-59
int weekday = tm_local.tm_wday;      // 0=Sunday, 6=Saturday
int yearday = tm_local.tm_yday;      // 0-365
```

### `strftime` - Format Time as String

```c
#include "hyperlight_guest.h"

int64_t now = time(NULL);
hl_tm tm_local;
localtime_r(&now, &tm_local);

char buf[128];
size_t len = strftime((uint8_t*)buf, sizeof(buf), 
                      (const uint8_t*)"%A %d %B %Y %H:%M:%S", 
                      &tm_local);
// buf = "Thursday 15 January 2026 15:34:56"
```

#### Supported Format Specifiers

| Specifier | Description | Example |
|-----------|-------------|---------|
| `%a` | Abbreviated weekday | "Thu" |
| `%A` | Full weekday | "Thursday" |
| `%b`, `%h` | Abbreviated month | "Jan" |
| `%B` | Full month | "January" |
| `%d` | Day of month (01-31) | "15" |
| `%e` | Day of month, space-padded | " 5" |
| `%H` | Hour 24h (00-23) | "15" |
| `%I` | Hour 12h (01-12) | "03" |
| `%j` | Day of year (001-366) | "015" |
| `%m` | Month (01-12) | "01" |
| `%M` | Minute (00-59) | "34" |
| `%p` | AM/PM | "PM" |
| `%P` | am/pm | "pm" |
| `%S` | Second (00-59) | "56" |
| `%u` | Weekday (1-7, Mon=1) | "4" |
| `%w` | Weekday (0-6, Sun=0) | "4" |
| `%y` | Year without century | "26" |
| `%Y` | Year with century | "2026" |
| `%z` | Timezone offset | "+0100" |
| `%Z` | Timezone name | "UTC" or "LOCAL" |
| `%%` | Literal % | "%" |
| `%n` | Newline | "\n" |
| `%t` | Tab | "\t" |

### `mktime` / `timegm` - Convert to Timestamp

```c
hl_tm tm = {
    .tm_year = 2026 - 1900,  // Years since 1900
    .tm_mon = 0,             // January (0-11)
    .tm_mday = 15,           // Day of month
    .tm_hour = 15,
    .tm_min = 34,
    .tm_sec = 56
};

// From local time to UTC timestamp
int64_t local_ts = mktime(&tm);

// From UTC time to UTC timestamp
int64_t utc_ts = timegm(&tm);
```

### Supported Clock IDs

| Clock ID | Description |
|----------|-------------|
| `hl_CLOCK_REALTIME` | Wall-clock time (UTC) |
| `hl_CLOCK_REALTIME_COARSE` | Same as `CLOCK_REALTIME` |
| `hl_CLOCK_MONOTONIC` | Time since sandbox creation |
| `hl_CLOCK_MONOTONIC_COARSE` | Same as `CLOCK_MONOTONIC` |
| `hl_CLOCK_BOOTTIME` | Same as `CLOCK_MONOTONIC` |

Note: `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID` are not supported.

## Timezone Handling

The host's timezone offset is captured when the sandbox is created and stored in the clock region. This allows guests to compute local time without additional host calls.

> **⚠️ Limitation: Static Timezone Offset**
>
> The timezone offset is a snapshot from sandbox creation time. It does **not** update
> if the host's timezone changes during the sandbox lifetime. This means:
>
> - **DST transitions are not reflected**: If a sandbox is created before a DST change
>   and continues running after, local time will be off by one hour.
> - **Manual timezone changes are not reflected**: If the host's timezone is changed
>   while the sandbox is running, the guest will still use the original offset.
>
> For applications where accurate local time across DST boundaries is critical,
> consider using UTC time and handling timezone conversion on the host side.

```rust
// Rust
use hyperlight_guest_bin::time::{utc_offset_seconds, local_time_ns};

let offset = utc_offset_seconds().unwrap(); // Seconds east of UTC
let local_ns = local_time_ns().unwrap();    // Local time in nanoseconds
```

```c
// C - use gettimeofday with timezone
hl_timeval tv;
hl_timezone tz;
gettimeofday(&tv, &tz);
int offset_seconds = -(tz.tz_minuteswest * 60); // Convert to seconds east
```

## Performance

Reading time via the paravirtualized clock is very fast because:

1. No VM exit is required
2. The clock page is in shared memory accessible to the guest
3. Only a few memory reads and TSC reads are needed

This makes it suitable for high-frequency timing operations like benchmarking or rate limiting.

## Error Handling

Time functions return `None` (Rust) or `-1` (C) if:

- The clock is not available (hypervisor doesn't support pvclock)
- The clock data is being updated (rare, retry will succeed)

For the high-level Rust API, `SystemTime::now()` and `Instant::now()` return a zero time if the clock is unavailable, rather than panicking.
