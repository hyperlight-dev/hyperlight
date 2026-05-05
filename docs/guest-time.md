# Paravirtualized Guest Clock

Hyperlight's `enable_guest_clock` Cargo feature gives guests a cheap way to ask
"what time is it?" without taking a VM exit. When the host is built with the
feature, every sandbox exposes a paravirtualized clock that the guest can read
using ordinary memory loads.

## What the guest gets

When the feature is enabled the host populates a single 4 KiB "clock page"
inside the sandbox's scratch region. The page carries two pieces of
information:

- **A hypervisor-specific calibration block at offset `0x00`.** Written by
  KVM (`kvm_clock`) or Hyper-V / MSHV (Reference TSC). Contains the TSC
  frequency, scaling constants, and a sequence lock the guest uses to read it
  atomically. The entire clock page is hypervisor-owned; Hyperlight does not
  write to it.
- **Hyperlight metadata in the scratch bookkeeping page** (separate from the
  clock page): a `u64` [`ClockType`](../src/hyperlight_common/src/time.rs) tag
  and `boot_time_ns`, the Unix-epoch origin of the monotonic clock computed
  by the host as `wall_now - monotonic_now` (see below). These live at fixed
  offsets from the top of scratch (`-0x28` and `-0x30`), NOT in the clock
  page, so a future TLFS extension cannot clobber them.

With those two pieces the guest can compute:

- **Monotonic nanoseconds since boot** — read the TSC, apply the scaling
  factors from the calibration block, giving you a `CLOCK_MONOTONIC`
  equivalent.
- **Wall-clock nanoseconds since the Unix epoch** — add `boot_time_ns` to the
  monotonic value above, giving you a `CLOCK_REALTIME` / `gettimeofday`. `boot_time_ns` is computed by the host as
  `SystemTime::now() - KVM_GET_CLOCK` (on KVM) or
  `SystemTime::now() - TIME_REF_COUNT` (on Hyper-V) after sandbox
  initialisation. Hyper-V has no equivalent to KVM's
  `MSR_KVM_WALL_CLOCK_NEW`, so we use this uniform host-computed approach
  on all backends.

> **Note (KVM only):** Wall-clock time returns `None` during
> `hyperlight_main` (guest init). On KVM, `KVM_GET_CLOCK` is unreliable
> until the "master clock" is established at first vCPU entry, so
> `boot_time_ns` is stamped after init completes. Monotonic time works
> fine during init. Wall-clock time becomes available on the first
> dispatch call.

Both reads are lock-free (well, seqlock-protected for the calibration block)
and never leave the guest.

## Using it in a Rust guest

The guest-side API lives in `hyperlight_guest::time` for the low-level
readers and `hyperlight_guest_bin::time` for a `std::time`-flavoured
wrapper:

```rust
// Low-level, no_std readers.
use hyperlight_guest::time;

if time::is_available() {
    let mono_ns: u64 = time::monotonic_time_ns().unwrap();
    let wall_ns: u64 = time::wall_clock_time_ns().unwrap();
}

// std::time-flavoured wrapper (hyperlight_guest_bin only).
use hyperlight_guest_bin::time::{Instant, SystemTime, UNIX_EPOCH};

let t0 = Instant::now()?;
// ... do work ...
let elapsed = t0.elapsed()?;

let now = SystemTime::now()?;
let unix_ns = now.duration_since(UNIX_EPOCH)?.as_nanos();
```

C guests that use picolibc get paravirt time for free: `hyperlight_guest_bin`
wires `clock_gettime(CLOCK_MONOTONIC|CLOCK_REALTIME)` and `gettimeofday` into
the same reader, so existing C code continues to work unchanged.

## Snapshot / restore semantics

Both `boot_time_ns` and the hypervisor calibration block live inside scratch
memory, which is not included in snapshots. On every
`MultiUseSandbox::restore`, the host re-arms the clock page: it re-installs
the pvclock MSR / Hyper-V register against the fresh vCPU state and stamps a
new `boot_time_ns` captured at the moment of restore. As a result a restored
guest observes wall-clock time reflecting the restore moment, not the
original boot — which is what wall clocks are supposed to do.

## Enabling the feature

Turn it on in the host's `Cargo.toml`:

```toml
[dependencies]
hyperlight-host = { version = "...", features = ["enable_guest_clock"] }
```

The feature is x86_64 only; on aarch64 it has no effect. It is off by default
so existing sandboxes don't pay for a facility they don't use. When off, the
clock page is still reserved in the layout (so memory maps are stable) but
left un-mapped against any hypervisor clock source; `hyperlight_guest::time`
readers then report "unavailable" and fall back to whatever the guest wants
to do about it (the picolibc wiring returns a synthetic 1-second-per-call
counter, which is enough to stop `strftime` crashing and not much else).

## Layout details

The clock page sits 3 pages below the very top of the scratch region:

| Offset from top | Size  | Contents                                       |
|-----------------|-------|------------------------------------------------|
| `-0x1000`       | 4 KiB | Bookkeeping (size, allocator counter, ...)     |
| `-0x2000`       | 4 KiB | Reserved for shared-state counter              |
| `-0x3000`       | 4 KiB | Paravirtualized clock page                     |

Because the clock page is at the top of scratch, both the guest's main stack
and its IST1 (exception) stack are configured to start one page below the
clock page (at `MAX_GVA + 1 - SCRATCH_TOP_CLOCK_PAGE_OFFSET`) so stack writes
— including page-fault handlers running on IST1 — cannot clobber the trailer.
The allocator reserves the top three pages unconditionally so the memory map
stays identical whether or not the feature is enabled.

## Non-goals

- **Sub-microsecond accuracy.** `boot_time_ns` is computed from two
  back-to-back host reads (`SystemTime::now()` and `KVM_GET_CLOCK` /
  `TIME_REF_COUNT`). On KVM, residual disagreement between `KVM_GET_CLOCK`
  and the pvclock page can add up to ~13ms of constant offset (observed on
  WSL2; root cause uncertain). On Hyper-V the offset should be negligible.
- **`CLOCK_PROCESS_CPUTIME_ID` and friends.** The clock page exposes only
  monotonic and wall-clock time; per-thread / per-process CPU time is out of
  scope.
- **Timers or sleeps.** The guest can read the clock but has no way to ask
  the hypervisor to wake it up later — that is still done through the
  existing guest-function call model.
