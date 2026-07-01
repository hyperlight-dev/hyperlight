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

//! Restore-path scratch-zeroing performance and leak tests.
//!
//! On snapshot restore the guest scratch region is re-zeroed. Depending on the
//! hypervisor and the `HYPERLIGHT_SCRATCH_ZERO_STRATEGY` environment variable
//! that is done either by zeroing the existing mapping in place (`eager`) or by
//! swapping in a fresh demand-zero section and remapping it into the guest
//! (`fresh`). These tests drive both strategies across a range of large scratch
//! sizes, over many restores, and assert that:
//!
//! * every restore succeeds, and
//! * the process footprint does not grow across restores — i.e. the `fresh`
//!   strategy, which allocates a new section each restore, releases the old one
//!   (no mapping/handle leak).
//!
//! They also record per-restore timing and footprint deltas so the two
//! strategies can be compared with real numbers. Results are printed (visible
//! with `--nocapture`) and, when `HYPERLIGHT_SCRATCH_PERF_OUT` (a file path) or
//! `GITHUB_STEP_SUMMARY` is set, written there too so CI captures them without
//! any extra workflow wiring.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
use hyperlight_testing::simple_guest_as_string;
use serial_test::serial;

/// Host env var that selects the scratch-zero strategy (see `ScratchZeroStrategy`).
const STRATEGY_ENV: &str = "HYPERLIGHT_SCRATCH_ZERO_STRATEGY";
/// Optional override for the number of measured restores per config.
const RESTORES_ENV: &str = "HYPERLIGHT_SCRATCH_PERF_RESTORES";
/// Optional file path to append machine-readable result lines to.
const OUT_FILE_ENV: &str = "HYPERLIGHT_SCRATCH_PERF_OUT";

const MIB: usize = 1024 * 1024;
/// Scratch sizes exercised — "a variety of large memory configs".
const SCRATCH_SIZES: [usize; 2] = [64 * MIB, 256 * MIB];
/// Default number of measured restores per config (overridable via env).
const DEFAULT_RESTORES: usize = 50;
/// Restores run before measurement to reach steady state (allocator / page-cache
/// warm-up), so the leak check observes only steady-state growth.
const WARMUP_RESTORES: usize = 5;

/// A label describing the build/runtime configuration, so results from the same
/// test across the CI matrix can be told apart. The enabled Cargo features are
/// the key disambiguator: the suite runs once with default features and again
/// with `trace_guest` (which adds per-exit overhead and changes the timings).
fn config_label() -> String {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut features = Vec::new();
    for (name, enabled) in [
        ("kvm", cfg!(feature = "kvm")),
        ("mshv3", cfg!(feature = "mshv3")),
        ("executable_heap", cfg!(feature = "executable_heap")),
        ("trace_guest", cfg!(feature = "trace_guest")),
        ("gdb", cfg!(feature = "gdb")),
        ("mem_profile", cfg!(feature = "mem_profile")),
    ] {
        if enabled {
            features.push(name);
        }
    }
    let features = if features.is_empty() {
        "none".to_owned()
    } else {
        features.join("+")
    };
    format!(
        "os={} arch={} profile={profile} features={features}",
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

// ---------------------------------------------------------------------------
// Process memory probes
//
// `current_rss_bytes` is reported for information. `current_leak_gauge` is the
// leak signal and is deliberately a metric that a leaked scratch mapping moves
// even when its demand-zero pages are never faulted in (so plain RSS would miss
// it): virtual size on Linux, open-handle count on Windows.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn read_statm_field(index: usize) -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").expect("read /proc/self/statm");
    let pages: u64 = statm
        .split_whitespace()
        .nth(index)
        .and_then(|s| s.parse().ok())
        .expect("parse /proc/self/statm");
    pages * page_size::get() as u64
}

/// Resident set size of the current process, in bytes.
#[cfg(target_os = "linux")]
fn current_rss_bytes() -> u64 {
    read_statm_field(1) // field 1 = resident pages
}

/// Virtual memory size (address space) of the current process, in bytes. A
/// leaked scratch mapping grows this even if its pages are never resident.
#[cfg(target_os = "linux")]
fn current_leak_gauge() -> u64 {
    read_statm_field(0) // field 0 = total program size (VmSize) pages
}

#[cfg(target_os = "linux")]
const LEAK_GAUGE_NAME: &str = "vmsize_bytes";

/// A per-restore mapping leak would grow the address space by
/// `restores * scratch_bytes`; require it to stay under a single scratch's worth,
/// which tolerates allocator noise while catching the regression with huge margin.
#[cfg(target_os = "linux")]
fn leak_threshold(scratch_bytes: usize, _restores: usize) -> u64 {
    scratch_bytes as u64
}

/// Working set of the current process, in bytes.
#[cfg(windows)]
fn current_rss_bytes() -> u64 {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let mut counters = PROCESS_MEMORY_COUNTERS::default();
    let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: `counters` is a valid, correctly-sized PROCESS_MEMORY_COUNTERS; the
    // pseudo-handle from GetCurrentProcess needs no closing.
    unsafe {
        GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb).expect("GetProcessMemoryInfo");
    }
    counters.WorkingSetSize as u64
}

/// Open-handle count of the current process. Each fresh scratch section owns a
/// file-mapping handle, so a leaked section grows this by one per restore.
#[cfg(windows)]
fn current_leak_gauge() -> u64 {
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    let mut count: u32 = 0;
    // SAFETY: the pseudo-handle needs no closing; `count` is a valid out-param.
    unsafe {
        GetProcessHandleCount(GetCurrentProcess(), &mut count).expect("GetProcessHandleCount");
    }
    count as u64
}

#[cfg(windows)]
const LEAK_GAUGE_NAME: &str = "handles";

/// A per-restore section-handle leak grows the count by `restores`; require it to
/// stay under half that, tolerating a little incidental handle churn.
#[cfg(windows)]
fn leak_threshold(_scratch_bytes: usize, restores: usize) -> u64 {
    (restores as u64 / 2).max(16)
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Measurement {
    scratch_bytes: usize,
    restores: usize,
    mean: Duration,
    min: Duration,
    max: Duration,
    rss_before: u64,
    rss_after: u64,
    leak_before: u64,
    leak_after: u64,
}

impl Measurement {
    /// Growth of the leak gauge across the measured restores (signed: memory can
    /// legitimately shrink).
    fn leak_growth(&self) -> i64 {
        self.leak_after as i64 - self.leak_before as i64
    }
}

fn build_sandbox(scratch_bytes: usize) -> MultiUseSandbox {
    let mut cfg = SandboxConfiguration::default();
    cfg.set_scratch_size(scratch_bytes);
    UninitializedSandbox::new(
        GuestBinary::FilePath(simple_guest_as_string().expect("simple guest path")),
        Some(cfg),
    )
    .expect("create uninitialized sandbox")
    .evolve()
    .expect("evolve sandbox")
}

/// Snapshot a fresh sandbox, then time `restores` restores of it (after a warm-up)
/// and capture the process footprint before and after.
fn measure(scratch_bytes: usize, restores: usize) -> Measurement {
    let mut sandbox = build_sandbox(scratch_bytes);
    let snapshot = sandbox.snapshot().expect("snapshot");

    // Warm up so the leak check observes only steady-state growth.
    for _ in 0..WARMUP_RESTORES {
        sandbox.restore(snapshot.clone()).expect("warm-up restore");
    }

    let rss_before = current_rss_bytes();
    let leak_before = current_leak_gauge();

    let mut min = Duration::MAX;
    let mut max = Duration::ZERO;
    let mut total = Duration::ZERO;
    for _ in 0..restores {
        let start = Instant::now();
        sandbox.restore(snapshot.clone()).expect("measured restore");
        let elapsed = start.elapsed();
        total += elapsed;
        min = min.min(elapsed);
        max = max.max(elapsed);
    }

    let rss_after = current_rss_bytes();
    let leak_after = current_leak_gauge();

    Measurement {
        scratch_bytes,
        restores,
        mean: total / restores as u32,
        min,
        max,
        rss_before,
        rss_after,
        leak_before,
        leak_after,
    }
}

fn restores_from_env() -> usize {
    std::env::var(RESTORES_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_RESTORES)
}

/// Run every scratch size under the given strategy, emit the results, and assert
/// no leak.
fn run_strategy(strategy: &str) {
    // SAFETY: the two perf tests share the `scratch_zero_env` serial group, so no
    // other thread reads or writes the environment concurrently.
    unsafe { std::env::set_var(STRATEGY_ENV, strategy) };

    let restores = restores_from_env();
    let measurements: Vec<Measurement> = SCRATCH_SIZES
        .iter()
        .map(|&s| measure(s, restores))
        .collect();

    // SAFETY: see above.
    unsafe { std::env::remove_var(STRATEGY_ENV) };

    report(strategy, &measurements);

    for m in &measurements {
        let growth = m.leak_growth();
        let threshold = leak_threshold(m.scratch_bytes, m.restores) as i64;
        assert!(
            growth < threshold,
            "scratch strategy '{strategy}': leak gauge ({LEAK_GAUGE_NAME}) grew by {growth} over \
             {} restores of a {}-MiB scratch (threshold {threshold}); suspected mapping leak \
             (before={} after={})",
            m.restores,
            m.scratch_bytes / MIB,
            m.leak_before,
            m.leak_after,
        );
    }
}

/// Emit results to stdout, an optional results file, and the GitHub Actions step
/// summary (when present).
fn report(strategy: &str, measurements: &[Measurement]) {
    let config = config_label();
    let mut lines = String::new();
    for m in measurements {
        let _ = writeln!(
            lines,
            "SCRATCH_PERF strategy={strategy} {config} scratch_mib={} restores={} mean_us={} \
             min_us={} max_us={} rss_before_kib={} rss_after_kib={} {LEAK_GAUGE_NAME}_before={} \
             {LEAK_GAUGE_NAME}_after={} leak_growth={}",
            m.scratch_bytes / MIB,
            m.restores,
            m.mean.as_micros(),
            m.min.as_micros(),
            m.max.as_micros(),
            m.rss_before / 1024,
            m.rss_after / 1024,
            m.leak_before,
            m.leak_after,
            m.leak_growth(),
        );
    }

    // Visible with `--nocapture`; captured by libtest otherwise.
    print!("{lines}");

    // Robust capture regardless of how the harness buffers stdout.
    append_to_env_file(OUT_FILE_ENV, &lines);

    // Per-hypervisor markdown table in the CI run summary, no workflow wiring.
    append_step_summary(strategy, measurements);
}

fn append_to_env_file(env_var: &str, contents: &str) {
    use std::io::Write as _;
    if let Ok(path) = std::env::var(env_var)
        && let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
    {
        let _ = f.write_all(contents.as_bytes());
    }
}

fn append_step_summary(strategy: &str, measurements: &[Measurement]) {
    let mut md = String::new();
    let _ = writeln!(
        md,
        "\n#### scratch-zero strategy: `{strategy}` — {}\n",
        config_label()
    );
    let _ = writeln!(
        md,
        "| scratch (MiB) | restores | mean (µs) | min (µs) | max (µs) | {LEAK_GAUGE_NAME} growth |"
    );
    let _ = writeln!(md, "|---:|---:|---:|---:|---:|---:|");
    for m in measurements {
        let _ = writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} |",
            m.scratch_bytes / MIB,
            m.restores,
            m.mean.as_micros(),
            m.min.as_micros(),
            m.max.as_micros(),
            m.leak_growth(),
        );
    }
    append_to_env_file("GITHUB_STEP_SUMMARY", &md);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Force the in-place ("eager") zero on every restore and confirm it is leak-free
/// across many restores of large scratch regions. On KVM this is the lazy
/// `madvise` path; on Windows/WHP and MSHV it is the eager memset — the slow
/// baseline the "fresh" strategy improves on.
#[test]
#[serial(scratch_zero_env)]
fn eager_scratch_zero_is_leak_free_and_timed() {
    run_strategy("eager");
}

/// Force the fresh-section-and-remap strategy on every restore and confirm the
/// old section is released each time (no mapping/handle leak) while restores stay
/// fast. This is the strategy used by default on Windows/WHP and MSHV.
#[test]
#[serial(scratch_zero_env)]
fn fresh_scratch_zero_is_leak_free_and_timed() {
    run_strategy("fresh");
}
