// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! A record of what a benchmark run measured, and on what.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Name of the manifest within the criterion results directory.
const FILE_NAME: &str = "benchmarks.json";

/// Written alongside the criterion results, so a run can be interpreted without
/// the benchmark binaries that produced it.
///
/// Criterion records an id per result directory but nothing about the run as a
/// whole. Results also accumulate: a directory carries benchmarks that no
/// longer exist, indistinguishable from the ones just measured. This lists what
/// the run actually covered.
#[derive(Serialize, Deserialize)]
pub(crate) struct Manifest {
    /// Seconds since the Unix epoch. Criterion timestamps nothing, and archived
    /// results lose their file times.
    timestamp: u64,
    pub host: Host,
    pub benchmarks: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Host {
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_cpus: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    /// The hypervisor hyperlight would use here, `kvm` and so on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<String>,
}

/// Where criterion keeps its results.
fn criterion_dir() -> PathBuf {
    env::var_os("CRITERION_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target").join("criterion"))
}

#[cfg(target_os = "linux")]
fn cpu_vendor_and_model() -> (Option<String>, Option<String>) {
    let Ok(text) = fs::read_to_string("/proc/cpuinfo") else {
        return (None, None);
    };
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == key))
            .map(|(_, v)| v.trim().to_string())
    };
    (field("vendor_id"), field("model name"))
}

#[cfg(target_os = "windows")]
fn cpu_vendor_and_model() -> (Option<String>, Option<String>) {
    // e.g. "Intel64 Family 6 Model 154 Stepping 3, GenuineIntel"
    let model = env::var("PROCESSOR_IDENTIFIER").ok();
    let vendor = model
        .as_deref()
        .and_then(|m| m.rsplit_once(','))
        .map(|(_, v)| v.trim().to_string());
    (vendor, model)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn cpu_vendor_and_model() -> (Option<String>, Option<String>) {
    (None, None)
}

/// Kvm and mshv cannot both be present, so the device that exists names the
/// hypervisor hyperlight would pick.
#[cfg(target_os = "linux")]
fn hypervisor() -> Option<String> {
    [("/dev/kvm", "kvm"), ("/dev/mshv", "mshv")]
        .into_iter()
        .find(|(device, _)| Path::new(device).exists())
        .map(|(_, name)| name.to_string())
}

#[cfg(target_os = "windows")]
fn hypervisor() -> Option<String> {
    Some("whp".to_string())
}

#[cfg(target_os = "macos")]
fn hypervisor() -> Option<String> {
    Some("hvf".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn hypervisor() -> Option<String> {
    None
}

/// Record `benchmarks` as the contents of the run about to start.
pub(crate) fn write(benchmarks: impl IntoIterator<Item = String>) -> Result<()> {
    let (cpu_vendor, cpu_model) = cpu_vendor_and_model();
    let mut benchmarks: Vec<String> = benchmarks.into_iter().collect();
    benchmarks.sort();

    let manifest = Manifest {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
        host: Host {
            os: env::consts::OS.to_string(),
            arch: env::consts::ARCH.to_string(),
            logical_cpus: std::thread::available_parallelism().ok().map(Into::into),
            cpu_vendor,
            cpu_model,
            hypervisor: hypervisor(),
        },
        benchmarks,
    };

    let dir = criterion_dir();
    fs::create_dir_all(&dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    let path = dir.join(FILE_NAME);
    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&path, json).with_context(|| format!("Failed to write {}", path.display()))
}

/// What a run recorded, or `None` when it left no manifest.
pub(crate) fn read(dir: &Path) -> Result<Option<Manifest>> {
    let path = dir.join(FILE_NAME);
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(None);
    };

    serde_json::from_str(&text)
        .map(Some)
        .with_context(|| format!("Failed to parse {}", path.display()))
}
