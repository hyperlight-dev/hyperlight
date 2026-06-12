//! Reads criterion benchmark results from `target/criterion/` JSON files and
//! renders a markdown table similar to criterion-table.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Metadata from a criterion `benchmark.json` file.
#[derive(Deserialize)]
struct BenchmarkMeta {
    group_id: String,
    function_id: String,
    value_str: Option<String>,
    throughput: Option<Throughput>,
    full_id: String,
}

/// Throughput specification from `benchmark.json`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
enum Throughput {
    Bytes(u64),
    Elements(u64),
}

/// Statistical estimates from a criterion `estimates.json` file.
#[derive(Deserialize)]
struct Estimates {
    slope: Option<Estimate>,
    mean: Estimate,
}

/// A single statistical estimate with confidence interval.
#[derive(Deserialize)]
struct Estimate {
    point_estimate: f64,
}

/// Change estimates from a criterion `change/estimates.json` file.
#[derive(Deserialize)]
struct ChangeEstimates {
    mean: ChangeEstimate,
}

/// A single change estimate with point value.
#[derive(Deserialize)]
struct ChangeEstimate {
    point_estimate: f64,
}

/// Parsed change information for a benchmark.
struct ChangeInfo {
    /// Relative change as a fraction (e.g., 0.05 = +5%, -0.02 = -2%).
    point_estimate: f64,
}

/// A single benchmark entry with its metadata and timing.
struct BenchEntry {
    full_id: String,
    group_id: String,
    function_id: String,
    value_str: Option<String>,
    estimate_ns: f64,
    #[allow(dead_code)]
    throughput: Option<Throughput>,
    /// Change vs the stored baseline, if available.
    change: Option<ChangeInfo>,
}

impl BenchEntry {
    /// Returns the column label for this benchmark (the function name).
    ///
    /// If `value_str` is set, the full `function_id` is the column.
    /// Otherwise, if `function_id` contains "/", the part before the last "/" is the column.
    fn column(&self) -> &str {
        if self.value_str.is_some() {
            return &self.function_id;
        }
        match self.function_id.rfind('/') {
            Some(idx) => &self.function_id[..idx],
            None => &self.function_id,
        }
    }

    /// Returns the row label for this benchmark (the parameter/value).
    ///
    /// Uses `value_str` if set, otherwise the part after the last "/" in `function_id`.
    fn row(&self) -> Option<&str> {
        if let Some(ref v) = self.value_str {
            return Some(v.as_str());
        }
        self.function_id.rfind('/').map(|idx| &self.function_id[idx + 1..])
    }
}

/// Reads all benchmark results from the given criterion output directory
/// and renders a markdown table.
///
/// If `allowlist` is provided, only benchmarks whose `full_id` is in the list are included.
pub fn render(criterion_dir: &Path, allowlist: Option<&[String]>) -> Result<String> {
    let mut entries = discover_benchmarks(criterion_dir)?;
    if let Some(names) = allowlist {
        entries.retain(|e| names.iter().any(|n| n == &e.full_id));
    }
    if entries.is_empty() {
        anyhow::bail!("No benchmark results found in {}", criterion_dir.display());
    }
    Ok(format_table(&entries))
}

/// Discovers all benchmark entries by walking the criterion directory.
fn discover_benchmarks(criterion_dir: &Path) -> Result<Vec<BenchEntry>> {
    let mut entries = Vec::new();
    walk_for_benchmarks(criterion_dir, &mut entries)?;
    Ok(entries)
}

/// Recursively walks directories looking for `new/benchmark.json` files.
fn walk_for_benchmarks(dir: &Path, entries: &mut Vec<BenchEntry>) -> Result<()> {
    let new_dir = dir.join("new");
    if new_dir.join("benchmark.json").exists() {
        if let Some(entry) = read_benchmark_entry(&new_dir)? {
            entries.push(entry);
        }
        return Ok(());
    }

    let read_dir = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory {}", dir.display()))?;

    for entry in read_dir {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Skip non-benchmark directories
            if name_str == "reports" || name_str.starts_with('.') {
                continue;
            }
            walk_for_benchmarks(&entry.path(), entries)?;
        }
    }

    Ok(())
}

/// Reads a single benchmark entry from a `new/` directory.
fn read_benchmark_entry(new_dir: &Path) -> Result<Option<BenchEntry>> {
    let meta_path = new_dir.join("benchmark.json");
    let estimates_path = new_dir.join("estimates.json");

    if !estimates_path.exists() {
        return Ok(None);
    }

    let meta: BenchmarkMeta = serde_json::from_str(
        &std::fs::read_to_string(&meta_path)
            .with_context(|| format!("Failed to read {}", meta_path.display()))?,
    )
    .with_context(|| format!("Failed to parse {}", meta_path.display()))?;

    let estimates: Estimates = serde_json::from_str(
        &std::fs::read_to_string(&estimates_path)
            .with_context(|| format!("Failed to read {}", estimates_path.display()))?,
    )
    .with_context(|| format!("Failed to parse {}", estimates_path.display()))?;

    // Prefer slope (linear regression) over mean, matching criterion's "typical" behavior
    let estimate_ns = estimates
        .slope
        .as_ref()
        .unwrap_or(&estimates.mean)
        .point_estimate;

    // Read change/estimates.json (sibling to new/) if it exists
    let change_path = new_dir
        .parent()
        .map(|p| p.join("change").join("estimates.json"));
    let change = change_path
        .filter(|p| p.exists())
        .and_then(|p| {
            let data = std::fs::read_to_string(&p).ok()?;
            let ce: ChangeEstimates = serde_json::from_str(&data).ok()?;
            Some(ChangeInfo {
                point_estimate: ce.mean.point_estimate,
            })
        });

    Ok(Some(BenchEntry {
        full_id: meta.full_id,
        group_id: meta.group_id,
        function_id: meta.function_id,
        value_str: meta.value_str,
        throughput: meta.throughput,
        estimate_ns,
        change,
    }))
}

/// Formats all benchmark entries into a markdown string.
fn format_table(entries: &[BenchEntry]) -> String {
    // Group entries by group_id, preserving discovery order
    let mut groups: BTreeMap<&str, Vec<&BenchEntry>> = BTreeMap::new();
    for entry in entries {
        groups.entry(&entry.group_id).or_default().push(entry);
    }

    let mut out = String::new();
    writeln!(out, "# Benchmarks\n").unwrap();
    writeln!(out, "## Benchmark Results\n").unwrap();

    for (group_id, group_entries) in &groups {
        writeln!(out, "### {group_id}\n").unwrap();
        write_group_table(&mut out, group_entries);
        writeln!(out).unwrap();
    }

    out
}

/// Writes a markdown table for a single benchmark group.
fn write_group_table(out: &mut String, entries: &[&BenchEntry]) {
    // Collect unique functions (columns) and values (rows), preserving order
    let mut functions: Vec<&str> = Vec::new();
    let mut values: Vec<Option<&str>> = Vec::new();

    for entry in entries {
        let col = entry.column();
        if !functions.contains(&col) {
            functions.push(col);
        }
        let row = entry.row();
        if !values.contains(&row) {
            values.push(row);
        }
    }

    // Build a lookup: (column, row) -> &BenchEntry
    let mut lookup: BTreeMap<(&str, Option<&str>), &BenchEntry> = BTreeMap::new();
    for entry in entries {
        lookup.insert((entry.column(), entry.row()), entry);
    }

    // Header row
    write!(out, "|").unwrap();
    // Row label column (empty header)
    write!(out, "            ").unwrap();
    for func in &functions {
        write!(out, " | `{func}`").unwrap();
    }
    writeln!(out, " |").unwrap();

    // Alignment row
    write!(out, "|:-----------|").unwrap();
    for _ in &functions {
        write!(out, ":------------------------ |").unwrap();
    }
    writeln!(out).unwrap();

    // Data rows
    for val in &values {
        let row_label = match val {
            Some(v) => format!("**`{v}`**"),
            None => String::new(),
        };
        write!(out, "| {row_label:10} ").unwrap();

        for func in &functions {
            if let Some(&entry) = lookup.get(&(*func, *val)) {
                let time_str = format_time(entry.estimate_ns);
                let change_str = format_change(&entry.change);
                write!(out, " | `{time_str}` ({change_str}) ").unwrap();
            } else {
                write!(out, " |                          ").unwrap();
            }
        }
        writeln!(out, " |").unwrap();
    }
}

/// Formats change vs baseline with tiered emojis (matching criterion-table style).
///
/// Uses `compare = 1 / ratio` (where ratio = new/old) to determine tier:
/// - `compare >= 1.8` (44%+ faster): 🚀
/// - `compare > 0.9` (within ~10% slower): ✅
/// - `compare <= 0.9` (10%+ slower): ❌
fn format_change(change: &Option<ChangeInfo>) -> String {
    let Some(change) = change else {
        return "---".to_string();
    };

    // ratio = new_time / old_time
    let ratio = 1.0 + change.point_estimate;
    // compare = old_time / new_time (criterion-table's convention)
    let compare = 1.0 / ratio;

    let speedup_str = if ratio < 1.0 {
        format!("{:.2}x faster", 1.0 / ratio)
    } else if ratio > 1.0 {
        format!("{:.2}x slower", ratio)
    } else {
        format!("{ratio:.2}x")
    };

    if compare >= 1.8 {
        format!("🚀 **{speedup_str}**")
    } else if compare > 0.9 {
        format!("✅ **{speedup_str}**")
    } else {
        format!("❌ *{speedup_str}*")
    }
}

/// Formats a time in nanoseconds to a human-readable string with appropriate units.
fn format_time(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{:.2} ns", ns)
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.2} s", ns / 1_000_000_000.0)
    }
}
