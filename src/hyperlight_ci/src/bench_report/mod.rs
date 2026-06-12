//! The `bench-report` subcommand: generates a markdown table from existing
//! criterion benchmark results in `target/criterion/`.

mod table;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use clap::Args;

/// Command-line arguments for the `bench-report` subcommand.
#[derive(Args)]
pub struct BenchReportArgs {
    /// Filter benchmarks by name (substring match, or exact with --exact)
    pub filter: Option<String>,

    /// Match the filter exactly instead of as a substring
    #[arg(long)]
    pub exact: bool,

    /// Benchmark binary to list benchmarks from (can be specified multiple times).
    /// When provided, only benchmarks available in these binaries are included.
    #[arg(long)]
    pub binary: Vec<PathBuf>,

    /// Path to the criterion output directory
    #[arg(long, default_value = "target/criterion")]
    pub criterion_dir: PathBuf,

    /// Output file path (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Entry point for the bench-report subcommand.
pub fn run(args: BenchReportArgs) -> Result<()> {
    let allowlist = build_allowlist(&args)?;
    let allowlist_ref = allowlist.as_deref();

    let markdown = table::render(&args.criterion_dir, allowlist_ref)?;

    if let Some(path) = &args.output {
        std::fs::write(path, &markdown)?;
    } else {
        print!("{markdown}");
    }

    Ok(())
}

/// Builds an allowlist of benchmark full_ids by querying binaries and applying the filter.
///
/// - If `--binary` is specified, lists benchmarks from each binary.
/// - If a text filter is specified, applies substring (or exact) matching.
/// - If neither is specified, returns `None` (include everything).
fn build_allowlist(args: &BenchReportArgs) -> Result<Option<Vec<String>>> {
    let mut names: Option<Vec<String>> = None;

    if !args.binary.is_empty() {
        let mut list = Vec::new();
        for binary in &args.binary {
            let output = Command::new(binary)
                .args(["--bench", "--list"])
                .output()
                .with_context(|| format!("Failed to run {} --bench --list", binary.display()))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if let Some(name) = line.strip_suffix(": benchmark") {
                    list.push(name.to_string());
                }
            }
        }
        names = Some(list);
    }

    if let Some(ref filter) = args.filter {
        let base = names.take();
        let iter: Box<dyn Iterator<Item = String>> = match base {
            Some(v) => Box::new(v.into_iter()),
            None => {
                // No binaries specified; discover all benchmarks from criterion dir
                let all = discover_all_ids(&args.criterion_dir)?;
                Box::new(all.into_iter())
            }
        };

        let filtered: Vec<String> = if args.exact {
            iter.filter(|id| id == filter).collect()
        } else {
            iter.filter(|id| id.contains(filter.as_str())).collect()
        };
        names = Some(filtered);
    }

    Ok(names)
}

/// Discovers all benchmark full_ids from the criterion directory.
fn discover_all_ids(criterion_dir: &PathBuf) -> Result<Vec<String>> {
    // Render with no filter to get all entries, then extract IDs
    // We can reuse the walk logic by reading benchmark.json files
    let mut ids = Vec::new();
    walk_for_ids(criterion_dir, &mut ids)?;
    Ok(ids)
}

/// Recursively walks directories looking for `new/benchmark.json` to extract full_ids.
fn walk_for_ids(dir: &std::path::Path, ids: &mut Vec<String>) -> Result<()> {
    let new_dir = dir.join("new");
    let meta_path = new_dir.join("benchmark.json");
    if meta_path.exists() {
        let data = std::fs::read_to_string(&meta_path)
            .with_context(|| format!("Failed to read {}", meta_path.display()))?;
        #[derive(serde::Deserialize)]
        struct Meta {
            full_id: String,
        }
        let meta: Meta = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse {}", meta_path.display()))?;
        ids.push(meta.full_id);
        return Ok(());
    }

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };

    for entry in read_dir {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "reports" || name_str.starts_with('.') {
                continue;
            }
            walk_for_ids(&entry.path(), ids)?;
        }
    }

    Ok(())
}
