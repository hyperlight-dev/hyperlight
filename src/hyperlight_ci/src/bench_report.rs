// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! The `bench-report` subcommand: generates a markdown table from existing
//! criterion benchmark results in `target/criterion/`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use criterion_swarm::{CriterionSwarm, NoopReporter};

use crate::config::BenchConfig;

/// Command-line arguments for the `bench-report` subcommand.
#[derive(Args)]
pub struct BenchReportArgs {
    /// Benchmark binary to list benchmarks from (can be specified multiple times).
    /// When provided, only benchmarks available in these binaries are included.
    #[arg(long)]
    pub binary: Vec<PathBuf>,

    /// Path to the criterion output directory
    #[arg(long, default_value = "target/criterion")]
    pub criterion_dir: PathBuf,

    /// Wrap the output in a collapsible <details> tag with the given summary text.
    #[arg(long)]
    pub collapsible: Option<String>,

    /// Report only the benchmarks selected by this config file
    #[arg(long, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Additional arguments to forward to criterion benchmarks (e.g. filter, --exact)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub bench_args: Vec<String>,
}

/// Entry point for the bench-report subcommand.
pub async fn run(args: BenchReportArgs) -> Result<()> {
    let mut benchmarks = discover_benchmarks(&args).await?;

    if let Some(path) = &args.config_file {
        benchmarks = BenchConfig::load(path)?.select(benchmarks)?;
    }

    let options = criterion_markdown::RenderOptions {
        collapsible: args.collapsible,
    };
    let markdown =
        criterion_markdown::render_with_options(&args.criterion_dir, &benchmarks, &options)?;

    print!("{markdown}");

    Ok(())
}

/// Discovers benchmark full_ids via CriterionSwarm.
///
/// All trailing arguments (filter, --exact, etc.) are forwarded as bench args
/// to CriterionSwarm so it handles filtering during discovery.
async fn discover_benchmarks(args: &BenchReportArgs) -> Result<Vec<String>> {
    let mut swarm = CriterionSwarm::builder();

    if !args.binary.is_empty() {
        swarm = swarm.binaries(&args.binary);
    }

    for arg in &args.bench_args {
        swarm = swarm.bench_arg(arg);
    }

    let discovered = swarm
        .output(NoopReporter)
        .prepare()
        .await
        .context("Failed to discover benchmarks")?;

    Ok(discovered
        .benchmarks()
        .into_iter()
        .map(str::to_string)
        .collect())
}
