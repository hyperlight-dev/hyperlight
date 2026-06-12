/*
Copyright 2025 The Hyperlight Authors.

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
//! The `bench-report` subcommand: generates a markdown table from existing
//! criterion benchmark results in `target/criterion/`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use criterion_swarm::{CriterionSwarm, NoopReporter};

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

    /// Additional arguments to forward to criterion benchmarks (e.g. filter, --exact)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub bench_args: Vec<String>,
}

/// Entry point for the bench-report subcommand.
pub async fn run(args: BenchReportArgs) -> Result<()> {
    let allowlist = build_allowlist(&args).await?;

    let markdown = criterion_markdown::render(&args.criterion_dir, &allowlist)?;

    print!("{markdown}");

    Ok(())
}

/// Builds an allowlist of benchmark full_ids by discovering benchmarks via CriterionSwarm.
///
/// All trailing arguments (filter, --exact, etc.) are forwarded as bench args
/// to CriterionSwarm so it handles filtering during discovery.
async fn build_allowlist(args: &BenchReportArgs) -> Result<Vec<String>> {
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
