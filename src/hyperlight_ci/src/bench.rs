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
//! The `bench` subcommand: runs criterion benchmarks in parallel via criterion-swarm.

use std::path::PathBuf;

use anyhow::Context;
use criterion_swarm::{CriterionSwarm, OutputMode};

/// An output mode flag for `--build-output` / `--benchmarks-output`.
#[derive(Clone, Debug)]
pub(crate) struct OutputModeFlags(OutputMode);

impl OutputModeFlags {
    /// Parse a single token into an `OutputMode` flag.
    fn parse_one(s: &str) -> Result<OutputMode, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "spinner" => Ok(OutputMode::SPINNER),
            "stream" => Ok(OutputMode::STREAM),
            "summary" => Ok(OutputMode::SUMMARY),
            "none" | "silent" => Ok(OutputMode::SILENT),
            other => Err(format!(
                "unknown output mode `{other}` (expected: spinner, stream, summary, none)"
            )),
        }
    }
}

impl std::str::FromStr for OutputModeFlags {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut mode = OutputMode::SILENT;
        for part in s.split(',') {
            mode = mode | Self::parse_one(part)?;
        }
        Ok(Self(mode))
    }
}

/// Merge a `Vec<OutputModeFlags>` into a single `OutputMode` by OR-ing them together.
fn merge_output_modes(flags: &[OutputModeFlags]) -> OutputMode {
    flags.iter().fold(OutputMode::SILENT, |acc, f| acc | f.0)
}

/// Command-line arguments for the `bench` subcommand.
#[derive(clap::Args)]
pub struct BenchArgs {
    /// Pre-built benchmark binary to use (skip build step; can be specified multiple times)
    #[arg(long)]
    pub binary: Vec<PathBuf>,

    /// Number of benchmarks to run in parallel (0 = all P-cores, default: 0)
    #[arg(long, short, default_value_t = 0)]
    pub jobs: usize,

    /// Build output mode (comma-separated or repeated): spinner, stream, summary, none
    #[arg(long, value_delimiter = ',', default_value = "spinner,stream,summary")]
    pub build_output: Vec<OutputModeFlags>,

    /// Benchmarks output mode (comma-separated or repeated): spinner, stream, summary, none
    #[arg(long, value_delimiter = ',', default_value = "spinner,stream,summary")]
    pub benchmarks_output: Vec<OutputModeFlags>,

    /// Additional features to pass to cargo when building benchmarks (can be specified multiple times)
    #[arg(short = 'F', long)]
    pub features: Vec<String>,

    /// Additional arguments to forward to criterion benchmarks
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub bench_args: Vec<String>,
}

pub async fn run(args: BenchArgs) -> anyhow::Result<()> {
    let mut swarm = CriterionSwarm::builder().jobs(args.jobs);

    if !args.binary.is_empty() {
        swarm = swarm.binaries(args.binary);
    }

    if !args.features.is_empty() {
        swarm = swarm.build_args(["--features".to_string(), args.features.join(",")]);
    }

    for arg in args.bench_args {
        swarm = swarm.bench_arg(arg);
    }

    let build_mode = merge_output_modes(&args.build_output);
    let bench_mode = merge_output_modes(&args.benchmarks_output);
    swarm = swarm.output(
        criterion_swarm::ProgressReporter::new()
            .build(build_mode)
            .benchmarks(bench_mode),
    );

    let swarm = swarm
        .prepare()
        .await
        .context("Failed to prepare criterion swarm")?;
    if bench_mode == (bench_mode | OutputMode::SUMMARY) {
        let total = swarm.benchmarks().len();
        let jobs = swarm.jobs().min(total);
        println!("Running {total} benchmarks with parallelism {jobs}");
    }
    swarm.run().await.context("Failed to run criterion swarm")
}
