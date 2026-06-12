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
mod bench;
mod bench_report;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "hyperlight-ci",
    about = "Hyperlight's CI and development tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run benchmarks using the benchmark binary directly
    Bench(bench::BenchArgs),
    /// Generate a markdown table from existing criterion benchmark results
    BenchReport(bench_report::BenchReportArgs),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Bench(args) => bench::run(args).await,
        Commands::BenchReport(args) => bench_report::run(args).await,
    }
}
