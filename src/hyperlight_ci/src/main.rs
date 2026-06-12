mod bench;
mod bench_report;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hyperlight-ci", about = "Hyperlight's CI and development tools")]
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Bench(args) => bench::run(args),
        Commands::BenchReport(args) => bench_report::run(args),
    }
}
