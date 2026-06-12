//! The `bench` subcommand: discovers, runs, and reports on criterion benchmarks
//! using the benchmark binary directly.

mod args;
mod discovery;
mod output;
mod process;
mod progress;
mod runner;
mod cpu;

pub use args::BenchArgs;

use anyhow::{Context, Result};

use self::discovery::BenchmarkDiscovery;
use self::runner::BenchRunner;

/// Entry point for the bench subcommand. Builds a single-threaded tokio runtime
/// and delegates to the async implementation.
pub fn run(args: BenchArgs) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?
        .block_on(run_async(args))
}

async fn run_async(args: BenchArgs) -> Result<()> {
    let discovery = BenchmarkDiscovery::new(&args.features, args.filter.as_deref(), args.exact);

    let binaries = if args.binary.is_empty() {
        if args.quiet < 2 {
            eprintln!("Building benchmarks ...");
        }
        discovery.build().await?
    } else {
        args.binary.clone()
    };

    let mut benches = Vec::new();
    for binary in &binaries {
        for name in discovery.list(binary).await? {
            benches.push((binary.clone(), name));
        }
    }

    if benches.is_empty() {
        anyhow::bail!("No benchmarks found");
    }

    let max_jobs = args.max_jobs();
    let use_progress = args.use_progress();

    if args.quiet < 2 {
        eprintln!(
            "Running {} benchmark(s) with parallelism {}",
            benches.len(),
            max_jobs
        );
    }

    let runner = BenchRunner::new(max_jobs, args.quiet, use_progress);
    runner.run(&benches).await?;

    Ok(())
}
