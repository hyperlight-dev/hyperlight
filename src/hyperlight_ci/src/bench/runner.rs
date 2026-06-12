//! Orchestrates parallel benchmark execution, wiring together process spawning
//! and progress reporting.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use cpu_pin::CpuInfo;

use super::cpu::PerformanceCoresPool;
use super::process::{self, ProcessOutput};
use super::progress::ProgressTracker;

/// Events sent from benchmark tasks to the orchestration loop.
enum BenchEvent {
    /// An output line was produced by the given benchmark.
    OutputLine { bench: String, line: String },
    /// The benchmark has completed.
    Done(BenchResult),
}

/// Result of a single benchmark run, combining identity with output.
struct BenchResult {
    bench: String,
    output_lines: Vec<String>,
    success: Result<()>,
}

impl BenchResult {
    fn status(&self) -> &str {
        if self.success.is_ok() {
            "done"
        } else {
            "FAILED"
        }
    }
}

/// Orchestrates parallel benchmark execution with progress reporting.
pub struct BenchRunner {
    max_jobs: usize,
    quiet_level: u8,
    use_progress: bool,
}

impl BenchRunner {
    /// Create a new runner with the given configuration.
    pub fn new(max_jobs: usize, quiet_level: u8, use_progress: bool) -> Self {
        Self {
            max_jobs,
            quiet_level,
            use_progress,
        }
    }

    /// Run all benchmarks in parallel.
    ///
    /// Each entry is a (binary_path, benchmark_name) pair.
    ///
    /// Quiet levels:
    /// - 0: show progress, completion headers, and per-benchmark output
    /// - 1: show progress and completion headers only (no output details)
    /// - 2+: fully silent (no progress, no output)
    pub async fn run(&self, benches: &[(PathBuf, String)]) -> Result<()> {
        let total = benches.len();
        let mut tracker = ProgressTracker::new(total, self.quiet_level, self.use_progress);

        if self.max_jobs > PerformanceCoresPool::num_cores() {
            bail!(
                "Requested number of jobs {} exceeds available performance cores {}, use --jobs=0 or --quick to use all available performance cores.",
                self.max_jobs,
                PerformanceCoresPool::num_cores(),
            );
        }

        let pool = PerformanceCoresPool::new(self.max_jobs)?;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<BenchEvent>();

        // Spawn all benchmarks (they'll wait on the semaphore internally)
        for (binary, bench) in benches {
            tracker.add_spinner(bench);

            let bench = bench.clone();
            let binary = binary.clone();
            let tx = tx.clone();
            let pool = pool.clone();

            tokio::spawn(async move {
                let core = pool.get().await;
                Self::run_one(&bench, &binary, core, &tx).await;
            });
        }

        // Drop our sender so rx closes when all tasks finish
        drop(tx);

        // Process events as they arrive
        let mut failed = Vec::new();
        let mut done_count = 0;

        while let Some(event) = rx.recv().await {
            match event {
                BenchEvent::OutputLine { bench, line } => {
                    tracker.update_spinner(&bench, &line);
                }
                BenchEvent::Done(result) => {
                    done_count += 1;
                    tracker.finish_spinner(&result.bench);
                    tracker.advance(done_count as u64);

                    let error = result.success.as_ref().err();
                    tracker.print_completion(
                        done_count,
                        total,
                        &result.bench,
                        result.status(),
                        &result.output_lines,
                        error,
                    );

                    if result.success.is_err() {
                        failed.push(result.bench);
                    }
                }
            }
        }

        tracker.finish();

        if !failed.is_empty() {
            anyhow::bail!(
                "{} benchmark(s) failed: {}",
                failed.len(),
                failed.join(", ")
            );
        }

        Ok(())
    }

    /// Run a single benchmark, streaming output events and sending the final result.
    async fn run_one(
        bench: &str,
        binary: &Path,
        core: impl Deref<Target = CpuInfo>,
        event_tx: &tokio::sync::mpsc::UnboundedSender<BenchEvent>,
    ) {
        // Create a channel for output lines from the process
        let (output_tx, mut output_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let bench_name = bench.to_string();
        let event_tx_clone = event_tx.clone();

        // Forward output lines as events
        let forwarder = tokio::spawn(async move {
            while let Some(line) = output_rx.recv().await {
                let _ = event_tx_clone.send(BenchEvent::OutputLine {
                    bench: bench_name.clone(),
                    line,
                });
            }
        });

        // Signal that this benchmark is starting
        let _ = event_tx.send(BenchEvent::OutputLine {
            bench: bench.to_string(),
            line: "Starting ...".to_string(),
        });

        let result = match process::run(bench, binary, core, &output_tx).await {
            Ok(ProcessOutput { output_lines }) => BenchResult {
                bench: bench.to_string(),
                output_lines,
                success: Ok(()),
            },
            Err(e) => BenchResult {
                bench: bench.to_string(),
                output_lines: vec![],
                success: Err(e),
            },
        };

        // Ensure all output forwarding completes before sending Done
        drop(output_tx);
        let _ = forwarder.await;

        let _ = event_tx.send(BenchEvent::Done(result));
    }
}
