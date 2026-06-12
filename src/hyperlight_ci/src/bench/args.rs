use std::path::PathBuf;

use clap::Args;

use crate::bench::cpu::PerformanceCoresPool;

/// Command-line arguments for the `bench` subcommand.
#[derive(Args)]
pub struct BenchArgs {
    /// Filter benchmarks by name (substring match, or exact with --exact)
    pub filter: Option<String>,

    /// Match the filter exactly instead of as a substring
    #[arg(long)]
    pub exact: bool,

    /// Pre-built benchmark binary to use (skip build step; can be specified multiple times)
    #[arg(long)]
    pub binary: Vec<PathBuf>,

    /// Number of benchmarks to run in parallel (0 = all CPUs, default: 0)
    #[arg(long, short, default_value_t = 0)]
    pub jobs: usize,

    /// Reduce output verbosity (repeatable: -q hides stderr, -qq hides everything)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub quiet: u8,

    /// Disable progress bar (auto-detected: shown only on TTY)
    #[arg(long)]
    pub no_progress: bool,

    /// Additional features to pass to cargo criterion
    #[arg(short = 'F', long, default_value = "")]
    pub features: String,
}

impl BenchArgs {
    /// Determine the maximum number of parallel benchmark jobs.
    pub fn max_jobs(&self) -> usize {
        match self.jobs {
            0 => PerformanceCoresPool::num_cores(),
            j => j,
        }
    }

    /// Whether progress bars should be displayed.
    pub fn use_progress(&self) -> bool {
        use std::io::IsTerminal;
        !self.no_progress && std::io::stderr().is_terminal() && self.quiet < 2
    }
}
