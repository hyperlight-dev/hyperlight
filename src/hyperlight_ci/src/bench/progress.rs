//! Progress bar and spinner management for benchmark output.

use std::collections::{HashMap, HashSet};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use super::output::{is_noisy_line, strip_bench_prefix};

/// Manages progress bars for a set of benchmarks.
pub struct ProgressTracker {
    multi: MultiProgress,
    overall: ProgressBar,
    spinners: HashMap<String, ProgressBar>,
    /// Benchmarks that have been registered but not yet started (no spinner visible).
    pending: HashSet<String>,
    quiet_level: u8,
    enabled: bool,
}

impl ProgressTracker {
    /// Create a new progress tracker.
    ///
    /// If `enabled` is false, all operations become no-ops (hidden bars, no output).
    pub fn new(total: usize, quiet_level: u8, enabled: bool) -> Self {
        let multi = MultiProgress::new();
        let overall = if enabled {
            let bar = multi.add(ProgressBar::new(total as u64));
            bar.set_style(
                ProgressStyle::with_template("{prefix} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("━━─"),
            );
            bar.set_prefix("Benchmarks");
            bar
        } else {
            ProgressBar::hidden()
        };

        Self {
            multi,
            overall,
            spinners: HashMap::new(),
            pending: HashSet::new(),
            quiet_level,
            enabled,
        }
    }

    /// Register a benchmark for tracking (spinner stays hidden until it starts running).
    pub fn add_spinner(&mut self, bench: &str) {
        if !self.enabled {
            return;
        }
        self.pending.insert(bench.to_string());
    }

    /// Update the spinner for a benchmark with an output line.
    ///
    /// On the first update, the spinner is created and becomes visible.
    /// Filters noisy lines and strips the benchmark prefix before displaying.
    pub fn update_spinner(&mut self, bench: &str, line: &str) {
        if is_noisy_line(line) {
            return;
        }
        // If this is a pending benchmark, create and show its spinner now
        if self.pending.remove(bench) {
            let bar = self.multi.insert_before(&self.overall, ProgressBar::new_spinner());
            bar.set_style(
                ProgressStyle::with_template("  {spinner:.green} {msg}")
                    .unwrap()
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
            );
            bar.enable_steady_tick(std::time::Duration::from_millis(100));
            self.spinners.insert(bench.to_string(), bar);
        }
        let Some(spinner) = self.spinners.get(bench) else { return };
        let display = strip_bench_prefix(line, bench);
        if !display.is_empty() {
            spinner.set_message(format!("\x1b[1;32m{bench}\x1b[0m: {display}"));
        }
    }

    /// Finish and remove the spinner for a benchmark.
    pub fn finish_spinner(&mut self, bench: &str) {
        if let Some(bar) = self.spinners.remove(bench) {
            bar.finish_and_clear();
            self.multi.remove(&bar);
        }
    }

    /// Advance the overall progress bar by one.
    pub fn advance(&self, position: u64) {
        self.overall.set_position(position);
    }

    /// Print a message respecting the progress system and quiet level.
    pub fn println(&self, msg: &str) {
        if self.enabled {
            let _ = self.multi.println(msg);
        } else if self.quiet_level < 1 {
            eprintln!("{msg}");
        }
    }

    /// Print the completion summary for a benchmark.
    ///
    /// At quiet_level 0, also prints filtered output lines.
    pub fn print_completion(
        &self,
        done_count: usize,
        total: usize,
        bench: &str,
        status: &str,
        output_lines: &[String],
        error: Option<&anyhow::Error>,
    ) {
        self.println(&format!(
            "[{done_count}/{total}] \x1b[1;32m{bench}\x1b[0m ... {status}"
        ));

        if self.quiet_level == 0 {
            for line in output_lines {
                if !is_noisy_line(line) {
                    let line = strip_bench_prefix(line, bench);
                    if !line.is_empty() && !line.starts_with("Benchmarking") {
                        self.println(&line);
                    }
                }
            }
            self.println("");
        }

        if let Some(e) = error {
            self.println(&format!("  error: {e}"));
        }
    }

    /// Finish the overall progress bar.
    pub fn finish(&self) {
        self.overall.finish_and_clear();
    }
}
