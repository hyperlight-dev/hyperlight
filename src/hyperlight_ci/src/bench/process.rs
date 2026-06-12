//! Spawns the benchmark binary for a single benchmark and streams its output.

use std::ops::Deref;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use cpu_pin::{CpuInfo, PinnedCommand as _};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Output of a completed benchmark process.
pub struct ProcessOutput {
    pub output_lines: Vec<String>,
}

/// Spawns the benchmark binary for a single benchmark.
///
/// Streams output lines through `output_tx` as they arrive (for live progress updates),
/// and returns the collected output when the process exits.
pub async fn run(
    bench: &str,
    binary: &Path,
    core: impl Deref<Target = CpuInfo>,
    output_tx: &mpsc::UnboundedSender<String>,
) -> Result<ProcessOutput> {
    let mut cmd = Command::new(binary);
    cmd.args(["--bench", "--color=always", "--noplot", "--exact"]);
    cmd.arg(bench);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let core_id = core.logical_cpus.first().unwrap();

    let mut child = cmd
        .spawn_pinned(*core_id)
        .with_context(|| format!("Failed to spawn benchmark binary: {}", binary.display()))?;

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut reader_stdout = BufReader::new(stdout).lines();
    let mut reader_stderr = BufReader::new(stderr).lines();
    let mut output_lines = Vec::new();

    // combine the stream of both stdout and stderr lines
    // do not exit until both streams have been closed
    loop {
        tokio::select! {
            line = reader_stdout.next_line() => {
                let Some(line) = line.context("Failed to read stdout")? else { break };
                let _ = output_tx.send(line.clone());
                output_lines.push(line);
            }
            line = reader_stderr.next_line() => {
                let Some(line) = line.context("Failed to read stderr")? else { break };
                let _ = output_tx.send(line.clone());
                output_lines.push(line);
            }
        }
    }

    let status = child
        .wait()
        .await
        .context("Failed to wait for benchmark binary")?;

    if !status.success() {
        bail!(
            "benchmark binary exited with status {} for benchmark '{}'",
            status,
            bench
        );
    }

    Ok(ProcessOutput { output_lines })
}
