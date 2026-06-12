use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use std::process::Stdio;

/// Discovers available benchmarks by querying the benchmark binary.
pub struct BenchmarkDiscovery {
    features: String,
    filter: Option<String>,
    exact: bool,
}

impl BenchmarkDiscovery {
    /// Create a new discovery instance with the given parameters.
    pub fn new(features: &str, filter: Option<&str>, exact: bool) -> Self {
        Self {
            features: features.to_string(),
            filter: filter.map(|s| s.to_string()),
            exact,
        }
    }

    /// Build all benchmark binaries and return their paths.
    pub async fn build(&self) -> Result<Vec<PathBuf>> {
        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            "--release",
            "--benches",
            "--message-format=json",
        ]);
        if !self.features.is_empty() {
            cmd.args(["--features", &self.features]);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .context("Failed to run cargo build for benchmarks")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to build benchmarks:\n{stderr}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut binaries = Vec::new();

        // Parse cargo's JSON output to find all benchmark binary paths
        for line in stdout.lines() {
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
                continue;
            }
            let is_bench = msg
                .get("target")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bench")));
            if !is_bench {
                continue;
            }
            if let Some(filenames) = msg.get("filenames").and_then(|f| f.as_array()) {
                for f in filenames {
                    if let Some(path) = f.as_str() {
                        if !path.ends_with(".d") {
                            binaries.push(PathBuf::from(path));
                        }
                    }
                }
            }
        }

        if binaries.is_empty() {
            bail!("No benchmark binaries found in cargo build output");
        }

        Ok(binaries)
    }

    /// List all benchmark names matching the configured filter.
    pub async fn list(&self, binary: &Path) -> Result<Vec<String>> {
        let mut cmd = Command::new(binary);
        cmd.args(["--bench", "--list"]);
        if self.exact {
            cmd.arg("--exact");
        }
        if let Some(filter) = &self.filter {
            cmd.arg(filter);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let output = cmd
            .output()
            .await
            .with_context(|| format!("Failed to run {} --bench --list", binary.display()))?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let benches: Vec<String> = stdout
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let line = line.strip_suffix(": benchmark")?;
                Some(line.to_string())
            })
            .collect();

        Ok(benches)
    }
}
