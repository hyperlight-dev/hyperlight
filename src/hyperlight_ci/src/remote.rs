// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! Benchmark results taken from a CI run rather than this machine.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Artifacts holding a criterion directory are named after the configuration
/// that produced them, `benchmarks_Linux_kvm_amd` and so on.
const ARTIFACT_PREFIX: &str = "benchmarks_";

/// How far back to look for a run that still has its benchmark artifacts.
/// They outlive the workflow by days, but not forever.
const RUNS_SEARCHED: usize = 15;

/// One configuration's results, and where they were unpacked.
pub(crate) struct Results {
    /// The configuration that produced them, `Linux_kvm_amd` and so on.
    pub label: String,
    pub dir: PathBuf,
}

#[derive(Deserialize)]
struct Artifact {
    name: String,
    expired: bool,
}

#[derive(Deserialize)]
struct ArtifactList {
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Run {
    #[serde(rename = "databaseId")]
    id: u64,
}

/// Run `gh` and hand back its stdout.
fn gh(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("gh")
        .args(args)
        .output()
        .context("Failed to run gh. The GitHub CLI provides the run artifacts")?;

    if !output.status.success() {
        bail!(
            "gh {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output.stdout)
}

/// Names of the benchmark artifacts a run still holds.
fn artifacts(repo: &str, run: u64) -> Result<Vec<String>> {
    let path = format!("repos/{repo}/actions/runs/{run}/artifacts");
    let list: ArtifactList = serde_json::from_slice(&gh(&["api", &path])?)
        .with_context(|| format!("Failed to read the artifacts of run {run}"))?;

    let mut names: Vec<String> = list
        .artifacts
        .into_iter()
        .filter(|a| !a.expired && a.name.starts_with(ARTIFACT_PREFIX))
        .map(|a| a.name)
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// The most recent run of `pull_request` that still has benchmark artifacts.
///
/// The newest run is not always the one to report: a run can be cancelled by
/// the next push, or be recent enough that the benchmarks have not finished.
pub(crate) fn latest_run_for(repo: &str, pull_request: u64) -> Result<u64> {
    let pr = pull_request.to_string();
    let branch = gh(&[
        "pr",
        "view",
        &pr,
        "--repo",
        repo,
        "--json",
        "headRefName",
        "--jq",
        ".headRefName",
    ])
    .with_context(|| format!("Failed to find pull request {pull_request}"))?;
    let branch = String::from_utf8_lossy(&branch).trim().to_string();

    let limit = RUNS_SEARCHED.to_string();
    let runs: Vec<Run> = serde_json::from_slice(&gh(&[
        "run",
        "list",
        "--repo",
        repo,
        "--branch",
        &branch,
        "--limit",
        &limit,
        "--json",
        "databaseId",
    ])?)
    .context("Failed to list the workflow runs of the branch")?;

    for run in &runs {
        if !artifacts(repo, run.id)?.is_empty() {
            return Ok(run.id);
        }
    }

    bail!("No run of {branch} still has benchmark artifacts")
}

/// Fetch every configuration's results from `run`, reusing what is already on
/// disk. Artifacts are immutable, so a run downloads once.
pub(crate) fn fetch(repo: &str, run: u64, cache: &Path) -> Result<Vec<Results>> {
    let names = artifacts(repo, run)?;
    if names.is_empty() {
        bail!("Run {run} has no benchmark artifacts. They may have expired");
    }

    let run_dir = cache.join(run.to_string());
    let mut results = Vec::new();

    for name in names {
        let label = name[ARTIFACT_PREFIX.len()..].to_string();
        let dir = run_dir.join(&label);

        if !dir.join("benchmarks.json").exists() {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;
            let (id, out) = (run.to_string(), dir.display().to_string());
            gh(&[
                "run", "download", &id, "--repo", repo, "-n", &name, "-D", &out,
            ])
            .with_context(|| format!("Failed to download {name}"))?;
        }

        results.push(Results { label, dir });
    }

    Ok(results)
}
