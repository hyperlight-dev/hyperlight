// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! Benchmark results taken from a CI run rather than this machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Artifacts holding a criterion directory are named after the configuration
/// that produced them, `benchmarks_Linux_kvm_amd` and so on.
const ARTIFACT_PREFIX: &str = "benchmarks_";

/// How far back to look for a run that still has its benchmark artifacts.
/// A day of the default branch is one run, so this spans how long they are kept.
const RUNS_SEARCHED: usize = 90;

/// Where benchmarks of the default branch come from. Pull requests benchmark
/// far more often, but never the branch they merge into.
const BASELINE_WORKFLOW: &str = "DailyBenchmarks.yml";

/// What a release calls the results it carries.
const ARCHIVE_SUFFIX: &str = ".tar.gz";

/// How many times to ask for a listing before taking it at its word.
const LISTINGS: usize = 5;

/// Marks a download that finished. Artifacts hold nothing every run is bound
/// to leave behind, and an interrupted one leaves the directory half written.
const DOWNLOADED: &str = ".downloaded";

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
    #[serde(rename = "headSha")]
    head_sha: String,
    #[serde(rename = "createdAt")]
    created_at: String,
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

/// Which repository to read, either `owner/name` or whichever one a git
/// remote points at, `remote:origin`.
pub(crate) fn repository(value: &str) -> Result<String> {
    let Some(remote) = value.strip_prefix("remote:") else {
        return Ok(value.to_string());
    };

    let output = Command::new("git")
        .args(["remote", "get-url", remote])
        .output()
        .context("Failed to run git")?;

    if !output.status.success() {
        bail!(
            "Failed to read the url of remote {remote}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let url = String::from_utf8_lossy(&output.stdout);
    owner_and_name(&url)
        .with_context(|| format!("Remote {remote} names no repository: {}", url.trim()))
}

/// The owner and name a clone url ends with, however it spells the host.
fn owner_and_name(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);

    let mut parts = url.rsplit(['/', ':']);
    let name = parts.next()?;
    let owner = parts.next()?;

    (!name.is_empty() && !owner.is_empty()).then(|| format!("{owner}/{name}"))
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

/// Runs matching `filter`, newest first.
///
/// GitHub answers out of an index that takes a moment to warm, leaving the
/// most recent runs out of the first replies. Taking one at its word picks a
/// baseline months older than the one asked for, so ask until two replies
/// agree on the newest run and keep everything either of them saw.
fn runs(repo: &str, filter: &[&str]) -> Result<Vec<Run>> {
    let limit = RUNS_SEARCHED.to_string();
    let mut seen: Vec<Run> = Vec::new();
    let mut newest = None;

    for _ in 0..LISTINGS {
        let mut args = vec![
            "run",
            "list",
            "--repo",
            repo,
            "--limit",
            &limit,
            "--json",
            "databaseId,headSha,createdAt",
        ];
        args.extend_from_slice(filter);

        let listed: Vec<Run> =
            serde_json::from_slice(&gh(&args)?).context("Failed to list the workflow runs")?;

        let latest = listed.first().map(|run| run.id);
        seen.extend(listed);

        if latest.is_some() && latest == newest {
            break;
        }
        newest = latest;
    }

    seen.sort_by(|left, right| (&right.created_at, right.id).cmp(&(&left.created_at, left.id)));
    seen.dedup_by_key(|run| run.id);
    Ok(seen)
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

    for run in runs(repo, &["--branch", &branch])? {
        if !artifacts(repo, run.id)?.is_empty() {
            return Ok(run.id);
        }
    }

    bail!("No run of {branch} still has benchmark artifacts")
}

/// Resolve a sha, tag or branch to the commit it names.
pub(crate) fn commit_sha(repo: &str, commit: &str) -> Result<String> {
    let path = format!("repos/{repo}/commits/{commit}");
    let sha = gh(&["api", &path, "--jq", ".sha"])
        .with_context(|| format!("Failed to find commit {commit}"))?;
    Ok(String::from_utf8_lossy(&sha).trim().to_string())
}

/// The commit a run measured.
pub(crate) fn run_commit(repo: &str, run: u64) -> Result<String> {
    let id = run.to_string();
    let sha = gh(&[
        "run", "view", &id, "--repo", repo, "--json", "headSha", "--jq", ".headSha",
    ])
    .with_context(|| format!("Failed to find what run {run} measured"))?;
    Ok(String::from_utf8_lossy(&sha).trim().to_string())
}

/// Whether `commit` is `ancestor` or was built on top of it.
fn descends_from(repo: &str, commit: &str, ancestor: &str) -> Result<bool> {
    let path = format!("repos/{repo}/compare/{ancestor}...{commit}");
    let status = gh(&["api", &path, "--jq", ".status"])?;
    Ok(matches!(
        String::from_utf8_lossy(&status).trim(),
        "identical" | "ahead"
    ))
}

/// The most recent benchmarks of the default branch taken at or before
/// `commit`.
///
/// The branch is benchmarked daily rather than per commit, so the run that
/// measured `commit` itself rarely exists. Anything measured after it carries
/// changes the commit never had.
pub(crate) fn run_at(repo: &str, commit: &str) -> Result<u64> {
    let commit = commit_sha(repo, commit)?;
    // A cancelled run leaves some configurations unmeasured.
    let runs = runs(
        repo,
        &["--workflow", BASELINE_WORKFLOW, "--status", "success"],
    )?;

    for run in &runs {
        if descends_from(repo, &commit, &run.head_sha)? && !artifacts(repo, run.id)?.is_empty() {
            return Ok(run.id);
        }
    }

    bail!("No benchmarks taken at or before {commit} still have their artifacts")
}

/// Where `pull_request` branched off the branch it targets.
pub(crate) fn merge_base_of(repo: &str, pull_request: u64) -> Result<String> {
    let pr = pull_request.to_string();
    let refs = gh(&[
        "pr",
        "view",
        &pr,
        "--repo",
        repo,
        "--json",
        "baseRefName,headRefOid",
        "--jq",
        ".baseRefName + \" \" + .headRefOid",
    ])
    .with_context(|| format!("Failed to find pull request {pull_request}"))?;

    let refs = String::from_utf8_lossy(&refs);
    let Some((base, head)) = refs.trim().split_once(' ') else {
        bail!("Pull request {pull_request} has no branch to compare against");
    };

    let path = format!("repos/{repo}/compare/{base}...{head}");
    let sha = gh(&["api", &path, "--jq", ".merge_base_commit.sha"])
        .with_context(|| format!("Failed to find where pull request {pull_request} branched"))?;
    Ok(String::from_utf8_lossy(&sha).trim().to_string())
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

        if !dir.join(DOWNLOADED).exists() {
            if dir.exists() {
                fs::remove_dir_all(&dir)
                    .with_context(|| format!("Failed to clear {}", dir.display()))?;
            }
            fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;

            let (id, out) = (run.to_string(), dir.display().to_string());
            gh(&[
                "run", "download", &id, "--repo", repo, "-n", &name, "-D", &out,
            ])
            .with_context(|| format!("Failed to download {name}"))?;

            fs::write(dir.join(DOWNLOADED), [])
                .with_context(|| format!("Failed to mark {} downloaded", dir.display()))?;
        }

        results.push(Results { label, dir });
    }

    Ok(results)
}

/// Names of the benchmark archives a release carries.
fn assets(repo: &str, tag: &str) -> Result<Vec<String>> {
    let names = gh(&[
        "release",
        "view",
        tag,
        "--repo",
        repo,
        "--json",
        "assets",
        "--jq",
        ".assets[].name",
    ])
    .with_context(|| format!("Failed to find release {tag}"))?;

    let mut names: Vec<String> = String::from_utf8_lossy(&names)
        .lines()
        .filter(|name| name.starts_with(ARTIFACT_PREFIX) && name.ends_with(ARCHIVE_SUFFIX))
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Fetch every configuration's results from the release tagged `tag`.
///
/// A release carries what it measured for as long as it exists, which is past
/// the day the workflow artifacts of the same run are swept away.
pub(crate) fn fetch_release(repo: &str, tag: &str, cache: &Path) -> Result<Vec<Results>> {
    let names = assets(repo, tag)?;
    if names.is_empty() {
        bail!("Release {tag} carries no benchmark results");
    }

    let release_dir = cache.join(format!("release-{tag}"));
    let mut results = Vec::new();

    for name in names {
        let label = name[ARTIFACT_PREFIX.len()..name.len() - ARCHIVE_SUFFIX.len()].to_string();
        let dir = release_dir.join(&label);

        if !dir.join(DOWNLOADED).exists() {
            if dir.exists() {
                fs::remove_dir_all(&dir)
                    .with_context(|| format!("Failed to clear {}", dir.display()))?;
            }
            fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;

            let out = dir.display().to_string();
            gh(&[
                "release", "download", tag, "--repo", repo, "-p", &name, "-D", &out,
            ])
            .with_context(|| format!("Failed to download {name}"))?;

            // The archive holds the criterion directory under a name of its own.
            let archive = dir.join(&name);
            unpack(&archive, &dir)?;
            fs::remove_file(&archive)
                .with_context(|| format!("Failed to remove {}", archive.display()))?;

            fs::write(dir.join(DOWNLOADED), [])
                .with_context(|| format!("Failed to mark {} downloaded", dir.display()))?;
        }

        results.push(Results { label, dir });
    }

    Ok(results)
}

/// Unpack `archive` into `into`, dropping the directory it wraps everything in.
fn unpack(archive: &Path, into: &Path) -> Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .arg("--strip-components=1")
        .status()
        .context("Failed to run tar. It unpacks the results a release carries")?;

    if !status.success() {
        bail!("Failed to unpack {}", archive.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_repository_a_clone_url_ends_with() {
        for url in [
            "git@github.com:hyperlight-dev/hyperlight.git",
            "https://github.com/hyperlight-dev/hyperlight.git",
            "https://github.com/hyperlight-dev/hyperlight",
            "ssh://git@github.com/hyperlight-dev/hyperlight.git",
            "  git@github.com:hyperlight-dev/hyperlight.git\n",
        ] {
            assert_eq!(
                owner_and_name(url).as_deref(),
                Some("hyperlight-dev/hyperlight"),
                "{url}"
            );
        }
    }

    #[test]
    fn keeps_a_repository_named_outright() {
        assert_eq!(
            repository("hyperlight-dev/hyperlight").unwrap(),
            "hyperlight-dev/hyperlight"
        );
    }
}
