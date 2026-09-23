// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! The `bench-report` subcommand: generates a markdown table from existing
//! criterion benchmark results in `target/criterion/`.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Args;
use criterion_swarm::{CriterionSwarm, NoopReporter};

use crate::config::BenchConfig;
use crate::{manifest, remote};

/// Where downloaded runs are kept.
const RUN_CACHE: &str = "target/ci-runs";

/// Where results come from, either a criterion directory or CI.
#[derive(Clone)]
pub enum Source {
    Dir(PathBuf),
    Run(u64),
    PullRequest(u64),
}

impl FromStr for Source {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Anything else is a path, so windows drive letters stay paths.
        let Some((kind @ ("run" | "pr"), id)) = value.split_once(':') else {
            return Ok(Self::Dir(value.into()));
        };
        let id = id
            .parse()
            .map_err(|_| format!("`{id}` is not a {kind} number"))?;
        Ok(match kind {
            "run" => Self::Run(id),
            _ => Self::PullRequest(id),
        })
    }
}

/// Results to report, identified by the host that produced them.
struct Input {
    label: Option<String>,
    dir: PathBuf,
    host: Option<Identity>,
}

/// What distinguishes one set of benchmark results from another.
#[derive(PartialEq)]
struct Identity {
    os: String,
    /// `amd` or `intel`.
    vendor: String,
    hypervisor: Option<String>,
}

impl Identity {
    /// Read from the name CI gives an artifact, `Linux_kvm_amd` and so on.
    fn from_label(label: &str) -> Option<Self> {
        let (os, rest) = label.split_once('_')?;
        let (hypervisor, vendor) = rest.rsplit_once('_')?;
        let os = os.to_lowercase();
        Some(Self {
            hypervisor: Some(canonical_hypervisor(&os, hypervisor)),
            os,
            vendor: vendor.to_lowercase(),
        })
    }

    /// Read from what a run recorded about the machine it ran on.
    fn from_host(host: &manifest::Host) -> Option<Self> {
        let vendor = match host.cpu_vendor.as_deref()? {
            vendor if vendor.contains("AMD") => "amd",
            vendor if vendor.contains("Intel") => "intel",
            _ => return None,
        };
        Some(Self {
            hypervisor: host
                .hypervisor
                .as_deref()
                .map(|name| canonical_hypervisor(&host.os, name)),
            os: host.os.clone(),
            vendor: vendor.to_string(),
        })
    }

    /// Whether both could be the same machine. What one of them does not say
    /// cannot contradict the other.
    fn matches(&self, other: &Self) -> bool {
        self.os == other.os
            && self.vendor == other.vendor
            && match (&self.hypervisor, &other.hypervisor) {
                (Some(ours), Some(theirs)) => ours == theirs,
                _ => true,
            }
    }
}

/// Windows runs on whp alone, so its artifacts are named after the runner
/// image instead. Elsewhere the name carries a version, `mshv3` for `mshv`.
fn canonical_hypervisor(os: &str, name: &str) -> String {
    match os {
        "windows" => "whp".to_string(),
        _ => name.trim_end_matches(char::is_numeric).to_string(),
    }
}

/// Command-line arguments for the `bench-report` subcommand.
#[derive(Args)]
pub struct BenchReportArgs {
    /// Benchmark binary to list benchmarks from (can be specified multiple times).
    /// When provided, only benchmarks available in these binaries are included.
    #[arg(long)]
    pub binary: Vec<PathBuf>,

    /// Results to report: a criterion directory, `run:<ID>` or `pr:<NUMBER>`
    #[arg(long, value_name = "SOURCE", default_value = "target/criterion")]
    pub candidate: Source,

    /// Results to compare against: a criterion directory, `run:<ID>` or `pr:<NUMBER>`.
    /// Defaults to the previous run held in the reported directory.
    #[arg(long, value_name = "SOURCE")]
    pub baseline: Option<Source>,

    /// Repository holding the CI runs
    #[arg(
        long,
        value_name = "OWNER/NAME",
        default_value = "hyperlight-dev/hyperlight"
    )]
    pub repo: String,

    /// Wrap the output in a collapsible <details> tag with the given summary text.
    #[arg(long)]
    pub collapsible: Option<String>,

    /// Report only the benchmarks selected by this config file
    #[arg(long, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Additional arguments to forward to criterion benchmarks (e.g. filter, --exact)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub bench_args: Vec<String>,
}

/// Entry point for the bench-report subcommand.
pub async fn run(args: BenchReportArgs) -> Result<()> {
    let candidates = resolve(&args.candidate, &args.repo)?;
    let mut baselines = match &args.baseline {
        Some(source) => resolve(source, &args.repo)?,
        None => Vec::new(),
    };

    // The first run of a configuration has nothing to compare against, and CI
    // carries on with the baseline it could not download.
    baselines.retain(|baseline| has_results(&baseline.dir));
    if baselines.is_empty() && args.baseline.is_some() {
        eprintln!("No baseline results found, reporting without a comparison");
    }

    // A CI run covers every hypervisor and cpu vendor, one section each.
    for candidate in &candidates {
        let label = candidate.label.as_deref();
        let markdown = report(
            &args,
            &candidate.dir,
            baseline_for(&baselines, candidate),
            title(args.collapsible.as_deref(), label),
        )
        .await?;
        print!("{markdown}");
    }

    Ok(())
}

/// Locate the results `source` points at.
fn resolve(source: &Source, repo: &str) -> Result<Vec<Input>> {
    let run = match source {
        Source::Dir(dir) => {
            return Ok(vec![Input {
                label: None,
                host: host_of(dir)?,
                dir: dir.clone(),
            }]);
        }
        Source::Run(run) => *run,
        Source::PullRequest(pull_request) => remote::latest_run_for(repo, *pull_request)?,
    };

    eprintln!("Fetching run {run} of {repo}");
    remote::fetch(repo, run, Path::new(RUN_CACHE))?
        .into_iter()
        .map(|results| {
            Ok(Input {
                // The artifact name says what produced it, so trust it over
                // anything an older run left without a hypervisor recorded.
                host: Identity::from_label(&results.label)
                    .map(Some)
                    .map_or_else(|| host_of(&results.dir), Ok)?,
                label: Some(results.label),
                dir: results.dir,
            })
        })
        .collect()
}

/// What the run in `dir` recorded about the machine it ran on.
fn host_of(dir: &Path) -> Result<Option<Identity>> {
    Ok(manifest::read(dir)?.and_then(|manifest| Identity::from_host(&manifest.host)))
}

/// Whether `dir` holds anything to report. Criterion writes nothing until a
/// benchmark runs, so an empty directory is one that never did.
fn has_results(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// The baseline to compare `candidate` against.
fn baseline_for<'a>(baselines: &'a [Input], candidate: &Input) -> Option<&'a Path> {
    match baselines {
        [] => None,
        // Nothing to tell apart, so a lone baseline stands in for whatever it
        // is compared against.
        [only] if only.host.is_none() || candidate.host.is_none() => Some(&only.dir),
        _ => {
            let host = candidate.host.as_ref()?;
            let what = candidate.label.as_deref().unwrap_or("these results");
            let mut found = baselines.iter().filter(|baseline| {
                baseline
                    .host
                    .as_ref()
                    .is_some_and(|other| host.matches(other))
            });

            match (found.next(), found.next()) {
                (Some(baseline), None) => Some(baseline.dir.as_path()),
                // Results that do not say which hypervisor produced them can
                // fit more than one configuration.
                (Some(_), Some(_)) => {
                    eprintln!("Several baselines fit {what}, reporting them alone");
                    None
                }
                _ => {
                    eprintln!("Nothing to compare {what} against, reporting them alone");
                    None
                }
            }
        }
    }
}

/// Name the report after the configuration it covers.
fn title(summary: Option<&str>, label: Option<&str>) -> Option<String> {
    match (summary, label) {
        (Some(summary), Some(label)) => Some(format!("{summary} {label}")),
        (summary, label) => summary.or(label).map(str::to_string),
    }
}

/// Render the results in `dir`.
async fn report(
    args: &BenchReportArgs,
    dir: &Path,
    baseline_root: Option<&Path>,
    title: Option<String>,
) -> Result<String> {
    let mut benchmarks = discover_benchmarks(args, dir).await?;

    if let Some(path) = &args.config_file {
        benchmarks = BenchConfig::load(path)?.select(benchmarks)?;
    }

    let mut renderer = criterion_markdown::Renderer::new(dir).benchmarks(benchmarks);

    // Criterion keeps the last run of a directory in `new` and the one before
    // it in `base`, so another directory is compared through its own last run.
    if let Some(root) = baseline_root {
        renderer = renderer.baseline_root(root).baseline("new");
    }

    // The summary doubles as the title of a collapsed report.
    if let Some(title) = title {
        renderer = renderer.title(title).collapsible(true);
    }

    renderer.render()
}

/// Benchmark ids for the results being reported.
///
/// A run records what it measured, so prefer that: listing the binaries builds
/// them and describes the current checkout rather than the run in hand, which
/// differ whenever results come from elsewhere. Explicit binaries or bench args
/// ask for the binaries, and older results carry no manifest.
async fn discover_benchmarks(args: &BenchReportArgs, dir: &Path) -> Result<Vec<String>> {
    if args.binary.is_empty() && args.bench_args.is_empty() {
        if let Some(manifest) = manifest::read(dir)? {
            return Ok(manifest.benchmarks);
        }
    }

    let mut swarm = CriterionSwarm::builder();

    if !args.binary.is_empty() {
        swarm = swarm.binaries(&args.binary);
    }

    for arg in &args.bench_args {
        swarm = swarm.bench_arg(arg);
    }

    let discovered = swarm
        .output(NoopReporter)
        .prepare()
        .await
        .context("Failed to discover benchmarks")?;

    Ok(discovered
        .benchmarks()
        .into_iter()
        .map(str::to_string)
        .collect())
}
