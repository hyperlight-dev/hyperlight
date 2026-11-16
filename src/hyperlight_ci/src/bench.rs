// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! The `bench` subcommand: runs criterion benchmarks in parallel via criterion-swarm.

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Context;
use criterion_swarm::{CriterionSwarm, OutputMode};

use crate::ballast::Ballast;
use crate::baseline::Worktree;
use crate::bench_report::DEFAULT_REPO;
use crate::config::BenchConfig;
use crate::{manifest, remote};

/// An output mode flag for `--build-output` / `--benchmarks-output`.
#[derive(Clone, Debug)]
pub(crate) struct OutputModeFlags(OutputMode);

impl OutputModeFlags {
    /// Parse a single token into an `OutputMode` flag.
    fn parse_one(s: &str) -> Result<OutputMode, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "spinner" => Ok(OutputMode::SPINNER),
            "stream" => Ok(OutputMode::STREAM),
            "summary" => Ok(OutputMode::SUMMARY),
            "none" | "silent" => Ok(OutputMode::SILENT),
            other => Err(format!(
                "unknown output mode `{other}` (expected: spinner, stream, summary, none, silent)"
            )),
        }
    }
}

impl std::str::FromStr for OutputModeFlags {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut mode = OutputMode::SILENT;
        for part in s.split(',') {
            mode |= Self::parse_one(part)?;
        }
        Ok(Self(mode))
    }
}

/// Merge a `Vec<OutputModeFlags>` into a single `OutputMode` by OR-ing them together.
fn merge_output_modes(flags: &[OutputModeFlags]) -> OutputMode {
    flags.iter().fold(OutputMode::SILENT, |acc, f| acc | f.0)
}

/// Command-line arguments for the `bench` subcommand.
#[derive(clap::Args)]
pub struct BenchArgs {
    /// Pre-built benchmark binary to use (skip build step; can be specified multiple times)
    ///
    /// One binary holds one commit, so a comparison builds its own.
    #[arg(long, conflicts_with = "baseline_ref")]
    pub binary: Vec<PathBuf>,

    /// Number of benchmarks to run in parallel (0 = all P-cores, default: 0)
    #[arg(long, short, default_value_t = 0)]
    pub jobs: usize,

    /// Build output mode (comma-separated or repeated): spinner, stream, summary, none
    #[arg(long, value_delimiter = ',')]
    pub build_output: Vec<OutputModeFlags>,

    /// Benchmarks output mode (comma-separated or repeated): spinner, stream, summary, none
    #[arg(long, value_delimiter = ',')]
    pub benchmarks_output: Vec<OutputModeFlags>,

    /// Additional features to pass to cargo when building benchmarks (can be specified multiple times)
    #[arg(short = 'F', long)]
    pub features: Vec<String>,

    /// Run only the benchmarks selected by this config file
    #[arg(long, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Run without holding a sandbox resident for the duration of the run
    #[arg(long)]
    pub no_ballast: bool,

    /// Measure this commit first and compare the run against it.
    ///
    /// Takes anything git resolves to a commit, including `A...B` for where
    /// two branched apart, or `base-of:<PR>` for where a pull request did.
    /// Both passes run on this machine, so the comparison reflects the commits
    /// rather than the difference between two runners.
    #[arg(long, value_name = "COMMIT", requires = "baseline_guests")]
    pub baseline_ref: Option<String>,

    /// Repository a `base-of:<PR>` baseline is read from, `<OWNER>/<NAME>` or
    /// `remote:<NAME>` for whichever one a git remote points at
    #[arg(long, value_name = "REPO")]
    pub repo: Option<String>,

    /// Guest binaries built from `--baseline-ref`, as a directory holding one
    /// `rust` and one `c` directory.
    #[arg(long, value_name = "DIR")]
    pub baseline_guests: Option<PathBuf>,
    /// Cargo target directory the `--baseline-ref` pass builds in. A directory
    /// seeded from a build of a nearby commit saves most of the compile.
    #[arg(long, value_name = "DIR", requires = "baseline_ref")]
    pub baseline_target_dir: Option<PathBuf>,
    /// Name criterion keeps the `--baseline-ref` results under
    #[arg(long, value_name = "NAME", default_value = "base")]
    pub baseline_name: String,

    /// Additional arguments to forward to criterion benchmarks
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub bench_args: Vec<String>,
}

pub async fn run(mut args: BenchArgs) -> anyhow::Result<()> {
    let Some(spec) = args.baseline_ref.take() else {
        let bench_args = std::mem::take(&mut args.bench_args);
        return measure(&args, bench_args, None, None).await;
    };

    let commit = resolve(&spec, args.repo.as_deref())?;

    // Both passes read the configuration named here, not whatever the commit
    // they measure happens to carry at the same relative path.
    if let Some(config_file) = args.config_file.take() {
        args.config_file = Some(
            std::path::absolute(&config_file)
                .with_context(|| format!("Failed to resolve {}", config_file.display()))?,
        );
    }
    // Each pass runs from its own checkout, so the directory they write to is
    // named outright rather than found relative to wherever that is.
    let home = std::path::absolute(manifest::criterion_dir())
        .context("Failed to resolve where criterion keeps its results")?;
    std::fs::create_dir_all(&home)
        .with_context(|| format!("Failed to create {}", home.display()))?;
    std::env::set_var("CRITERION_HOME", &home);
    let target_dir = args
        .baseline_target_dir
        .as_deref()
        .map(std::path::absolute)
        .transpose()
        .context("Failed to resolve the baseline target directory")?;

    // A baseline left by an earlier run would otherwise stand in for any
    // benchmark this one cannot measure, which is every benchmark the commit
    // being measured against never had.
    clear_baseline(&home, &args.baseline_name)
        .with_context(|| format!("Failed to clear the {} baseline", args.baseline_name))?;

    let guests = args
        .baseline_guests
        .clone()
        .expect("clap requires guests alongside a baseline commit");
    let worktree = Worktree::add(&commit)?;
    worktree.place_guests(&guests)?;

    // A benchmark binary finds its guests relative to the source it was built
    // from, so the baseline reads the worktree and this tree keeps its own.
    let here = std::env::current_dir().context("Failed to read the working directory")?;
    std::env::set_current_dir(worktree.path())
        .with_context(|| format!("Failed to enter {}", worktree.path().display()))?;
    let measured = measure(
        &args,
        with(&args, "--save-baseline"),
        None,
        target_dir.as_deref(),
    )
    .await;
    std::env::set_current_dir(&here)
        .with_context(|| format!("Failed to return to {}", here.display()))?;
    measured.with_context(|| format!("Failed to measure {commit}"))?;

    let measured_against = worktree.commit().to_string();
    drop(worktree);

    measure(
        &args,
        with(&args, "--baseline-lenient"),
        Some(measured_against),
        None,
    )
    .await
}

/// Drop every saved copy of the baseline `name`, leaving the measurements
/// beside them alone.
fn clear_baseline(home: &std::path::Path, name: &str) -> anyhow::Result<()> {
    if !home.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(home)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }

        // A benchmark may be grouped under the same name a baseline is saved
        // under. Measurements tell the two apart: a saved baseline holds them,
        // a group holds the benchmarks below it.
        let measured = path.join("estimates.json").is_file();
        if measured && path.file_name().is_some_and(|dir| dir == name) {
            std::fs::remove_dir_all(&path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
        } else if !measured {
            clear_baseline(&path, name)?;
        }
    }
    Ok(())
}

/// The commit a baseline names.
///
/// `base-of:<PR>` is where a pull request branched, read the way
/// `bench-report` reads the same spelling. Anything else is left to git, which
/// already understands branches, tags, shas and the revisions built from them.
fn resolve(spec: &str, repo: Option<&str>) -> anyhow::Result<String> {
    let Some(pull_request) = spec.strip_prefix("base-of:") else {
        return Ok(spec.to_string());
    };

    let pull_request = pull_request
        .parse()
        .map_err(|_| anyhow::anyhow!("`{pull_request}` is not a pull request number"))?;
    let repo = remote::repository(repo.unwrap_or(DEFAULT_REPO))?;

    remote::merge_base_of(&repo, pull_request)
}

/// The criterion arguments for one pass, naming the baseline it reads or writes.
///
/// The comparison is lenient because a commit may add a benchmark the one it
/// is measured against never had, which strict reading treats as a failure.
fn with(args: &BenchArgs, flag: &str) -> Vec<String> {
    let mut bench_args = args.bench_args.clone();
    bench_args.push(flag.to_string());
    bench_args.push(args.baseline_name.clone());
    bench_args
}

/// The cargo arguments that build the benchmarks.
fn cargo_args(features: &[String], target_dir: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let mut cargo_args = Vec::new();
    if !features.is_empty() {
        cargo_args.extend(["--features".to_string(), features.join(",")]);
    }
    if let Some(dir) = target_dir {
        let dir = dir
            .to_str()
            .with_context(|| format!("{} is not valid UTF-8", dir.display()))?;
        cargo_args.push(format!("--target-dir={dir}"));
    }
    Ok(cargo_args)
}

async fn measure(
    args: &BenchArgs,
    bench_args: Vec<String>,
    baseline: Option<String>,
    target_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let config = args
        .config_file
        .as_deref()
        .map(BenchConfig::load)
        .transpose()?;

    let mut swarm = CriterionSwarm::builder().jobs(args.jobs);

    if !args.binary.is_empty() {
        swarm = swarm.binaries(args.binary.clone());
    }

    swarm = swarm.build_args(cargo_args(&args.features, target_dir)?);

    for arg in bench_args {
        swarm = swarm.bench_arg(arg);
    }

    let mut build_output = args.build_output.clone();
    let mut benchmarks_output = args.benchmarks_output.clone();

    if build_output.is_empty() {
        let mode = if std::io::stderr().is_terminal() {
            OutputMode::SPINNER | OutputMode::SUMMARY
        } else {
            OutputMode::STREAM | OutputMode::SUMMARY
        };
        build_output.push(OutputModeFlags(mode));
    }

    if benchmarks_output.is_empty() {
        let mode = if std::io::stderr().is_terminal() {
            OutputMode::SPINNER | OutputMode::STREAM | OutputMode::SUMMARY
        } else {
            OutputMode::STREAM | OutputMode::SUMMARY
        };
        benchmarks_output.push(OutputModeFlags(mode));
    }

    let build_mode = merge_output_modes(&build_output);
    let bench_mode = merge_output_modes(&benchmarks_output);
    swarm = swarm.output(
        criterion_swarm::ProgressReporter::new()
            .build(build_mode)
            .benchmarks(bench_mode),
    );

    let mut swarm = swarm
        .prepare()
        .await
        .context("Failed to prepare criterion swarm")?;

    if let Some(config) = &config {
        let selected: HashSet<String> = config
            .select(swarm.benchmarks().into_iter().map(str::to_string))?
            .into_iter()
            .collect();
        swarm.retain(|name| selected.contains(name));
    }

    if bench_mode == (bench_mode | OutputMode::SUMMARY) {
        let total = swarm.benchmarks().len();
        let jobs = swarm.jobs().min(total);
        println!("Running {total} benchmarks with parallelism {jobs}");
    }

    let benchmarks: Vec<String> = swarm.benchmarks().into_iter().map(str::to_string).collect();

    // A run that fails leaves the results of the last one in place, which a
    // manifest written up front would claim as this run's.
    manifest::clear().context("Failed to clear the benchmark manifest")?;

    // Held until the run finishes.
    let ballast = if args.no_ballast {
        None
    } else {
        Some(Ballast::start(target_dir)?)
    };

    let result = swarm.run().await.context("Failed to run criterion swarm");
    drop(ballast);
    result?;

    manifest::write(benchmarks, baseline).context("Failed to write the benchmark manifest")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{cargo_args, clear_baseline, resolve};

    /// Only the baseline being rebuilt goes, so a run holds on to the
    /// measurements it is not about to replace.
    #[test]
    fn clearing_a_baseline_leaves_the_measurements_beside_it() {
        let home = std::env::temp_dir().join(format!("hl-clear-{}", std::process::id()));
        let bench = home.join("group").join("case");
        for set in ["base", "new", "change", "keepsake"] {
            std::fs::create_dir_all(bench.join(set)).unwrap();
            std::fs::write(bench.join(set).join("estimates.json"), b"{}").unwrap();
        }

        clear_baseline(&home, "base").unwrap();

        assert!(!bench.join("base").exists(), "the baseline is rebuilt");
        assert!(bench.join("new").exists(), "the last run stays");
        assert!(bench.join("change").exists(), "its comparison stays");
        assert!(bench.join("keepsake").exists(), "other baselines stay");

        std::fs::remove_dir_all(home).unwrap();
    }

    /// A benchmark may be grouped under the name a baseline is saved under,
    /// and the group holds every measurement below it.
    #[test]
    fn clearing_a_baseline_spares_a_benchmark_of_the_same_name() {
        let home = std::env::temp_dir().join(format!("hl-group-{}", std::process::id()));
        let grouped = home.join("base").join("case");
        for set in ["base", "new"] {
            std::fs::create_dir_all(grouped.join(set)).unwrap();
            std::fs::write(grouped.join(set).join("estimates.json"), b"{}").unwrap();
        }

        clear_baseline(&home, "base").unwrap();

        assert!(
            home.join("base").is_dir(),
            "a group named after the baseline is not a saved result"
        );
        assert!(grouped.join("new").exists(), "its measurements stay");
        assert!(
            !grouped.join("base").exists(),
            "the baseline saved within it still goes"
        );

        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn clearing_a_baseline_that_was_never_measured_is_no_work() {
        let home = std::env::temp_dir().join(format!("hl-absent-{}", std::process::id()));
        assert!(clear_baseline(&home, "base").is_ok());
    }

    /// git already reads branches, tags, shas and the revisions built from
    /// them, so a baseline names one directly.
    #[test]
    fn a_commit_is_left_to_git() {
        for spec in ["main", "HEAD^1", "3ee2d4cb", "v1.2.3"] {
            assert_eq!(resolve(spec, None).unwrap(), spec);
        }
    }

    #[test]
    fn cargo_args_name_features_and_target_dir() {
        assert!(cargo_args(&[], None).unwrap().is_empty());
        assert_eq!(
            cargo_args(
                &["kvm".to_string(), "mshv3".to_string()],
                Some(Path::new("/tmp/baseline-target"))
            )
            .unwrap(),
            [
                "--features",
                "kvm,mshv3",
                "--target-dir=/tmp/baseline-target"
            ]
        );
    }

    #[test]
    fn a_pull_request_without_a_number_is_reported() {
        let error = resolve("base-of:not-a-number", None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a pull request number"), "{error}");
    }
}
