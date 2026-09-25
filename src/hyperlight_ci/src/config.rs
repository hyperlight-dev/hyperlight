// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.
//! The benchmark report configuration shared by the `bench` and `bench-report` subcommands.

use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::RegexSet;
use serde::Deserialize;

/// Unknown keys are rejected so a stale key cannot silently disable filtering.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    allowlist: Vec<String>,
    #[serde(default)]
    denylist: Vec<String>,
    improvement: Option<f64>,
    strong_improvement: Option<f64>,
    regression: Option<f64>,
    repo: Option<String>,
    summary_limit: Option<usize>,
    reproduce: Option<bool>,
}

/// Benchmark id patterns selecting which results are reported.
#[derive(Debug)]
pub struct BenchConfig {
    allow: RegexSet,
    deny: RegexSet,
    /// Where a change is worth reporting, when the file says.
    pub improvement: Option<f64>,
    pub strong_improvement: Option<f64>,
    pub regression: Option<f64>,
    /// Which repository the runs belong to.
    pub repo: Option<String>,
    /// How many changes to call out before the tables.
    pub summary_limit: Option<usize>,
    /// Whether a report says how to ask for it again.
    pub reproduce: Option<bool>,
}

impl BenchConfig {
    /// Read `allowlist` and `denylist` pattern arrays from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read benchmark config {}", path.display()))?;

        Self::parse(&text).with_context(|| format!("Invalid benchmark config {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let file: ConfigFile = toml::from_str(text)?;

        Ok(Self {
            allow: RegexSet::new(&file.allowlist)?,
            deny: RegexSet::new(&file.denylist)?,
            improvement: file.improvement,
            strong_improvement: file.strong_improvement,
            regression: file.regression,
            repo: file.repo,
            summary_limit: file.summary_limit,
            reproduce: file.reproduce,
        })
    }

    /// Keep the selected benchmarks, rejecting allowlist patterns that match nothing.
    ///
    /// Empty lists keep every benchmark. A denylist pattern matching nothing is
    /// accepted, because a benchmark may be absent on some platforms.
    pub fn select(&self, benchmarks: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
        let mut used = vec![false; self.allow.len()];
        let mut selected = Vec::new();

        for benchmark in benchmarks {
            let matches = self.allow.matches(&benchmark);
            for index in matches.iter() {
                used[index] = true;
            }

            let allowed = self.allow.is_empty() || matches.matched_any();
            if allowed && !self.deny.is_match(&benchmark) {
                selected.push(benchmark);
            }
        }

        let stale: Vec<&str> = self
            .allow
            .patterns()
            .iter()
            .zip(&used)
            .filter(|(_, used)| !**used)
            .map(|(pattern, _)| pattern.as_str())
            .collect();

        if !stale.is_empty() {
            bail!(
                "Benchmark allowlist patterns match no benchmark: {}",
                stale.join(", ")
            );
        }

        if selected.is_empty() && self.filters() {
            bail!("Benchmark config excludes every benchmark");
        }

        Ok(selected)
    }

    /// Whether the config restricts the reported benchmarks at all.
    fn filters(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn benchmarks(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn reads_the_thresholds_when_given() {
        let config = BenchConfig::parse("improvement = 1.5\nregression = 0.5").unwrap();

        assert_eq!(config.improvement, Some(1.5));
        assert_eq!(config.regression, Some(0.5));
        assert_eq!(config.strong_improvement, None);
    }

    #[test]
    fn leaves_the_thresholds_alone_when_absent() {
        let config = BenchConfig::parse(r#"allowlist = ["^sandboxes/"]"#).unwrap();

        assert_eq!(config.improvement, None);
        assert_eq!(config.strong_improvement, None);
        assert_eq!(config.regression, None);
    }

    #[test]
    fn selects_only_allowlisted_benchmarks() {
        let config = BenchConfig::parse(r#"allowlist = ["^sandboxes/", "^guest_calls/"]"#).unwrap();
        let selected = config
            .select(benchmarks(&[
                "sandboxes/create",
                "snapshots/save",
                "guest_calls/small",
            ]))
            .unwrap();

        assert_eq!(selected, ["sandboxes/create", "guest_calls/small"]);
    }

    #[test]
    fn denylist_subtracts_from_the_allowlist() {
        let config = BenchConfig::parse(
            r#"
            allowlist = ["^sandboxes/"]
            denylist = ["^sandboxes/noisy"]
            "#,
        )
        .unwrap();

        let selected = config
            .select(benchmarks(&["sandboxes/create", "sandboxes/noisy_case"]))
            .unwrap();

        assert_eq!(selected, ["sandboxes/create"]);
    }

    #[test]
    fn empty_allowlist_keeps_everything_not_denied() {
        let config = BenchConfig::parse(r#"denylist = ["^snapshots/"]"#).unwrap();
        let selected = config
            .select(benchmarks(&["sandboxes/create", "snapshots/save"]))
            .unwrap();

        assert_eq!(selected, ["sandboxes/create"]);
    }

    #[test]
    fn rejects_allowlist_patterns_matching_nothing() {
        let config =
            BenchConfig::parse(r#"allowlist = ["^sandboxes/", "^renamed_away/"]"#).unwrap();
        let error = config
            .select(benchmarks(&["sandboxes/create"]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("^renamed_away/"), "{error}");
        assert!(!error.contains("^sandboxes/"), "{error}");
    }

    #[test]
    fn accepts_denylist_patterns_matching_nothing() {
        let config = BenchConfig::parse(
            r#"
            allowlist = ["^sandboxes/"]
            denylist = ["^windows_only/"]
            "#,
        )
        .unwrap();

        let selected = config.select(benchmarks(&["sandboxes/create"])).unwrap();
        assert_eq!(selected, ["sandboxes/create"]);
    }

    #[test]
    fn rejects_a_config_that_excludes_everything() {
        let config = BenchConfig::parse(
            r#"
            allowlist = ["^sandboxes/"]
            denylist = ["^sandboxes/"]
            "#,
        )
        .unwrap();

        let error = config
            .select(benchmarks(&["sandboxes/create"]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("excludes every benchmark"), "{error}");
    }

    #[test]
    fn config_without_keys_keeps_every_benchmark() {
        let config = BenchConfig::parse("").unwrap();
        let selected = config
            .select(benchmarks(&["sandboxes/create", "snapshots/save"]))
            .unwrap();

        assert_eq!(selected, ["sandboxes/create", "snapshots/save"]);
    }

    #[test]
    fn empty_lists_keep_every_benchmark() {
        let config = BenchConfig::parse("allowlist = []\ndenylist = []").unwrap();
        let selected = config
            .select(benchmarks(&["sandboxes/create", "snapshots/save"]))
            .unwrap();

        assert_eq!(selected, ["sandboxes/create", "snapshots/save"]);
    }

    #[test]
    fn rejects_unknown_keys() {
        let error = BenchConfig::parse(r#"patterns = ["^sandboxes/"]"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn rejects_invalid_pattern() {
        let error = BenchConfig::parse(r#"allowlist = ["^sandboxes/("]"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("regex parse error"), "{error}");
    }
}
