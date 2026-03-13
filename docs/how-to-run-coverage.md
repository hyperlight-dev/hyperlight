# How to Run Coverage

This guide explains how to generate code coverage reports for Hyperlight.

## Prerequisites

- A working Rust toolchain
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) (installed automatically by the `just` recipes)
- Guest binaries must be built first: `just guests`

## Local Usage

Build guest binaries (required before running coverage):

```sh
just guests
```

### Text Summary

Print a coverage summary to the terminal:

```sh
just coverage
```

### HTML Report

Generate a browsable HTML report in `target/coverage/html/`:

```sh
just coverage-html
```

Open `target/coverage/html/index.html` in a browser to explore per-file and per-line coverage.

### LCOV Output

Generate an LCOV file at `target/coverage/lcov.info` for use with external tools or CI integrations:

```sh
just coverage-lcov
```

## Available Recipes

| Recipe | Output | Description |
|---|---|---|
| `just coverage` | stdout | Text summary of line coverage |
| `just coverage-html` | `target/coverage/html/` | HTML report for browsing |
| `just coverage-lcov` | `target/coverage/lcov.info` | LCOV format for tooling |
| `just coverage-ci <hypervisor>` | All of the above | CI recipe: HTML + LCOV + text summary |

## CI Integration

Coverage runs automatically on a **weekly schedule** (every Monday at 06:00 UTC) via the `Coverage.yml` workflow. It can also be triggered manually from the Actions tab using `workflow_dispatch`. The workflow runs on a single configuration (kvm/amd) to keep resource usage reasonable. It:

1. Builds guest binaries (`just guests`)
2. Installs `cargo-llvm-cov`
3. Runs `just coverage-ci kvm` — this mirrors `test-like-ci` by running multiple test phases with different feature combinations and merging the results into a single coverage report
4. Displays a coverage summary directly in the **GitHub Actions Job Summary** (visible on the workflow run page)
5. Uploads the full HTML report and LCOV file as downloadable build artifacts

### Viewing Coverage Results

- **Quick view**: Open the workflow run in the Actions tab — the coverage table is displayed in the **Job Summary** section at the bottom of the run page.
- **Detailed view**: Download the `coverage-html-*` artifact from the Artifacts section, extract the ZIP, and open `index.html` in a browser for per-file, per-line drill-down.
- **Tooling integration**: Download the `coverage-lcov-*` artifact for use with IDE plugins, Codecov, Coveralls, or other coverage services.

## How It Works

`cargo-llvm-cov` instruments Rust code using LLVM's source-based code coverage. It replaces `cargo test` — when you run `cargo llvm-cov`, it compiles the project with coverage instrumentation, runs the test suite, and then merges the raw profiling data into a human-readable report.

The CI recipe (`coverage-ci`) mirrors the `test-like-ci` workflow by running multiple test phases with different feature combinations:

1. **Default features** — all drivers enabled (kvm + mshv3 + build-metadata)
2. **Single driver** — only one hypervisor driver + build-metadata
3. **Crashdump** — tests with the `crashdump` feature enabled
4. **Tracing** — tests with `trace_guest` feature (host-side crates only)

Each phase uses `--no-report` to accumulate raw profiling data, then a single `report` step merges everything into unified HTML, LCOV, and text reports. This ensures coverage reflects all exercised code paths across all feature combinations.

Coverage is collected for the host-side workspace crates (`hyperlight_common`, `hyperlight_host`, `hyperlight_testing`, `hyperlight_component_util`, `hyperlight_component_macro`). Guest crates (`hyperlight-guest`, `hyperlight-guest-bin`, `hyperlight-guest-capi`, `hyperlight-guest-tracing`) and the `fuzz` crate are excluded because guest crates are `no_std` and cannot be compiled for the host target under coverage instrumentation.
