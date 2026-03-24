# How to Run Coverage

This guide explains how to generate code coverage reports for Hyperlight.

## Prerequisites

- A working Rust toolchain
- Rust nightly toolchain (required for branch coverage; installed automatically by the `just` recipes)
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) (installed automatically by the `just` recipes)
- Guest binaries must be built first: `just guests`

## Local Usage

Coverage is a two-step process: first **collect** profiling data by running the tests, then **generate** a report in the desired format.

### Step 1: Run tests with coverage instrumentation

Build guest binaries (required before running coverage):

```sh
just guests
```

Run all tests and examples under coverage instrumentation:

```sh
just coverage-run
```

This collects profiling data without generating a report. You only need to run this once — you can then generate multiple report formats from the same data.

### Step 2: Generate a report

#### Text Summary

Print a coverage summary to the terminal:

```sh
just coverage
```

#### HTML Report

Generate a browsable HTML report in `target/coverage/html/`:

```sh
just coverage-html
```

Open `target/coverage/html/index.html` in a browser to explore per-file and per-line coverage.

#### LCOV Output

Generate an LCOV file at `target/coverage/lcov.info` for use with external tools or CI integrations:

```sh
just coverage-lcov
```

## Available Recipes

| Recipe | Output | Description |
|---|---|---|
| `just coverage-run` | profiling data | Runs tests with coverage instrumentation (must be run first) |
| `just coverage` | stdout | Text summary of line coverage |
| `just coverage-html` | `target/coverage/html/` | HTML report for browsing |
| `just coverage-lcov` | `target/coverage/lcov.info` | LCOV format for tooling |
| `just coverage-ci <hypervisor>` | All of the above | CI recipe: runs tests + generates HTML + LCOV + text summary |

> **Note:** `coverage`, `coverage-html`, and `coverage-lcov` require `coverage-run` to have been executed first. Only `coverage-ci` runs tests and generates all reports in a single command.

## CI Integration

Coverage runs automatically on a **weekly schedule** (every Monday at 06:00 UTC) via the `Coverage.yml` workflow. It can also be triggered manually from the Actions tab using `workflow_dispatch`. The workflow runs on a single configuration (kvm/amd) to keep resource usage reasonable. It:

1. Builds guest binaries (`just guests`)
2. Runs `just coverage-ci kvm` — this mirrors `test-like-ci` by running multiple test phases with different feature combinations and merging the results into a single coverage report
3. Displays a coverage summary directly in the **GitHub Actions Job Summary** (visible on the workflow run page)
4. Uploads the full HTML report and LCOV file as downloadable build artifacts

### Viewing Coverage Results

- **Quick view**: Open the workflow run in the Actions tab — the coverage table is displayed in the **Job Summary** section at the bottom of the run page.
- **Detailed view**: Download the `coverage-html-*` artifact from the Artifacts section, extract the ZIP, and open `index.html` in a browser for per-file, per-line drill-down.
- **Tooling integration**: Download the `coverage-lcov-*` artifact for use with IDE plugins, Codecov, Coveralls, or other coverage services.

## Why cargo-llvm-cov

We use [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) over alternatives like [tarpaulin](https://github.com/xd009642/tarpaulin) and [grcov](https://github.com/mozilla/grcov) for three reasons:

- **Cross-platform**: Works on Linux, macOS, and Windows. Tarpaulin's default `ptrace` backend is Linux-only (can be configured to use LLVM, but has some limitations), which doesn't fit Hyperlight's multi-OS target. `cargo-llvm-cov` uses LLVM's built-in instrumentation, so coverage works the same way everywhere.
- **Simple setup**: A single `cargo install` plus `rustup component add llvm-tools` — no manual profdata wrangling or multi-step pipelines. `grcov` requires setting environment variables, collecting raw profiles, and running a separate post-processing step.
- **Accurate**: LLVM source-based instrumentation provides precise line, region, and branch coverage with minimal overhead, directly mapped to source code. Tarpaulin's `ptrace` approach can produce inaccuracies on certain language features and is limited to line coverage by default.

## How It Works

`cargo-llvm-cov` instruments Rust code using LLVM's source-based code coverage. It replaces `cargo test` — when you run `cargo llvm-cov`, it compiles the project with coverage instrumentation, runs the test suite, and then merges the raw profiling data into a human-readable report. The nightly toolchain is used to enable **branch coverage** (`--branch`).

The `coverage-run` recipe mirrors the `test-like-ci` + `run-examples-like-ci` workflows by running all test phases and examples with different feature combinations:

1. **Default features** — all drivers enabled (kvm + mshv3 + build-metadata)
2. **Single driver** — only one hypervisor driver + build-metadata
3. **Isolated tests** — tests that require running separately due to global state
4. **Integration tests** — including `executable_heap` feature
5. **Crashdump** — tests + example with the `crashdump` feature enabled
6. **Tracing** — tests with `trace_guest` feature (host-side crates only)
7. **Examples** — metrics, logging, tracing (with and without `function_call_metrics`), guest-debugging (with `gdb` feature)

Each phase uses `--no-report` to accumulate raw profiling data. The report recipes (`coverage`, `coverage-html`, `coverage-lcov`) then generate the desired output format from the collected data. `coverage-ci` combines both steps into a single command.

Coverage is collected for the host-side workspace crates (`hyperlight_common`, `hyperlight_host`, `hyperlight_testing`, `hyperlight_component_util`, `hyperlight_component_macro`). Guest crates (`hyperlight-guest`, `hyperlight-guest-bin`, `hyperlight-guest-capi`, `hyperlight-guest-tracing`) and the `fuzz` crate are excluded because guest crates are `no_std` and cannot be compiled for the host target under coverage instrumentation.
