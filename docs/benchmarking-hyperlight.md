# Benchmark Notes

Hyperlight uses the [Criterion](https://bheisler.github.io/criterion.rs/book/index.html) framework to run and analyze benchmarks. A benefit to this framework is that it doesn't require the nightly toolchain.

## When Benchmarks are ran

1. Every time a branch gets a push
    - Compares the current branch benchmarking results to the "dev-latest" release (which is the most recent push to "main" branch). This is done as part of `dep_rust.yml`, which is invoked by `ValidatePullRequest.yml`. These benchmarks are for the developer to compare their branch to main, and the results can only be seen in the GitHub action logs, and nothing is saved. 

    ```
    sandboxes/create_sandbox
                        time:   [33.803 ms 34.740 ms 35.763 ms]
                        change: [+0.7173% +3.7017% +7.1346%] (p = 0.03 < 0.05)
                        Change within noise threshold.*
    ```
   
2. For each release
    - For each release, benchmarks are ran as part of the release pipeline in `CreateRelease.yml`, which invokes `Benchmarks.yml`. These benchmark results are compared to the previous release, and are uploaded as port of the "Release assets" on the GitHub release page.

Currently, benchmarks are ran on windows, linux-kvm (ubuntu), and linux-hyperv (mariner). Only release builds are benchmarked, not debug.

## Criterion artifacts

When running `cargo bench -- --save-baseline my_baseline`, criterion runs all benchmarks defined in `src/hyperlight_host/benches/`, prints the results to the stdout, as well as produces several artifacts. All artifacts can be found in `target/criterion/`. For each benchmarking group, for each benchmark, a subfolder with the name of the benchmark is created. This folder in turn contains folders `my_baseline`, `new`  and `report`. When running `cargo bench`, criterion always creates `new` and `report`, which always contains the most recent benchmark result and html report, but because we provided the `--save-baseline` flag, we also have a `my_baseline` folder, which is an exact copy of `new`. Moreover, if this `my_baseline` folder already existed before we ran `cargo bench -- --save-baseline my_baseline`, criterion would also compare the benchmark results with the old `my_baseline` folder, and then overwrite the folder.

The first time we run `cargo bench -- --save-baseline my_baseline` (starting with a clean project), we get the following structure. 

```
target/criterion/
|-- report
`-- sandboxes
    |-- create_sandbox
    |   |-- my_baseline
    |   |-- new
    |   `-- report
    |-- create_sandbox_and_call_context
    |   |-- my_baseline
    |   |-- new
    |   `-- report
    `-- report
```

If we run the exact same command again, we get 

```
target/criterion/
|-- report
`-- sandboxes
    |-- create_sandbox
    |   |-- change
    |   |-- my_baseline
    |   |-- new
    |   `-- report
    |-- create_sandbox_and_call_context
    |   |-- change
    |   |-- my_baseline
    |   |-- new
    |   `-- report
    `-- report
```

Note that it overwrote the previous `my_baseline` with the new result. But notably, there is a new `change` folder, which contains the benchmarking difference between the two runs. In addition, on stdout you'll also find a comparison to our previous `my_baseline` run.

```
                        time:   [40.434 ms 40.777 ms 41.166 ms]
                        change: [+0.0506% +1.1399% +2.2775%] (p = 0.06 > 0.05)
                        No change in performance detected.
Found 1 outliers among 100 measurements (1.00%)
```

**Note** that Criterion does not differ between release and debug/dev benchmark results, so it's up to the developer to make sure baselines of the same config are compared.

## Running benchmarks locally

Use `just bench` to run benchmarks. Benchmarks only run with release builds for performance consistency. Comparing local benchmarks results to github-saved benchmarks doesn't make much sense, since you'd be using different hardware, but you can use `just bench-download os hypervisor [tag] ` to download and extract the GitHub release benchmarks to the correct place folder. You can then run `just bench-ci main` to compare to (and overwrite) the previous release benchmarks. Note that `main` is the name of the baselines stored in GitHub.
