# Fuzzing Hyperlight

This directory contains the fuzzing infrastructure for Hyperlight. We use `cargo-fuzz` to run the fuzzers - i.e., small programs that run specific tests with semi-random inputs to find bugs. Because `cargo-fuzz` is not yet stable, we use the nightly toolchain. Also, because `cargo-fuzz` doesn't support Windows, we have to run this WSL or Linux (Mariner/Ubuntu).

You can run the fuzzers with:
```sh
just fuzz <fuzz_target>
```
which evaluates to the following command `cargo +nightly fuzz run fuzz_host_print --release`. We use the release profile to make sure the release-optimized guest is used. The default fuzz profile which is release+debugsymbols would cause our debug guests to be loaded, since we currently determine which test guest to load based on whether debug symbols are present.

As per Microsoft's Offensive Research & Security Engineering (MORSE) team, all host exposed functions that receive or interact with guest data must be continuously fuzzed for, at least, 500 million fuzz test cases without any crashes. Because `cargo-fuzz` doesn't support setting a maximum number of iterations; instead, we use the `--max_total_time` flag to set a maximum time to run the fuzzer. We have a GitHub action (acting like a CRON job) that runs the fuzzers for 24 hours every week.

Currently, we fuzz the parameters and return type to a hardcoded `PrintOutput` guest function, and the `HostPrint` host function. We plan to add more fuzzers in the future.

## On Failure 

If you encounter a failure, you can re-run an entire seed (i.e., group of inputs) with:
```sh
cargo +nightly fuzz run <fuzzer_target> -- -seed=<seed-number>
```

The seed number can be seed in a specific run, like:
![fuzz-seed](doc-assets/image.png)

Or, if repro-ing a failure from CI, you can download the artifact from the fuzzing run, and run it like:

```sh
cargo +nightly fuzz run -O <fuzzer_target> <fuzzer-input (e.g., fuzz/artifacts/fuzz_target_1/crash-93c522e64ee822034972ccf7026d3a8f20d5267c>
```