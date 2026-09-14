# Fuzzing Hyperlight

This directory contains the fuzzing infrastructure for Hyperlight. We use `cargo-fuzz` to run the fuzzers - i.e., small programs that run specific tests with semi-random inputs to find bugs. Because `cargo-fuzz` is not yet stable, we use the nightly toolchain. Also, because `cargo-fuzz` doesn't support Windows, we have to run this WSL or Linux (Mariner/Ubuntu).

You can run the fuzzers with:
```sh
just fuzz <fuzz_target>
```
which evaluates to the following command `cargo +nightly fuzz run fuzz_host_print --release`. We use the release profile to make sure the release-optimized guest is used. The default fuzz profile which is release+debugsymbols would cause our debug guests to be loaded, since we currently determine which test guest to load based on whether debug symbols are present.

As per Microsoft's Offensive Research & Security Engineering (MORSE) team, all host exposed functions that receive or interact with guest data must be continuously fuzzed for, at least, 500 million fuzz test cases without any crashes. Because `cargo-fuzz` doesn't support setting a maximum number of iterations; instead, we use the `--max_total_time` flag to set a maximum time to run the fuzzer. We have a GitHub action (acting like a CRON job) that runs the fuzzers for 24 hours every week.

Targets cover guest and host calls, printing, tracing, packed-ring parsing,
canonical ring images, malformed consumer I/O, and producer/consumer round trips.

## Malformed virtqueues

`fuzz_virtq_malformed` exercises ring parsing, canonical images, and
`VirtqConsumer` without a producer. Ring metadata and payloads have separate
memory bounds. The consumer attempts at most eight polls per input, with two
read/write rounds of at most 256 bytes per received chain, followed by completion.
Consumer errors are accepted, including failed reads and reply writes.
Panics and sanitizer findings fail the run.

Inputs have a 16-byte header and 12-byte descriptor records. Descriptor addresses
use signed, wrapping offsets from the payload base. Header byte 13 selects the
I/O length minus one. Trailing three-byte records select a little-endian `u16`
offset and a replacement byte. Offsets wrap within the ring followed by the
payload. When available, one mutation runs before each poll, read, reply write,
and completion.
Mutations run on the same thread between calls.

```sh
just fuzz-timed fuzz_virtq_malformed 60
cargo test -p hyperlight-fuzz --bin fuzz_virtq_malformed
```

## Virtqueue round trip

`fuzz_virtq_roundtrip` checks one request/reply round trip without a VM. Inputs
vary the payloads, I/O chunk size, and spare reply capacity. A fixed queue of
16 descriptors and 64-byte pool slots exercises fragmented messages. The target
checks payload bytes, completion types, backpressure, and resource release.

Inputs have a four-byte header and at most 1024 payload bytes. The header selects
the request/reply split, I/O chunk size, and spare reply capacity.
The malformed target shares the memory backend and covers malformed descriptors.

```sh
just fuzz-timed fuzz_virtq_roundtrip 60
```

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