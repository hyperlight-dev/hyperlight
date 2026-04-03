### HyperlightSurrogate

`hyperlight_surrogate.exe` is a tiny Rust application we use to create multiple virtual machine (VM) partitions per process when running on Windows with the Windows Hypervisor Platform (WHP, e-g Hyper-V). This binary has no functionality. Its purpose is to provide a running process into which memory will be mapped via the `WHvMapGpaRange2` Windows API. Hyperlight does this memory mapping to pass parameters into, and fetch return values out of, a given VM partition.

> Note: The use of surrogates is a temporary workaround on Windows until WHP allows us to create more than one partition per running process.

These surrogate processes are managed by the host via the [surrogate_process_manager](./src/hyperlight_host/src/hypervisor/surrogate_process_manager.rs) which pre-creates an initial pool of surrogates at startup (512 by default, configurable via the `HYPERLIGHT_INITIAL_SURROGATES` environment variable). If the pool is exhausted, additional processes are created on demand up to a configurable maximum (`HYPERLIGHT_MAX_SURROGATES`, also defaulting to 512). Once the maximum is reached, callers block until a process is returned to the pool.

> **Note:** `HYPERLIGHT_MAX_SURROGATES` is authoritative — if `HYPERLIGHT_INITIAL_SURROGATES` exceeds it, the initial count is silently clamped down to the maximum. For example, setting only `HYPERLIGHT_MAX_SURROGATES=256` limits both the initial pool and the ceiling to 256.

`hyperlight_surrogate.exe` gets built during `hyperlight-host`'s build script, gets embedded into the `hyperlight-host` Rust library via [rust-embed](https://crates.io/crates/rust-embed), and is extracted at runtime next to the executable when the surrogate process manager is initialized. The extracted filename includes a short BLAKE3 hash of the binary content (e.g., `hyperlight_surrogate_a1b2c3d4.exe`) so that multiple hyperlight versions can coexist without file-deletion races.
