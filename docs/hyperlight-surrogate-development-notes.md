### HyperlightSurrogate

`hyperlight_surrogate.exe` is a tiny Rust application we use to create multiple virtual machine (VM) partitions per process when running on Windows with the Windows Hypervisor Platform (WHP, e-g Hyper-V). This binary has no functionality. Its purpose is to provide a running process into which memory will be mapped via the `WHvMapGpaRange2` Windows API. Hyperlight does this memory mapping to pass parameters into, and fetch return values out of, a given VM partition.

> Note: The use of surrogates is a temporary workaround on Windows until WHP allows us to create more than one partition per running process.

These surrogate processes are managed by the host via the [surrogate_process_manager](./src/hyperlight_host/src/hypervisor/surrogate_process_manager.rs) which pre-creates an initial pool of surrogates at startup (512 by default, configurable via the `HYPERLIGHT_INITIAL_SURROGATES` environment variable). If the pool is exhausted, additional processes are created on demand up to a configurable maximum (`HYPERLIGHT_MAX_SURROGATES`, also defaulting to 512). Once the maximum is reached, callers block until a process is returned to the pool.

> **Note:** `HYPERLIGHT_MAX_SURROGATES` is authoritative — if `HYPERLIGHT_INITIAL_SURROGATES` exceeds it, the initial count is silently clamped down to the maximum. For example, setting only `HYPERLIGHT_MAX_SURROGATES=256` limits both the initial pool and the ceiling to 256.

`hyperlight_surrogate.exe` gets built during `hyperlight-host`'s build script, gets embedded into the `hyperlight-host` Rust library via [rust-embed](https://crates.io/crates/rust-embed), and is extracted at runtime next to the executable when the surrogate process manager is initialized. The extracted filename includes a short BLAKE3 hash of the binary content (e.g., `hyperlight_surrogate_a1b2c3d4.exe`) so that multiple hyperlight versions can coexist without file-deletion races.

### HVF surrogate (macOS)

On macOS with Hypervisor.framework (HVF) the constraint is similar — only one VM per process — but the implementation is fundamentally different. HVF binds a VM to the process that created it and offers no cross-process mapping API like `WHvMapGpaRange2`, so `hvf_surrogate` is a real server process rather than an empty suspended one:

- Each sandbox's VM and vCPU are created, run, and destroyed inside a pooled `hvf_surrogate` process; the host is an IPC client (length-prefixed JSON frames over an inherited unix socket pair; the protocol is defined in the `hyperlight-hvf` crate's `proto` module).
- Guest memory is never copied: the host allocates it from named POSIX shm objects (or file-backed regions), and the surrogate maps the same objects into its own address space and then into the guest.
- The surrogate's main thread is the vCPU thread — HVF requires vCPU creation, register access, and `hv_vcpu_run` to happen on a single thread. A reader thread dispatches requests and answers `Cancel` immediately via `hv_vcpus_exit` (the only HVF call allowed from a non-owning thread); a writer thread serializes all responses.
- The extracted surrogate binary is ad-hoc codesigned with the `com.apple.security.hypervisor` entitlement at extraction time, since Hypervisor.framework refuses to create VMs from unentitled binaries.

The pool is managed by `hvf_surrogate_manager` and honors the same `HYPERLIGHT_INITIAL_SURROGATES` / `HYPERLIGHT_MAX_SURROGATES` environment variables (defaulting to 0 initial / 128 max — HVF currently allows 127 concurrent VMs system-wide, so exceeding the pool fails fast rather than surprising the guest). Setting `HYPERLIGHT_MAX_SURROGATES=0` disables surrogates and selects the direct in-process backend, which limits the process to a single live sandbox at a time.
