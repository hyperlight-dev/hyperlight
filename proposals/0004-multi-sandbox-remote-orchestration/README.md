# HIP 0004 - Multi-sandbox orchestration via remote sandbox processes

<!-- toc -->

- [Summary](#summary)
- [Motivation](#motivation)
    - [Goals](#goals)
    - [Non-Goals](#non-goals)
- [Proposal](#proposal)
    - [User Stories](#user-stories)
        - [Story 1](#story-1)
        - [Story 2](#story-2)
        - [Story 3](#story-3)
    - [Notes/Constraints/Caveats](#notesconstraintscaveats)
        - [Per-hypervisor-call RPC was rejected](#per-hypervisor-call-rpc-was-rejected)
        - [Relationship to the in-process HVF backend](#relationship-to-the-in-process-hvf-backend)
        - [Why one sandbox per surrogate process?](#why-one-sandbox-per-surrogate-process)
        - [macOS specifics carried over from #1681's work](#macos-specifics-carried-over-from-1681s-work)
        - [Cargo distribution caveat (from #1706)](#cargo-distribution-caveat-from-1706)
        - [Host functions](#host-functions)
        - [Relationship to the virtqueue transport (HIPs 0001 and 0002)](#relationship-to-the-virtqueue-transport-hips-0001-and-0002)
        - [Send/Sync as a side benefit](#sendsync-as-a-side-benefit)
    - [Risks and Mitigations](#risks-and-mitigations)
        - [Per-call IPC latency regresses benchmarks vs. in-process execution](#per-call-ipc-latency-regresses-benchmarks-vs-in-process-execution)
        - [A surrogate dies mid-call](#a-surrogate-dies-mid-call)
        - [Security surface of an entitled helper binary and an IPC protocol](#security-surface-of-an-entitled-helper-binary-and-an-ipc-protocol)
        - [macOS developer-experience friction (entitlements, signing, toolchain)](#macos-developer-experience-friction-entitlements-signing-toolchain)
        - [Resource limits: ~127 concurrent VMs system-wide on HVF, plus per-surrogate memory footprint](#resource-limits-127-concurrent-vms-system-wide-on-hvf-plus-per-surrogate-memory-footprint)
- [Design Details](#design-details)
    - [Crate layout](#crate-layout)
    - [Public API sketch (host side)](#public-api-sketch-host-side)
    - [Protocol](#protocol)
    - [Snapshot transfer](#snapshot-transfer)
    - [Process lifecycle](#process-lifecycle)
    - [Call flow](#call-flow)
    - [Phase 2 (optional, separate PR, may require a small core extension)](#phase-2-optional-separate-pr-may-require-a-small-core-extension)
    - [Test Plan](#test-plan)
        - [Unit tests](#unit-tests)
        - [Integration tests](#integration-tests)
        - [e2e tests](#e2e-tests)
- [Implementation History](#implementation-history)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)

<!-- /toc -->

## Summary

Hyperlight's macOS Hypervisor.framework (HVF) backend, introduced in #1674, supports creating multiple sandboxes in a single process but executes only one at a time: HVF permits at most one VM per process, so all sandboxes share a single address space that is swapped in under a global write lock, incurring a full unmap/remap of the guest's memory regions on every context switch.

This HIP proposes a new opt-in crate, `hyperlight-remote`, that hosts each sandbox in its own surrogate helper process and exposes a `SandboxBuilder` / `MultiUseSandbox`-shaped API in the host process. The unit of remoting is a _high-level Hyperlight operation_ — evolve, call guest function, snapshot, restore, interrupt — dispatched as a single request over a local IPC channel. Each surrogate process runs an unmodified in-process `hyperlight-host` (on macOS, the #1674 backend), so the one-VM-per-process constraint is satisfied by construction and guests execute with true parallelism across processes.

The crate is experimental and non-production. It is designed for development and test scenarios — running parallel sandbox workloads on a single machine, above all a developer's Apple silicon laptop — and will be labelled and documented as such. Production deployment, support, and compatibility guarantees are out of scope (see Non-Goals) and would be revisited in a follow-up proposal once the design proves out. This matches how maintainers have described Hyperlight's own macOS/HVF interest: primarily developer-experience, non-production-service use cases.

The design follows the direction agreed with maintainers in the discussion of #1681 and issue #1706: remoting sits _above_ the public API as a wrapper, not below it at the hypervisor-trait level, requires no changes to Hyperlight's core, and works on every supported platform. It directly addresses #1796 (macOS multi-sandbox support) and implements the wrapper envisioned by #1706.

## Motivation

### Goals

1. Ship an experimental, non-production crate, labelled as such, scoped to development and test scenarios. Success is measured by whether it makes local parallel sandbox testing practical.
2. Allow multiple Hyperlight sandboxes to execute concurrently in a single host application on macOS (Apple silicon), where HVF allows only one VM per process. This closes #1796.
3. Implement the remote-sandbox wrapper described in #1706 as a separate crate — no changes to `hyperlight-host`'s hypervisor layer, keeping the remoting code outside Hyperlight's trusted computing base.
4. One IPC round-trip per high-level sandbox operation. A guest function call must cost exactly one request/response exchange regardless of how many hypervisor operations it expands into.
5. Cross-platform: the same wrapper works on top of KVM, MSHV, WHP, and HVF, and immediately improves dev-test fault isolation (a surrogate crash cannot abort the host process or a test run). Running sandboxes in reduced-privilege processes for production defense-in-depth is #1706's original motivation and remains a possible future direction, not something this HIP commits to.

### Non-Goals

1. Production use, deployment, or support of any kind. The crate is experimental: its API may change or be removed without the usual compatibility considerations, and it must not be relied on to run untrusted code outside development environments. Promotion to production would be a follow-up HIP.
2. Matching in-process latency. We accept a per-operation IPC cost and aim to keep it small and predictable; latency-sensitive workloads should use in-process backends.
3. Changes to `hyperlight-host` internals: the hypervisor trait, sandbox memory management, or host-function machinery are not modified. (A small, separately-reviewable opt-in extension for shared-memory-backed buffers is discussed as a future phase, not a prerequisite.)
4. Integrating `hyperlight-wasm`, `hyperlight-js`, or `hyperlight-unikraft` with the wrapper. Those may follow once the API settles (see the cargo distribution caveat below).
5. Distributed or multi-host orchestration. IPC is a local unix-domain socket between a host and its child processes on one machine.
6. macOS x86_64 support (HVF lacks the APIs Hyperlight requires) or supporting macOS guests in CI beyond what #1674 already enabled.

## Proposal

### User Stories

#### Story 1

A developer at a startup building a parallel function-execution framework uses an Apple silicon MacBook as their primary machine. Their scheduler tests launch dozens of sandboxes with varying execution times and assert on contention, overlap, and preemption behaviour. Today they must either run these tests on remote Linux machines or accept the one-at-a-time execution of the #1674 backend, which makes the tests meaningless. With `hyperlight-remote`, the same tests run locally: each sandbox lives in its own surrogate process, guests execute in parallel, and the wall-clock assertions behave the same as they do on a Linux CI runner.

#### Story 2

A developer's test suite spawns hundreds of sandboxes over a full run, and every so often a guest bug takes one down. With in-process execution that aborts the entire test process; using the same wrapper on Linux (KVM) or Windows (WHP), the crash is contained to its surrogate — the failing test reports an error, the pool respawns the helper, and the run continues. Hardening this containment into a production defense-in-depth story (separate, low-privilege processes) is left as future work beyond this HIP.

#### Story 3

A test harness runs thousands of guest-function calls per second across a pool of sandboxes. Calls that touch large data use Hyperlight's existing file-mapping facilities (`mapped_file_cow`), which pass file paths — not bytes — across the boundary; when the virtqueue transport (HIPs 0001/0002) lands, those payloads move through shared-memory rings instead. Either way the IPC channel carries only small call metadata and parameter blobs, so throughput remains acceptable even though every call pays one IPC round-trip.

### Notes/Constraints/Caveats

#### Per-hypervisor-call RPC was rejected

The initial macOS prototype (#1681) implemented the `VirtualMachine` trait behind an IPC proxy, with each `run_vcpu`/register access round-tripping to a surrogate. Maintainers rejected that layer: each minor operation would require a kernel scheduler entry, and there are several such operations per high-level call. This HIP moves the remoting boundary up to the public API, so the IPC cost is paid once per Hyperlight operation instead of tens of times.

#### Relationship to the in-process HVF backend

#1674 (merged) provides an in-process backend where every sandbox in the process shares one VM and one address space; only one executes at a time, holding a global write lock while its memory regions are mapped in. `hyperlight-remote` builds on it: each surrogate process runs that backend with exactly one sandbox — its best case, with no lock contention and no space swapping. The upstream plan to eventually run several sandboxes simultaneously in-process (e.g. via nested virtualisation where available) is complementary; this HIP is available now, on current hardware, with no nesting requirement.

#### Why one sandbox per surrogate process?

This is a limitation of macOS: HVF allows one VM per process. On other platforms a surrogate could host several VMs, but we keep 1:1 everywhere for uniformity, simpler lifecycle management, and blast-radius reasons. Surrogates are pooled and reused across sequential sandboxes.

#### macOS specifics carried over from #1681's work

- Every surrogate executable must carry the `com.apple.security.hypervisor` entitlement. The surrogate binary is nested-built, embedded via `rust-embed`, extracted at runtime next to the host executable with a content-hash suffix, and ad-hoc codesigned with the entitlement at extraction time (matching the codesigning machinery #1674 already added for development builds).
- HVF currently permits ~127 concurrent VMs system-wide. The surrogate pool fails fast rather than hanging when it cannot create a new VM.
- Pool sizing reuses the existing `HYPERLIGHT_INITIAL_SURROGATES` / `HYPERLIGHT_MAX_SURROGATES` conventions so that WHP-surrogate users find familiar knobs.

#### Cargo distribution caveat (from #1706)

Because of rust-lang/cargo#9227, a root crate cannot transparently swap `hyperlight-host` for a wrapper crate throughout a dependency graph. This HIP therefore proposes a _new crate name_ (`hyperlight-remote`) with its own types that mirror the `SandboxBuilder`/`MultiUseSandbox` API shapes, rather than a crate masquerading as `hyperlight-host`. This is less "drop-in" but avoids git-dependency hacks, keeps both usable side by side, and means downstream crates like `hyperlight-wasm` are unaffected until they choose to integrate.

#### Host functions

Hyperlight host functions are arbitrary Rust closures, which cannot be serialized. The wrapper supports two tiers:

1. _Proxied (default):_ the wrapper registers a trampoline for each host function; when a guest calls it, the surrogate sends a `HostCall` request back to the host, the host runs the real closure, and the result returns. API-compatible with in-process usage; costs one nested round-trip per host function call, during which the surrogate's guest is blocked.
2. _Native (opt-in):_ for hot host functions, the embedder registers an implementation directly in the surrogate's registry (name + typed binary dispatch, in the spirit of the mesh prototype shown in #1706). No round-trip; the implementation must be available to (or shipped with) the surrogate binary.

#### Relationship to the virtqueue transport (HIPs 0001 and 0002)

Upstream is building a new host-guest data plane: a packed-virtqueue ring buffer for Hyperlight I/O (HIP 0001, `rng-buf` — primitives in #1382/#1634 merged, transport in #1793/#1794 open) with large payloads carried as external byte streams rather than embedded serialization vectors (HIP 0002). The two fit together because the virtqueue lives entirely in guest shared memory:

- The rings are serviced wherever the guest memory is mapped. In phase 1 that is the surrogate, which plays the ring's device role inside its in-process `hyperlight-host` — no change needed on our side.
- The batching HIP 0001 enables (many calls per VM exit) also shrinks what crosses our IPC channel: a batched guest burst is one run inside the surrogate plus one reply.
- With the phase-2 shm sharing below, the host process can map the same rings and service device-side work directly against shared memory — bulk host↔guest data then moves with no surrogate or IPC involvement, and the IPC channel shrinks to a pure control plane (evolve/run/snapshot/interrupt). This stays a phase-2 benefit; the virtqueue transport is not merged yet.

#### Send/Sync as a side benefit

On the in-process HVF backend, sandboxes carry vCPU thread-affinity costs (register re-sync when a sandbox migrates between threads). The remote handle holds only a socket and pool state, so it is cheaply `Send + Sync` — one less macOS-specific papercut.

### Risks and Mitigations

#### Per-call IPC latency regresses benchmarks vs. in-process execution

Mitigation: one round-trip per operation; compact binary framing; warm surrogate pool to avoid spawn costs on the hot path; large payloads already flow via file mappings, not IPC. We will publish benchmark numbers (in-process vs. remote on identical workloads) in the implementation PR and keep a benchmark job so the cost stays visible. These numbers are informative, not release-gating: they help users judge when the wrapper's cost is worth paying. If profiling justifies it later, a phase-2 shm-backed zero-copy buffer path exists (see Design Details) — but the copy-based design ships first.

#### A surrogate dies mid-call

Mitigation: the pool monitors children; the corresponding sandbox transitions to a poisoned state and the pending call fails with a distinguishable error; the surrogate is respawned into the pool. Other sandboxes are unaffected — which is itself an isolation improvement over in-process execution.

#### Security surface of an entitled helper binary and an IPC protocol

The surrogate must hold the hypervisor entitlement on macOS, and a local socket accepts requests that drive a VM. Mitigation: the socket is created before exec and passed as an inherited fd (no named socket on disk to hijack); the extraction directory is owner-only with content-hashed filenames, following the existing WHP-surrogate conventions. The protocol and process-management code still get maintainer review in the implementation PR, scaled to the non-production scope. The TCB argument also runs in our favour: nothing in `hyperlight-host` itself changes.

#### macOS developer-experience friction (entitlements, signing, toolchain)

Mitigation: automatic ad-hoc signing at extraction; documented one-time signing step for the user's own binary (already required by #1674); clear error messages when the entitlement is missing (`NoHypervisorFound` today — improved to an explicit "re-sign with the entitlement" hint).

#### Resource limits: ~127 concurrent VMs system-wide on HVF, plus per-surrogate memory footprint

Mitigation: bounded pool with fail-fast behaviour, documented ceiling, and metrics/log lines when the pool saturates.

## Design Details

### Crate layout

A single new workspace crate `hyperlight-remote` containing the wrapper API (host side), the surrogate binary (runs an unmodified `hyperlight-host`), the IPC protocol (a versioned message enum shared by both, in a small `hyperlight-remote-proto` crate so the surrogate stays dependency-lean), and the process pool manager. Nothing in existing crates changes; `hyperlight-host` gains at most a feature flag that the surrogate enables. The crate's README, rustdoc front page, and publish metadata carry an explicit **experimental / non-production** notice, and no existing `hyperlight-*` crate depends on it.

### Public API sketch (host side)

```rust
let sandbox = RemoteSandboxBuilder::from_file("guest.so")
    .host_function("Add", |a: i32, b: i32| Ok(a + b)) // proxied by default
    .input_data_size(0x1000)
    .build()?;

let result: i64 = sandbox.call_guest_function_by_name("Fib", arg)?; // 1 RTT
```

`RemoteSandboxBuilder` mirrors `SandboxBuilder` (from_file / from_bytes / from_snapshot, sizes, host functions, guest log level), and the built handle mirrors `MultiUseSandbox` (call*, snapshot, restore, interrupt_handle, status). Where a method is meaningless remotely it is omitted rather than stubbed (e.g. debug-register hooks), and omissions are documented in one table.

### Protocol

Length-prefixed binary frames over an inherited unix-domain socket (STREAM). Messages are a `#[non_exhaustic]`, protocol-version-tagged enum; serialization via a compact binary codec (`postcard`), chosen for `serde` compatibility and cheap one-shot encodes — deliberately not JSON, and with enough structure to swap in something like FlatBuffers later without protocol breakage. Initial requests: `Evolve`, `Call { function, metadata, params }`, `Snapshot { dest_path }`, `Restore { snapshot_path }`, `Interrupt`, `Drop`, `HostCall { function, params }` (surrogate→host), plus ack/error responses carrying Hyperlight error variants.

### Snapshot transfer

Snapshots (guest memory blobs) never travel through the IPC channel. The host passes a file path; the surrogate writes the snapshot there (benefiting from the sparse-write work in #1788) and returns metadata. `Restore` symmetrically takes a path. This keeps the protocol messages small regardless of snapshot size.

### Process lifecycle

A lazily-created pool spawns surrogates on demand up to `HYPERLIGHT_MAX_SURROGATES`, pre-spawning `HYPERLIGHT_INITIAL_SURROGATES`. A surrogate is checked out for the lifetime of one sandbox and returned to the pool when the sandbox drops (kill-on-drop as a backstop). Child exits are detected via `SIGCHLD`/waitpid bookkeeping; unexpected death poisons the sandbox and schedules a replacement surrogate. On macOS the extraction + ad-hoc codesign step happens once per binary hash, before the first spawn.

### Call flow

1. Host serializes parameters (typically < one page) into the request frame and sends `Call`.
2. Surrogate writes parameters into its sandbox's input buffer, runs the guest — using plain in-process `hyperlight-host`, with however many hypervisor operations that entails, all local — and reads the output buffer.
3. Surrogate replies with the serialized result.
4. Host-side guest function calls that transfer large data use `map_file_cow`-style path-passing before/after the call, never the frame — and once the virtqueue transport lands (HIPs 0001/0002), bulk payloads move through shared-memory rings instead, and the frames stay metadata-only either way.

### Phase 2 (optional, separate PR, may require a small core extension)

Back the sandbox's input/output buffers with POSIX shm (`shm_open` on macOS, `memfd` on Linux) shared between host and surrogate, so step 1/3 copy nothing and the frame carries only lengths. This is the zero-copy design from #1681, relocated to the buffer layer where it does not touch the hypervisor trait. It is an optimization, not a dependency of this HIP. Phase 2 is also what unlocks direct host-side servicing of the HIP 0001 virtqueues (see the note above).

### Test Plan

##### Unit tests

- Protocol codec round-trips for every message, including unknown-variant handling for forward compatibility.
- Pool manager state machine: checkout/return, max enforcement, respawn on death, kill-on-drop.
- Builder parity: a test that reflectively enumerates `SandboxBuilder` methods and asserts each is mirrored, omitted-with-documentation, or N/A on `RemoteSandboxBuilder`.

##### Integration tests

- **True-parallelism proof (the motivating test):** N sandboxes run CPU-bound guests of staggered durations; the test asserts the total wall-clock is materially below the serial sum and that execution intervals overlap. This test fails on the in-process #1674 backend by design and is the acceptance criterion for #1796.
- Crash propagation: kill -9 a surrogate mid-call; assert the caller gets a `SurrogateDied`-style error, the host process and sibling sandboxes survive, and the pool respawns.
- Proxied and native host functions, including a host function that itself calls another sandbox.
- Snapshot/restore round-trip through file paths across process boundaries.
- Pool ceiling behaviour when exceeding `HYPERLIGHT_MAX_SURROGATES` and the HVF VM limit.
- Run the existing `hyperlight-host` integration suite against the wrapper on macOS (the #1681 branch ran the full suite through this architecture).

##### e2e tests

- An execution-framework-style scheduler test suite of the kind that motivated this HIP, running on a MacBook to validate the parallelism end to end.
- GitHub Actions on the macOS runners #1674 already enabled for HVF: build, sign, run the above, plus the latency benchmark job publishing in-process vs. remote numbers for guest-function call and snapshot/restore.

## Implementation History

- 2026-08-17: #1674 merged — in-process single-execution HVF backend, the base each surrogate runs.
- 2026-07-22: #1681 opened — first macOS multi-sandbox implementation using per-hypervisor-call RPC surrogates. Maintainer discussion there rejected the RPC layer and converged on the high-level wrapper direction of #1706; that implementation is superseded by this HIP and will be rewritten on top of the merged in-process backend. Much of its macOS work (entitlement handling, extraction/signing, guest toolchain fixes, page-size fixes) carries over directly.
- 2026-08-05: #1706 opened by a maintainer describing the remote-process wrapper this HIP implements, including a mesh-based prototype.
- 2026-09-03: #1796 opened to track macOS multi-sandbox support.
- This HIP: draft for maintainer review, per the process in `proposals/0000-hip-process`.

## Drawbacks

- Every operation pays an IPC round-trip (order of tens of microseconds on a unix socket, plus serialization). Workloads dominated by many tiny guest calls will feel this and should stay in-process.
- A surrogate process costs memory beyond the guest image (a full `hyperlight-host` runtime per sandbox) and counts against process/VM ceilings — on HVF, ~127 VMs system-wide.
- More moving parts: a protocol to version, a binary to embed/extract/sign, and pool lifecycle semantics to document and test.
- The wrapper-API coupling means new `SandboxBuilder`/`MultiUseSandbox` surface must be mirrored (or consciously not mirrored) here too — a small ongoing tax.
- As an experimental crate, its API may change or be withdrawn between releases; dev pipelines that adopt it must expect churn.

## Alternatives

1. **Per-hypervisor-call RPC surrogates (the #1681 prototype).** Rejected by maintainers: several kernel scheduler entries per high-level operation, and remoting code inside what Hyperlight considers its TCB. The high-level boundary of this HIP is the direct response.
2. **Extend the in-process backend to execute sandboxes simultaneously.** Upstream has signalled intent here (the hvf module docs mention nested virtualisation where available). It is complementary, not blocking: it has nesting/hardware prerequisites and its own performance questions, while this HIP works on current macOS and hardware and additionally provides dev-test fault isolation. If it lands and performs, some users may prefer it; the wrapper could later grow into #1706's production isolation story (reduced-privilege processes) under a follow-up proposal.
3. **Build on OpenVMM `mesh`** as the IPC/hosting substrate, per the working prototype shown in #1706. Attractive long-term (proven RPC, mesh spawn/lockdown plumbing), but currently blocked on: mesh not being published standalone, no macOS port, and unfinished process-lockdown (minijail) work. We borrow its _shape_ — high-level ops, host-function registry in the surrogate — while shipping a smaller protocol of our own, and our protocol versioning leaves a later move to mesh open.
