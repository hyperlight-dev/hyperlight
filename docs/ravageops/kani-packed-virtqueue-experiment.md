# Using Kani to verify Hyperlight's packed virtqueue notifications

## Summary

This experiment added formal verification to a small, self-contained part of
Hyperlight's communication code. Hyperlight runs untrusted code inside small,
hardware-isolated virtual machines. Its host and guest exchange work through
virtqueues, which are shared-memory ring buffers based on the VIRTIO standard.

The experiment used the Kani Rust Verifier to check two properties of
Hyperlight's packed virtqueue implementation:

1. advancing a ring cursor produces the correct index and wrap state; and
2. descriptor-event notification decisions match an independent mathematical
   model for a batch containing up to one complete ring of descriptors.

Kani found a real notification bug. If a batch advanced by exactly one full
ring, the cursor returned to the same physical index with the opposite wrap
bit. The old implementation discarded part of that state and could decide not
to notify a peer that had explicitly requested a notification. A peer relying
on that notification could wait indefinitely. A related partial-wrap case
could send an unnecessary notification for an event that had already passed.

The arithmetic was corrected, ordinary regression tests were added, and the
Kani proofs now pass across the modelled state space. The work also added a
repeatable local command and a narrowly scoped GitHub Actions workflow.

This is a confirmed correctness and availability bug. It may be relevant to
denial-of-service analysis for downstream users that enable descriptor-based
notification suppression, but the available evidence does not establish an
exploitable security vulnerability in Hyperlight.

## Background

### What is Hyperlight?

[Hyperlight](https://github.com/hyperlight-dev/hyperlight) is a Rust library
for running untrusted functions inside lightweight virtual machines. Unlike a
general-purpose virtual machine, a Hyperlight guest does not run a kernel or a
full operating system. This keeps startup and function-call overhead low while
retaining a hardware-enforced isolation boundary.

The host and guest still need a way to exchange requests, responses, and
notifications. Hyperlight uses packed virtqueues for this transport. A
virtqueue stores descriptors in a fixed-size circular ring. Each descriptor
describes a buffer that one side has made available to the other.

Because the ring is circular, a physical index is not enough to identify a
position. Index 0 before one trip around the ring is different from index 0
after that trip. Packed virtqueues therefore pair the index with a wrap bit
that changes whenever the cursor crosses the end of the ring.

### What is Kani?

[Kani](https://model-checking.github.io/kani/) is a model checker for Rust. A
normal unit test checks the inputs selected by the test author. A Kani proof
harness instead introduces symbolic values and asks whether an assertion holds
for every value allowed by its assumptions. If an assertion can fail, Kani
returns a concrete counterexample.

Kani does not prove that an entire application is correct. Its value depends
on choosing a useful property, defining an independent reference model, and
stating the boundary of the proof accurately.

## Why this was a useful experiment

Sandbox and virtualisation code has several characteristics that make formal
verification worth exploring:

- small arithmetic mistakes can affect whether two isolated components make
  progress;
- wrap-around logic has boundary cases that are easy to omit from example-based
  tests;
- shared-memory transports depend on compact state machines with precise
  invariants; and
- some failures appear only at specific combinations of index, wrap state,
  event position, and batch length.

The packed-ring notification calculation was a practical first target. It was
small enough to model without abstracting the whole virtual machine, but it
sat on a path that can determine whether a peer receives a kick or interrupt.
The core decision was pure arithmetic, which let Kani explore it without
modelling the hypervisor, operating system, or shared-memory backend.

The target answered two practical questions: whether Kani could be integrated
into Hyperlight's `no_std` shared crate, and whether a formal property could
find behaviour that the existing unit tests had missed.

## The property under test

Packed virtqueues support notification suppression. In descriptor-event mode,
a peer supplies an event position as an offset and wrap bit. After publishing
a batch, the producer should notify the peer if it crossed that requested
position. The
[VIRTIO 1.3 specification](https://docs.oasis-open.org/virtio/virtio/v1.3/virtio-v1.3.html)
defines the descriptor-event offset and wrap counter used for this decision.

The proof models the ring as two consecutive logical phases, each containing
`ring_size` positions. The physical offset identifies a slot, while the wrap
bit identifies its phase. This gives a logical span of `2 * ring_size`.

For an old cursor, a new cursor, and a requested event, the reference model
computes the forward distance from the old cursor to the event. A notification
is expected when the event lies in the half-open interval traversed by the
batch: the old position is included, and the new position is excluded.

The proof covers:

- every power-of-two `u16` ring size supported by the model, from 1 to 32,768;
- every valid starting offset and either wrap state;
- every batch length from zero through one complete ring; and
- every valid descriptor-event offset and either event wrap state.

Reachability checks ensure that the proof exercises zero progress, ordinary
progress, partial wrapping, full-ring advancement, and the excluded new-cursor
boundary. These checks help detect proofs that pass only because their
assumptions accidentally rule out important cases.

## What failed

The old code adjusted the requested event according to its wrap state, then
called the standard wrapping comparison with only the physical head of the old
cursor. When the batch crossed the ring boundary, that physical head no longer
represented the old cursor in the same logical window as the event and new
cursor.

A minimal example uses a ring containing eight descriptors:

| State | Offset | Wrap bit |
|---|---:|---:|
| Cursor before the batch | 0 | true |
| Requested descriptor event | 0 | true |
| Cursor after publishing eight descriptors | 0 | false |

The batch traversed the complete ring, including the requested event at the
old cursor. The correct result is therefore to notify. The previous comparison
saw equal physical old and new indices and calculated zero progress, producing
`false`.

The failure was demonstrated in two independent ways before applying the fix:

- Kani produced a counterexample to the descriptor-notification property; and
- a focused Rust unit test reproduced the missed full-ring notification.

Kani also exposed the broader phase-normalisation issue rather than only the
single example. In a partial-wrap history, an event immediately behind the old
cursor could be treated as if it were still ahead, causing an unnecessary
notification.

## The correction

The notification calculation now places the requested event and the old
cursor in the same wrapping `u16` window as the new cursor. Each is shifted
back by the ring length when its wrap bit differs from the new cursor's wrap
bit. The existing wrapping comparison can then evaluate the traversed interval
without losing phase information.

The low-level batching API now also:

- documents that the snapshot must come from the same producer;
- documents that no more than one ring may be published between the snapshot
  and the notification check; and
- rejects a cursor carrying a different ring size.

The high-level batch API already enforces the one-ring progress bound through
exclusive borrowing and ring-capacity checks. At the low-level public API, the
same-sized cursor provenance rule remains a documented caller obligation
because a cursor does not carry a ring identity.

## Changes made

The experiment produced the following repository changes:

- [`ring/verification.rs`](../../src/hyperlight_common/src/virtq/ring/verification.rs)
  contains the Kani cursor and notification proofs, their independent
  wide-integer model, and nine reachability checks.
- [`ring.rs`](../../src/hyperlight_common/src/virtq/ring.rs) enables the proof
  module under `cfg(kani)`, corrects the phase calculation, validates cursor
  ring size, documents the public contract, and adds focused regressions.
- [`producer.rs`](../../src/hyperlight_common/src/virtq/producer.rs) adds a
  high-level regression that fills a four-entry ring in one batch and confirms
  that finishing the batch sends exactly one notification.
- [`Cargo.toml`](../../Cargo.toml) declares `cfg(kani)` as an expected
  configuration, alongside the existing Loom configuration.
- [`Justfile`](../../Justfile) adds `just kani` as the local proof command.
- [`.github/workflows/Kani.yml`](../../.github/workflows/Kani.yml) adds a
  path-filtered pull-request workflow. It uses read-only permissions,
  immutable action revisions, and Kani 0.68.0 installed with `--locked`.
- [`CHANGELOG.md`](../../CHANGELOG.md) records the corrected wrapped
  descriptor-event decisions.

No runtime dependency was added. Kani supplies its proof API when it compiles
the crate for verification.

## Results

After the fix:

- both Kani proof harnesses completed successfully with Kani 0.68.0 and CBMC
  6.11.0;
- all nine proof reachability checks were satisfied;
- the `hyperlight-common` library suite passed 363 tests;
- the full repository `just test` command passed, including unit, isolated,
  integration, and documentation tests;
- the full-ring, partial-wrap, mismatched-ring-size, and high-level batch
  regressions passed;
- strict Clippy checks for all `hyperlight-common` targets and features passed
  with warnings denied;
- formatting and licence-header checks passed; and
- `cargo audit` and `cargo deny check advisories` reported no dependency
  vulnerability failure.

Independent Rust, behavioural, security, documentation, and final engineering
reviews approved the final revision after their findings were addressed.

An earlier repository-wide `just clippy` attempt on macOS failed in generated
Hypervisor.framework bindings because bindgen emitted self-transmutes that
Clippy treats as errors under `-D warnings`. Those generated bindings are
outside this change. The affected `hyperlight-common` crate passed the strict
scoped Clippy check.

The GitHub Actions workflow was inspected and its exact Kani command passed
locally. It has not yet run on a GitHub-hosted runner.

## Security assessment

The old behaviour could leave a peer asleep after work had been published. In
a system that relies exclusively on descriptor-event notifications, this is an
availability failure and could look like a denial of service.

The investigation did not find evidence for a confirmed Hyperlight security
vulnerability:

- Hyperlight's current non-test runtime code does not enable descriptor-based
  notification suppression;
- the default notification mode remains enabled;
- no memory-safety, confidentiality, integrity, isolation, or privilege
  boundary failure was found; and
- an untrusted peer that refuses to process a queue already controls its own
  progress.

Downstream code that enables descriptor suppression may have a different trust
and scheduling model. For such users, the original bug could have security
relevance as an externally triggered availability failure. Demonstrating that
would require an integration trace showing that an untrusted party can force
the affected state while the receiver depends solely on the missing
notification.

The experiment confirms the defect in the checked revision. It does not
establish whether the defect was previously unpublished or unknown outside the
repository.

## What the proof does not establish

The successful proofs should not be read as mathematical certification of
Hyperlight or even of the complete virtqueue implementation. They establish
two arithmetic properties within explicit assumptions.

Kani does not cover the following in this experiment:

- shared-memory address validation or `MemOps` implementations;
- unsafe memory mappings;
- atomic ordering and fences;
- concurrent changes made by the peer;
- cursor histories spanning more than one complete ring; or
- correct provenance for a stale cursor from another ring of the same size.

Hyperlight's Loom tests and integration tests remain the relevant evidence for
concurrent behaviour. Broader formal verification would need separate models
for memory access, publication ordering, descriptor ownership, and the
producer-consumer protocol.

## Reproducing the verification

Install Kani using its
[documented two-step process](https://model-checking.github.io/kani/install-guide.html):

```console
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

Run both proofs from the repository root:

```console
just kani
```

The underlying command is:

```console
cargo kani -p hyperlight-common --lib --no-default-features
```

Run the ordinary regression coverage with:

```console
cargo test --locked -p hyperlight-common --lib virtq::
```

The full repository test command requires the project prerequisites and guest
binaries described in Hyperlight's contribution documentation:

```console
just test
```

## Outcome

The experiment showed where Kani fitted this codebase: pure ring arithmetic
with clear inputs, outputs, and invariants. The proofs found a real liveness
defect, supplied a counterexample, and now guard the same modelled state space
in CI. Conventional tests captured the failure at both the arithmetic and
public batch API levels.

The result is not a claim that Hyperlight is mathematically compliant as a
whole. It is a repeatable verification increment: two stated properties, a
confirmed defect and correction, explicit proof boundaries, regression tests,
and continuous checking for the code paths involved.
