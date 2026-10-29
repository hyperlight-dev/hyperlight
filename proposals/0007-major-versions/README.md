# HIP 0007 - Major Versions

## Elevator pitch

We are proposing the acceptance criteria for Hyperlight to reach 1.0 status, what
major versions mean for Hyperlight, as well as discuss the process for future
major Hyperlight releases.

## Status quo

Hyperlight is currently at version 0.18.0, with monthly releases happening and
every release including breaking changes. While we do try and minimize the
breakage by deprecating APIs before we remove them entirely, we still cannot
guarantee that users can always upgrade from one version to another.

Versions also carry a social signal. When a project is "pre-1.0" that tends to
imply it is unstable, experimental, or "beta"-quality. We have heard this from
multiple potential users. Though whether this perspective is justified is a
separate discussion.

## What we propose to do about it

We're proposing for Hyperlight to reach 1.0 status and start making API
compatibility guarantees between versions. Within a major version, minor and
patch releases will preserve compatibility for stable public APIs in the host
and guest crates. Upgrading may require rebuilding guest binaries and
regenerating snapshots, but should not require source changes.

What is explicitly excluded from the stability guarantees however is ABI
stability. When upgrading from one minor version to another (e.g. 1.0.0 to 1.1.0)
users will be expected to recompile their guest binaries and regenerate
snapshots. This is necessary to allow Hyperlight to keep evolving the guest-host
communication boundary.

Hyperlight 1.0.0 will not be the last major version we're releasing either. On
some cadence, possibly ~yearly, we will be releasing new major versions of
Hyperlight. This gives us an opportunity to make breaking changes to the API as
needed, for example to add multi-threading support to Hyperlight. This HIP does
not lock us into any specific cadence, all it declares is the intent to release
new major versions beyond 1.0.0.

## Implementation details and plan

### Requirements

There are six areas of work we need to finish before shipping Hyperlight 1.0:

* **aarch64 support:** support ARM64 on macOS, Linux, and Windows, with guest
  crashdumps on at least Linux.
* **Snapshot-based lifecycle:** finish the snapshot-first lifecycle, including
  creating sandboxes from snapshots and persisting snapshots to disk.
* **IO queue support:** finish integrating packed virtqueues for guest-host IO,
  including their behavior across snapshot and restore, and validate the design
  by integrating it in hyperlight-wasm.
* **Transport refactor:** finish replacing Flatbuffers with a Serde-based
  encoding, keeping serialization details out of the public API.
* **Security, testing, & fuzzing:** complete a security review, address
  release-blocking findings, and cover the new IO and snapshot paths with tests
  and fuzzing.
* **Public API:** remove deprecated APIs and review the host and guest interfaces
  for consistency before committing to supporting them throughout 1.x.

All of these items will be tracked separately in Hyperlight, and some may even
require their own follow-up proposals.

### Release Process

The release itself should be relatively straight-forward. If we do things right,
it shouldn't be too different from most other releases. With the sole exception
that we'll probably want to write a slightly larger release post instead of our
usual one.

Depending on the timing we may want to time the release alongside a CNCF/LF
event, to try and create a moment. However, that shouldn't come at the cost of
quality and readiness, so this is an opportunity only.

### Guaranteeing compatibility

We're already quite careful in how we replace APIs. However, we might want to
take extra care by introducing additional guard rails by for example running
[cargo semver-checks](https://github.com/obi1kenobi/cargo-semver-checks) in CI.
Native guest binaries and snapshots must match the exact Hyperlight version
they run on, including the patch version. We should version-tag both and reject
mismatches explicitly, guarding against ABI compatibility assumptions across
versions (see also: [hyrum's law](https://www.hyrumslaw.com/)).

We'll want to think about all the ways to ensure we can guarantee stability,
while also ensuring we keep the flexibility in all the places we do want it.
And of course also clearly documenting what we do and don't guarantee.

## Frequently Asked Questions

### Why not commit to ABI stability?

Because we've seen what happens when you do. C++ has effectively frozen its ABI,
and it's been paying for it ever since. `std::regex` is famously slow and can't
be fixed, `std::unique_ptr` can't be passed in a register, and when `std::string`
needed to change in C++11 it took a split "dual ABI" in libstdc++ and years of
pain to roll out. Titus Winters' paper
[*ABI: Now or Never*](https://wg21.link/p1863) lays this out well: once you promise
ABI stability, every past mistake becomes permanent. We don't want that for
Hyperlight, especially not while the guest-host boundary is still moving.

So instead we only promise API stability. If you upgrade from 1.0 to 1.1 you'll
need to recompile your guests and regenerate your snapshots, but you shouldn't
need to change any code. Guests targeting WebAssembly through `hyperlight-wasm`
can retain their Wasm binaries across Hyperlight upgrades. The native runtime
still needs to be rebuilt, and any Hyperlight snapshots regenerated.

### Why are you planning to release more major versions?

Because 1.0 isn't the end. It means we're happy enough with the API to commit to
it, not that we think we got everything right. There are things we already know
we want that won't fit in the current design. Multi-threading is the obvious
one: a lot of today's APIs assume a single guest thread, and changing that is
going to break things.

Major versions give us a place to put those changes. Minor releases stay boring
and compatible, and breaking changes get batched up and shipped together when
there's a good reason to. That might be yearly, it might be less often. What we
don't want is to end up stuck with a 1.0 we can never move away from.

### What does Hyperlight 1.0 mean for Guests?

What we're proposing here only affects the `hyperlight-dev/hyperlight` crates.
Hyperlight Wasm, Hyperlight Unikraft, and all other guests are not required to
reach 1.0 status when Hyperlight does. Though a follow-up goal will of course be
to have those reach 1.0 status too.
