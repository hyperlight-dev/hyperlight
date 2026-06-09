# Snapshot versioning

Hyperlight snapshots are written to disk as OCI image layouts and may be
loaded by a different build than the one that produced them. This
document describes how to evolve the snapshot format while keeping
existing snapshots loadable, or while rejecting them with a clear error.

## What is versioned

A snapshot carries three independently evolvable version markers:

* **Memory blob ABI**, `SNAPSHOT_ABI_VERSION` (a `u32` inside the
  config blob, defined in
  [src/hyperlight_host/src/sandbox/snapshot/file/media_types.rs](../src/hyperlight_host/src/sandbox/snapshot/file/media_types.rs)).
  This is the host/guest runtime contract baked into the captured
  memory: the `HyperlightPEB` layout (the struct host and guest share
  to exchange state, field offsets and types), the `OutBAction` port
  numbers (the I/O ports the guest writes to for `Log`, `CallFunction`,
  `Abort`, `DebugPrint`), the layout of the sandbox memory regions
  (stack, heap, guest binary, input and output buffers, page tables),
  and the calling convention used for guest function entry. The loader
  trusts the captured bytes to match this contract, so any change here
  invalidates older snapshots unless an explicit compat path translates
  them.
* **Snapshot blob encoding**, `MT_SNAPSHOT_V1`
  (`application/vnd.hyperlight.snapshot.memory.v1`), aliased as
  `MT_SNAPSHOT_CURRENT`. This is the on-wire format of the snapshot
  blob: framing, section ordering, alignment, dirty/zero-page elision,
  anything about how the bytes are packed inside the OCI layer.
* **Config schema**, `MT_CONFIG_V1`
  (`application/vnd.hyperlight.snapshot.config.v1+json`), aliased as
  `MT_CONFIG_CURRENT`. This is the JSON shape of the config blob:
  field names, types, required vs optional, the descriptors the loader
  needs in order to reconstruct the sandbox (memory sizes, buffer
  sizes, `abi_version`, `hyperlight_version`, etc.). Renaming a field,
  changing its type, or adding a required field is a schema change and
  bumps this constant.

The `OCI_LAYOUT_VERSION` constant is pinned by the OCI image-layout
spec at `1.0.0`.

The config blob also records `hyperlight_version`, the `CARGO_PKG_VERSION`
of the host crate at write time. This is informational only. The loader
records it for diagnostics and does not gate loading on it.

## Enforcement

The format is large and easy to change by accident. Two mechanisms
catch a change to it so reviewers do not have to spot every break by
eye, and so a developer who breaks the format unintentionally finds
out at build time rather than in production.

Compile-time tripwires in
[src/hyperlight_host/src/sandbox/snapshot/tripwires.rs](../src/hyperlight_host/src/sandbox/snapshot/tripwires.rs)
hold a copy of every value that defines the format:
`SNAPSHOT_ABI_VERSION`, the snapshot and config media-type strings, the
OCI layout version, every `HyperlightPEB` field offset and the struct's
total size, and every `OutBAction` discriminant. If the source value
drifts from the copy in `tripwires.rs`, the crate fails to compile.

The snapshot golden verify test
(`cargo test -p hyperlight-host --test snapshot_goldens`) loads
snapshots from a local cache (populated by `just snapshot-goldens-pull`,
which fetches the tag set for the current `GOLDENS_VERSION` from GHCR)
and runs them through the current loader. If the new loader cannot
decode the old bytes, the test fails.

## Changing the format

When you change anything on the list above, you have three options.

### Option 1: avoid the break

Restructure the change so the on-disk contract stays put. Prefer this
whenever possible.

### Option 2: backwards-compatible break

You break the ABI for new snapshots, and you teach the loader to
accept the older version as well by translating it into the current
contract on the fly. For example, if you renumber the `OutBAction`
ports, the host's port dispatch keeps a match arm for the old port
number alongside the new one, so a resumed v1 guest that still writes
to the old port is handled correctly.

Steps:

1. Make the source change.
2. Update `Snapshot::to_oci` to write the new format.
3. Bump `SNAPSHOT_ABI_VERSION`. The writer stamps this value into
   every config blob it produces.
4. Update `Snapshot::from_oci` to load both the old and the new
   format, dispatching on `abi_version`.
5. Update the tripwire assertions in `tripwires.rs` and any affected
   tests to match the new values.
6. Bump `GOLDENS_VERSION` to the next major and push fresh goldens. See
   [Goldens version numbering](#goldens-version-numbering) and
   [Regenerating goldens](#regenerating-goldens).
7. Keep the old goldens on GHCR and extend the verify test to exercise
   them as well, so the compatibility path stays covered. See
   [Verifying multiple golden versions](#verifying-multiple-golden-versions).

Old snapshots on disk continue to load. New snapshots use the new
contract. The compatibility path is now part of the supported surface
and must stay correct until you formally drop the old major.

### Option 3: hard break

You change the contract and the loader rejects old snapshots outright.
Using the same `OutBAction` example, the host's port dispatch only
matches on the new port number, and a resumed v1 guest writing to the
old port has nowhere to land.

Steps:

1. Make the source change.
2. Update `Snapshot::to_oci` to write the new format.
3. Bump `SNAPSHOT_ABI_VERSION`.
4. Update the tripwire assertions in `tripwires.rs` and any affected
   tests to match the new values.
5. Bump `GOLDENS_VERSION` to the next major and push fresh goldens. See
   [Goldens version numbering](#goldens-version-numbering) and
   [Regenerating goldens](#regenerating-goldens).
6. Record the break in `CHANGELOG.md`. Anyone holding old snapshots on
   disk has to regenerate them against the new build.

The loader's single-version check enforces the rejection. An old
snapshot loaded against the new build fails the
`abi_version == SNAPSHOT_ABI_VERSION` test with a clear error.

## Regenerating goldens

The verify test (`cargo test -p hyperlight-host --test snapshot_goldens`)
loads the tag set `{GOLDENS_VERSION}-{hv}-{cpu}-{profile}-{kind}` from a
local cache that `just snapshot-goldens-pull` populates from GHCR. After
bumping `GOLDENS_VERSION`, the matching tags must be pushed before the
verify job can pass.

### Iterating locally

`just snapshot-goldens-generate` regenerates the cache for the current
`GOLDENS_VERSION` from the local source, so the verify test runs green
against your in-progress changes on your own platform. Use this loop
for iteration that does not need to cross hypervisor boundaries. To
validate the change on every platform, dispatch the regen workflow
(see [Push procedure](#push-procedure)).

### Goldens version numbering

`GOLDENS_VERSION` follows a `vMAJOR.MINOR` scheme. The tag set on GHCR
for a given version is keyed by the full string, so `v1.0`, `v1.1`, and
`v2.0` are independent namespaces that never collide.

* Bump **MAJOR** when the snapshot ABI changes (Option 2 or Option 3
  above). The old tag set stays on GHCR untouched.
* Bump **MINOR** when the set of golden checks changes but the ABI does
  not (for example, a new check is added). The new tag set contains
  every check, including the unchanged ones, regenerated against the
  current source.

A version is frozen once `main` references it. The regen workflow,
before every push, reads `GOLDENS_VERSION` from the tip of `main` and
refuses to push to that tag. Any other tag, including the version the
current PR is introducing, is in-flight and may be overwritten freely.
This lets a developer iterate on a v1 to v2 bump by pushing v2 as many
times as needed, with no risk of touching v1.

Overwriting a tag leaves the previous manifest on GHCR as an orphan.
A scheduled cleanup workflow that reaps orphans and abandoned in-flight
tags is a follow-up.

### Push procedure

1. Land the source bumps on a branch.
2. Dispatch the `Regenerate Snapshot Goldens` workflow against that
   branch. The workflow walks every supported
   `(hypervisor, cpu, profile)` combination on the self-hosted runner
   pool, generates the canonical init and call snapshots locally with
   `cargo test --test snapshot_goldens -- generate <dir>`, and pushes
   each OCI layout to GHCR using `oras copy`. Before every push it
   reads `GOLDENS_VERSION` from the tip of `main` and refuses the push
   if the target tag matches.
3. The verify job on the PR can now find the tags and passes.

The workflow takes a `version` input that must equal `GOLDENS_VERSION`
in source. This guards against pushing a tag set the test binary would
ignore.

## Adding a new check under the current ABI

Adding a new entry to `CHECKS` does not change the snapshot ABI. It
does change the set of tags the verify test expects, so it requires a
minor `GOLDENS_VERSION` bump.

Steps:

1. Add the entry to `CHECKS` in
   `src/hyperlight_host/tests/snapshot_goldens/`.
2. Bump `GOLDENS_VERSION` minor (e.g. `v1.2` to `v1.3`). The verify
   test now looks for tags under the new prefix and fails until they
   exist.
3. A maintainer dispatches `Regenerate Snapshot Goldens` against the
   branch with `version` set to the new `GOLDENS_VERSION`. The workflow
   runs every check on every combination and publishes a complete tag set
   under the new prefix. The previous tag set stays on GHCR untouched.
4. The verify job finds the new tag set and passes.

The previous minor's tags can be deleted from GHCR once nothing depends
on them.

## Verifying multiple golden versions

The verify test pulls exactly one tag set, the one for the current
`GOLDENS_VERSION`. That covers the hard-break case (Option 3), where a
fresh tag set replaces the previous one.

The backwards-compatible case (Option 2) needs more. A v1 loader path
is only correct if real v1 goldens load against the new build, which
means verifying against multiple versions in the same run.

The intended design is to replace the single `GOLDENS_VERSION` constant
with a slice of currently supported major versions, e.g.
`pub const GOLDENS_VERSIONS: &[&str] = &["v1.3", "v2.0"];`, and have
the verify test run every check against every entry. Dropping an old
major is then a one-line removal from that slice.

The single-version variant suffices for Option 3. Build the
multi-version variant the first time you take Option 2.
