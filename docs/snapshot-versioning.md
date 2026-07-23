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
  This is what the host reads back from a snapshot: the `OutBAction`
  and `VmAction` port numbers, the input and output buffer stack
  format, the offset and size of each memory region (including the
  `HyperlightPEB` size), and the calling convention for guest function
  entry. A change to any of these breaks older snapshots unless the
  loader adds a compat path.
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

Each media-type axis is a `_VN` constant with a `_CURRENT` alias. The
writer emits `_CURRENT`. The loader matches each `_VN` explicitly. To
add a version, declare `MT_FOO_V2`, point `MT_FOO_CURRENT` at it, and
add a loader arm that translates the old version or rejects it.

The config blob also records `hyperlight_version`, the `CARGO_PKG_VERSION`
of the host crate at write time. This is informational only. The loader
records it for diagnostics and does not gate loading on it.

## Compatibility cleanup

Record compatibility paths here when a future hard snapshot break can remove
them.

### Original ELF entry point

The persisted `original_entrypoint_addr` field defaults to zero so snapshots
made before it was added remain loadable. At the next hard break, make the
field required, remove `serde(default)`, and reject zero as an invalid entry
point rather than treating it as unknown.

### Missing MSR state

Configs written before MSR capture may omit the `msr_state` object. The loader
represents an omitted object as empty values and an empty allow list, which
restores the destination baseline. A present object requires both `msrs` and
`allowed_msrs`.

At the next hard break, make `msr_state` required and remove its
`serde(default)` missing-field fallback.

## Enforcement

The format is large and easy to change by accident. Two mechanisms
catch a change to it so reviewers do not have to spot every break by
eye, and so a developer who breaks the format unintentionally finds
out at build time rather than in production.

Compile-time tripwires in
[src/hyperlight_host/src/sandbox/snapshot/tripwires.rs](../src/hyperlight_host/src/sandbox/snapshot/tripwires.rs)
hold a copy of every value that defines the format:
`SNAPSHOT_ABI_VERSION`, the snapshot and config media-type strings, the
OCI layout version, the `HyperlightPEB` size, every `OutBAction` and
`VmAction` discriminant, and `BASE_ADDRESS`. If the source value
drifts from the copy in `tripwires.rs`, the crate fails to compile.

The snapshot golden verify test
(`cargo test -p hyperlight-host --test snapshot_goldens`) loads
snapshots from a local directory (populated by `just snapshot-goldens-pull`,
which fetches the tag set for the current `GOLDENS_VERSION` from GHCR)
and runs them through the current loader. If the new loader cannot
decode the old bytes, the test fails.

To run the golden tests locally you need the [`oras`](https://oras.land/docs/installation)
CLI on your `PATH` to pull the published goldens. `just test-like-ci`
does not pull, so fill the local directory first:

```sh
just snapshot-goldens-pull    # fetch this host's goldens from GHCR
just snapshot-goldens-verify  # run them through the current loader
```

Each host verifies only its own `(arch, hypervisor, cpu vendor, profile)`
golden. A missing entry fails the test rather than being skipped.

On a pull request the verify test runs on every supported arch and
hypervisor runner. The default path pulls the published tag set for the
current `GOLDENS_VERSION` and verifies it against the branch's loader. A
pull request that intentionally changes the format takes the labelled
path described in [Breaking the format on a pull request](#breaking-the-format-on-a-pull-request).

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
6. Bump `GOLDENS_VERSION` to the next major. Apply the `regen-goldens`
   label to the pull request so the verify job regenerates against the
   branch. See
   [Breaking the format on a pull request](#breaking-the-format-on-a-pull-request)
   and [Goldens version numbering](#goldens-version-numbering).
7. Add the outgoing version to `COMPAT_VERSIONS` in
   `tests/snapshot_goldens/goldens_version.rs`, so the verify run pulls
   and checks the old goldens through the compatibility path. See
   [Verifying multiple golden versions](#verifying-multiple-golden-versions).

Old snapshots on disk continue to load. New snapshots use the new
contract. The compatibility path becomes part of the supported surface
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
5. Bump `GOLDENS_VERSION` to the next major. Apply the `regen-goldens`
   label to the pull request so the verify job regenerates against the
   branch. See
   [Breaking the format on a pull request](#breaking-the-format-on-a-pull-request)
   and [Goldens version numbering](#goldens-version-numbering).
6. Record the break in `CHANGELOG.md`. Anyone holding old snapshots on
   disk has to regenerate them against the new build.

The loader's single-version check enforces the rejection. An old
snapshot loaded against the new build fails the
`abi_version == SNAPSHOT_ABI_VERSION` test with a clear error.

## Regenerating goldens

The verify test (`cargo test -p hyperlight-host --test snapshot_goldens`)
loads the tag `{GOLDENS_VERSION}-{arch}-{hv}-{cpu}-{profile}` from a
local directory that `just snapshot-goldens-pull` populates from GHCR. A
freshly bumped `GOLDENS_VERSION` has no tags on GHCR until the bump
merges to `main` and the publish workflow runs, so pull requests that
bump the version verify through the `regen-goldens` label instead (see
[Breaking the format on a pull request](#breaking-the-format-on-a-pull-request)).

A snapshot is bound to its CPU vendor. The loader rejects a snapshot
whose `cpu_vendor` differs from the running host, so an Intel golden
loads only on Intel and an AMD golden only on AMD. Each cell publishes
its own per-vendor golden and each host verifies only its own. aarch64
covers Apple under KVM only.

### Iterating locally

`just snapshot-goldens-generate` regenerates the directory for the current
`GOLDENS_VERSION` from the local source, so the verify test runs green
against your in-progress changes on your own platform. Use this loop
for iteration that does not need to cross hypervisor boundaries.
Cross-platform coverage comes from the publish workflow's matrix, which
runs automatically when the bump merges to `main` (see
[Publishing a new version](#publishing-a-new-version)).

### Goldens version numbering

`GOLDENS_VERSION` follows a `vMAJOR.MINOR` scheme. The tag set on GHCR
for a given version is keyed by the full string, so `v1.0`, `v1.1`, and
`v2.0` are independent namespaces that never collide.

* Bump **MAJOR** when the snapshot ABI changes (Option 2 or Option 3
  above). MAJOR tracks `SNAPSHOT_ABI_VERSION`: every format break bumps
  both, so a new MAJOR means the on-disk contract moved and old
  snapshots load through a compatibility path or not at all. The old
  tag set stays on GHCR untouched.
* Bump **MINOR** when the set of golden checks changes but the ABI does
  not (for example, a new check/test is added). The on-disk contract is
  unchanged, so `SNAPSHOT_ABI_VERSION` stays put. The new tag set
  contains every check, including the unchanged ones, regenerated
  against the current source.

`GOLDENS_VERSION` and `SNAPSHOT_ABI_VERSION` are two separate counters
with different purposes. `SNAPSHOT_ABI_VERSION` is the integer stamped into
every snapshot blob, and the loader reads it to decide how to parse the
bytes. `GOLDENS_VERSION` names the published golden tag set on GHCR. A
format break bumps both. A check-set change bumps only
`GOLDENS_VERSION`.

A version is published once, when the bump merges to `main`, and is
frozen from then on. The publish workflow only publishes a version
whose completion marker is absent from GHCR, so a published baseline
cannot be clobbered by a later run. While a developer iterates on a v1
to v2 bump the new version is unpublished, so they verify locally with
`just snapshot-goldens-generate` and the `regen-goldens` label rather
than pushing to GHCR.

The freeze is enforced by the publish workflow's marker check, not by a
registry policy. Each `(hv, cpu, profile)` combination generates its snapshot
and uploads it as a workflow artifact. A single publish job downloads
every artifact, pushes each as its tag, then pushes a
`{version}-complete` marker last. Pushing the whole set from one job
means a partial run leaves no marker, so the next run republishes
rather than freezing an incomplete set. Republishing a complete version
takes a manual dispatch with `force: true`, reserved for recovering a
corrupted push.

### Breaking the format on a pull request

A pull request that bumps `GOLDENS_VERSION` introduces a tag set that
GHCR does not carry yet, so the default pull-and-verify path has nothing
to load. The `regen-goldens` label switches the verify job into
regenerate mode for that pull request.

* **Without the label**, the job pulls the published tag set for the
  current `GOLDENS_VERSION` and verifies it against the branch. Missing
  tags fail the job. This is what turns an accidental format break into
  a red build: the published bytes stop loading, and the author must
  either restructure the change or own the break with the label.
* **With the `regen-goldens` label**, the job generates the current
  golden from the branch source, pulls the `COMPAT_VERSIONS` goldens
  from the registry, and runs both through the branch loader. This
  proves the new format is internally loadable on each runner and that
  every kept old major still loads.

The label is an explicit, reviewable assertion that the format break is
intended. The verify job never regenerates on its own initiative, so a
flaky pull or a mistyped version stays a hard failure rather than
silently degrading into a self-check.

### Publishing a new version

Publishing is automatic. When a bump to `GOLDENS_VERSION` merges to
`main`, the `Regenerate Snapshot Goldens` workflow runs on the push and
publishes the new version's tag set. No manual step is needed, and a
merge that does not change `GOLDENS_VERSION` does not publish (the push
trigger is filtered to the file that holds the version,
`tests/snapshot_goldens/goldens_version.rs`).

The workflow walks every supported `(arch, hypervisor, cpu, profile)`
combination on the self-hosted runner pool, generates the canonical
snapshot with
`cargo test --test snapshot_goldens -- generate <dir>`, and uploads each
OCI layout as a workflow artifact. A single publish job downloads them
all and pushes each with `oras cp` as the tag
`{version}-{arch}-{hv}-{cpu}-{profile}`, then pushes the
`{version}-complete` marker.

A lightweight `check-published` job gates the matrix. It reads `GOLDENS_VERSION`
from source and checks GHCR for the `{version}-complete` marker tag. If
the marker is present the version is fully published and the workflow
stops there, so re-running it, or merging an unrelated change, is a
no-op. The marker is pushed last by the publish job, which runs only
after every matrix job uploaded its snapshot, so a version counts as
published only as a whole set. This makes publishing idempotent, keeps
a complete baseline from being clobbered, and lets a run that follows a
partial push fill in the missing combinations.

The workflow can also be dispatched manually. The `version` input must
equal `GOLDENS_VERSION` in the dispatched ref, which guards against
publishing a tag set the test binary would ignore. A manual dispatch
with `force: true` republishes a version that already exists, reserved
for recovering a corrupted or partial push.

The push-triggered publish closes the window in which a pull request
that bumped the version needs the `regen-goldens` label. Once `main`
carries the bump and the publish lands, new pull requests pass on the
default pull-and-verify path.

### Bootstrapping the first version

The first publish runs through the normal path. The merge that adds
`goldens_version.rs` touches the file the push trigger watches, so the workflow
fires. `check-published` lists GHCR tags for the marker. An empty
registry returns an empty list, so the job publishes. The matrix lands
the first tag set and its marker.

The first `oras` push creates the GHCR package
`ghcr.io/hyperlight-dev/hyperlight-snapshot-goldens` on demand. The
organization must allow the Actions `GITHUB_TOKEN` to create packages.
A cold start that fails here means that setting is off. Turn it on and
re-run.

To seed a version by hand, dispatch the workflow with `force: true` and
a `version` input equal to the `GOLDENS_VERSION` in the dispatched ref.

## Adding a new check under the current ABI

Adding a new entry to `CHECKS` does not change the snapshot ABI. It
does change the set of tags the verify test expects, so it requires a
minor `GOLDENS_VERSION` bump.

Steps:

1. Add the entry to `CHECKS` in
   `src/hyperlight_host/tests/snapshot_goldens/`. Set its
   `since_abi_major`
   to the current `SNAPSHOT_ABI_VERSION`. This records the major the
   check belongs to, so a multi-version run skips it for any golden
   from an earlier major.
2. Bump `GOLDENS_VERSION` minor (e.g. `v1.2` to `v1.3`). The new prefix
   has no published tags, so the default verify path fails until they
   exist.
3. Apply the `regen-goldens` label to the pull request. The verify job
   regenerates the full check set against the branch and runs it back
   through the branch loader. See
   [Breaking the format on a pull request](#breaking-the-format-on-a-pull-request).
4. Once the change lands, the new prefix is published per
   [Publishing a new version](#publishing-a-new-version). The older
   tag set stays on GHCR untouched.

The older minor's tags can be deleted from GHCR once nothing depends
on them.

`since_abi_major` is a major. The verify run loads one golden per major: the
current version and each `COMPAT_VERSIONS` entry. A minor bump
regenerates the current golden, so it holds every check. A compat
golden is a major's final minor, so it holds every check that major
shipped. One golden per major makes major granularity enough.

## Verifying multiple golden versions

The verify test checks every version in its verify set: the current
`GOLDENS_VERSION` plus each entry in `COMPAT_VERSIONS`
(`tests/snapshot_goldens/goldens_version.rs`). `COMPAT_VERSIONS` is
empty under one ABI, so the set is the current version alone. A hard
break (Option 3) leaves it empty, because the new tag set replaces the
old.

A backwards-compatible break (Option 2) keeps an old major loadable, so
you verify it too. Add its version string to `COMPAT_VERSIONS`:

```rust
pub const COMPAT_VERSIONS: &[&str] = &["v1.0"];
```

The verify loop resolves a golden per platform per version, pulls each
through `just snapshot-goldens-pull`, and runs the checks. Each `Check`
records the `SNAPSHOT_ABI_VERSION` it was introduced in through
`since_abi_major`, and the run skips a check whose `since_abi_major` is
newer than the golden's major. A check from a later major stays clear of
an older golden that lacks the state it reads.

Two pieces still need your code when the check set changed since the old
major:

* The loader accepts the old `abi_version` (Option 2 step 4), so the old
  golden loads.
* Register the host functions the old golden's checks call.

