# Hyperlight snapshot on-disk format

Hyperlight serialises a `Snapshot` to disk as an [OCI Image Layout]
directory. `Snapshot::save` writes one. `Snapshot::load` and
`Snapshot::checked_load` read one back.

Only a snapshot taken after the guest has run can be persisted. Such a
snapshot carries the captured vCPU registers needed to resume a call.
`Snapshot::save` rejects a pre-init snapshot.

`Snapshot::compact(None)` packs live memory pages into a single layer.
`Snapshot::compact(Some(&base))` retains referenced immutable layers identical
to the base and packs other live pages into at most one new layer. Base matching
uses the layer's address, geometry, and complete blob contents, so a separately
loaded base works too. The base must have the same memory layout.

Compaction leaves its inputs unchanged and preserves execution state, metadata,
transport state, page-table topology, and cached hashes of retained layers.
Repacked memory gets a fresh hash on its first ordinary save.
Packed layers are placed to preserve the loader's guest-code GPA-span bound
without keeping unused code bytes. If retained base layers alone fall short
and all live pages are already retained, one zero-filled host page supplies
the required span.
It does not change the file format:
save and restore the result normally. Saving includes every required blob,
including preserved base blobs; omitting or sharing those blobs during transport
is the caller's responsibility. Compaction copies live non-base pages and is
explicit rather than automatically performed on every snapshot.

[OCI Image Layout]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md

## Directory layout

```text
path/
  oci-layout                          {"imageLayoutVersion":"1.0.0"}
  index.json                          one manifest descriptor per tag,
                                      tagged via the OCI standard
                                      `org.opencontainers.image.ref.name`
                                      annotation
  blobs/sha256/
    <manifest-digest>                 OCI image manifest JSON
    <config-digest>                   Hyperlight config JSON
    <data-digest>                     one raw blob per snapshot blob:
                                      guest data, then page tables
```

Three blob kinds per tag:

* **manifest** (`application/vnd.oci.image.manifest.v1+json`). Tiny JSON
  pointer record selected via `index.json`. References one config and the
  snapshot blobs by digest.
* **config** (`application/vnd.hyperlight.snapshot.config.v7+json`). The
  snapshot descriptor: arch, hypervisor, CPU vendor, ABI version,
  resume address and captured registers, memory and transport layout,
  registered host functions, the start address, data length, and page-table
  length of each blob, the blob with the page tables for a restore, snapshot
  generation counter, and namespaced application metadata.
  Loaded eagerly and fully parsed.
* **layers / data** (`application/vnd.hyperlight.snapshot.memory.v2`).
  One raw, host-page-aligned blob per snapshot blob, in config order. Each
  blob holds guest data followed by the page-table tree of the snapshot that
  created it. Each blob is mmap'd on restore, and the guest maps only its
  data.

The runtime queue protocol and snapshot bootstrap state are described in
[Virtqueue host and guest communication](./virtio-host-guest-communication.md).

Manifest layers follow the config's snapshot blob order.

Blob filenames are the sha256 of the blob bytes, so identical blobs
across tags are stored once.

### Immutable blob reuse

`Snapshot::save` caches each shared memory layer's SHA-256. Existing regular
blob files with the expected length are trusted by their content-addressed
filenames without reading or hashing their contents, even at a new destination.
There is no backing-file cache. Missing blobs are written atomically; symlinks
and wrong-length files are replaced.
`Snapshot::checked_load` seeds the verified digest cache; ordinary `load`
retains declared digests separately for reuse on save without hashing memory.
Metadata blobs retain their normal write path.

`base.checked_load_overlay(path, reference)` resolves memory layers from an existing base
when their cached SHA-256, size, GPA and data/page-table geometry match. It shares
the base's layer objects without opening or reading those files from the new
layout; the matching files may be omitted. Other blobs are verified normally.
This is explicit content resolution from the supplied base, not validation of
an on-disk copy of a reused blob. Retaining the same objects through restore,
capture and base-preserving compaction avoids both byte comparisons and repeated
hashing of immutable base memory.

`Snapshot::load` trusts declared memory digests without reading memory to verify
them. Ordinary saves preserve those declarations, and
`base.load_overlay(path, reference)` resolves matching layers
by digest and geometry. Declared hashes are stored separately from computed or
verified hashes: checked base loading never reuses a mere declaration, and
checked saving still hashes every layer. This changes prior ordinary
`load`-then-`save` behavior: it preserves declared digests instead of computing
them from actual bytes, including when the declared digest is incorrect.
Structural validation remains enabled in all modes. A declaration is neither
content authentication nor permission to read another actor's memory; callers
must restrict base sharing to authorized, immutable objects. Incorrect digests
can substitute guest state or publish bytes under an incorrect name.

Both overlay methods require persisted provenance declaring the supplied whole
snapshot as a base; a matching memory layer alone is insufficient. Each new VM
snapshot has a stable UUID stored as `snapshot_id` in the OCI config, with
ancestor IDs in `bases`. Metadata-only copies retain the VM snapshot's ID.
Restore/capture inherits the restored snapshot and its bases, including without
compaction. `compact(Some(base))` replaces the target's history with the specified
base's inherited bases plus the base itself; `compact(None)` clears all bases.
Neither operation retains unused layers merely to establish provenance.
Provenance is carried by the whole `SnapshotMemory` object, not individual
blobs, so capture inherits it directly from the existing memory backing.

Uncompacted captures can grow ancestry even without adding memory layers.
Periodically compact without a base to reset it, or compact against a fixed
base with a short ancestry list to retain that base without accumulating the
target's checkpoint history. Both operations can recover save capacity after
ancestry exceeds the config JSON size limit.

These IDs are trusted declarations, not content digests or cryptographic proofs
of ancestry, even with checked loading. Legacy v6 configs without provenance still
load standalone, receiving a new in-memory ID. Save that base to persist its ID
before relying on independently loaded copies for overlay. A layout without a
matching base declaration cannot be overlaid.

Callers must keep loaded and published memory blobs immutable for the lifetime
of these snapshots and outside writable guest mounts. Host-side mutation and
silent storage corruption are outside the save-time threat boundary. Saving
does not detect same-length corruption; use `Snapshot::checked_load` to verify
persisted contents explicitly.

`Snapshot::checked_save` takes the fully verifying path: it recomputes all
memory-layer digests without using the cache and hashes existing memory blob
files before reusing them. Mismatched contents are atomically replaced from
the snapshot's memory. It otherwise has the same layout and tag semantics as
`save`. This is not protection against concurrent modification of loaded
backing files, which must remain immutable while snapshots use them.

## Application metadata

`Snapshot::with_metadata` creates a snapshot that shares the source snapshot's
sandbox state and stores a serializable value under an application-owned
namespace. `Snapshot::metadata` deserializes the value for that namespace.
The source snapshot remains unchanged.

Metadata is stored in the config blob as a JSON object with namespaces as
keys. Snapshots without metadata omit the field. The loader treats a missing
field as an empty map, so snapshots written before metadata support remain
loadable. Metadata counts toward the config blob size limit.

## Transport initialization

The config stores queue sizes, buffer sizes, pool sizes, and scratch geometry.
Loading validates this layout and generates empty G2H and fully prefilled H2G
bootstrap images. The snapshot ABI defines their initialization rules.

Ring images stay cached in memory for bulk-copy restore. Retained payloads
are stored in ordinary memory layers through their guest aliases.

## What is one snapshot

A single saved `Snapshot` consists of exactly:

* one entry in `index.json`, carrying the `tag` as
  `org.opencontainers.image.ref.name`, plus advisory
  `dev.hyperlight.snapshot.arch`,
  `dev.hyperlight.snapshot.hypervisor`, and
  `dev.hyperlight.snapshot.cpu.vendor` annotations that mirror the
  config blob for tooling visibility,
* one **manifest** blob (referenced by that index entry),
* one **config** blob (referenced by the manifest's `config` field),
* one or more data **layer** blobs.

Saving two snapshots under different tags into the same `path`
produces two index entries and two manifests. Configs and layers are
deduplicated by content, so identical bytes are stored once and
referenced by both manifests.

Saving the same tag a second time replaces that tag's index entry
and writes a fresh manifest. The previous manifest, and any of its
config or layer blobs that no other tag references, become orphans
in `blobs/sha256/`.

## Write semantics

`Snapshot::save(path, tag)` opens or creates the OCI layout at
`path` and writes one snapshot under `tag`, an [`OciTag`] whose
grammar is validated when it is parsed. It returns the manifest
descriptor digest as an [`OciDigest`], a content address that selects
the written manifest on a later load. The parent directory of `path`
must exist. `path` itself is created if absent. An existing
layout at `path` is preserved: other tags are kept, and a tag equal
to `tag` is replaced.

[`OciTag`]: https://docs.rs/hyperlight-host/latest/hyperlight_host/sandbox/snapshot/struct.OciTag.html
[`OciDigest`]: https://docs.rs/hyperlight-host/latest/hyperlight_host/sandbox/snapshot/struct.OciDigest.html

`index.json` is rewritten via a tmp file plus `rename`, the commit
point for the whole operation. Concurrent readers observe either the
prior layout or the new one, never a partial write. Saving does not
call `fsync` on files or directories. Power-loss durability is the
caller's responsibility: sync all referenced blob files and layout
metadata, then sync the directory hierarchy bottom-up: `blobs/sha256`,
`blobs`, the layout root, and the layout's existing parent directory.
This also persists the directory entries that make a newly created layout
reachable. If the caller created additional ancestor directories, continue
upward through their first previously durable ancestor.

Replaced tags leave orphan blobs behind. To compact, remove the
directory and re-save. Concurrent writers to the same `path` are
unsupported.

This mirrors the merge behaviour of `containers/image` (skopeo,
podman), `go-containerregistry` (crane), and `regclient`.

## Read semantics

`Snapshot::load(path, reference)` reads a snapshot. It does not check
the manifest, config, or data blobs against their sha256 digests.
It retains declared memory digests for ordinary saves; `load_overlay` also
shares matching layers from an explicitly supplied, authorized base.
`reference` is an
[`OciReference`], either a tag that matches the
`org.opencontainers.image.ref.name` annotation or the manifest
digest returned by `save`. `Snapshot::checked_load` adds the digest
check on every blob, catching accidental corruption on disk.
Both run every other check (OCI structure, descriptor sizes, schema
versions, arch / hypervisor / CPU vendor / ABI tags, layout bounds,
entrypoint bounds). The caller is responsible for trusting the source.

A reference that matches no manifest, or a tag that matches more than
one manifest in `index.json`, is rejected.

[`OciReference`]: https://docs.rs/hyperlight-host/latest/hyperlight_host/sandbox/snapshot/enum.OciReference.html

## Portability

Snapshot images are bound to a specific CPU architecture, hypervisor,
and CPU vendor. All three are recorded in the config blob and checked
at load time, with mismatches rejected with a clear error. The
hypervisor tag (`kvm`, `mshv`, `whp`) constrains the host OS. The CPU
vendor is the x86_64 CPUID leaf-0 vendor string (e.g. `GenuineIntel`)
or the aarch64 `MIDR_EL1` implementer byte. A load on a different
vendor is rejected because the resumed CPU state can be incompatible.
A future version may relax this binding once a wider compatibility set
is proven safe.
