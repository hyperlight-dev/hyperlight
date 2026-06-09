# Hyperlight snapshot on-disk format

Hyperlight serialises a `Snapshot` to disk as an [OCI Image Layout]
directory. `Snapshot::to_oci` writes one. `Snapshot::from_oci` and
`Snapshot::from_oci_unchecked` read one back.

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
    <snapshot-digest>                 raw memory bytes
                                      (`memory_size` bytes)
```

Three blob kinds per tag:

* **manifest** (`application/vnd.oci.image.manifest.v1+json`). Tiny JSON
  pointer record selected via `index.json`. References one config and
  one layer by digest.
* **config** (`application/vnd.hyperlight.snapshot.config.v1+json`). The
  snapshot descriptor: arch, ABI version, entrypoint sregs, memory
  layout, registered host functions, snapshot generation counter.
  Loaded eagerly and fully parsed.
* **layer / memory** (`application/vnd.hyperlight.snapshot.memory.v1`).
  The raw guest memory image, exactly `memory_size` bytes. mmap'd on
  restore.

Blob filenames are the sha256 of the blob bytes, so identical blobs
across tags are stored once.

## What is one snapshot

A single saved `Snapshot` consists of exactly:

* one entry in `index.json`, carrying the `tag` as
  `org.opencontainers.image.ref.name`,
* one **manifest** blob (referenced by that index entry),
* one **config** blob (referenced by the manifest's `config` field),
* one **layer** blob (the only entry in the manifest's `layers`
  array, holding the raw memory image).

Saving two snapshots under different tags into the same `path`
produces two index entries and two manifests. Configs and layers are
deduplicated by content, so identical bytes are stored once and
referenced by both manifests.

Saving the same tag a second time replaces that tag's index entry
and writes a fresh manifest. The previous manifest, and any of its
config or layer blobs that no other tag references, become orphans
in `blobs/sha256/`.

## Write semantics

`Snapshot::to_oci(path, tag)` opens or creates the OCI layout at
`path` and writes one snapshot under `tag`. The parent directory of
`path` must already exist. `path` itself is created if absent. An
existing layout at `path` is preserved: other tags are kept, and a
tag equal to `tag` is replaced.

`index.json` is rewritten via a tmp file plus `rename`, the commit
point for the whole operation. A crash before that rename leaves the
prior layout intact. A crash after it leaves the new layout intact.

Replaced tags leave orphan blobs behind. To compact, remove the
directory and re-save. Concurrent writers to the same `path` are
unsupported.

This mirrors the merge behaviour of `containers/image` (skopeo,
podman), `go-containerregistry` (crane), and `regclient`.

## Read semantics

`Snapshot::from_oci(path, tag)` verifies sha256 for manifest, config,
and snapshot blobs. `Snapshot::from_oci_unchecked` skips the digest
verification, trading integrity for performance, and keeps every
other check (OCI structure, descriptor sizes, schema versions, arch /
hypervisor / ABI tags, layout bounds, entrypoint bounds).

A missing tag or duplicate tag in `index.json` is rejected.

## Portability

Snapshot images are bound to a specific CPU architecture and
hypervisor. Both are recorded in the config blob and checked at load
time, with mismatches rejected with a clear error. The hypervisor
tag (`kvm`, `mshv`, `whp`) constrains the host OS.
