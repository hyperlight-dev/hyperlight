# Hyperlight snapshot on-disk format

Hyperlight serialises a `Snapshot` to disk as an [OCI Image Layout]
directory. `Snapshot::save` writes one. `Snapshot::load` and
`Snapshot::checked_load` read one back.

Only a snapshot taken after the guest has run can be persisted. Such a
snapshot carries the captured vCPU registers needed to resume a call.
`Snapshot::save` rejects a pre-init snapshot.

Each immutable snapshot blob is stored in one OCI layer. Related snapshots can
share layer files.

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
    <layer-digest>                    raw immutable snapshot blob
```

Three blob kinds per tag:

* **manifest** (`application/vnd.oci.image.manifest.v1+json`). Tiny JSON
  pointer record selected via `index.json`. References one config and ordered
  layers by digest.
* **config** (`application/vnd.hyperlight.snapshot.config.v2+json`). The
  snapshot descriptor. Records host compatibility, resume state, memory layout,
  layer metadata, host functions, and snapshot generation.
* **layer / memory** (`application/vnd.hyperlight.snapshot.memory.v2`).
  Stores one immutable blob. Each file contains memory data, optional page
  tables, and alignment padding.

Blob filenames are the sha256 of the blob bytes, so identical blobs
across tags are stored once.

`Snapshot::save` writes config and memory media type v2 with snapshot ABI 3.
The load methods also accept v1 config and memory media types with ABI 2. A v1
snapshot has one flat memory layer. The loader represents it as one current
snapshot layer. Config and memory media type versions must match.

Config entry `layers[n]` describes manifest layer `n`:

* `data`, an optional guest physical address and length.
* `live_data`, the blob ranges mapped into the guest.
* `page_tables`, an optional page-table range.

The corresponding manifest descriptor's `size` is the layer file size.
`host_page_size` defines layer alignment. `active_page_table_layer` selects
the page tables restored into scratch. Only `live_data` is mapped. Each blob's
guest physical address range stays reserved.

## What is one snapshot

A saved `Snapshot` consists of:

* one entry in `index.json`, carrying the `tag` as
  `org.opencontainers.image.ref.name`, plus advisory
  `dev.hyperlight.snapshot.arch`,
  `dev.hyperlight.snapshot.hypervisor`, and
  `dev.hyperlight.snapshot.cpu.vendor` annotations that mirror the
  config blob for tooling visibility,
* one **manifest** blob (referenced by that index entry),
* one **config** blob (referenced by the manifest's `config` field),
* one ordered **layer** blob per immutable snapshot blob.

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
prior layout or the new one, never a partial write. Power-loss
durability is the caller's responsibility: add `fsync` on the file
and parent directory if a crash must not lose a committed tag.

Replaced tags leave orphan blobs behind. To compact, remove the
directory and re-save. Concurrent writers to the same `path` are
unsupported.

This mirrors the merge behaviour of `containers/image` (skopeo,
podman), `go-containerregistry` (crane), and `regclient`.

## Read semantics

`Snapshot::load(path, reference)` reads a snapshot. It does not check
the manifest, config, or layer blobs against their sha256 digests.
`reference` is an
[`OciReference`], either a tag that matches the
`org.opencontainers.image.ref.name` annotation or the manifest
digest returned by `save`. `Snapshot::checked_load` checks every referenced
blob, catching accidental corruption on disk.
Both run every other check (OCI structure, descriptor sizes, schema
versions, arch / hypervisor / CPU vendor / ABI tags, layout bounds,
entrypoint bounds). The caller is responsible for trusting the source.

A reference that matches no manifest, or a tag that matches more than
one manifest in `index.json`, is rejected.

[`OciReference`]: https://docs.rs/hyperlight-host/latest/hyperlight_host/sandbox/snapshot/enum.OciReference.html

## Portability

Snapshot images are bound to a CPU architecture, hypervisor, CPU vendor, and
host page size. The config records these values. Loading rejects mismatches. The
hypervisor tag (`kvm`, `mshv`, `whp`) constrains the host OS. The CPU
vendor is the x86_64 CPUID leaf-0 vendor string (e.g. `GenuineIntel`)
or the aarch64 `MIDR_EL1` implementer byte. A load on a different
vendor is rejected because the resumed CPU state can be incompatible. Layer
alignment depends on the host page size.
A future version may relax this binding once a wider compatibility set
is proven safe.
