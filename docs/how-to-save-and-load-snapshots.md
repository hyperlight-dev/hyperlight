# Saving, loading and distributing snapshots

A snapshot saves guest memory and CPU state as an OCI image layout.

## Save and load

Use `hyperlight-host`, a supported hypervisor and your
[guest binary](./how-to-build-a-hyperlight-guest-binary.md).
This example assumes `guest.bin` exports `Echo(String) -> String`.

```rust
use std::sync::Arc;

use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::SandboxBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut sandbox = SandboxBuilder::from_file("guest.bin").build()?;
    let _: String = sandbox.call("Echo", "hello".to_string())?;

    let snapshot = sandbox.snapshot()?;
    let tag = OciTag::new("v1")?;
    let digest = snapshot.save("./snapshot", &tag)?;

    let loaded = Arc::new(Snapshot::checked_load("./snapshot", digest)?);
    let mut restored = SandboxBuilder::from_snapshot(loaded).build()?;
    let reply: String = restored.call("Echo", "hello again".to_string())?;
    println!("{reply}");
    Ok(())
}
```

* The layout's parent directory must exist. Saving replaces the selected tag
  and keeps other tags.
* Load by tag or by the manifest digest returned by `save`.
* `checked_load` verifies blob digests. `load` skips digest verification.
  Both check format and platform compatibility. Trust the publisher.
  Digests do not prove authenticity.
* Keep loaded blob files unchanged until the snapshot and any restored
  sandboxes are dropped.
* Supply every host callback registered at capture, with matching names and
  signatures. Use `SandboxBuilder::host_function` for capture and restore.
* Use the builder for runtime settings such as host functions, log level, and
  mapped files. Scratch size and transport settings come from the snapshot.
* Loading needs the saved layout, not the original guest binary.

## Push and pull

Use any OCI registry and a client that supports OCI image layouts.
These examples use [ORAS](https://oras.land/docs/installation) and GHCR.
Replace `ghcr.io/OWNER/snapshot` with your registry and repository:

```sh
oras login ghcr.io
```

### Push

Upload the saved layout to the registry:

```sh
oras cp --from-oci-layout ./snapshot:v1 ghcr.io/OWNER/snapshot:v1
```

### Pull

Download the snapshot into a separate local layout:

```sh
oras cp --to-oci-layout ghcr.io/OWNER/snapshot:v1 ./downloaded-snapshot:v1
```

Load `./downloaded-snapshot` with `OciTag::new("v1")?`.
To pin the registry source by digest, replace `ghcr.io/OWNER/snapshot:v1` with
`ghcr.io/OWNER/snapshot@sha256:DIGEST`.

## Portability

The loading host must match the snapshot's CPU architecture (e.g. x86_64 or
aarch64), hypervisor (e.g. KVM, MSHV or WHP) and CPU vendor (e.g. Intel, AMD or
Apple). Forward and backward compatibility across Hyperlight versions is not
guaranteed.

See the [runnable example](../src/hyperlight_host/examples/snapshot/main.rs),
[format reference](./snapshot-oci-format.md) and
[versioning rules](./snapshot-versioning.md).
