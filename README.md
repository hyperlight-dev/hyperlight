<div align="center">
    <h1>Hyperlight</h1>
    <img src="https://raw.githubusercontent.com/hyperlight-dev/hyperlight/refs/heads/main/docs/assets/hyperlight-logo.png" width="150px" alt="hyperlight logo"/>
    <p>
        <strong>A lightweight VMM for running untrusted code in micro VMs with minimal overhead.</strong><br>
        A <a href="https://www.cncf.io/projects/hyperlight/">Cloud Native Computing Foundation</a> sandbox project.
    </p>
</div>

Hyperlight lets you safely run untrusted code inside hypervisor-isolated micro VMs that spin up in milliseconds, with guest function calls completing in microseconds. You embed it as a library in your Rust application, hand it a guest binary, and call functions across the VM boundary as naturally as calling a local function. To minimize startup time and memory footprint, there's no guest kernel or OS. Guests are purpose-built using the Hyperlight guest library.

- Supports [KVM](https://linux-kvm.org/page/Main_Page), [MSHV](https://github.com/rust-vmm/mshv), and [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/#windows-hypervisor-platform)
- No kernel or OS in the VM. Guests are regular ELF binaries written in `no_std` Rust or C
- Host and guest communicate through typed function calls
- Guests are sandboxed by default with no access to the host filesystem, network, etc.

## How it works

**Host** - create a sandbox, register a host function, and call into the guest:

```rust
// Create an uninitialized sandbox by giving it the path to a guest binary.
// Allocates memory but does not yet run a VM.
let mut sandbox = UninitializedSandbox::new(GuestBinary::FilePath(guest_path), None)?;

// Register a host function that the guest can call. In a real app this
// might query a database, read a config, or call an external API.
// By default, guests can only print to the host.
sandbox.register("GetWeekday", || Ok("Wednesday".to_string()))?;

// Initialize the sandbox. Starts the VM and runs guest setup code.
let mut sandbox: MultiUseSandbox = sandbox.evolve()?;

// Call a function inside the VM
let greeting: String = sandbox.call("SayHello", "World".to_string())?;
println!("{greeting}"); // "Hello, World! Today is Wednesday."
```

Guest state persists across calls. Use `snapshot()` and `restore()` to save and reset VM memory. This avoids recreating the VM while ensuring each call starts from a clean state.

**Guest** (Rust) - declare host functions and expose guest functions with simple macros. Guests can also be [written in C](./src/hyperlight_guest_capi).

```rust
#[host_function("GetWeekday")]
fn get_weekday() -> Result<String>;

#[guest_function("SayHello")]
fn say_hello(name: String) -> Result<String> {
    let weekday = get_weekday()?;
    Ok(format!("Hello, {name}! Today is {weekday}."))
}
```

To get started, see the [Getting Started](./docs/getting-started.md) guide. For more details on writing guests, see [How to build a Hyperlight guest binary](./docs/how-to-build-a-hyperlight-guest-binary.md).

## When to use Hyperlight

Hyperlight is a good fit when you need to:

- Run untrusted or third-party code with hypervisor-level isolation
- Create and tear down sandboxes in ~1-2ms
- Make guest function calls with microsecond-level overhead
- Embed sandboxed execution directly in your application
- Build functions-as-a-service with hypervisor-level isolation
- Run lightweight, purpose-built guest programs
- Reuse sandboxes efficiently with snapshot and restore

Hyperlight is *not* designed for:

- General-purpose virtualization (use a full VMM instead)
- Running full-blown Linux guest workloads that need syscalls, networking, or filesystem access

## Getting started

See [docs/getting-started.md](./docs/getting-started.md) for detailed prerequisites and platform-specific setup for:
- **Running** Hyperlight
- **Building guests**
- **Contributing**

Or skip setup entirely with a codespace:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/hyperlight-dev/hyperlight)

## Repository Structure

| Directory | Description |
|---|---|
| [src/hyperlight_host](./src/hyperlight_host) | Host library - creates and manages micro VMs |
| [src/hyperlight_guest](./src/hyperlight_guest) | Core guest library - minimal building blocks for guest-host interaction |
| [src/hyperlight_guest_bin](./src/hyperlight_guest_bin/) | Extended guest library - panic handler, heap, musl, logging, exceptions |
| [src/hyperlight_guest_capi](./src/hyperlight_guest_capi) | C API wrapper around `hyperlight_guest_bin` for use via FFI |
| [src/hyperlight_guest_macro](./src/hyperlight_guest_macro) | Macros for registering guest and host functions |
| [src/hyperlight_guest_tracing](./src/hyperlight_guest_tracing) | Tracing support for guests |
| [src/hyperlight_common](./src/hyperlight_common) | Shared code used by both host and guest |
| [src/hyperlight_component_macro](./src/hyperlight_component_macro) | Proc macros for WIT-based host/guest bindings |
| [src/hyperlight_component_util](./src/hyperlight_component_util) | Shared implementation for WIT binding generation |
| [src/hyperlight_testing](./src/hyperlight_testing) | Shared test utilities |
| [src/schema](./src/schema) | FlatBuffer schema definitions |
| [src/trace_dump](./src/trace_dump) | Tool for dumping and visualizing trace data |
| [src/tests](./src/tests) | Test guest programs (Rust and C) |

## Related Projects

- [hyperlight-wasm](https://github.com/hyperlight-dev/hyperlight-wasm) - Run WebAssembly modules inside Hyperlight micro VMs
- [hyperlight-js](https://github.com/hyperlight-dev/hyperlight-js) - Run JavaScript inside Hyperlight micro VMs
- [cargo-hyperlight](https://github.com/hyperlight-dev/cargo-hyperlight) - Cargo subcommand for building and scaffolding Hyperlight guests

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Community

- **Meetings**: Every other Wednesday 09:00 PST/PDT ([convert to your time](https://dateful.com/convert/pst-pdt-pacific-time?t=09)). Agenda and join info in the [Community Meeting Notes](https://hackmd.io/blCrncfOSEuqSbRVT9KYkg#Agenda).
- **Slack**: [#hyperlight](https://cloud-native.slack.com/archives/hyperlight) on CNCF Slack ([join here](https://www.cncf.io/membership-faq/#how-do-i-join-cncfs-slack)).
- **Docs**: [`docs/` directory](./docs/README.md)
- **Code of Conduct**: [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md)

---

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fhyperlight-dev%2Fhyperlight.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fhyperlight-dev%2Fhyperlight?ref=badge_large)
