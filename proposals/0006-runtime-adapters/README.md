# HIP 0006 - Runtime adapters

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
    - [Extending Hyperlight costs a second sandbox](#extending-hyperlight-costs-a-second-sandbox)
    - [Users learn one API](#users-learn-one-api)
    - [One snapshot per state](#one-snapshot-per-state)
    - [Core has no runtime hooks](#core-has-no-runtime-hooks)
    - [Goals](#goals)
    - [Non-Goals](#non-goals)
- [Design](#design)
    - [What a runtime crate writes](#what-a-runtime-crate-writes)
    - [The Runtime trait](#the-runtime-trait)
    - [Lifecycle](#lifecycle)
    - [Guest calls](#guest-calls)
    - [Snapshots](#snapshots)
    - [Building](#building)
    - [Core API](#core-api)
- [Examples](#examples)
    - [Implementations](#implementations)
    - [JS usage](#js-usage)
    - [Wasm usage](#wasm-usage)
- [Risks and Drawbacks](#risks-and-drawbacks)
- [Alternatives](#alternatives)
    - [Overall design](#overall-design)
    - [The trait](#the-trait)
    - [The builder](#the-builder)
    - [Snapshot identity](#snapshot-identity)
- [Open Questions](#open-questions)
<!-- /toc -->

## Summary

Hyperlight is built to be extended. hyperlight-js, hyperlight-wasm and
[hyperlight-unikraft] each run a language runtime in a Hyperlight guest. Each
wraps core's sandbox in its own types: a sandbox struct per lifecycle state,
a builder that copies core's settings, and its own snapshot and restore rules.

This HIP adds a `Runtime` trait to core. A runtime crate implements it, and
users build `Sandbox<ItsRuntime>` with core's `SandboxBuilder`, so core's
`Sandbox` becomes the sandbox type for every runtime. Core owns
construction, snapshots, restore and persistence for every runtime. The
runtime adds only what core cannot know: its guest, its host bindings, and
hooks that keep host and guest state in step. Language operations, such as
`handle_event`, come from one extension trait per runtime.

## Motivation

Core already owns capture, restore, host-function dispatch and poisoning. It
has no place for a runtime to plug in, so each runtime crate wraps core's
sandbox in its own.

### Extending Hyperlight costs a second sandbox

To add a runtime, a crate must:

* Define a sandbox type per lifecycle state and move the inner sandbox
  between them. JS has `ProtoJSSandbox`, `JSSandbox` and `LoadedJSSandbox`,
  and each transition consumes the sandbox.
* Forward every core method it exposes, and keep up as core grows.
* Wrap core's builder to add its guest and defaults, repeating every setting.
  The JS and Wasm builders do this and silently ignore sizes below their
  minimums.
* Reimplement snapshot, restore and persistence for its own types.

With the trait, a runtime crate writes one impl and defines no sandbox or
builder types. In the prototype, JS's lifecycle code shrinks from 1,371 to
568 lines and Wasm's from 955 to 281.

### Users learn one API

Each runtime has its own types, builder and snapshot rules, so users relearn
construction, snapshots and restore for each. With the trait, every runtime
uses core's builder and `Sandbox`, and host functions are registered the same
way everywhere.

### One snapshot per state

Sandboxes start from snapshots saved on a cold path and loaded from disk.
Wrapper types make this hard. [hyperlight-js#354] types snapshots by
lifecycle state and saves one loaded state as two snapshots that users must
copy together. With the trait, every state is one core snapshot, and any
compatible snapshot restores into any sandbox of the same runtime. No bundle
format is needed ([hyperlight#1865]).

### Core has no runtime hooks

Some runtime state is tied to guest state and must be fixed after every
restore. Unikraft resets host sockets and enters a guest `resume` function.
JS and Wasm tell the guest about host functions added since the snapshot.
Each runtime must also reject snapshots it cannot use, and Unikraft encodes
this in OCI tags. Core offers no hook for any of this, so each runtime wraps
`restore` and `snapshot`.

### Goals

* Core's `Sandbox` and `SandboxBuilder` serve every runtime. Runtime crates
  define no sandbox or builder types.
* A runtime crate integrates by implementing one trait.
* One core snapshot per saved state.
* A runtime keeps only what core does not model.
* A runtime can reject a snapshot before any change.
* A runtime controls who may call its guest by name.

### Non-Goals

* A unified command-line tool.

## Design

### What a runtime crate writes

| Item | Required | Purpose |
|---|---|---|
| `impl Runtime` | Yes | Name, call key, guest, default settings and lifecycle hooks |
| Guest binary | Yes | Built and embedded by the crate's build script. `default_builder` returns it. |
| Extension trait | No | Language operations on `Sandbox<ItsRuntime>`, such as `register_handler` |

Language operations live in a trait because Rust's orphan rules forbid
inherent methods on another crate's type. One trait per runtime lets users
import one name, usually through the crate's `prelude`.

The smallest runtime names itself, returns its embedded guest and lets users
call it by name:

```rust
static GUEST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guest"));

pub struct MyRuntime;

impl Runtime for MyRuntime {
    const NAME: &'static str = "my-runtime";
    type CallKey = ();

    fn default_builder(&self) -> SandboxBuilder {
        SandboxBuilder::from_bytes(GUEST)
    }
}

let mut sandbox = SandboxBuilder::from_runtime(MyRuntime).build()?;
let sum: i32 = sandbox.call("Add", (2i32, 3i32))?;
```

### The Runtime trait

A runtime is a host-side value, such as `JsRuntime`. It holds only what core
does not model: language-level bindings such as JS host modules,
guest-protocol state such as whether a Wasm module is loaded, and the
runtime's own settings. Host functions, console output, sizes and snapshot
storage stay in core. The builder moves the runtime into the sandbox, and it
stays on the host for the sandbox's lifetime. Snapshots never contain it.

A runtime must give its name, call key and guest. Every hook has a default,
and a runtime overrides only the hooks it needs.

```rust
pub trait Runtime: Sized + Send {
    /// Identifies this runtime in its snapshots. Keep it stable across releases.
    const NAME: &'static str;

    /// Who may call the guest by name. See [Guest calls](#guest-calls).
    type CallKey;

    /// This runtime's guest, and settings the caller may override.
    fn default_builder(&self) -> SandboxBuilder;

    /// Runs in `build` before the VM exists, for every source.
    fn pre_build(&mut self, builder: SandboxBuilder) -> Result<SandboxBuilder> {
        Ok(builder)
    }

    /// Runs last in `build` from a guest binary, after the guest initialized.
    fn post_init(_sandbox: &mut Sandbox<Self>) -> Result<()> {
        Ok(())
    }

    /// Runs in `restore` and `build` from a snapshot, before guest state changes.
    fn pre_restore(&self, _snapshot: &Snapshot) -> Result<()> {
        Ok(())
    }

    /// Runs last in `restore` and `build` from a snapshot.
    fn post_restore(_sandbox: &mut Sandbox<Self>, _snapshot: &Snapshot) -> Result<()> {
        Ok(())
    }

    /// Runs first in `snapshot`, before capture.
    fn pre_snapshot(&self) -> Result<()> {
        Ok(())
    }

    /// Runs last in `snapshot`. Returns `snapshot` or one derived from it.
    fn post_snapshot(&self, snapshot: Arc<Snapshot>) -> Result<Arc<Snapshot>> {
        Ok(snapshot)
    }
}
```

What each item is for:

* `NAME` (required). Core records it in every snapshot the runtime takes,
  and rejects a snapshot from another runtime or from none. Runtimes also use
  it as the namespace for their snapshot metadata.
* `CallKey` (required). Decides whether users may call guest functions by
  name. Some guests need a calling protocol: JS handlers, for example, must
  go through `handle_event`. A key only the runtime crate can construct
  removes `call` from its sandboxes, so only that crate calls the guest,
  through `runtime_call`. `()` keeps `call` for users. See
  [Guest calls](#guest-calls).
* `default_builder` (required). The builder `from_runtime` starts from:
  the guest binary, the sizes it needs, files it reads at boot, or a guest
  picked from runtime settings. Users override any of these settings with
  core's setters.
* `pre_build`. Registers the host functions the guest's protocol calls.
  Snapshots store host-function signatures, not implementations, so this runs
  for every build. It also rejects sizes below the runtime's minimums,
  declares guest MSRs, and fixes the runtime's bindings for the sandbox's
  lifetime. A snapshot source already has the snapshot's layout.
* `post_init`. Gives the guest its configuration before first use,
  collects what the guest reported during initialization, such as console
  output or an early exit, and starts per-sandbox host state such as metrics.
  Snapshots capture its effects, so it never runs for snapshot builds.
* `pre_restore`. Rejects snapshots from another release or configuration
  of the runtime, or that need bindings this sandbox lacks. It must not
  change any state.
* `post_restore`. Reloads host state from the snapshot's metadata, tells
  the guest about bindings added since the snapshot, resets host resources
  tied to the discarded guest state, and enters a guest resume function.
* `pre_snapshot`. Rejects states the runtime cannot resume, such as an
  exited guest. It runs before capture, so a rejection costs nothing.
* `post_snapshot`. Records what `pre_restore` and `post_restore` read,
  such as the runtime's version, with `Snapshot::with_metadata` under `NAME`.

[Implementations](#implementations) shows what each runtime does in each.

### Lifecycle

Core runs these steps in order. A check or hook that fails stops the
operation.

| Operation | Steps | On failure |
|---|---|---|
| Build from a guest binary | `pre_build`, create VM, `post_init` | Fails `build`. A failed `post_init` drops the new sandbox. |
| Build from a snapshot | runtime check, `pre_build`, host-function check, `pre_restore`, create VM, `post_restore` | Fails `build`. A failed `post_restore` drops the new sandbox. |
| `restore` | runtime check, host-function check, `pre_restore`, restore state, `post_restore` | Before state is restored, leaves the sandbox unchanged. A failed `post_restore` poisons it. |
| `snapshot` | `pre_snapshot`, capture, `post_snapshot` | Leaves the sandbox unchanged and caches nothing. |

Hooks follow these rules:

* `post_init` and `post_restore` may call the guest through
  `Sandbox::runtime_call`. They must return the errors of those calls. Core
  poisons the sandbox only for calls that leave the guest inconsistent, so a
  swallowed error that does not poison goes unnoticed.
* The user can restore again after a failed `post_restore`, so the hook must
  tolerate running after its own partial changes.
* Guest calls in hooks have no time limit, and `build` has no interrupt
  handle.
* Hooks return `HyperlightError::Runtime` to keep the runtime's own error
  type. The runtime crate downcasts it back, so callers match its variants.

The snapshot cache holds the finished snapshot. Repeated `snapshot` calls
without guest or runtime changes run no hooks, and `runtime_mut` clears the
cache.

### Guest calls

`CallKey` decides who may call guest functions by name on a runtime's
sandbox.

```rust
impl<R: SandboxHooks<CallKey = ()>> Sandbox<R> {
    pub fn call<Output: SupportedReturnType>(
        &mut self,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output>;
}

impl<R: Runtime> Sandbox<R> {
    pub fn runtime_call<Output: SupportedReturnType>(
        &mut self,
        key: R::CallKey,
        func_name: &str,
        args: impl ParameterTuple,
    ) -> Result<Output>;
}
```

`call` and `Callable` exist when the key is `()`, as it is for `Sandbox<()>`.
`runtime_call` takes a key value, so only code that can construct the key can
call it.

* Use `()` when users call guest functions by name with Hyperlight
  values. hyperlight-wasm does, because Wasm exports are ordinary guest calls.
* Use a private key when the guest needs a calling protocol.
  hyperlight-js does, because handler calls go through `handle_event`, which
  validates JSON and sets GC options. Its key is
  `pub struct JsCallKey(pub(crate) ())`, which users can name but not
  construct. A user who writes `call` gets a compile error naming the
  unsatisfied `CallKey = ()` bound.

The key is zero-sized, and the check is only in the type system.

### Snapshots

* Core records `NAME` in every snapshot a runtime takes. The runtime check
  compares it with the sandbox's runtime. It rejects a runtime snapshot in a
  plain `Sandbox<()>`, a plain snapshot in a runtime sandbox, and one
  runtime's snapshot in another's sandbox. `Sandbox::from_snapshot` runs it
  too.
* The name is an optional `runtime` field of the OCI config, so plain
  snapshots serialize as before. Runtimes store anything else they check as
  metadata, with core's `Snapshot::with_metadata` and `Snapshot::metadata`.
* Runtime-ready and application snapshots differ only in when they were
  taken. Returning to a clean runtime is `restore(runtime_snapshot)`.
* Snapshots store host-function signatures. Building from a snapshot uses the
  new builder's and runtime's bindings, and `restore` keeps the sandbox's.
* A sandbox may have more bindings than the snapshot's guest knows, and
  `post_restore` tells the guest about them. Wasm does this only while no
  module is loaded. A JS guest learns a module's functions when code first
  imports it, so functions added to a module the guest already imported stay
  unavailable.
* Snapshots saved before adoption have no runtime name, so runtime sandboxes
  reject them.
* Restore accepts different heap and I/O sizes.

### Building

Each constructor names where the guest comes from.

| Constructor | Guest | Settings start from |
|---|---|---|
| `from_file(path)`, `from_bytes(bytes)` | The given binary | Core defaults |
| `from_snapshot(snapshot)` | The snapshot | The snapshot's layout |
| `from_runtime(runtime)` | `runtime.default_builder()` | The runtime's defaults |

`runtime(runtime)` attaches a runtime to a `SandboxBuilder<()>`, usually one
from `from_snapshot`. It changes neither the guest nor the settings.

```rust
// Cold path
let sandbox = SandboxBuilder::from_runtime(JsRuntime::new()).heap_size(8 << 20).build()?;
// Warm path
let sandbox = SandboxBuilder::from_snapshot(snapshot).runtime(JsRuntime::new()).build()?;
```

* Defaults enter only through a constructor, so no setter can come before
  them. Every setter overrides them.
* A snapshot fixes the layout. `build` warns about layout setters on a
  snapshot builder and uses the snapshot's layout, before `pre_build` runs.
* `from_file(path).runtime(runtime)` runs the runtime on another guest, with
  none of its defaults.

### Core API

`Sandbox` and `SandboxBuilder` gain a runtime type parameter that defaults to
`()`, so existing code keeps its types. `call` and `runtime_call` are in
[Guest calls](#guest-calls).

```rust
pub struct SandboxBuilder<R = ()> { /* existing fields */ runtime: R }
pub struct Sandbox<R = ()> { /* existing fields */ runtime: R }

/// Sealed. Implemented for `()` and every `Runtime`.
pub trait SandboxHooks: Sized + Send + sealed::Sealed {
    /// `()` for `()`, and `Runtime::CallKey` for a runtime.
    type CallKey;
}

impl SandboxBuilder<()> {
    // from_file and from_bytes are unchanged. from_snapshot starts with the
    // snapshot's layout.
    pub fn from_runtime<R: Runtime>(runtime: R) -> SandboxBuilder<R>;
    pub fn runtime<R: Runtime>(self, runtime: R) -> SandboxBuilder<R>;
}

impl<R: SandboxHooks> SandboxBuilder<R> {
    // Existing setters, and getters for every transport setting.
    pub fn build(self) -> Result<Sandbox<R>>;
}

impl<R: SandboxHooks> Sandbox<R> {
    // snapshot, restore, status, interruption and mapping are unchanged.
    pub fn runtime(&self) -> &R;
    pub fn runtime_mut(&mut self) -> &mut R;
    pub fn host_function_definitions(&self) -> Result<Vec<HostFunctionDefinition>>;
}

impl Registerable for Sandbox<()> { /* ... */ }

impl Snapshot {
    pub fn host_function_definitions(&self) -> Vec<HostFunctionDefinition>;
}

pub enum HyperlightError {
    // Existing variants.
    Runtime(Box<dyn std::error::Error + Send + Sync>),
    SnapshotRuntimeMismatch { snapshot: Option<String>, sandbox: Option<String> },
}

pub fn file_cow_size(path: impl AsRef<Path>) -> Result<u64>;
```

* `SandboxHooks` lets `Sandbox<()>` share build, snapshot and restore with
  runtime sandboxes, so `()` need not be a `Runtime`. Users never implement or
  name it.
* `runtime` and `runtime_mut` let extension traits reach runtime state.
* `host_function_definitions` lists registered host-function signatures,
  sorted by name. Wasm builds its guest's `env` imports from it.
* Late host-function registration exists only on `Sandbox<()>`, since a
  runtime binds its host functions at build. File and memory mappings stay on
  every sandbox, since they change no guest protocol state.
* `file_cow_size` returns the size a `mapped_file_cow` mapping will have.
  Unikraft passes it to its guest before the build maps the file.

## Examples

### Implementations

What each runtime implements in the prototype.

| Item | hyperlight-js | hyperlight-wasm | hyperlight-unikraft |
|---|---|---|---|
| Runtime state | Host modules, module loader, call statistics | Whether a module is loaded | Console, environment, mounts, sockets, named host calls, exit state |
| `NAME` | `hyperlight-js` | `hyperlight-wasm` | `hyperlight-unikraft` |
| `CallKey` | `JsCallKey` | `()` | `UnikraftCallKey` |
| `default_builder` | Embedded guest, heap, scratch and transport sizes | Embedded guest, heap, scratch and input pool sizes | Embedded or external kernel, sizes, initrd mapping |
| `pre_build` | Rejects sizes below its minimums. Registers `CallHostJsFunction`, the module loader and `CurrentTimeMicros` | Rejects sizes below its minimums | Registers console, clock, environment, file system and socket host functions, and guest MSRs |
| `post_init` | Sends host-module names with `RegisterHostModules` | Calls `InitWasmRuntime` with the sandbox's host functions | Collects console output and any exit status from initialization |
| `pre_restore` | Requires the same version and only known host modules | Requires the same version | Requires the same compatibility key |
| `post_restore` | Resends host-module names when they changed | Rebuilds `env` imports when host functions changed and no module is loaded | Resets sockets and enters the guest `resume` function |
| `pre_snapshot` | None | None | Rejects an exited guest |
| `post_snapshot` | Adds its version and host-module names | Adds its version and whether a module is loaded | Adds its compatibility key |
| Extension trait | `register_handler`, `register_module`, `handle_event` | `load_module`, `load_module_from_buffer`, `load_module_by_mapping` | `run`, `call`, `submit`, `step`, `join` and output access |
| `Clone` | Copies host modules and module loader, so a pool builds many sandboxes from one value | Yes. It has no settings to copy. | No |
| Domain builder | No | No | `SandboxBuilder` produces a `UnikraftRuntime` for its CLI |

### JS usage

Save an application snapshot once, then serve requests from it in another
process.

```rust
use std::sync::Arc;

use hyperlight_js::prelude::*;

// Cold path.
let mut sandbox = SandboxBuilder::from_runtime(JsRuntime::new()).build()?;
sandbox.register_handler("handler", script)?;
sandbox.snapshot()?.save("snapshots", &"app".parse()?)?;

// Hot path, in another process.
let app = Arc::new(Snapshot::checked_load("snapshots", "app".parse::<OciTag>()?)?);
let mut sandbox = SandboxBuilder::from_snapshot(app.clone())
    .runtime(JsRuntime::new())
    .build()?;
let response = sandbox.handle_event("handler", event, None)?;
sandbox.restore(app)?;
```

### Wasm usage

Build from a runtime snapshot, then swap modules by restoring it.

```rust
use std::sync::Arc;

use hyperlight_wasm::{OciTag, SandboxBuilder, Snapshot, WasmRuntime, WasmSandboxExt};

let runtime = Arc::new(Snapshot::checked_load("snapshots", "runtime".parse::<OciTag>()?)?);
let mut sandbox = SandboxBuilder::from_snapshot(runtime.clone())
    .runtime(WasmRuntime::new())
    .host_function("Log", |message: String| println!("{message}"))
    .build()?;

sandbox.load_module("a.aot")?;
let sum: i32 = sandbox.call("add", (2i32, 3i32))?;

sandbox.restore(runtime)?;
sandbox.load_module("b.aot")?;
```

Modules import the sandbox's host functions from `env`. The Wasm guest loads
one module per runtime state. Loading a second module without restoring
fails.

## Risks and Drawbacks

* Users import an extension trait to get language methods.
* Every hook has a default. A runtime that omits a hook it needs compiles and
  misbehaves at run time. For example, a runtime that omits `pre_restore`
  accepts its own snapshots from any release.
* Two runtimes with the same `NAME` accept each other's snapshots in core.
  Their `pre_restore` checks still apply.
* `Sandbox<R>` adds a type parameter to core's main type. It appears in docs
  and error messages.
* A runtime crate that hands out its `CallKey` lets users bypass its calling
  protocol.
* With a `()` key, users can call a runtime's internal guest functions, such
  as Wasm's `LoadWasmModule`, and skip its checks.
* Runtime-ready and loaded states share a type. Calling an unregistered JS
  handler or loading a second Wasm module fails at run time.
* Runtime settings changed through `runtime_mut` after the build have no
  effect. JS host modules are fixed at build.
* Hooks run guest code with no time limit. A guest from an untrusted
  application snapshot can stall `build` or `restore`, and `build` has no
  interrupt handle. Each runtime bounds the guest work its hooks start.
* Host changes a failed `post_restore` made, such as Unikraft's socket reset,
  are not rolled back.
* An extension trait method can be shadowed by a later inherent method of the
  same name on `Sandbox<R>`.
* Removing the legacy types breaks runtime crate users.

## Alternatives

### Overall design

* Keep each runtime's sandbox types and add snapshots to them, as
  [hyperlight-js#354] does. Keeps three types per runtime and two snapshots
  per loaded state.
* A newtype per runtime wrapping `Sandbox`. Each runtime forwards every
  core method, and forwarding drifts.
* Move JS and Wasm into hyperlight-host. Couples core releases to QuickJS
  and Wasmtime.
* OCI bundles ([hyperlight#1865]). Every loaded snapshot still stores a
  second full snapshot.

### The trait

* Language operations in core, such as a generic `load`. Generic verbs
  replace domain names such as `register_handler`.
* `()` as a `Runtime`, with `default_builder` optional. Marks a
  runtime's guest optional, though every runtime has one.
* A `#[doc(hidden)]` `runtime_call`. Hidden only by convention. Any user
  can call it and skip a runtime's protocol.

### The builder

* `runtime()` applies the runtime's defaults. A setter called before it
  is lost unless the builder records which settings the caller made.
* A builder per runtime crate. Repeats core's settings.

### Snapshot identity

* No runtime identity in core. Core's host-function check misses
  runtime snapshots in plain sandboxes when the runtime registers no protocol
  host functions, as Wasm does.
* A runtime version in core. Runtimes differ in what makes snapshots
  compatible, so each checks its own version in `pre_restore`.

## Open Questions

* Whether `Sandbox::runtime` and `Sandbox::runtime_mut` are hidden from docs.
* Whether a layout setter on a snapshot builder fails `build`. The prototype
  warns.
* Core silently raises a pool smaller than one buffer and does not size queues
  to fit their pools. JS sizes its queues itself. Both belong with the
  replacement for `SandboxConfiguration`.
* Core has no sandbox-count metrics. JS and Wasm each count their sandboxes.
* Whether building from a snapshot and restoring cost more than before. The
  prototype has no benchmark numbers yet.

[hyperlight#1865]: https://github.com/hyperlight-dev/hyperlight/issues/1865
[hyperlight-js#354]: https://github.com/hyperlight-dev/hyperlight-js/pull/354
[hyperlight-unikraft]: https://github.com/hyperlight-dev/hyperlight-unikraft
