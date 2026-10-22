# hyperlight-component-csharp

Generates C# host bindings for a WIT world. A .NET host uses them to call a
Hyperlight component guest and to serve its imports.

hyperlight-wasm's .NET packages use this crate to generate bindings at build
time. Hyperlight itself has no .NET host.

## Usage

```rust
let cs = hyperlight_component_csharp::generate_from_path(
    Path::new("wit/world.wit"),
    None,            // world name, or None for the last world
    "MyApp.Guest",   // root C# namespace
)?;
std::fs::write("Bindings.g.cs", cs)?;
```

`generate` takes a `hyperlight_component_util::util::WitSource`, the input
type of the bindgen macros. It reads the world through the same component type
elaboration as the macros.

For a world `w`, the output has:

* `WComponent`, which calls the guest's exports.
* `WComponent.RegisterImports`, which registers host implementations of the
  guest's imports.
* A C# type for each record, variant, enum and flags type.

See [docs/component-wire-format.md](../../docs/component-wire-format.md) for
the type mapping and the wire format.

## Runtime.cs

The generated code needs the C# types in [`src/Runtime.cs`](src/Runtime.cs).
The Rust constant `hyperlight_component_csharp::RUNTIME_SOURCE` holds the text
of this file, so tools can write it out next to the generated code.

A .NET host library, such as hyperlight-wasm's, includes this file in its build.
It implements the file's `IGuestCaller` and `IHostFunctionRegistry` interfaces
with its sandbox.
