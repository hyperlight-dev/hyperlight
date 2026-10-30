# hyperlight-component-csharp

> **Warning:** This crate is experimental. Its API and the generated C# can
> change in any release.

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

Values use the [component wire format](../../docs/component-wire-format.md).
The generated code targets .NET 8 or later.

## Generated code

For a world `w`, the generator emits:

* `WComponent`, constructed from an `IGuestCaller`. It has a property for each
  exported interface and a method for each function the world exports.
* `WComponent.RegisterImports`, which registers host functions on an
  `IHostFunctionRegistry` from an implementation of each imported interface.
* A C# interface `IName` for each imported interface `name`, and `IWImports`
  for functions the world imports.
* Types for every record, variant, enum and flags in the world's interfaces.
* A C# interface `IR` for each resource `r`, with a method for each of its
  methods. The constructor and static functions are `NewR` and `RFunction` on
  the interface that defines `r`.
* `WResources` when the world uses resources. It holds the handle tables.
  `RegisterImports` returns it and the `WComponent` constructor takes it.

| WIT type | C# type |
|---|---|
| `bool`, integers, floats | `bool`, `sbyte` to `ulong`, `float`, `double` |
| `char` | `System.Text.Rune` |
| `string` | `string` |
| `list<u8>`, `list<u8, N>` | `byte[]` |
| `list<T>`, `list<T, N>` | `IReadOnlyList<T>` |
| `tuple<...>` | Value tuple |
| `option<T>` | `T?`, or `Option<T>` when `T` is an `option` |
| `result<T, E>` | `Result<T, E>`, with `Unit` for a missing type |
| `record` | Sealed record with `required init` properties |
| `variant` | Abstract record with a nested sealed record per case |
| `enum` | `enum` with `uint` values |
| `flags` | `[Flags]` enum with `uint` values |
| `own<r>`, `borrow<r>` | `IR` |

Resources defined by the guest, async functions, futures, streams, maps and
flags with more than 32 members are rejected.

For a root namespace `Root`, types from `ns:pkg/iface` are in
`Root.Ns.Pkg.Iface`. The C# interface or exports class for `iface` is in
`Root.Ns.Pkg`. A world that uses two versions of a package gets the version
after `Pkg`, such as `Root.Ns.Pkg.V1_0_0`.

## Runtime.cs

The generated code needs the C# types in [`src/Runtime.cs`](src/Runtime.cs).
The Rust constant `hyperlight_component_csharp::RUNTIME_SOURCE` holds the text
of this file, so tools can write it out next to the generated code.

A .NET host library, such as hyperlight-wasm's, includes this file in its build.
It implements the file's `IGuestCaller` and `IHostFunctionRegistry` interfaces
with its sandbox.
