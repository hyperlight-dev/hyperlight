# Component wire format

Bindings generated from WIT exchange values in this format. It is used by
`host_bindgen!`, `guest_bindgen!`, the hyperlight-wasm guest runtime, and the
C# generator in `hyperlight-component-csharp`. The host and guest must be built
from the same Hyperlight version.

## Calls

A component function is a Hyperlight guest or host function. Each WIT
parameter is a separate `VecBytes` argument holding the encoded value. The
result is one `VecBytes` value. A function without a result returns an empty
buffer.

## Function names

| Function | Wire name | Example |
|---|---|---|
| Member of an imported or exported instance | `<instance>#<function>` | `wasi:http/types@0.2.0#[method]fields.get` |
| Imported or exported by the world itself | `<function>` | `run` |

`<instance>` and `<function>` are the import and export names in the
component type, including package versions and resource method prefixes.

## Values

Integers, floats and lengths are little-endian. Compound values concatenate
their parts with no alignment.

| WIT type | Encoding |
|---|---|
| `bool` | 1 byte, `0` or `1` |
| `s8`, `u8` | 1 byte |
| `s16`, `u16` | 2 bytes |
| `s32`, `u32`, `f32` | 4 bytes |
| `s64`, `u64`, `f64` | 8 bytes |
| `char` | Unicode scalar value as `u32` |
| `string` | `u32` byte length, then UTF-8 bytes |
| `list<T>` | `u32` element count, then each element |
| `list<T, N>` | `N` elements |
| `record`, `tuple` | Fields in declaration order |
| `option<T>` | `u8` tag. `0` is `none`. `1` is `some`, followed by the payload |
| `result<T, E>` | `u8` tag. `0` is `ok` and `1` is `err`, followed by the payload if the case has a type |
| `variant` | `u32` case index, followed by the payload if the case has a type |
| `enum` | `u32` case index |
| `flags` | Bitset of `ceil(n / 8)` bytes. Flag `i` is bit `i % 8` of byte `i / 8` |
| `own<R>`, `borrow<R>` | `u32` handle |

[`src/tests/component_wire/vectors.txt`](../src/tests/component_wire/vectors.txt)
lists encodings of the types in
[`wire.wit`](../src/tests/component_wire/wire.wit). The Rust host bindings and
the C# bindings are both tested against it.
[`csharp/edge.wit`](../src/tests/component_wire/csharp/edge.wit) covers C#
naming cases. `just test-csharp-bindings` generates C# for both and runs the C#
tests.

## C# host bindings

`hyperlight_component_csharp::generate_from_path` generates C# for the host
side of a world. The generated code depends on the `Hyperlight.Component`
namespace in `hyperlight_component_csharp::RUNTIME_SOURCE`. It targets .NET 8
or later.

For a world `w`, the generator emits:

* `WComponent`, constructed from an `IGuestCaller`. It has a property for each
  exported interface and a method for each function the world exports.
* `WComponent.RegisterImports`, which registers host functions on an
  `IHostFunctionRegistry` from an implementation of each imported interface.
* A C# interface `IName` for each imported interface `name`, and `IWImports`
  for functions the world imports.
* Types for every record, variant, enum and flags in the world's interfaces.

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

Resources, async functions, futures, streams, maps and flags with more than 32
members are rejected.

Records, variant cases, `Option` and `Result` compare lists by element.
Variants and `Result` have `Match` and `Switch` methods that take one function
per case. These give a compile error when a case is missing.

For a root namespace `Root`, types from `ns:pkg/iface` are in
`Root.Ns.Pkg.Iface`. The C# interface or exports class for `iface` is in
`Root.Ns.Pkg`. A world that uses two versions of a package gets the version
after `Pkg`, such as `Root.Ns.Pkg.V1_0_0`.
