# Component wire format

Bindings generated from WIT exchange values in this format. It is used by
`host_bindgen!`, `guest_bindgen!`, the hyperlight-wasm guest runtime, and the
C# generator in
[`hyperlight-component-csharp`](../src/hyperlight_component_csharp). The host
and guest must be built from the same Hyperlight version.

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
| `flags` | Bitset of `ceil(n / 8)` bytes. Flag `i` is bit `i % 8` of byte `i / 8`. Other bits are zero |
| `own<R>`, `borrow<R>` | `u32` handle |

Receivers read a nonzero `bool`, `option` tag or `result` tag as `true`,
`some` or `err`. They ignore unused flag bits and trailing bytes.

## Resources

Resources are defined by the host. A handle indexes the host's table for the
resource type. Passing `own<R>` to the guest adds the value to the table, and
passing `borrow<R>` adds it until the call returns. The guest returns a handle
to give the value back or to lend it to a host method. Resources defined by the
guest are not supported.

## Tests

The Rust and C# host bindings are both tested against
[`witguest`](../src/tests/rust_guests/witguest), which implements
[`guest.wit`](../src/tests/rust_guests/witguest/guest.wit).
[`edge.wit`](../src/tests/csharp_host/edge.wit) covers C# naming cases. After
`just guests`, `just test-csharp-bindings` runs the C# tests.
