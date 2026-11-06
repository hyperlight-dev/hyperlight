# HIP 0008 - Postcard serialization for host-guest messages

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
- [Design Details](#design-details)
- [Results](#results)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Summary

Replace FlatBuffers with [serde](https://serde.rs) and
[postcard](https://docs.rs/postcard) for the control data of host-guest
messages: function calls, results, guest logs and guest trace events. Byte
payloads stay outside the control data as external values, as described in
[HIP 0002](../0002-envelope-external-byte-stream/README.md). The Rust message
types become the schema.

## Motivation

Hyperlight uses none of FlatBuffers' strengths:

* **Reading in place.** The host can't parse guest memory in place safely,
  because the guest can change it during parsing. The host copies control data
  out first.
* **Schema evolution.** Host and guest must be built from the same Hyperlight
  version, which the host enforces when it loads a guest.
* **Large payloads.** Byte values travel as external values since HIP 0002.
* **Multiple languages.** Only Rust encodes and decodes messages. C guests use
  the Rust C API, and other languages can do the same.

Hyperlight still pays these costs for FlatBuffers:

* About 6,100 lines of generated code, a pinned `flatc` and a manual
  regeneration step.
* Conversion code between each generated type and its Rust type, and a
  verifier pass on every decode.
* A hand-tuned size estimator for trace events, with its own fuzz target.
* Slow encoding. Builder overhead dominates for messages this small.

serde lets the Rust types be the schema. Deriving `Serialize` and
`Deserialize` replaces the generated code and the conversions, and decoding
can borrow strings from the received buffer.

postcard fits this use:

* **Not self-describing.** Formats such as CBOR and MessagePack tag each value
  with its type. Host and guest share the Rust types, so postcard encodes only
  the values, with varint integers and lengths.
* **Stable, specified format.** postcard 1.0 has a written
  [wire specification](https://postcard.jamesmunns.com/wire-format) that stays
  fixed until 2.0. Host and guest can build with different postcard 1.x
  releases. bitcode, for example, may change its format in any major version.
* **Built for `no_std`.** postcard targets embedded devices first, so it runs
  in the guest without the standard library.

### Goals

* Faster encoding and decoding of control data.
* Less code: no generated code, conversions or size estimator.
* Equal or stronger validation of untrusted guest data.

### Non-Goals

* Wire compatibility across Hyperlight versions.
* Changing how byte payloads travel.

## Proposal

Each message's control data is one postcard value. Message types derive
`Serialize` and `Deserialize`. Decoding borrows the host function name and the
strings in logs and trace events. Byte values appear in control data only as
their length.

The message header carries the control data length in a new `control_len`
field. The header grows from 12 to 16 bytes:

```rust
#[repr(C)]
pub struct MsgHeader {
    pub kind: MsgKind,
    reserved: [u8; 3],
    pub cid: u32,
    /// Control data plus external byte values.
    pub payload_len: u32,
    /// Control data only. Never exceeds `payload_len`. New in this HIP.
    pub control_len: u32,
}
```

A postcard value marks its own end, but the host must copy control data out
of guest memory before it parses it. It needs the length to copy exactly the
control data in one read. Without it, the host would have to read guest memory
byte by byte while parsing, or copy the external bytes as well.

## Design Details

Message types:

* **Function call:** name, call type, return type and parameters.
* **Value:** `Int`, `UInt`, `Long`, `ULong`, `Float`, `Double`, `String`,
  `Bool`, `Void`, or `ExternalBytes { length, chunked }` for an external byte
  value. `chunked` selects `ByteChunks` or `VecBytes` on the receiver.
* **Result:** `Ok(value)` or `Err { code, message }`.
* **Guest log:** message, source, level, caller, source file and line.
* **Trace batch:** postcard events back to back in one buffer of up to
  4 KiB. The encoder sends the batch when the next event does not fit, so no
  size estimate is needed.

FlatBuffers is removed: the generated code, `src/schema`, the `flatbuffers`
dependency, the `flatc` recipes and the FlatBuffers docs.

## Results

Preliminary estimates from short benchmark runs:

| Benchmark | KVM | MSHV |
|---|---|---|
| Guest call | about −5% | −10% to −18% |
| Guest call with a host function call | −9% to −29% | −15% to −21% |
| 24 KiB in, 8 KiB out | 0% to −4% | −3% to −5% |
| Encode control data | −53% to −73% | −51% to −75% |

## Drawbacks

* No language-neutral schema. A non-Rust encoder or decoder would need to
  implement postcard's wire format.

## Alternatives

* **Keep FlatBuffers:** the costs listed in [Motivation](#motivation).
* **rkyv:** built for reading in place, which the host can't use because it
  must copy first.
* **No control data length:** postcard needs none, but the host does. See
  [Proposal](#proposal).
* **A hand-written codec:** possibly slightly faster for these small
  messages, but more code to own and fuzz.
