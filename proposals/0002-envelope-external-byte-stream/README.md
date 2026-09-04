# HIP 0002 - Serialized envelope + external byte stream for large payloads

## Summary

The FlatBuffer remains the schema defined control plane. Large bytes are carried as an ordered
external payload stream immediately after the envelope.

This preserves the requirement that payload structure is described by FlatBuffers, while avoiding
the expensive host-side path of serializing large bytes into a local FlatBuffer vector before
copying them to shared memory.

FlatBuffers terminology appears here because it is Hyperlight's serialization framework at the time
of writing. The optimization is format independent and applies wherever serialized metadata can
describe bytes carried in a separate payload stream.

## Motivation

Hyperlight requires host/guest data to be described by FlatBuffers, but large `vector<ubyte>`
payloads are expensive on the serialization path:

1. the host serializes bytes into a local FlatBuffer `vector<ubyte>`;
2. the `virtq` layer copies that FlatBuffer into shared memory.

For large byte payloads, this creates an avoidable intermediate copy.

This is especially important for the
[virtq transport described by HIP 0001](https://github.com/hyperlight-dev/hyperlight/pull/1112),
which uses scatter/gather lists. A large payload can span several segments, so embedding it in a
serialization buffer requires flattening those segments into a contiguous owned buffer before
serialization. Keeping the payload external lets virtq preserve its segmented representation and
avoids that copy.

## Proposal

Keep message structure fully described by FlatBuffers, while avoiding embedding large byte payloads
inside FlatBuffer vectors.

Use FlatBuffers as a small verified envelope, and place large byte payloads in an ordered external
byte stream immediately after the envelope.

The external payload is treated as a single logical byte stream, even if virtq stores it across
multiple descriptor segments internally. The transport layer is already responsible for preserving
the order of those bytes and for enforcing segment bounds while reading or writing them.

Because of that, the FlatBuffer envelope does not need to name individual virtq segments or offsets.
It only needs to declare the length of each external byte value. The receiver consumes those lengths
from the external stream in a protocol defined order.

Example schema shape:

```fbs
table ExternalBytes {
    length: ulong;
}

table hlbytesref {
    bytes: ExternalBytes (required);
}
```

This is not a FlatBuffers `vector<ubyte>`. It is a FlatBuffer-verified declaration that a byte value
exists in the external payload stream.

The wire layout is:

```
size-prefixed FlatBuffer envelope
external byte stream
```

For example:

```
virtq segment 0:
  FlatBuffer envelope

virtq segment 1..N:
  large raw payload bytes
```

The external bytes are consumed in protocol defined order. For function call parameters, this can be
parameter order. For return values, there is usually only one value. If a message can contain
multiple external byte values, the receiver walks those values in the agreed order and consumes each
declared `length` from the external byte stream.

### Serialization Optimization

For messages in either direction:

1. The sender builds a small FlatBuffer envelope locally.
2. The envelope contains `ExternalBytes.length` for large byte values.
3. The sender writes the header and envelope into the virtq payload.
4. The sender writes the large byte payload directly after the envelope into shared-memory payload
   segments via the virtq write path.

This avoids constructing a large local FlatBuffer that embeds the byte payload. The shared-memory
ownership and synchronization model remains unchanged; the optimization is limited to the
serialization path, where large byte buffers can be written directly to virtq/shared-memory payload
segments instead of first being copied into an intermediate FlatBuffer byte vector.

### Consumption Semantics

For host-to-guest messages, the guest may borrow trusted host-written external bytes if the borrow
lifetime is tied to the current virtq message.

For guest-to-host messages, the host should validate the envelope and then copy/snapshot external
bytes before processing, because the guest is untrusted and may mutate shared memory after
verification.

| Direction     | Behavior                                                           |
| ------------- | ------------------------------------------------------------------ |
| Host -> Guest | Guest may borrow trusted host-written external bytes               |
| Guest -> Host | Host validates the envelope, then copies external bytes before use |

Further zero-copy optimizations may be possible for guest-to-host payloads, but only under a
stricter lifetime model. A borrowed slice into shared memory must be scoped to an exclusive access
guard and must not outlive the point where the guest can run again. In practice, this means the
borrow would need to compete with guest execution for the same shared-memory access capability:
while the host is holding the borrowed view, the guest must not be executing or able to mutate that
memory.

### Validation Requirements

FlatBuffer verification validates only the envelope. Hyperlight must also validate the external byte
stream semantics:

- every `ExternalBytes.length` must fit in the current message;
- length addition must not overflow;
- the sum of all external byte lengths must match the remaining external payload stream length,
  unless the protocol explicitly permits padding;
- external bytes must be consumed in deterministic protocol order;
- the external stream must belong to the current virtq message, not arbitrary shared memory;
- host-side guest-to-host handling must copy bytes before processing.

Because the virtq layer already owns segment ordering and bounds, the FlatBuffer does not need to
include segment indices or offsets.

## Relationship to Apache Arrow

This is inspired by the Apache Arrow IPC pattern, where FlatBuffers describe large external buffers
instead of embedding all bytes directly inside the FlatBuffer object.

Arrow uses explicit buffer descriptors such as `offset` and `length`:

- https://github.com/apache/arrow/blob/main/format/Schema.fbs
- https://github.com/apache/arrow/blob/main/format/Message.fbs

Hyperlight can use a simpler form because virtq already provides the ordered payload stream. The
FlatBuffer envelope only needs to declare lengths and typed meaning; the virtq layer supplies the
actual byte placement.
