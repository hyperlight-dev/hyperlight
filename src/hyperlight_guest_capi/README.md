This is a c-api wrapper over the hyperlight-guest/hyperlight-guest-bin crate. The purpose of this crate is to allow the creation of guests in the c language. This crate generates a .lib/.a library file depending on the platform, as well necessary header files. 

For examples on how to use it, see the c [simpleguest](../tests/c_guests/c_simpleguest/).

## Byte chunks

`ByteChunks` parameters use an array of borrowed pointer and length spans:

```c
hl_ByteChunks value = call->parameters[0].value.ByteChunks;
for (uintptr_t i = 0; i < value.count; i++) {
  consume(value.chunks[i].data, value.chunks[i].len);
}
```

The parameter view is valid until the guest function returns. A value from
`hl_get_host_return_value_as_ByteChunks` remains valid until
`hl_free_byte_chunks`. `hl_result_from_ByteChunks` copies the supplied spans.

# Important

Guest function wrappers return an `hl_ReturnValue*` created by an
`hl_result_from_*` function.

## NOTE

The `hl_result_from_*` constructors establish matching tags, union payloads,
and ownership.
