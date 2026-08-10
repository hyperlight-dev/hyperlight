This is a c-api wrapper over the hyperlight-guest/hyperlight-guest-bin crate. The purpose of this crate is to allow the creation of guests in the c language. This crate generates a .lib/.a library file depending on the platform, as well necessary header files. 

For examples on how to use it, see the c [simpleguest](../tests/c_guests/c_simpleguest/).

# Important

Guest function wrappers return an `hl_ReturnValue*` created by an
`hl_result_from_*` function.

## NOTE

The `hl_result_from_*` constructors establish matching tags, union payloads,
and ownership.
