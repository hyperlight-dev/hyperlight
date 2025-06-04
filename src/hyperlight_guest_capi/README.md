This is a c-api wrapper over the hyperlight-guest/hyperlight-guest-bin crate. The purpose of this crate is to allow the creation of guests in the c language. This crate generates a .lib/.a library file depending on the platform, as well necessary header files. 

For examples on how to use it, see the c [simpleguest](../tests/c_guests/c_simpleguest/).

# Important

All guest functions must return a `hl_Vec*` obtained by calling one of the `hl_flatbuffer_result_from_*` functions. These functions will return a flatbuffer encoded byte-buffer of given value, for example `hl_flatbuffer_result_from_int(int)` will return the flatbuffer representation of the given int.

## NOTE

**You may not construct and return your own `hl_Vec*`**, as the hyperlight api assumes that all returned `hl_Vec*` are constructed through calls to a `hl_flatbuffer_result_from_*` function. 

Additionally, note that type `hl_Vec*` is used in two different contexts. First, `hl_Vec*` is used input-parameter-type for guest functions that take a buffer of bytes. This buffer of bytes can contain **arbitrary** bytes. Second, all guest functions return a `hl_Vec*` (it might be hidden away by c macros). These `hl_Vec*` are flatbuffer-encoded data, and are not arbitrary. 

