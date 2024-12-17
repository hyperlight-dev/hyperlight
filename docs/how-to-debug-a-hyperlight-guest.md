# How to debug a Hyperlight guest

Currently Hyperlight support gdb debugging of a guest running inside a Hyperlight sandbox.
When the option is enabled Hyperlight starts listening on port `8081` for a gdb connection.

Note: It will only accept one connection, if the connection is closed, the debug session is also closed.

## Example
```bash
cargo run --example hello-world --features gdb
```
The execution will wait for gdb to attach.

One can use a simple gdb config to provide the symbols and desired configuration:

For the above example, when running from the repository root directory, the below contents
of `.gdbinit` file can be used.
```gdb
file src/tests/rust_guests/bin/debug/simpleguest
target remote :8081
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout regs
layout src
```