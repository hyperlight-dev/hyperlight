# How to debug a Hyperlight guest

Hyperlight supports gdb debugging of a guest running inside a Hyperlight sandbox.
When Hyperlight is compiled with the `gdb` feature enabled, a Hyperlight sandbox can be configured
to start listening for a gdb connection.

## Example
The snipped of a rust host application below configures the Hyperlight Sandbox to
listen on port `9050` for a gdb client to connect.

```rust
    let mut cfg = SandboxConfiguration::default();
    cfg.set_guest_debug_port(9050);

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        Some(cfg), // configuration
        None, // default run options
        None, // default host print function
    )?;
```

The execution of the guest will wait for gdb to attach.

One can use a simple gdb config to provide the symbols and desired configuration:

For the above snippet, the below contents of the `.gdbinit` file can be used to
provide configuration to gdb startup.
```gdb
file path/to/symbols.elf
target remote :9050
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout src
```

One can find more information about the `.gdbinit` file at [gdbinit(5)](https://www.man7.org/linux/man-pages/man5/gdbinit.5.html).
