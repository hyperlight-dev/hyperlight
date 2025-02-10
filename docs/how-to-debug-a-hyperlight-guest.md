# How to debug a Hyperlight guest using gdb

Hyperlight supports gdb debugging of a guest running inside a Hyperlight sandbox.
When Hyperlight is compiled with the `gdb` feature enabled, a Hyperlight sandbox can be configured
to start listening for a gdb connection.

## Supported features

The Hyperlight `gdb` feature enables:

1. KVM guest debugging:
   - an entry point breakpoint is automatically set for the guest to stop
   - add and remove HW breakpoints (maximum 4 set breakpoints at a time)
   - add and remove SW breakpoints
   - read and write registers
   - read and write addresses
   - step/continue
   - get code offset from target

## Expected behavior

Below is a list describing some cases of expected behavior from a gdb debug 
session of a guest binary running inside a Hyperlight sandbox.

- when the `gdb` feature is enabled and a SandboxConfiguration is provided a
  debug port, the created sandbox will wait for a gdb client to connect on the
  configured port
- when the gdb client attaches, the guest vCPU is expected to be stopped at the
  entrypoint
- if a gdb client disconnects unexpectedly, the debug session will be closed and
  the guest will continue executing disregarding any prior breakpoints

## How it works

The gdb feature is designed to work like a Request - Response protocol between
a thread that accepts commands from a gdb cliend and the hypervisor handler over
a communication channel.

All the functionality is implemented on the hypervisor side so it has access to
the shared memory and the vCPU.

The gdb thread uses the `gdbstub` crate to handle the communication with the gdb client.
When the gdb client requests one of the supported features mentioned above, a request
is sent over the communication channel to the hypervisor handler for the sandbox
to resolve.

## Example

### Sandbox configuration

The snippet of a rust host application below configures the Hyperlight Sandbox to
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

### Gdb configuration

One can use a simple gdb config to provide the symbols and desired configuration.

The below contents of the `.gdbinit` file can be used to provide a basic configuration
to gdb startup.

```gdb
# Path to symbols
file path/to/symbols.elf
# The port on which Hyperlight listens for a connection
target remote :9050
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout src
```
One can find more information about the `.gdbinit` file at [gdbinit(5)](https://www.man7.org/linux/man-pages/man5/gdbinit.5.html).

### End to end example

Using the [Sandbox configuration](#sandbox-configuration) above to configure the [hello-world](https://github.com/hyperlight-dev/hyperlight/blob/main/src/hyperlight_host/examples/hello-world/main.rs) example
in Hyperlight one can run the below commands to debug the guest binary:

```bash
# Terminal 1
$ cargo run --example hello-world --features gdb
```

```bash
# Terminal 2
$ cat .gdbinit
file file src/tests/rust_guests/bin/debug/simpleguest
target remote :9050
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout src

$ gdb
```
