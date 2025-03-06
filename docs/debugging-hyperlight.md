# Debugging Hyperlight

Support for debugging Hyperlight is currently very limited and experimental. Despite this we offer some very primitive tools to help.

When creating a Uninitialized sandbox, passing a `SandboxRunOptions::RunInProcess(false)` will make the guest run inside a regular host process, rather than inside a hypervisor partition. This allows you to step through the code of the guest using your IDE's debugger. However, there are no symbols, and breakpoints are not supported, so you'll be stepping through assembly.

However, on Windows platform, passing `SandboxRunOptions::RunInProcess(true)` is supported, and will load the guest binary using the win32 `LoadLibrary` function. This has the advantage of also allowing your IDE to set breakpoints in the guest, and also loading symbols, allowing for easy debugging.

## Notes on running guest in-process

The support for running a guest using in-process mode is experimental, highly unsafe, and has many limitations. It requires
enabling cargo feature `inprocess`, and only works when hyperlight-host is built with debug_assertions. Inprocess currently does not support calling guest functions that returns errors. If a guest panics, it will surface as assertion fault ""ERROR: The guest either panicked or returned an Error. Running inprocess-mode currently does not support error handling."

Running in process is specifically only for testing, and should never be used in production as it offers no security guarantees.

## Logging

Hyperlight guests supports logging using the log crate. Any log records logged inside a hyperlight guest using the various
log macros trace!/info!/warning!, etc., will be logged, given that a logger has been instantiated in the host. This can be 
very helpful for debugging as well.

## Getting debug print output of memory configuration, virtual processor register state, and other information

Enabling the feature `print_debug` and running a debug build will result in some debug output being printed to the console. Amongst other things this output will show the memory configuration and virtual processor register state.

To enable this permanently in the rust analyzer for Visual Studio Code so that this output shows when running tests using `Run Test` option add the following to your `settings.json` file:

```json
"rust-analyzer.runnables.extraArgs": [
    "--features=print_debug"
],
```

Alternatively, this can be enabled when running a test from the command line:

```sh
cargo test --package hyperlight-host --test integration_test --features print_debug -- static_stack_allocate --exact --show-output
```

## Dumping the memory configuration, virtual processor register state and memory contents on a crash or unexpected VM Exit

To dump the details of the memory configuration, the virtual processors register state and the contents of the VM memory set the feature `crashdump` and run a debug build. This will result in a dump file being created in the temporary directory. The name and location of the dump file will be printed to the console and logged as an error message.

There are no tools at this time to analyze the dump file, but it can be useful for debugging.

## Debugging guests

For more information on how to debug the Hyperlight guests check the following [link](./how-to-debug-a-hyperlight-guest.md).
