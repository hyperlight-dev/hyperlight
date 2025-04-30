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

## Dumping the guest state to an ELF core dump

To dump the state of the vCPU (general purpose registers, registers) to an `ELF` core dump file set the feature `crashdump` and run a debug build. This will result in a dump file being created in the temporary directory.
The name and location of the dump file will be printed to the console and logged as an error message.

### Inspecting the core dump

After the core dump has been created, to inspect the state of the guest, load the core dump file using `gdb` or `lldb`.
A `gdb` version later than `15.0` and `lldb` version later than `17` have been used to test this feature.

To do this in vscode, the following configuration can be used to add debug configurations:

```vscode
{
    "version": "0.2.0",
    "inputs": [
        {
            "id": "core_dump",
            "type": "promptString",
            "description": "Path to the core dump file",
        },
        {
            "id": "program",
            "type": "promptString",
            "description": "Path to the program to debug",
        }
    ],
    "configurations": [
        {
            "name": "[GDB] Load core dump file",
            "type": "cppdbg",
            "request": "launch",
            "program": "${input:program}",
            "coreDumpPath": "${input:core_dump}",
            "cwd": "${workspaceFolder}",
            "MIMode": "gdb",
            "externalConsole": false,
            "miDebuggerPath": "/usr/bin/gdb",
            "setupCommands": [
            {
                "description": "Enable pretty-printing for gdb",
                "text": "-enable-pretty-printing",
                "ignoreFailures": true
            },
            {
                "description": "Set Disassembly Flavor to Intel",
                "text": "-gdb-set disassembly-flavor intel",
                "ignoreFailures": true
            }
            ]
        },
        {
        "name": "[LLDB] Load core dump file",
        "type": "lldb",
        "request": "launch",
        "stopOnEntry": true,
        "processCreateCommands": [],
        "targetCreateCommands": [
            "target create -c ${input:core_dump} ${input:program}",
        ],
        },
    ]
}
```
NOTE: The `CodeLldb` debug session does not stop after launching. To see the code, stack frames and registers you need to
press the `pause` button. This is a known issue with the `CodeLldb` extension [#1245](https://github.com/vadimcn/codelldb/issues/1245).
The `cppdbg` extension works as expected and stops at the entry point of the program.


## Debugging guests

For more information on how to debug the Hyperlight guests check the following [link](./how-to-debug-a-hyperlight-guest.md).
