# How to debug a Hyperlight guest using gdb on Linux

Hyperlight supports gdb debugging of a **KVM** or **MSHV** guest running inside a Hyperlight sandbox on Linux.
When Hyperlight is compiled with the `gdb` feature enabled, a Hyperlight sandbox can be configured
to start listening for a gdb connection.

## Supported features

The Hyperlight `gdb` feature enables **KVM** and **MSHV** guest debugging to:
   - stop at an entry point breakpoint which is automatically set by Hyperlight
   - add and remove HW breakpoints (maximum 4 set breakpoints at a time)
   - add and remove SW breakpoints
   - read and write registers
   - read and write addresses
   - step/continue
   - get code offset from target

## Expected behavior

Below is a list describing some cases of expected behavior from a gdb debug 
session of a guest binary running inside a Hyperlight sandbox on Linux.

- when the `gdb` feature is enabled and a SandboxConfiguration is provided a
  debug port, the created sandbox will wait for a gdb client to connect on the
  configured port
- when the gdb client attaches, the guest vCPU is expected to be stopped at the
  entry point
- if a gdb client disconnects unexpectedly, the debug session will be closed and
  the guest will continue executing disregarding any prior breakpoints
- if multiple sandbox instances are created, each instance will have its own
  gdb thread listening on the configured port
- if two sandbox instances are created with the same debug port, the second
  instance logs an error and the gdb thread will not be created, but the sandbox
  will continue to run without gdb debugging

## Example

### Sandbox configuration

The `guest-debugging` example in Hyperlight demonstrates how to configure a Hyperlight
sandbox to listen for a gdb client on a specific port.

### CLI Gdb configuration

One can use a gdb config file to provide the symbols and desired configuration.

The below contents of the `.gdbinit` file can be used to provide a basic configuration
to gdb startup.

```gdb
# Path to symbols
file path/to/symbols.elf
# The port on which Hyperlight listens for a connection
target remote :8080
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout src
```
One can find more information about the `.gdbinit` file at [gdbinit(5)](https://www.man7.org/linux/man-pages/man5/gdbinit.5.html).

### End to end example

Using the example mentioned at [Sandbox configuration](#sandbox-configuration) 
one can run the below commands to debug the guest binary:

```bash
# Terminal 1
$ cargo run --example guest-debugging --features gdb
```

```bash
# Terminal 2
$ cat .gdbinit
file src/tests/rust_guests/bin/debug/simpleguest
target remote :8080
set disassembly-flavor intel
set disassemble-next-line on
enable pretty-printer
layout src

$ gdb
```

### Using VSCode to debug a Hyperlight guest

To replicate the above behavior using VSCode follow the below steps:
- To use gdb: 
    1. install the `gdb` package on the host machine
    2. install the [C/C++ Extension Pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-extension-pack) extension in VSCode to add debugging capabilities
- To use lldb:
    1. install `lldb` on the host machine
    2. install the [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) extension in VSCode to add debugging capabilities
- create a `.vscode/launch.json` file in the project directory with the below content:
    ```json
    {
        "version": "0.2.0",
        "configurations": [
            {
                "name": "LLDB",
                "type": "lldb",
                "request": "launch",
                "targetCreateCommands": ["target create ${workspaceFolder}/src/tests/rust_guests/bin/debug/simpleguest"],
                "processCreateCommands": ["gdb-remote localhost:8080"]
            },
            {
                "name": "GDB",
                "type": "cppdbg",
                "request": "launch",
                "program": "${workspaceFolder}/src/tests/rust_guests/bin/debug/simpleguest",
                "args": [],
                "stopAtEntry": true,
                "hardwareBreakpoints": {"require": false, "limit": 4},
                "cwd": "${workspaceFolder}",
                "environment": [],
                "externalConsole": false,
                "MIMode": "gdb",
                "miDebuggerPath": "/usr/bin/gdb",
                "miDebuggerServerAddress": "localhost:8080",
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
            }
        ]
    }
    ```
- in `Run and Debug` tab, select either `GDB` or `LLDB` configuration and click on the `Run`
  button to start the debugging session.
  The debugger will connect to the Hyperlight sandbox and the guest vCPU will
  stop at the entry point.


## How it works

The gdb feature is designed to work like a Request - Response protocol between
a thread that accepts commands from a gdb client and main thread of the sandbox.

All the functionality is implemented on the hypervisor side so it has access to
the shared memory and the vCPU.

The gdb thread uses the `gdbstub` crate to handle the communication with the gdb client.
When the gdb client requests one of the supported features mentioned above, a request
is sent over the communication channel to the main thread for the sandbox
to resolve.

Below is a sequence diagram that shows the interaction between the entities
involved in the gdb debugging of a Hyperlight guest running inside a **KVM** or **MSHV** sandbox.

```
                               ┌───────────────────────────────────────────────────────────────────────────────────────────────┐
                               │                                       Hyperlight Sandbox                                      │
     USER                      │                                                                                               │
┌────────────┐                 │  ┌──────────────┐                      ┌───────────────────────────┐              ┌────────┐  │
│ gdb client │                 │  │  gdb thread  │                      │  main sandbox thread      │              │  vCPU  │  │
└────────────┘                 │  └──────────────┘                      └───────────────────────────┘              └────────┘  │
      |                        │          |               create_gdb_thread           |                                 |      │
      |                        │          |◄─────────────────────────────────────────┌─┐         vcpu stopped          ┌─┐     │
      |    attach              │         ┌─┐                                         │ │◄──────────────────────────────┴─┘     │
     ┌─┐───────────────────────┼────────►│ │                                         │ │     entrypoint breakpoint      |      │
     │ │   attach response     │         │ │                                         │ │                                |      │
     │ │◄──────────────────────┼─────────│ │                                         │ │                                |      │
     │ │                       │         │ │                                         │ │                                |      │
     │ │  add_breakpoint       │         │ │                                         │ │                                |      │
     │ │───────────────────────┼────────►│ │          add_breakpoint                 │ │                                |      │
     │ │                       │         │ │────────────────────────────────────────►│ │  add_breakpoint                |      │
     │ │                       │         │ │                                         │ │────┐                           |      │
     │ │                       │         │ │                                         │ │    │                           |      │
     │ │                       │         │ │                                         │ │◄───┘                           |      │
     │ │                       │         │ │          add_breakpoint response        │ │                                |      │
     │ │  add_breakpoint response        │ │◄────────────────────────────────────────│ │                                |      │
     │ │◄──────────────────────┬─────────│ │                                         │ │                                |      │
     │ │   continue            │         │ │                                         │ │                                |      │
     │ │───────────────────────┼────────►│ │            continue                     │ │                                |      │
     │ │                       │         │ │────────────────────────────────────────►│ │         resume vcpu            |      │
     │ │                       │         │ │                                         │ │──────────────────────────────►┌─┐     │
     │ │                       │         │ │                                         │ │                               │ │     │
     │ │                       │         │ │                                         │ │                               │ │     │
     │ │                       │         │ │                                         │ │                               │ │     │
     │ │                       │         │ │                                         │ │                               │ │     │
     │ │                       │         │ │                                         │ │         vcpu stopped          │ │     │
     │ │                       │         │ │        notify vcpu stop reason          │ │◄──────────────────────────────┴─┘     │
     │ │   notify vcpu stop reason       │ │◄────────────────────────────────────────│ │                                |      │
     │ │◄──────────────────────┬─────────│ │                                         │ │                                |      │
     │ │    continue until end │         │ │                                         │ │                                |      │
     │ │───────────────────────┼────────►│ │            continue                     │ │         resume vcpu            |      │
     │ │                       │         │ │────────────────────────────────────────►│ │──────────────────────────────►┌─┐     │
     │ │                       │         │ │                                         │ │                               │ │     │
     │ │                       │         │ │        comm channel disconnected        │ │         vcpu halted           │ │     │
     │ │   target finished exec│         │ │◄────────────────────────────────────────┤ │◄──────────────────────────────┴─┘     │
     │ │◄──────────────────────┼─────────┴─┘          target finished exec           └─┘                                |      │
     │ │                       │          |                                           |                                 |      │
     └─┘                       │          |                                           |                                 |      │
      |                        └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Dumping the guest state to an ELF core dump when an unhandled crash occurs

When a guest crashes because of an unknown VmExit or unhandled exception, the vCPU state is dumped to an `ELF` core dump file.
This can be used to inspect the state of the guest at the time of the crash.

To make Hyperlight dump the state of the vCPU (general purpose registers, registers) to an `ELF` core dump file, enable the `crashdump`
feature and run.
The feature enables the creation of core dump files for both debug and release builds of Hyperlight hosts.
By default, Hyperlight places the core dumps in the temporary directory (platform specific).
To change this, use the `HYPERLIGHT_CORE_DUMP_DIR` environment variable to specify a directory.
The name and location of the dump file will be printed to the console and logged as an error message.

**NOTE**: If the directory provided by `HYPERLIGHT_CORE_DUMP_DIR` does not exist, Hyperlight places the file in the temporary directory.
**NOTE**: By enabling the `crashdump` feature, you instruct Hyperlight to create core dump files for all sandboxes when an unhandled crash occurs.
To selectively disable this feature for a specific sandbox, you can set the `guest_core_dump` field to `false` in the `SandboxConfiguration`.
```rust
    let mut cfg = SandboxConfiguration::default();
    cfg.set_guest_core_dump(false); // Disable core dump for this sandbox
```

### Inspecting the core dump

After the core dump has been created, to inspect the state of the guest, load the core dump file using `gdb` or `lldb`.
**NOTE: This feature has been tested with version `15.0` of `gdb` and version `17` of `lldb`, earlier versions may not work, it is recommended to use these versions or later.**

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
**NOTE: The `CodeLldb` debug session does not stop after launching. To see the code, stack frames and registers you need to
press the `pause` button. This is a known issue with the `CodeLldb` extension [#1245](https://github.com/vadimcn/codelldb/issues/1245).
The `cppdbg` extension works as expected and stops at the entry point of the program.**

## Compiling guests with debug information for release builds

This section explains how to compile a guest with debugging information but still have optimized code, and how to separate the debug information from the binary.

### Creating a release build with debug information

To create a release build with debug information, you can add a custom profile to your `Cargo.toml` file:

```toml
[profile.release-with-debug]
inherits = "release"
debug = true
```

This creates a new profile called `release-with-debug` that inherits all settings from the release profile but adds debug information.

### Splitting debug information from the binary

To reduce the binary size while still having debug information available, you can split the debug information into a separate file.
This is useful for production environments where you want smaller binaries but still want to be able to debug crashes.

Here's a step-by-step guide:

1. Build your guest with the release-with-debug profile:
   ```bash
   cargo build --profile release-with-debug
   ```

2. Locate your binary in the target directory:
   ```bash
   TARGET_DIR="target"
   PROFILE="release-with-debug"
   ARCH="x86_64-unknown-none" # Your target architecture
   BUILD_DIR="${TARGET_DIR}/${ARCH}/${PROFILE}"
   BINARY=$(find "${BUILD_DIR}" -type f -executable -name "guest-binary" | head -1)
   ```

3. Extract debug information into a full debug file:
   ```bash
   DEBUG_FILE_FULL="${BINARY}.debug.full"
   objcopy --only-keep-debug "${BINARY}" "${DEBUG_FILE_FULL}"
   ```

4. Create a symbols-only debug file (smaller, but still useful for stack traces):
   ```bash
   DEBUG_FILE="${BINARY}.debug"
   objcopy --keep-file-symbols "${DEBUG_FILE_FULL}" "${DEBUG_FILE}"
   ```

5. Strip debug information from the original binary but keep function names:
   ```bash
   objcopy --strip-debug "${BINARY}"
   ```

6. Add a debug link to the stripped binary:
   ```bash
   objcopy --add-gnu-debuglink="${DEBUG_FILE}" "${BINARY}"
   ```

After these steps, you'll have:
- An optimized binary with function names for basic stack traces
- A symbols-only debug file for stack traces
- A full debug file for complete source-level debugging

### Analyzing core dumps with the debug files

When you have a core dump from a crashed guest, you can analyze it with different levels of detail using either GDB or LLDB.

#### Using GDB

1. For basic analysis with function names (stack traces):
   ```bash
   gdb ${BINARY} -c /path/to/core.dump
   ```

2. For full source-level debugging:
   ```bash
   gdb -s ${DEBUG_FILE_FULL} ${BINARY} -c /path/to/core.dump
   ```

#### Using LLDB

LLDB provides similar capabilities with slightly different commands:

1. For basic analysis with function names (stack traces):
   ```bash
   lldb ${BINARY} -c /path/to/core.dump
   ```

2. For full source-level debugging:
   ```bash
   lldb -o "target create -c /path/to/core.dump ${BINARY}" -o "add-dsym ${DEBUG_FILE_FULL}"
   ```

3. If your debug symbols are in a separate file:
   ```bash
   lldb ${BINARY} -c /path/to/core.dump
   (lldb) add-dsym ${DEBUG_FILE_FULL}
   ```

### VSCode Debug Configurations

You can configure VSCode (in `.vscode/launch.json`) to use these files by modifying the debug configurations:

#### For GDB

```json
{
    "name": "[GDB] Load core dump with full debug symbols",
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
        }
    ]
}
```

#### For LLDB

```json
{
    "name": "[LLDB] Load core dump with full debug symbols",
    "type": "lldb",
    "request": "launch",
    "program": "${input:program}",
    "cwd": "${workspaceFolder}",
    "processCreateCommands": [],
    "targetCreateCommands": [
        "target create -c ${input:core_dump} ${input:program}"
    ],
    "postRunCommands": [
        // if debug symbols are in a different file
        "add-dsym ${input:debug_file_path}"
    ]
}
```
