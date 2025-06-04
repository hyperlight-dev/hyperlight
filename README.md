<div align="center">
    <h1>Hyperlight</h1>
    <img src="https://raw.githubusercontent.com/hyperlight-dev/hyperlight/refs/heads/main/docs/assets/hyperlight-logo.png" width="150px" alt="hyperlight logo"/>
    <p><strong>Hyperlight is a lightweight Virtual Machine Manager (VMM) designed to be embedded within applications. It enables safe execution of untrusted code within <i>micro virtual machines</i> with very low latency and minimal overhead.</strong> <br> We are a <a href="https://cncf.io/">Cloud Native Computing Foundation</a> sandbox project. </p>    
</div>

> Note: Hyperlight is a nascent project with an evolving API and no guaranteed support. Assistance is provided on a
> best-effort basis by the developers.

---

## Overview

Hyperlight is a library for creating _micro virtual machines_  — or _sandboxes_ — specifically optimized for securely
running untrusted code with minimal impact. It supports both Windows and Linux,
utilizing [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/#windows-hypervisor-platform)
on Windows, and either Microsoft Hypervisor (mshv) or [KVM](https://linux-kvm.org/page/Main_Page) on Linux.

These micro VMs operate without a kernel or operating system, keeping overhead low. Instead, guests are built
specifically for Hyperlight using the Hyperlight Guest library, which provides a controlled set of APIs that facilitate
interaction between host and guest:

- The host can call functions implemented and exposed by the guest (known as _guest functions_).
- Once running, the guest can call functions implemented and exposed by the host (known as _host functions_).

By default, Hyperlight restricts guest access to a minimal API. The only _host function_ available by default allows the
guest to print messages, which are displayed on the host console or redirected to stdout, as configured. Hosts can
choose to expose additional host functions, expanding the guest’s capabilities as needed.

Below is an example demonstrating the use of the Hyperlight host library in Rust to execute a simple guest application.
It is followed by an example of a simple guest application using the Hyperlight guest library, also written in Rust.

### Host

```rust
use std::{thread, sync::{Arc, Mutex}};

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
use hyperlight_host::{UninitializedSandbox, MultiUseSandbox, func::HostFunction0, sandbox_state::transition::Noop, sandbox_state::sandbox::EvolvableSandbox};

fn main() -> hyperlight_host::Result<()> {
    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_string().unwrap()),
        None // default configuration
    )?;

    // Registering a host function makes it available to be called by the guest
    uninitialized_sandbox.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Note: This function is unused by the guest code below, it's just here for demonstration purposes

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

    // Call a function in the guest
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    // in order to call a function it first must be defined in the guest and exposed so that 
    // the host can call it
    let result: i32 = multi_use_sandbox.call_guest_function_by_name(
        "PrintOutput",
        message,
    );

    assert!(result.is_ok());

    Ok(())
}
```

### Guest

```rust
#![no_std]
#![no_main]
extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{
    ParameterType, ParameterValue, ReturnType,
};
use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_common::flatbuffer_wrappers::util::get_flatbuffer_result_from_int;

use hyperlight_guest::error::{HyperlightGuestError, Result};
use hyperlight_guest_bin::guest_function::definition::GuestFunctionDefinition;
use hyperlight_guest_bin::guest_function::register::register_function;
use hyperlight_guest_bin::host_comm::{call_host_function, call_host_function_without_returning_result};

fn print_output(function_call: &FunctionCall) -> Result<Vec<u8>> {
    if let ParameterValue::String(message) = function_call.parameters.clone().unwrap()[0].clone() {
        call_host_function(
            "HostPrint",
            Some(Vec::from(&[ParameterValue::String(message.to_string())])),
            ReturnType::Int,
        )?;
        let result = get_host_value_return_as_int()?;
        Ok(get_flatbuffer_result_from_int(result))
    } else {
        Err(HyperlightGuestError::new(
            ErrorCode::GuestFunctionParameterTypeMismatch,
            "Invalid parameters passed to simple_print_output".to_string(),
        ))
    }
}

#[no_mangle]
pub extern "C" fn hyperlight_main() {
    let print_output_def = GuestFunctionDefinition::new(
        "PrintOutput".to_string(),
        Vec::from(&[ParameterType::String]),
        ReturnType::Int,
        print_output as i64,
    );
    register_function(print_output_def);
}

#[no_mangle]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    let function_name = function_call.function_name.clone();
    return Err(HyperlightGuestError::new(
        ErrorCode::GuestFunctionNotFound,
        function_name,
    ));
}
```

For additional examples of using the Hyperlight host Rust library, see
the [./src/hyperlight_host/examples](./src/hyperlight_host/examples) directory.

For examples of guest applications, see the [./src/tests/c_guests](./src/tests/c_guests) directory for C guests and
the [./src/tests/rust_guests](./src/tests/rust_guests) directory for Rust guests.

> Note: Hyperlight guests can be written using the Hyperlight Rust or C Guest libraries.

## Repository Structure

- Hyperlight Host Libraries (i.e., the ones that create and manage the VMs)
    - [src/hyperlight_host](./src/hyperlight_host) - This is the Rust Hyperlight host library.

- Hyperlight Guest Libraries (i.e., the ones to make it easier to create guests that run inside the VMs)
    - [src/hyperlight_guest](./src/hyperlight_guest) - The core Rust library for Hyperlight guests. It provides only the essential building blocks for interacting with the host environment, including the VM exit mechanism (`outb`), abstractions for calling host functions and receiving return values, and the input/output stacks used for guest-host communication.
    - [src/hyperlight_guest_bin](./src/hyperlight_guest_bin/) - An extension to the core Rust library for Hyperlight guests. It contains more opinionated components (e.g., panic handler, heap initialization, musl-specific imports, logging, and exception handling).
    - [src/hyperlight_guest_capi](./src/hyperlight_guest_capi) - A C-compatible wrapper around `hyperlight_guest_bin`, exposing its core functionality for use in C programs and other languages via FFI.

- Hyperlight Common (functionality used by both the host and the guest)
    - [src/hyperlight_common](./src/hyperlight_common)

- Test Guest Applications:
    - [src/tests/rust_guests](./src/tests/rust_guests) - This directory contains three Hyperlight Guest programs written
      in Rust, which are intended to be launched within partitions as "guests".
    - [src/tests/c_guests](./src/tests/c_guests) - This directory contains two Hyperlight Guest programs written in C,
      which are intended to be launched within partitions as "guests".

- Tests:
    - [src/hyperlight-testing](./src/hyperlight_testing) - Shared testing code for Hyperlight projects built in Rust.

## Try it yourself!

You can run Hyperlight on:

- [Linux with KVM][kvm].
- [Windows with Windows Hypervisor Platform (WHP).][whp] -  Note that you need Windows 11 / Windows Server 2022 or later to use hyperlight, if you are running on earlier versions of Windows then you should consider using our devcontainer on [GitHub codespaces]((https://codespaces.new/hyperlight-dev/hyperlight)) or WSL2.
- Windows Subsystem for Linux 2 (see instructions [here](https://learn.microsoft.com/en-us/windows/wsl/install) for Windows client and [here](https://learn.microsoft.com/en-us/windows/wsl/install-on-server) for Windows Server) with KVM.
- Azure Linux with mshv (note that you need mshv to be installed to use Hyperlight)

After having an environment with a hypervisor setup, running the example has the following pre-requisites:

1. On Linux or WSL, you'll most likely need build essential. For Ubuntu, run `sudo apt install build-essential`. For
   Azure Linux, run `sudo dnf install build-essential`.
2. [Rust](https://www.rust-lang.org/tools/install). Install toolchain v1.85 or later.
3. [just](https://github.com/casey/just). `cargo install just` On Windows you also need [pwsh](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4).
4. [clang and LLVM](https://clang.llvm.org/get_started.html).
    - On Ubuntu, run:

        ```sh
        wget https://apt.llvm.org/llvm.sh
        chmod +x ./llvm.sh
        sudo ./llvm.sh 17 all
        sudo ln -s /usr/lib/llvm-17/bin/clang-cl /usr/bin/clang-cl
        sudo ln -s /usr/lib/llvm-17/bin/llvm-lib /usr/bin/llvm-lib
        sudo ln -s /usr/lib/llvm-17/bin/lld-link /usr/bin/lld-link
        sudo ln -s /usr/lib/llvm-17/bin/llvm-ml /usr/bin/llvm-ml
        sudo ln -s /usr/lib/llvm-17/bin/ld.lld /usr/bin/ld.lld
        sudo ln -s /usr/lib/llvm-17/bin/clang /usr/bin/clang
        ```

    - On Windows, see [this](https://learn.microsoft.com/en-us/cpp/build/clang-support-msbuild?view=msvc-170).

    - On Azure Linux, run:

        ```sh
        sudo dnf remove clang -y || true
        sudo dnf install clang17 -y
        sudo dnf install clang17-tools-extra -y
        ```

Then, we are ready to build and run the example:

```sh
just build  # build the Hyperlight library
just rg     # build the rust test guest binaries
cargo run --example hello-world
```

If all worked as expected, you should see the following message in your console:

```text
Hello, World! I am executing inside of a VM :)
```

If you get the error `Error: NoHypervisorFound` and KVM or mshv is set up then this may be a permissions issue. In bash,
you can use `ls -l /dev/kvm` or  `ls -l /dev/mshv` to check which group owns that device and then `groups` to make sure
your user is a member of that group.

For more details on how to verify that KVM is correctly installed and permissions are correct, follow the
guide [here](https://help.ubuntu.com/community/KVM/Installation).

### Or you can use a codespace

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/hyperlight-dev/hyperlight)

## Contributing to Hyperlight

If you are interested in contributing to Hyperlight, running the entire test-suite is a good way to get started. To do
so, on your console, run the following commands:

```sh
just guests  # build the c and rust test guests
just build  # build the Hyperlight library
just test # runs the tests
```

Also , please review the [CONTRIBUTING.md](./CONTRIBUTING.md) file for more information on how to contribute to
Hyperlight.

> Note: For general Hyperlight development, you may also need flatc (Flatbuffer compiler): for instructions,
> see [here](https://github.com/google/flatbuffers).
> Copyright © contributors to Hyperlight, established as Hyperlight a Series of LF Projects, LLC.

## Join our Community Meetings

This project holds fortnightly community meetings to discuss the project's progress, roadmap, and any other topics of interest. The meetings are open to everyone, and we encourage you to join us.

- **When**: Every other Wednesday 09:00 (PST/PDT) [Convert to your local time](https://dateful.com/convert/pst-pdt-pacific-time?t=09)
- **Where**: Zoom! - Agenda and information on how to join can be found in the [Hyperlight Community Meeting Notes](https://hackmd.io/blCrncfOSEuqSbRVT9KYkg#Agenda). Please log into hackmd to edit!

## Chat with us on the CNCF Slack

The Hyperlight project Slack is hosted in the CNCF Slack #hyperlight. To join the Slack, [join the CNCF Slack](https://www.cncf.io/membership-faq/#how-do-i-join-cncfs-slack), and join the #hyperlight channel.

## More Information

For more information, please refer to our compilation of documents in the [`docs/` directory](./docs/README.md).

## Code of Conduct

See the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

[wsl2]: https://docs.microsoft.com/en-us/windows/wsl/install

[kvm]: https://help.ubuntu.com/community/KVM/Installation

[whp]: https://devblogs.microsoft.com/visualstudio/hyper-v-android-emulator-support/#1-enable-hyper-v-and-the-windows-hypervisor-platform
