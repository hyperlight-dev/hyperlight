# Getting Started with Hyperlight

This guide covers everything you need to start using Hyperlight in your own project.

## Prerequisites to run Hyperlight

These are the minimum requirements to use Hyperlight as a library in your own project.

- **A supported hypervisor:**
  - Linux: [KVM](https://help.ubuntu.com/community/KVM/Installation) or Microsoft Hypervisor (MSHV)
  - Windows: [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/#windows-hypervisor-platform) (WHP)
- **[Rust](https://www.rust-lang.org/tools/install)**, installed via `rustup`. On Windows, this also installs MSVC and the Windows SDK.
- **Platform build tools** (provides the C linker required by Rust):
  - Ubuntu/Debian: `sudo apt install build-essential`
  - Azure Linux: `sudo dnf install build-essential`
  - Windows: Installed automatically by `rustup`

### Building guest binaries

If you're writing Hyperlight guest programs (not just using the host library), you'll also need:

- **Clang/LLVM** (see [platform-specific instructions](#platform-specific-setup) below)
- **[cargo-hyperlight](https://github.com/hyperlight-dev/cargo-hyperlight)** - install via `cargo install --locked cargo-hyperlight`

## Platform-specific setup

### Windows

Requires Windows 11 Pro/Enterprise/Education or Windows Server 2025 or later.

1. Enable the Windows Hypervisor Platform (requires a reboot):

    ```powershell
    Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart
    ```

2. If building guest binaries, install Clang/LLVM via the Visual Studio installer (installed by `rustup`):

    ```powershell
    $vsPath = & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -property installationPath
    & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" modify `
        --installPath $vsPath `
        --add Microsoft.VisualStudio.Component.VC.Llvm.Clang `
        --quiet --norestart
    ```

### Ubuntu / Debian

1. Install build tools:

    ```sh
    sudo apt install build-essential
    ```

2. Ensure KVM is available and your user has access:

    ```sh
    ls -l /dev/kvm
    # If needed, add yourself to the kvm group:
    sudo usermod -aG kvm $USER
    ```

    For more details, see the [KVM installation guide](https://help.ubuntu.com/community/KVM/Installation).

3. If building guest binaries, install LLVM/Clang:

    ```sh
    wget https://apt.llvm.org/llvm.sh
    chmod +x llvm.sh
    sudo ./llvm.sh 18
    ```

    The LLVM binaries are installed to `/usr/lib/llvm-18/bin/`. You may want to add this to your PATH:

    ```sh
    echo 'export PATH=/usr/lib/llvm-18/bin:$PATH' >> ~/.bashrc
    source ~/.bashrc
    ```

### Azure Linux

1. Install build tools:

    ```sh
    sudo dnf install build-essential
    ```

2. Ensure mshv is available (`/dev/mshv`).

3. If building guest binaries, install clang:

    ```sh
    sudo dnf install clang
    ```

### WSL2

Follow the Ubuntu/Debian instructions above inside your WSL2 instance. WSL2 uses KVM.
See [install WSL](https://learn.microsoft.com/en-us/windows/wsl/install) for setup instructions.

## Quick start

The easiest way to get started is to use the `cargo hyperlight scaffold` command. This creates a ready-to-build project with both a host application and a guest binary:

```sh
cargo install --locked cargo-hyperlight
cargo hyperlight scaffold my-project
```

Build and run:

```sh
cd my-project/guest && cargo hyperlight build
cd ../host && cargo run
```

You should see:

```text
Hello, World! Today is Wednesday.
2 + 3 = 5
count = 1
count = 2
count = 3
count after restore = 1
```

> **Note:** If you modify the guest code, remember to rebuild it with `cargo hyperlight build` before running the host again. The host loads the guest binary from disk, so changes won't take effect until the guest is recompiled.

## Troubleshooting

If you get `Error: NoHypervisorFound`, check that your hypervisor device exists and is accessible:

**Linux:**

```sh
ls -l /dev/kvm
ls -l /dev/mshv
```

Verify your user is in the owning group with `groups`. If not, add yourself (e.g., `sudo usermod -aG kvm $USER`) and log out/in.

**Windows** (Admin PowerShell):

```powershell
Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match 'Hyper-V|HypervisorPlatform|VirtualMachinePlatform'} | Format-Table
```

For additional debugging tips, see [How to build a Hyperlight guest binary](./how-to-build-a-hyperlight-guest-binary.md).

## Or use a codespace

Skip all setup and use a preconfigured environment:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/hyperlight-dev/hyperlight)
