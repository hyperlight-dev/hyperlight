# Getting Started with Hyperlight

This guide covers everything you need to start using Hyperlight in your own project.

## Prerequisites to run Hyperlight

These are the minimum requirements to use Hyperlight as a library in your own project.

- **A supported hypervisor:**
  - Linux: [KVM](https://help.ubuntu.com/community/KVM/Installation) or Microsoft Hypervisor (MSHV)
  - Windows: [Windows Hypervisor Platform](https://docs.microsoft.com/en-us/virtualization/api/#windows-hypervisor-platform) (WHP)
  - macOS (Apple silicon): [Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (HVF)
- **[Rust](https://www.rust-lang.org/tools/install)**, installed via `rustup`.
- **Platform build tools** (provides the C linker required by Rust):
  - Ubuntu/Debian: `sudo apt install build-essential`
  - Azure Linux: `sudo dnf install build-essential`
  - Windows: Visual Studio Build Tools with the C++ workload and the Windows SDK. `rustup` prompts you to install them if missing.

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

### macOS

Requires macOS 26 or later on Apple silicon. Hyperlight uses
[Hypervisor.framework](https://developer.apple.com/documentation/hypervisor) (HVF)
via the `hvf` cargo feature of `hyperlight-host`, which is not enabled by default:

```toml
hyperlight-host = { version = "0.16.0", features = ["hvf"] }
```

Two macOS-specific things to know:

1. **Entitlement.** Every executable that creates a VM — your application, and
   Hyperlight's per-sandbox surrogate processes — must be signed with the
   `com.apple.security.hypervisor` entitlement. Ad-hoc signing is sufficient for
   development. Save this as `hvf-entitlements.plist`:

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>com.apple.security.hypervisor</key>
        <true/>
    </dict>
    </plist>
    ```

    and sign your binary after every build:

    ```sh
    codesign --sign - --entitlements hvf-entitlements.plist --force target/debug/your-app
    ```

    Hyperlight's surrogate binaries are extracted and ad-hoc signed automatically
    at runtime; only your own executables need manual signing. Without the
    entitlement, sandbox creation fails with `NoHypervisorFound`.

2. **One VM per process.** Hypervisor.framework allows only a single VM per
   process, so Hyperlight runs each sandbox's VM in a small surrogate helper
   process (see [Hyperlight Surrogate](./hyperlight-surrogate-development-notes.md)).
   This is transparent in normal use. Setting `HYPERLIGHT_MAX_SURROGATES=0`
   disables surrogates and selects the in-process backend, which limits the
   process to one live sandbox at a time.

If building guest binaries on macOS:

- Use `rustup` for your Rust installation — guest builds require the toolchain
  pinned in `rust-toolchain.toml`, and distributions that shadow it (e.g.
  Homebrew Rust) do not work.
- Install LLVM (`brew install llvm`); Xcode's `ar` cannot archive the ELF
  objects used when linking C guests.
- Until a `cargo-hyperlight` release newer than 0.1.13 is published, install it
  from git (0.1.13 does not compile on macOS):

    ```sh
    cargo install --locked --git https://github.com/hyperlight-dev/cargo-hyperlight cargo-hyperlight
    ```

### WSL2

Follow the Ubuntu/Debian instructions above inside your WSL2 instance. WSL2 uses KVM.
See [install WSL](https://learn.microsoft.com/en-us/windows/wsl/install) for setup instructions.

## Quick start

The easiest way to get started is to use the `cargo hyperlight new` command. This creates a ready-to-build project with both a host application and a guest binary:

```sh
cargo install --locked cargo-hyperlight
cargo hyperlight new my-project
```

Build and run:

```sh
cd my-project/guest && cargo hyperlight build
cd ../host && cargo run
```

You should see:

```text
Hello, World! Today is Monday.
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
