/*
Copyright 2025  The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! # Crash Dump Example
//!
//! This example demonstrates Hyperlight's crash dump feature, which generates
//! ELF core dump files containing vCPU state (general-purpose registers,
//! segment registers, XSAVE state) and guest memory (snapshot, scratch,
//! and any dynamically mapped regions). These can be loaded into `gdb`
//! for post-mortem debugging.
//!
//! The crash dump feature must be enabled via the `crashdump` Cargo feature:
//!
//! ```bash
//! cargo run --example crashdump --features crashdump
//! ```
//!
//! ## What this example shows
//!
//! 1. **Automatic crash dump** — When a guest triggers a VM-level fault
//!    that bypasses the guest's exception handler (e.g., writing to a
//!    region the hypervisor mapped as read-only), Hyperlight automatically
//!    writes an ELF core dump file.
//!
//! 2. **On-demand crash dump** — When the guest's IDT catches the fault
//!    (e.g., undefined instruction) and reports it back as a `GuestAborted`
//!    error, the automatic crash dump is not triggered. You can call
//!    [`MultiUseSandbox::generate_crashdump`] explicitly to capture the
//!    VM state.
//!
//! 3. **Disabling crash dumps per sandbox** — You can opt out of crash dump
//!    generation for individual sandboxes via
//!    [`SandboxConfiguration::set_guest_core_dump`].
//!
//! 4. **On-demand crash dump from a debugger** — The `generate_crashdump()`
//!    method is available for use from gdb while the guest is mid-execution.
//!
//! ## How crashes are reported
//!
//! The Hyperlight guest runtime includes an exception handler that catches most
//! hardware faults (page faults, undefined instructions, etc.) and reports them
//! back to the host as `GuestAborted` errors with diagnostic information.
//!
//! Automatic core dumps are triggered for unhandled VM-level exits that bypass
//! the guest exception handler. For most debugging workflows, the on-demand
//! `generate_crashdump()` method (called from gdb) is the recommended way to
//! capture VM state.
//!
//! ## Controlling the output directory
//!
//! Set the `HYPERLIGHT_CORE_DUMP_DIR` environment variable to specify a custom
//! output directory. If unset, core dump files are written to the system's
//! temporary directory:
//!
//! ```bash
//! HYPERLIGHT_CORE_DUMP_DIR=/tmp/hl_dumps cargo run --example crashdump --features crashdump
//! ```
//!
//! Core dump files are named `hl_core_<timestamp>.elf`.

#![allow(clippy::disallowed_macros)]

#[cfg(all(crashdump, target_os = "linux"))]
use std::io::Write;

use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};

fn main() -> hyperlight_host::Result<()> {
    env_logger::init();

    let guest_path =
        hyperlight_testing::simple_guest_as_string().expect("Cannot find simpleguest binary");

    println!("=== Hyperlight Crash Dump Example ===\n");

    // -----------------------------------------------------------------------
    // Part 1: Automatic crash dump (VM-level fault bypasses guest handler)
    // -----------------------------------------------------------------------
    println!("--- Part 1: Automatic crash dump (memory access violation) ---\n");

    guest_crash_auto_dump(&guest_path)?;

    // -----------------------------------------------------------------------
    // Part 2: On-demand crash dump (guest-caught exception)
    // -----------------------------------------------------------------------
    println!("\n--- Part 2: On-demand crash dump (guest-caught exception) ---\n");

    guest_crash_with_on_demand_dump(&guest_path)?;

    // -----------------------------------------------------------------------
    // Part 3: Guest crash with crash dump feature disabled per-sandbox
    // -----------------------------------------------------------------------
    println!("\n--- Part 3: Guest crash with crash dump disabled per sandbox ---\n");

    guest_crash_with_dump_disabled(&guest_path)?;

    // -----------------------------------------------------------------------
    // Part 4: On-demand crash dump (from gdb)
    // -----------------------------------------------------------------------
    println!("\n--- Part 4: On-demand crash dump API ---");

    print_on_demand_info();

    println!("\n=== Done ===");
    Ok(())
}

/// Demonstrates an **automatic** crash dump triggered by a VM-level fault
/// that bypasses the guest exception handler entirely.
///
/// The guest has an IDT (Interrupt Descriptor Table) that catches most CPU
/// exceptions (page faults, undefined instructions, etc.) and reports them
/// back to the host as `GuestAborted` errors.
///
/// However, some faults are intercepted by the **hypervisor** before the
/// CPU delivers them to the guest. For example, when the guest writes to
/// a memory region that the hypervisor mapped as read-only (via EPT/NPT),
/// the hypervisor sees an MMIO write exit. The guest IDT never fires.
///
/// These hypervisor-level exits produce `MemoryAccessViolation` errors,
/// and Hyperlight automatically writes a crash dump for them.
///
/// This function:
/// 1. Maps a file into the guest as read-only (via `map_file_cow`)
/// 2. Calls `WriteMappedBuffer` which tries to write to that region
/// 3. The hypervisor rejects the write → `MemoryAccessViolation`
/// 4. The crash dump is written automatically (no explicit call needed)
#[cfg(all(crashdump, target_os = "linux"))]
fn guest_crash_auto_dump(guest_path: &str) -> hyperlight_host::Result<()> {
    let cfg = SandboxConfiguration::default();

    let uninitialized_sandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(guest_path.to_string()), Some(cfg))?;

    let mut sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    // Map a file as read-only into the guest at a known address.
    let mapping_file = create_mapping_file();
    let guest_base: u64 = 0x200000000;
    let len = sandbox.map_file_cow(mapping_file.as_path(), guest_base)?;
    println!("Mapped {len} bytes at guest address {guest_base:#x} (read-only).\n");

    // Call WriteMappedBuffer — the guest maps the address in its page tables
    // as writable, but the hypervisor's EPT/NPT mapping is read-only.
    // The write triggers an MMIO exit that the guest exception handler
    // never sees.
    println!("Calling guest function 'WriteMappedBuffer' on read-only region...");
    let result = sandbox.call::<bool>("WriteMappedBuffer", (guest_base, len));

    match result {
        Ok(_) => println!("Unexpected success."),
        Err(e) => {
            println!("Guest crashed with a memory access violation (as expected).");
            println!("Error: {e}\n");
            println!(
                "The crash dump was written automatically by the VM run loop.\n\
                 No explicit generate_crashdump() call was needed."
            );
        }
    }

    Ok(())
}

/// Fallback when crashdump feature or Linux is not available.
#[cfg(not(all(crashdump, target_os = "linux")))]
fn guest_crash_auto_dump(_guest_path: &str) -> hyperlight_host::Result<()> {
    println!(
        "This part requires the `crashdump` feature and Linux.\n\
         Re-run with: cargo run --example crashdump --features crashdump"
    );
    Ok(())
}

/// Create a temporary file with known content to map into the guest.
///
/// Creates a page-aligned (4 KiB) file containing a marker string.
#[cfg(all(crashdump, target_os = "linux"))]
fn create_mapping_file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join("hyperlight_crashdump_example.bin");
    let mut f = std::fs::File::create(&path).expect("create mapping file");
    let mut content = vec![0u8; 4096];
    let marker = b"HYPERLIGHT_CRASHDUMP_EXAMPLE";
    content[..marker.len()].copy_from_slice(marker);
    f.write_all(&content).expect("write mapping file");
    path
}

/// Demonstrates an **on-demand** crash dump for a guest-caught exception.
///
/// When the guest triggers a CPU exception that its IDT handles (e.g., an
/// undefined instruction via `ud2`), the guest exception handler catches
/// it and sends a `GuestAborted` error back to the host via an I/O port.
///
/// Because the error is reported through the I/O path (not a VM-level
/// fault), the automatic crash dump code in the VM run loop is not reached.
/// To get a crash dump in this case, call `generate_crashdump()` explicitly.
fn guest_crash_with_on_demand_dump(guest_path: &str) -> hyperlight_host::Result<()> {
    let cfg = SandboxConfiguration::default();

    let uninitialized_sandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(guest_path.to_string()), Some(cfg))?;

    let mut sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    // A normal call succeeds.
    let message = "Hello from crashdump example!\n".to_string();
    sandbox.call::<i32>("PrintOutput", message)?;

    // This call triggers a ud2 instruction in the guest. The guest's IDT
    // catches the #UD exception and reports it back to the host as a
    // GuestAborted error via I/O. This does NOT trigger an automatic crash
    // dump — we must call generate_crashdump() explicitly.
    println!("Calling guest function 'TriggerException'...");
    let result = sandbox.call::<()>("TriggerException", ());

    match result {
        Ok(_) => println!("Unexpected success."),
        Err(e) => {
            println!("Guest crashed as expected.");
            println!("Error: {e}\n");

            #[cfg(crashdump)]
            {
                // Generate the core dump explicitly. The automatic crash dump
                // path in the VM run loop is bypassed when the guest exception
                // handler catches the fault and reports it via IO (GuestAborted).
                // Calling generate_crashdump() is the recommended post-mortem
                // debugging workflow.
                sandbox.generate_crashdump()?;
            }

            #[cfg(not(crashdump))]
            println!(
                "The `crashdump` feature is not enabled.\n\
                 Re-run with: cargo run --example crashdump --features crashdump"
            );
        }
    }

    Ok(())
}

/// Shows how to disable crash dump generation for a specific sandbox.
///
/// This is useful when you know certain sandboxes will intentionally crash
/// (e.g., during fuzzing or testing) and you don't want the overhead of
/// writing core dump files.
fn guest_crash_with_dump_disabled(guest_path: &str) -> hyperlight_host::Result<()> {
    #[allow(unused_mut)]
    let mut cfg = SandboxConfiguration::default();

    #[cfg(crashdump)]
    {
        // Disable core dump generation for this sandbox
        cfg.set_guest_core_dump(false);
        println!("Core dump generation disabled via cfg.set_guest_core_dump(false).");
    }

    let uninitialized_sandbox =
        UninitializedSandbox::new(GuestBinary::FilePath(guest_path.to_string()), Some(cfg))?;

    let mut sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    println!("Calling guest function 'TriggerException'...");
    let result = sandbox.call::<()>("TriggerException", ());

    match result {
        Ok(_) => println!("Unexpected success."),
        Err(e) => {
            println!("Guest crashed as expected: {e}");

            #[cfg(crashdump)]
            println!("No core dump was generated (disabled for this sandbox).");

            #[cfg(not(crashdump))]
            println!(
                "The `crashdump` feature is not enabled.\n\
                 Re-run with: cargo run --example crashdump --features crashdump"
            );
        }
    }

    Ok(())
}

/// Prints information about the on-demand crash dump API.
///
/// The [`MultiUseSandbox::generate_crashdump`] method captures the current
/// vCPU state and writes it to an ELF core dump file. This is primarily
/// useful when attached to a running process via gdb — for example, when a
/// guest function hangs or takes too long to complete.
///
/// ## gdb workflow
///
/// ```text
/// # Attach to the running process
/// sudo gdb -p <pid>
///
/// # Find the thread running the guest
/// (gdb) info threads
/// (gdb) thread <thread_number>
///
/// # Navigate to the frame with the sandbox variable
/// (gdb) backtrace
/// (gdb) frame <frame_number>
///
/// # Generate the core dump
/// (gdb) call sandbox.generate_crashdump()
/// ```
///
/// The core dump file will be written to `HYPERLIGHT_CORE_DUMP_DIR` (or the
/// system temp directory) as `hl_core_<timestamp>.elf`.
fn print_on_demand_info() {
    #[cfg(crashdump)]
    println!(
        "\nThe on-demand crash dump API is available:\n\
         \n\
         MultiUseSandbox::generate_crashdump()\n\
         \n\
         This is designed for use from a debugger (e.g., gdb) while the\n\
         guest is mid-execution. Attach to your process with gdb and call\n\
         sandbox.generate_crashdump() to capture the VM state.\n\
         \n\
         See docs/how-to-debug-a-hyperlight-guest.md for the full workflow."
    );
}

// ---------------------------------------------------------------------------
// GDB-based crash dump validation tests
//
// These tests follow the same pattern used by the `guest-debugging` example:
// generate a core dump, then load it in GDB (batch mode) and verify the
// output contains the expected register values and mapped memory content.
//
// Requires:
//   - The `crashdump` cargo feature
//   - Linux (mmap-based file mapping is used)
//   - `rust-gdb` available on PATH
// ---------------------------------------------------------------------------
#[cfg(crashdump)]
#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use hyperlight_host::sandbox::SandboxConfiguration;
    use hyperlight_host::{GuestBinary, MultiUseSandbox, UninitializedSandbox};
    use serial_test::serial;

    #[cfg(not(windows))]
    const GDB_COMMAND: &str = "rust-gdb";

    /// Guest base address where we map the test data file.
    /// This address sits outside the normal sandbox memory layout.
    const MAP_GUEST_BASE: u64 = 0x200000000;

    /// Sentinel string written into the mapped region so we can verify
    /// GDB can read it back from the core dump.
    const TEST_SENTINEL: &[u8] = b"HYPERLIGHT_CRASHDUMP_TEST";

    // -- helpers ------------------------------------------------------------

    /// Returns `true` if `rust-gdb` (or `gdb` on Windows) is available.
    fn gdb_is_available() -> bool {
        Command::new(GDB_COMMAND)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_or(false, |s| s.success())
    }

    /// Create a page-aligned temp file in `dir` containing [`TEST_SENTINEL`]
    /// padded to one page (4 KiB).
    fn create_test_data_file(dir: &Path) -> PathBuf {
        let path = dir.join("test_mapping.bin");
        let mut f = fs::File::create(&path).expect("create test data file");
        let mut content = vec![0u8; 4096];
        content[..TEST_SENTINEL.len()].copy_from_slice(TEST_SENTINEL);
        f.write_all(&content).expect("write test data");
        path
    }

    /// Build a sandbox, map a file with known content, trigger a crash and
    /// return the path to the generated ELF core dump.
    ///
    /// `dump_dir` controls where `HYPERLIGHT_CORE_DUMP_DIR` points.
    fn generate_crashdump_with_content(dump_dir: &Path) -> PathBuf {
        // Direct core dump output to a known directory
        // SAFETY: No other threads are reading this env var concurrently
        // in this test process. Tests using this helper are marked #[serial].
        unsafe {
            std::env::set_var("HYPERLIGHT_CORE_DUMP_DIR", dump_dir.as_os_str());
        }

        let data_file = create_test_data_file(dump_dir);

        // Create sandbox with default config (crashdump enabled)
        let guest_path =
            hyperlight_testing::simple_guest_as_string().expect("Cannot find simpleguest binary");
        let cfg = SandboxConfiguration::default();
        let u_sbox =
            UninitializedSandbox::new(GuestBinary::FilePath(guest_path), Some(cfg)).unwrap();
        let mut sbox: MultiUseSandbox = u_sbox.evolve().unwrap();

        // Map an additional test file into the guest at a known address.
        // The core dump already includes snapshot and scratch regions
        // automatically. This mapping lets us verify that GDB can read
        // a specific sentinel string from a known address.
        sbox.map_file_cow(&data_file, MAP_GUEST_BASE)
            .expect("map_file_cow");

        // Trigger a crash — TriggerException causes a GuestAborted error via
        // the guest exception handler's IO-based reporting mechanism.
        let result = sbox.call::<()>("TriggerException", ());
        assert!(result.is_err(), "TriggerException should return an error");

        // Use the on-demand crash dump API to capture the VM state.
        // The automatic crash dump path in the VM run loop is bypassed for
        // IO-based errors (GuestAborted), so we call generate_crashdump()
        // explicitly — this is the recommended workflow for post-mortem
        // debugging anyway.
        sbox.generate_crashdump()
            .expect("generate_crashdump should succeed");

        // Find the generated hl_core_*.elf file
        let mut elf_files: Vec<PathBuf> = fs::read_dir(dump_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n.starts_with("hl_core_") && n.ends_with(".elf"))
            })
            .collect();

        assert!(
            !elf_files.is_empty(),
            "No core dump file (hl_core_*.elf) found in {}",
            dump_dir.display()
        );

        // Return the newest one (lexicographic sort by timestamp works)
        elf_files.sort();
        elf_files.pop().unwrap()
    }

    /// Write GDB batch commands to `cmd_path`, run GDB, and return the
    /// content of the logging output file.
    fn run_gdb_batch(cmd_path: &Path, out_path: &Path, cmds: &str) -> String {
        fs::write(cmd_path, cmds).expect("write gdb command file");

        let output = Command::new(GDB_COMMAND)
            .arg("-nx") // skip .gdbinit
            .arg("--nw")
            .arg("--batch")
            .arg("-x")
            .arg(cmd_path)
            .output()
            .expect("Failed to spawn rust-gdb — is it installed?");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        fs::read_to_string(out_path).unwrap_or_else(|_| {
            panic!("GDB did not produce an output file.\nstdout:\n{stdout}\nstderr:\n{stderr}");
        })
    }

    // -- tests --------------------------------------------------------------

    /// Verify that GDB can load the crash dump and display vCPU registers.
    #[test]
    #[serial]
    fn test_crashdump_gdb_registers() {
        if !gdb_is_available() {
            eprintln!("Skipping test: {GDB_COMMAND} not found on PATH");
            return;
        }

        let dump_dir = tempfile::tempdir().expect("create temp dir");
        let core_path = generate_crashdump_with_content(dump_dir.path());
        let guest_path = hyperlight_testing::simple_guest_as_string().expect("simpleguest binary");

        let cmd_file = dump_dir.path().join("gdb_reg_cmds.txt");
        let out_file = dump_dir.path().join("gdb_reg_output.txt");

        let cmds = format!(
            "\
set pagination off
set logging file {out}
set logging enabled on
file {binary}
core-file {core}
echo === REGISTERS ===\\n
info registers
echo === DONE ===\\n
set logging enabled off
quit
",
            out = out_file.display(),
            binary = guest_path,
            core = core_path.display(),
        );

        let gdb_output = run_gdb_batch(&cmd_file, &out_file, &cmds);
        println!("GDB register output:\n{gdb_output}");

        assert!(
            gdb_output.contains("=== REGISTERS ==="),
            "GDB should have printed the REGISTERS marker.\nOutput:\n{gdb_output}"
        );
        assert!(
            gdb_output.contains("rip") && gdb_output.contains("rsp"),
            "GDB should show rip and rsp register values.\nOutput:\n{gdb_output}"
        );
        assert!(
            gdb_output.contains("=== DONE ==="),
            "GDB should have completed successfully.\nOutput:\n{gdb_output}"
        );
    }

    /// Verify that GDB can read the mapped memory region from the core dump
    /// and that it contains the sentinel string we wrote before the crash.
    #[test]
    #[serial]
    fn test_crashdump_gdb_memory() {
        if !gdb_is_available() {
            eprintln!("Skipping test: {GDB_COMMAND} not found on PATH");
            return;
        }

        let dump_dir = tempfile::tempdir().expect("create temp dir");
        let core_path = generate_crashdump_with_content(dump_dir.path());
        let guest_path = hyperlight_testing::simple_guest_as_string().expect("simpleguest binary");

        let cmd_file = dump_dir.path().join("gdb_mem_cmds.txt");
        let out_file = dump_dir.path().join("gdb_mem_output.txt");

        let cmds = format!(
            "\
set pagination off
set logging file {out}
set logging enabled on
file {binary}
core-file {core}
echo === MEMORY ===\\n
x/s {addr:#x}
echo === DONE ===\\n
set logging enabled off
quit
",
            out = out_file.display(),
            binary = guest_path,
            core = core_path.display(),
            addr = MAP_GUEST_BASE,
        );

        let gdb_output = run_gdb_batch(&cmd_file, &out_file, &cmds);
        println!("GDB memory output:\n{gdb_output}");

        let sentinel_str =
            std::str::from_utf8(TEST_SENTINEL).expect("TEST_SENTINEL is valid UTF-8");

        assert!(
            gdb_output.contains("=== MEMORY ==="),
            "GDB should have printed the MEMORY marker.\nOutput:\n{gdb_output}"
        );
        assert!(
            gdb_output.contains(sentinel_str),
            "GDB should read back the sentinel string \"{sentinel_str}\" from mapped memory.\n\
             Output:\n{gdb_output}"
        );
        assert!(
            gdb_output.contains("=== DONE ==="),
            "GDB should have completed successfully.\nOutput:\n{gdb_output}"
        );
    }
}
