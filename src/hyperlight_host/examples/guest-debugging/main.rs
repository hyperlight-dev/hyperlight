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
#![allow(clippy::disallowed_macros)]
use std::thread;

use hyperlight_host::sandbox::SandboxConfiguration;
#[cfg(gdb)]
use hyperlight_host::sandbox::config::DebugInfo;
use hyperlight_host::{MultiUseSandbox, UninitializedSandbox};

/// Build a sandbox configuration that enables GDB debugging when the `gdb` feature is enabled.
fn get_sandbox_cfg() -> Option<SandboxConfiguration> {
    #[cfg(gdb)]
    {
        let mut cfg = SandboxConfiguration::default();
        let debug_info = DebugInfo { port: 8080 };
        cfg.set_guest_debug_info(debug_info);

        Some(cfg)
    }

    #[cfg(not(gdb))]
    None
}

fn main() -> hyperlight_host::Result<()> {
    let cfg = get_sandbox_cfg();

    // Create an uninitialized sandbox with a guest binary and debug enabled
    let mut uninitialized_sandbox_dbg = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        cfg, // sandbox configuration
    )?;

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        None, // sandbox configuration
    )?;

    // Register a host functions
    uninitialized_sandbox_dbg.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Register a host functions
    uninitialized_sandbox.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Note: This function is unused, it's just here for demonstration purposes

    // Initialize sandboxes to be able to call host functions
    let mut multi_use_sandbox_dbg: MultiUseSandbox = uninitialized_sandbox_dbg.evolve()?;
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve()?;

    // Call guest function
    multi_use_sandbox_dbg
        .call::<()>("UseSSE2Registers", ())
        .unwrap();

    let message =
        "Hello, World! I am executing inside of a VM with debugger attached :)\n".to_string();
    multi_use_sandbox_dbg
        .call::<i32>(
            "PrintOutput", // function must be defined in the guest binary
            message.clone(),
        )
        .unwrap();

    let message =
        "Hello, World! I am executing inside of a VM without debugger attached :)\n".to_string();
    multi_use_sandbox
        .call::<i32>(
            "PrintOutput", // function must be defined in the guest binary
            message.clone(),
        )
        .unwrap();

    Ok(())
}

#[cfg(gdb)]
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use hyperlight_host::{Result, new_error};
    use io::{BufReader, BufWriter, Read, Write};
    use serial_test::serial;

    use super::*;

    #[cfg(not(windows))]
    const GDB_COMMAND: &str = "rust-gdb";
    #[cfg(windows)]
    const GDB_COMMAND: &str = "gdb";

    fn write_cmds_file(cmd_file_path: &str, cmd: &str) -> io::Result<()> {
        let file = File::create(cmd_file_path)?;
        let mut writer = BufWriter::new(file);

        // write from string to file
        writer.write_all(cmd.as_bytes())?;

        writer.flush()
    }

    fn run_guest_and_gdb(
        cmd_file_path: &str,
        out_file_path: &str,
        cmd: &str,
        checker: fn(String) -> bool,
    ) -> Result<()> {
        // write gdb commands to file

        write_cmds_file(&cmd_file_path, cmd).expect("Failed to write gdb commands to file");

        let features = "gdb";

        // build it before running to avoid a race condition below
        Command::new("cargo")
            .arg("build")
            .arg("--example")
            .arg("guest-debugging")
            .arg("--features")
            .arg(features)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .status()
            .map_err(|e| new_error!("Failed to build guest process: {}", e))?;

        let mut guest_child = Command::new("cargo")
            .arg("run")
            .arg("--example")
            .arg("guest-debugging")
            .arg("--features")
            .arg(features)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| new_error!("Failed to start guest process: {}", e))?;

        // wait 3 seconds for the gdb to connect
        thread::sleep(Duration::from_secs(3));

        let mut gdb = Command::new(GDB_COMMAND)
            .arg("-nx") // Don't load any .gdbinit files
            .arg("--nw")
            .arg("--batch")
            .arg("-x")
            .arg(cmd_file_path)
            .spawn()
            .map_err(|e| new_error!("Failed to start gdb process: {}", e))?;

        // wait 3 seconds for the gdb to connect
        thread::sleep(Duration::from_secs(10));

        // check if the guest process has finished
        match guest_child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    Err(new_error!(
                        "Guest process exited with non-zero status: {}",
                        status
                    ))?;
                }
            }
            Ok(None) => {
                guest_child
                    .kill()
                    .map_err(|e| new_error!("Failed to kill child process: {}", e))?;
            }
            Err(e) => {
                Err(new_error!("error attempting to wait guest: {}", e))?;
            }
        }

        // check if the gdb process has finished
        match gdb.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    Err(new_error!(
                        "Gdb process exited with non-zero status: {}",
                        status
                    ))?;
                }
            }
            Ok(None) => {
                gdb.kill()
                    .map_err(|e| new_error!("Failed to kill guest process: {}", e))?;
            }
            Err(e) => {
                Err(new_error!("error attempting to wait gdb: {}", e))?;
            }
        }

        check_output(&out_file_path, checker)
    }

    fn check_output(out_file_path: &str, checker: fn(contents: String) -> bool) -> Result<()> {
        let results = File::open(out_file_path)
            .map_err(|e| new_error!("Failed to open gdb.output file: {}", e))?;
        let mut reader = BufReader::new(results);
        let mut contents = String::new();
        reader.read_to_string(&mut contents).unwrap();

        if checker(contents) {
            Ok(())
        } else {
            Err(new_error!(
                "Failed to find expected output in gdb.output file"
            ))
        }
    }

    fn cleanup(out_file_path: &str, cmd_file_path: &str) -> Result<()> {
        let res1 = std::fs::remove_file(out_file_path)
            .map_err(|e| new_error!("Failed to remove gdb.output file: {}", e));
        let res2 = std::fs::remove_file(cmd_file_path)
            .map_err(|e| new_error!("Failed to remove gdb-commands.txt file: {}", e));

        res1?;
        res2?;

        Ok(())
    }

    #[test]
    #[serial]
    fn test_gdb_end_to_end() {
        let out_dir = std::env::var("OUT_DIR").expect("Failed to get out dir");
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("Failed to get manifest dir")
            .replace('\\', "/");
        let out_file_path = format!("{out_dir}/gdb.output");
        let cmd_file_path = format!("{out_dir}/gdb-commands.txt");

        let cmd = format!(
            "file {manifest_dir}/../tests/rust_guests/bin/debug/simpleguest
                target remote :8080

                set pagination off
                set logging file {out_file_path}
                set logging enabled on

                break hyperlight_main
                    commands
                    echo \"Stopped at hyperlight_main breakpoint\\n\"
                    backtrace

                    continue
                end

                continue

                set logging enabled off
                quit
            "
        );

        #[cfg(windows)]
        let cmd = format!("set osabi none\n{}", cmd);

        let checker = |contents: String| contents.contains("Stopped at hyperlight_main breakpoint");

        let result = run_guest_and_gdb(&cmd_file_path, &out_file_path, &cmd, checker);

        // cleanup
        let cleanup_result = cleanup(&out_file_path, &cmd_file_path);
        assert!(cleanup_result.is_ok(), "{}", cleanup_result.unwrap_err());
        // check if the test passed - done at the end to ensure cleanup is done
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }

    #[test]
    #[serial]
    fn test_gdb_sse_check() {
        let out_dir = std::env::var("OUT_DIR").expect("Failed to get out dir");
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("Failed to get manifest dir")
            .replace('\\', "/");
        println!("manifest dir {manifest_dir}");
        let out_file_path = format!("{out_dir}/gdb-sse.output");
        let cmd_file_path = format!("{out_dir}/gdb-sse--commands.txt");

        let cmd = format!(
            "file {manifest_dir}/../tests/rust_guests/bin/debug/simpleguest
                target remote :8080

                set pagination off
                set logging file {out_file_path}
                set logging enabled on

                break main.rs:simpleguest::use_sse2_registers
                commands 1
                    print $xmm1.v4_float
                    break +2
                    commands 2
                        print $xmm1.v4_float
                        continue
                    end
                    continue
                end
                

                continue

                set logging enabled off
                quit
            "
        );

        #[cfg(windows)]
        let cmd = format!("set osabi none\n{}", cmd);

        let checker = |contents: String| contents.contains("$2 = [1.20000005, 0, 0, 0]");
        let result = run_guest_and_gdb(&cmd_file_path, &out_file_path, &cmd, checker);

        // cleanup
        let cleanup_result = cleanup(&out_file_path, &cmd_file_path);
        assert!(cleanup_result.is_ok(), "{}", cleanup_result.unwrap_err());
        // check if the test passed - done at the end to ensure cleanup is done
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }
}
