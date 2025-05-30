/*
Copyright 2024 The Hyperlight Authors.

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

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
#[cfg(gdb)]
use hyperlight_host::sandbox::config::DebugInfo;
use hyperlight_host::sandbox::SandboxConfiguration;
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
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

    // Create an uninitialized sandbox with a guest binary
    let mut uninitialized_sandbox = UninitializedSandbox::new(
        hyperlight_host::GuestBinary::FilePath(
            hyperlight_testing::simple_guest_as_string().unwrap(),
        ),
        cfg, // sandbox configuration
    )?;

    // Register a host functions
    uninitialized_sandbox.register("Sleep5Secs", || {
        thread::sleep(std::time::Duration::from_secs(5));
        Ok(())
    })?;
    // Note: This function is unused, it's just here for demonstration purposes

    // Initialize sandbox to be able to call host functions
    let mut multi_use_sandbox: MultiUseSandbox = uninitialized_sandbox.evolve(Noop::default())?;

    // Call guest function
    let message = "Hello, World! I am executing inside of a VM :)\n".to_string();
    let result = multi_use_sandbox.call_guest_function_by_name(
        "PrintOutput", // function must be defined in the guest binary
        ReturnType::Int,
        Some(vec![ParameterValue::String(message.clone())]),
    );

    assert!(result.is_ok());

    Ok(())
}

#[cfg(gdb)]
#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use hyperlight_host::{new_error, Result};
    use io::{BufReader, BufWriter, Read, Write};

    use super::*;

    fn write_cmds_file(cmd_file_path: &str, out_file_path: &str) -> io::Result<()> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("Failed to get manifest dir");
        let file = File::create(cmd_file_path)?;
        let mut writer = BufWriter::new(file);

        // write from string to file
        writer.write_all(
            format!(
                "file {manifest_dir}/../tests/rust_guests/bin/debug/simpleguest
                target remote :8080

                set pagination off
                set logging file {out_file_path}
                set logging on

                break hyperlight_main
                    commands
                    echo \"Stopped at hyperlight_main breakpoint\\n\"
                    backtrace
                    continue
                end

                continue

                set logging off
                quit
            "
            )
            .as_bytes(),
        )?;

        writer.flush()
    }

    fn run_guest_and_gdb(cmd_file_path: &str, out_file_path: &str) -> Result<()> {
        // write gdb commands to file

        write_cmds_file(&cmd_file_path, &out_file_path)
            .expect("Failed to write gdb commands to file");

        #[cfg(mshv3)]
        let features = "gdb,mshv3";
        #[cfg(not(mshv3))]
        let features = "gdb";

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

        let mut gdb = Command::new("rust-gdb")
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

        check_output(&out_file_path)
    }

    fn check_output(out_file_path: &str) -> Result<()> {
        let results = File::open(out_file_path)
            .map_err(|e| new_error!("Failed to open gdb.output file: {}", e))?;
        let mut reader = BufReader::new(results);
        let mut contents = String::new();
        reader.read_to_string(&mut contents).unwrap();

        if contents.contains("Stopped at hyperlight_main breakpoint") {
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
    fn test_gdb_end_to_end() {
        let out_dir = std::env::var("OUT_DIR").expect("Failed to get out dir");
        let out_file_path = format!("{out_dir}/gdb.output");
        let cmd_file_path = format!("{out_dir}/gdb-commands.txt");

        let result = run_guest_and_gdb(&cmd_file_path, &out_file_path);

        // cleanup
        let cleanup_result = cleanup(&out_file_path, &cmd_file_path);
        assert!(cleanup_result.is_ok(), "{}", cleanup_result.unwrap_err());
        // check if the test passed - done at the end to ensure cleanup is done
        assert!(result.is_ok(), "{}", result.unwrap_err());
    }
}
