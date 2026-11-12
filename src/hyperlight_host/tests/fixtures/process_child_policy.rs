// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

#[cfg(target_os = "linux")]
fn main() -> hyperlight_host::Result<()> {
    use hyperlight_host::{new_error, process};

    // SAFETY: capture runs once before threads. Any invitation comes from the trusted launcher.
    let startup = unsafe { process::ProcessStartup::capture() }?;
    if startup.is_none() && std::env::args().skip(1).collect::<Vec<_>>() == ["--policy-child"] {
        return Ok(());
    }
    let startup = startup.ok_or_else(|| new_error!("Worker startup resources are required"))?;
    let allow_children = match std::fs::read("/child-policy") {
        Ok(mode) if mode == b"allow" => true,
        Ok(mode) if mode == b"deny" => false,
        Ok(_) => return Err(new_error!("Invalid packaged child policy")),
        // Existing qualification images require denial without a policy file.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let mut functions = process::ProcessHostFunctions::default();
    functions.bind(
        process::HostFunctionContract::<(i32, i32), i32>::new(
            "HostAdd",
            process::Idempotency::Idempotent,
        ),
        move |a, b| {
            let check = move || {
                let result = std::process::Command::new("/program")
                    .arg("--policy-child")
                    .status();
                if allow_children {
                    assert!(result.expect("Child creation must succeed").success());
                } else {
                    let error = result.expect_err("Child process creation must be denied");
                    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
                }
            };
            check();
            std::thread::spawn(move || {
                check();
                a + b
            })
            .join()
            .expect("Confined Rust thread must complete")
        },
    )?;
    functions.bind(
        process::HostFunctionContract::<(), u32>::new(
            "ProcessId",
            process::Idempotency::Idempotent,
        ),
        std::process::id,
    )?;
    functions.run(startup)
}

#[cfg(not(target_os = "linux"))]
fn main() -> hyperlight_host::Result<()> {
    Err(hyperlight_host::new_error!("Linux qualification fixture"))
}
