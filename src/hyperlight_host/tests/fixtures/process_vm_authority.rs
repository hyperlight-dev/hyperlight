// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::io::Read;
use std::sync::Mutex;

use hyperlight_host::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider, OsResourceRights,
    ProcessControl, ProcessHostFunctions, ProcessOptions, ProcessProfile, ProcessResourceManifest,
    ProcessStartup, RequestedControl, VmBackend,
};
use hyperlight_host::{Result, SandboxBuilder, new_error};

const WORKER: &str = "vm-authority";
const ECHO: HostFunctionContract<(String,), String> =
    HostFunctionContract::new("HostEchoString", Idempotency::NonIdempotent);

fn run_worker(startup: ProcessStartup) -> Result<()> {
    if startup.name()? != WORKER {
        return Err(new_error!("Unexpected VM-authority worker name"));
    }
    let backend = startup.vm_authority_backend()?;
    let manifest = ProcessResourceManifest::new()
        .with_vm_authority(backend)?
        .with_file(OsResourceRights::READ)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            resources
                .take_vm_authority(backend)?
                .install_for_current_generation()?;
            let ids = resources.ids();
            let [guest_id] = ids.as_slice() else {
                return Err(new_error!(
                    "The VM-authority worker requires one guest resource"
                ));
            };
            let mut guest = resources.take_file(*guest_id, OsResourceRights::READ)?;
            let mut bytes = Vec::new();
            guest.read_to_end(&mut bytes)?;
            let inner = Mutex::new(SandboxBuilder::from_bytes(bytes).build()?);
            functions.bind(ECHO, move |input: String| -> Result<String> {
                inner
                    .lock()
                    .map_err(|error| new_error!("Nested sandbox lock failed: {error}"))?
                    .call("Echo", input)
            })
        },
    )
}

fn profile() -> ProcessProfile {
    ProcessProfile::new([
        RequestedControl {
            control: ProcessControl::MemoryLimit(512 << 20),
            required: true,
        },
        RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        },
    ])
}

fn backend() -> Result<VmBackend> {
    #[cfg(target_os = "windows")]
    {
        Ok(VmBackend::Whp)
    }
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/dev/kvm").exists() {
            Ok(VmBackend::Kvm)
        } else if std::path::Path::new("/dev/mshv").exists() {
            Ok(VmBackend::Mshv)
        } else {
            Err(new_error!("No supported Linux VM authority device exists"))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(new_error!(
            "Function-worker VM authority is unavailable on this platform"
        ))
    }
}

fn run_controller() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [guest] = args.as_slice() else {
        return Err(new_error!("Usage: process_vm_authority GUEST"));
    };
    let backend = backend()?;
    let mut provider = MeshProcessProvider::discover().map_err(|error| {
        new_error!(
            "Process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    provider.register_vm_authority(WORKER, backend)?;
    provider.register_file(WORKER, std::fs::File::open(guest)?, OsResourceRights::READ)?;
    let worker =
        HostFunctionProcess::new(ProcessOptions::for_provider(WORKER, profile())).function(ECHO);
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .host_function_process(worker)
        .build()?;
    let expected = "generation-bound nested VM".to_owned();
    let actual = sandbox.call::<String>("RoundTripHostString", expected.clone())?;
    if actual != expected {
        return Err(new_error!("Nested sandbox returned the wrong value"));
    }
    println!("Generation-bound VM authority created a nested sandbox");
    Ok(())
}

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    match unsafe { ProcessStartup::capture() }? {
        Some(startup) => run_worker(startup),
        None => run_controller(),
    }
}
