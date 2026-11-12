// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use hyperlight_host::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
    OsResourceExportPolicy, OsResourceRights, ProcessControl, ProcessHostFunctions, ProcessOptions,
    ProcessProfile, ProcessResourceManifest, ProcessStartup, RequestedControl,
};
use hyperlight_host::{Result, SandboxBuilder, new_error};

const WORKER: &str = "file-resource";
const RIGHTS: OsResourceRights = OsResourceRights::READ.union(OsResourceRights::WRITE);
const ECHO: HostFunctionContract<(String,), String> =
    HostFunctionContract::new("HostEchoString", Idempotency::NonIdempotent);

#[cfg(target_os = "linux")]
fn anonymous_file() -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;

    // SAFETY: memfd_create returns a new owned descriptor on success.
    let descriptor =
        unsafe { libc::memfd_create(c"hyperlight-process-resource".as_ptr(), libc::MFD_CLOEXEC) };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is the unique owned result of memfd_create.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(target_os = "linux"))]
fn anonymous_file() -> Result<std::fs::File> {
    Ok(tempfile::tempfile()?)
}

fn qualification_rights() -> Result<Option<OsResourceRights>> {
    match std::env::var("HYPERLIGHT_TEST_RESOURCE_RIGHTS").as_deref() {
        Ok("read") => Ok(Some(OsResourceRights::READ)),
        Ok("write") => Ok(Some(OsResourceRights::WRITE)),
        Ok("read-write") => Ok(Some(RIGHTS)),
        Err(_) => Ok(None),
        Ok(value) => Err(new_error!("Unknown test resource rights '{value}'")),
    }
}

fn run_qualification_worker(startup: ProcessStartup, rights: OsResourceRights) -> Result<()> {
    let mut manifest = ProcessResourceManifest::new().with_file(rights)?;
    if std::env::var("HYPERLIGHT_TEST_RESOURCE_EXPORTS").as_deref() != Ok("disabled") {
        manifest = manifest
            .with_file_exports(OsResourceExportPolicy::files(OsResourceRights::READ, 1)?)?;
    }
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            let ids = resources.ids();
            let [id] = ids.as_slice() else {
                return Err(new_error!(
                    "The file-resource worker requires exactly one resource"
                ));
            };
            let file = Arc::new(Mutex::new(resources.take_file(*id, rights)?));
            let generation = resources
                .generation()
                .ok_or_else(|| new_error!("The file-resource worker has no resource generation"))?;
            let exporter = resources.exporter();
            functions.bind(ECHO, move |input: String| -> Result<String> {
                let mut file = file
                    .lock()
                    .map_err(|error| new_error!("Transferred file lock failed: {error}"))?;
                let mut original = String::new();
                if rights.contains(OsResourceRights::READ) {
                    file.seek(SeekFrom::Start(0))?;
                    file.read_to_string(&mut original)?;
                }
                if rights.contains(OsResourceRights::WRITE) {
                    file.seek(SeekFrom::End(0))?;
                    write!(file, "[generation={generation}]{input}")?;
                    file.flush()?;
                }
                if let Some(exporter) = &exporter {
                    let result = format!("{original}[generation={generation}]{input}");
                    let mut exported = anonymous_file()?;
                    exported.write_all(result.as_bytes())?;
                    exported.seek(SeekFrom::Start(0))?;
                    exporter.export_file(&exported, OsResourceRights::READ)?;
                }
                Ok(original)
            })
        },
    )
}

fn run_scenario_worker(startup: ProcessStartup) -> Result<()> {
    let manifest = ProcessResourceManifest::new()
        .with_file(RIGHTS)?
        .with_file(OsResourceRights::READ)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [ECHO.erase()],
        manifest,
        move |resources, functions| {
            let ids = resources.ids();
            let [read_write_id, read_only_id] = ids.as_slice() else {
                return Err(new_error!(
                    "The resource-transfer scenario requires exactly two resources"
                ));
            };
            let read_write = resources.take_file(*read_write_id, RIGHTS)?;
            let read_only = resources.take_file(*read_only_id, OsResourceRights::READ)?;
            let files = Arc::new(Mutex::new((read_write, read_only)));
            functions.bind(ECHO, move |input: String| -> Result<String> {
                let mut files = files
                    .lock()
                    .map_err(|error| new_error!("Transferred file lock failed: {error}"))?;
                let (read_write, read_only) = &mut *files;
                read_write.seek(SeekFrom::Start(0))?;
                let mut writable_value = String::new();
                read_write.read_to_string(&mut writable_value)?;
                read_write.seek(SeekFrom::End(0))?;
                write!(read_write, "{input}")?;
                read_write.flush()?;

                read_only.seek(SeekFrom::Start(0))?;
                let mut read_only_value = String::new();
                read_only.read_to_string(&mut read_only_value)?;
                let denial = match read_only.write_all(input.as_bytes()) {
                    Ok(()) => {
                        return Err(new_error!(
                            "Read-only capability unexpectedly permitted a write"
                        ));
                    }
                    Err(denial) => denial,
                };
                #[cfg(unix)]
                let expected_denial = denial.kind() == std::io::ErrorKind::PermissionDenied
                    || denial.raw_os_error() == Some(libc::EBADF);
                #[cfg(not(unix))]
                let expected_denial = denial.kind() == std::io::ErrorKind::PermissionDenied;
                if !expected_denial {
                    return Err(new_error!(
                        "Read-only capability returned an unexpected write error: {denial}"
                    ));
                }
                Ok(format!(
                    "read-write={writable_value};read-only={read_only_value};write-denied=true"
                ))
            })
        },
    )
}

fn run_worker(startup: ProcessStartup) -> Result<()> {
    if startup.name()? != WORKER {
        return Err(new_error!("Unexpected file-resource worker name"));
    }
    match qualification_rights()? {
        Some(rights) => run_qualification_worker(startup, rights),
        None => run_scenario_worker(startup),
    }
}

fn profile() -> ProcessProfile {
    ProcessProfile::new(vec![RequestedControl {
        control: ProcessControl::MemoryLimit(512 << 20),
        required: true,
    }])
}

fn run_controller() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [guest, read_write_path, read_only_path, input] = args.as_slice() else {
        return Err(new_error!(
            "Usage: process_file_resource GUEST READ_WRITE_FILE READ_ONLY_FILE INPUT"
        ));
    };
    let input = input
        .to_str()
        .ok_or_else(|| new_error!("Input must be valid UTF-8"))?
        .to_owned();
    let read_write_path = Path::new(read_write_path);
    let read_only_path = Path::new(read_only_path);
    let mut read_write = OpenOptions::new()
        .read(true)
        .write(true)
        .open(read_write_path)?;
    let read_write_verification = read_write.try_clone()?;
    read_write.seek(SeekFrom::Start(0))?;
    let mut writable_original = String::new();
    read_write.read_to_string(&mut writable_original)?;
    let mut read_only = OpenOptions::new().read(true).open(read_only_path)?;
    let mut read_only_verification = read_only.try_clone()?;
    let mut read_only_original = String::new();
    read_only.read_to_string(&mut read_only_original)?;

    let mut provider = MeshProcessProvider::discover().map_err(|error| {
        new_error!(
            "Process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    provider.register_file(WORKER, read_write, RIGHTS)?;
    provider.register_file(WORKER, read_only, OsResourceRights::READ)?;
    let worker =
        HostFunctionProcess::new(ProcessOptions::for_provider(WORKER, profile())).function(ECHO);
    let mut sandbox = SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider.clone())
        .host_function_process(worker)
        .build()?;
    let result = sandbox.call::<String>("RoundTripHostString", input.clone())?;
    let expected_result =
        format!("read-write={writable_original};read-only={read_only_original};write-denied=true");
    if result != expected_result {
        return Err(new_error!(
            "Typed resource transfer returned '{result}', expected '{expected_result}'"
        ));
    }
    let mut read_write_verification = read_write_verification;
    read_write_verification.seek(SeekFrom::Start(0))?;
    let mut writable_actual = String::new();
    read_write_verification.read_to_string(&mut writable_actual)?;
    if writable_actual != format!("{writable_original}{input}") {
        return Err(new_error!(
            "Read/write capability did not update its resource"
        ));
    }
    read_only_verification.seek(SeekFrom::Start(0))?;
    let mut read_only_actual = String::new();
    read_only_verification.read_to_string(&mut read_only_actual)?;
    if read_only_actual != read_only_original {
        return Err(new_error!("Read-only capability changed its resource"));
    }
    println!("Typed resource capability transfer:");
    println!("  read/write capability: read and write succeeded");
    println!("  read-only capability: read succeeded");
    println!(
        "  read-only capability write: denied ({})",
        std::io::ErrorKind::PermissionDenied
    );
    Ok(())
}

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    match unsafe { ProcessStartup::capture() }? {
        Some(startup) => run_worker(startup),
        None => run_controller(),
    }
}
