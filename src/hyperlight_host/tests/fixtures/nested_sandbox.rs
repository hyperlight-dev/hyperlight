// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Same-process nested Hyperlight sandbox proof.

use std::io::{BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use hyperlight_host::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, MeshProcessProvider,
    OsResourceExportPolicy, OsResourceRights, ProcessControl, ProcessHostFunctions, ProcessOptions,
    ProcessProfile, ProcessResourceExporter, ProcessResourceManifest, ProcessStartup,
    RequestedControl, VmBackend,
};
use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::{HyperlightError, Result, SandboxBuilder, new_error};

const WORKER: &str = "nested-sandbox";
const MAX_PENDING_EXPORTS: usize = 16;
const MARKER_RIGHTS: OsResourceRights = OsResourceRights::READ.union(OsResourceRights::WRITE);
const COMPOSE: HostFunctionContract<(String, u32), String> =
    HostFunctionContract::new("NestedSandboxCompose", Idempotency::NonIdempotent);
const COMPOSE_RECOVERABLE: HostFunctionContract<(String, String, u32), String> =
    HostFunctionContract::new("NestedSandboxComposeRecoverable", Idempotency::Idempotent);
const EVIDENCE: HostFunctionContract<(), String> =
    HostFunctionContract::new("NestedSandboxEvidence", Idempotency::Idempotent);
const CRASH_NON_IDEMPOTENT: HostFunctionContract<(String, u32), String> = HostFunctionContract::new(
    "NestedSandboxComposeCrashNonIdempotent",
    Idempotency::NonIdempotent,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PidEvidence {
    worker: u32,
    inner_sandbox_host: u32,
    inner_host: u32,
    guest_generation: u64,
    marker_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallEvidence {
    pids: PidEvidence,
    resource_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RecoveryState {
    Empty,
    Started {
        key: String,
        message: String,
        repeat: u32,
    },
    Completed {
        key: String,
        message: String,
        repeat: u32,
        worker: u32,
        inner_sandbox_host: u32,
        inner_host: u32,
        guest_generation: u64,
        marker_generation: u64,
        result: String,
    },
}

#[derive(Clone, Debug)]
enum ExportInvocation {
    Ordinary,
    Recoverable {
        key: String,
        message: String,
        repeat: u32,
    },
}

impl PidEvidence {
    fn encode(self) -> String {
        format!(
            "worker={};inner-sandbox-host={};inner-host={};guest-generation={};marker-generation={}",
            self.worker,
            self.inner_sandbox_host,
            self.inner_host,
            self.guest_generation,
            self.marker_generation
        )
    }

    fn parse(value: &str) -> Result<Self> {
        let mut fields = value.split(';');
        let worker = parse_pid(fields.next(), "worker")?;
        let inner_sandbox_host = parse_pid(fields.next(), "inner-sandbox-host")?;
        let inner_host = parse_pid(fields.next(), "inner-host")?;
        let guest_generation = parse_generation(fields.next(), "guest-generation")?;
        let marker_generation = parse_generation(fields.next(), "marker-generation")?;
        if fields.next().is_some() {
            return Err(new_error!("Nested PID evidence has surplus fields"));
        }
        Ok(Self {
            worker,
            inner_sandbox_host,
            inner_host,
            guest_generation,
            marker_generation,
        })
    }
}

fn parse_pid(field: Option<&str>, name: &str) -> Result<u32> {
    let prefix = format!("{name}=");
    field
        .and_then(|field| field.strip_prefix(&prefix))
        .ok_or_else(|| new_error!("Nested PID evidence is missing '{name}'"))?
        .parse()
        .map_err(|error| new_error!("Nested PID evidence has invalid '{name}': {error}"))
}

fn parse_generation(field: Option<&str>, name: &str) -> Result<u64> {
    let prefix = format!("{name}=");
    field
        .and_then(|field| field.strip_prefix(&prefix))
        .ok_or_else(|| new_error!("Nested PID evidence is missing '{name}'"))?
        .parse()
        .map_err(|error| new_error!("Nested PID evidence has invalid '{name}': {error}"))
}

fn expected(message: &str, repeat: u32) -> String {
    let host = format!("process-host-function({message})");
    let values = std::iter::repeat_n(host, repeat as usize)
        .collect::<Vec<_>>()
        .join(",");
    format!("inner-guest-function({values})")
}

fn export_value(exporter: &ProcessResourceExporter, value: &str) -> Result<()> {
    let mut exported = pathname_free_file()?;
    exported.write_all(value.as_bytes())?;
    exported.seek(SeekFrom::Start(0))?;
    exporter.export_file(&exported, OsResourceRights::READ)?;
    Ok(())
}

fn validate_repeat(repeat: u32) -> Result<()> {
    if repeat == 0 || repeat > 64 {
        return Err(new_error!("Nested sandbox repeat must be between 1 and 64"));
    }
    Ok(())
}

fn validate_record_field(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(new_error!(
            "Recovery {name} must be nonempty and contain no newlines"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_process_exited(process_id: i32) -> Result<()> {
    let path = std::path::PathBuf::from(format!("/proc/{process_id}"));
    for _ in 0..100 {
        if !path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(new_error!(
        "Nested worker process {process_id} remained after teardown"
    ))
}

#[cfg(not(target_os = "linux"))]
fn ensure_process_exited(_process_id: i32) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_status(process_id: u32) -> Option<(u32, u32)> {
    let status = std::fs::read_to_string(format!("/proc/{process_id}/status")).ok()?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse()
        .ok()?;
    let namespace = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()?;
    Some((parent, namespace))
}

#[cfg(target_os = "linux")]
fn report_contains_namespace_process(root_process_id: i32, namespace_id: u32) -> Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let Some(process_id) = entry
            .ok()
            .and_then(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        else {
            continue;
        };
        let Some((_, namespace)) = process_status(process_id) else {
            continue;
        };
        let mut ancestor = process_id;
        for _ in 0..64 {
            if ancestor == root_process_id as u32 {
                if namespace == namespace_id {
                    return Ok(true);
                }
                break;
            }
            let Some((parent, _)) = process_status(ancestor) else {
                break;
            };
            if parent == 0 || parent == ancestor {
                break;
            }
            ancestor = parent;
        }
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn report_contains_namespace_process(root_process_id: i32, namespace_id: u32) -> Result<bool> {
    Ok(root_process_id as u32 == namespace_id)
}

fn read_recovery_state(file: &mut (impl Read + Seek)) -> Result<RecoveryState> {
    file.seek(SeekFrom::Start(0))?;
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    if value.is_empty() {
        return Ok(RecoveryState::Empty);
    }
    let mut lines = value.lines();
    let state = lines
        .next()
        .ok_or_else(|| new_error!("Recovery record state is missing"))?;
    let key = lines
        .next()
        .ok_or_else(|| new_error!("Recovery record key is missing"))?
        .to_owned();
    let message = lines
        .next()
        .ok_or_else(|| new_error!("Recovery record message is missing"))?
        .to_owned();
    let repeat = lines
        .next()
        .ok_or_else(|| new_error!("Recovery record repeat is missing"))?
        .parse()
        .map_err(|error| new_error!("Recovery record repeat is invalid: {error}"))?;
    match state {
        "started" if lines.next().is_none() => Ok(RecoveryState::Started {
            key,
            message,
            repeat,
        }),
        "completed" => {
            let worker = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record worker PID is missing"))?
                .parse::<u32>()
                .map_err(|_| new_error!("Recovery record worker PID is invalid"))?;
            let inner_sandbox_host = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record sandbox-host PID is missing"))?
                .parse::<u32>()
                .map_err(|_| new_error!("Recovery record sandbox-host PID is invalid"))?;
            let inner_host = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record inner-host PID is missing"))?
                .parse::<u32>()
                .map_err(|_| new_error!("Recovery record inner-host PID is invalid"))?;
            let guest_generation = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record guest generation is missing"))?
                .parse::<u64>()
                .map_err(|_| new_error!("Recovery record guest generation is invalid"))?;
            let marker_generation = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record marker generation is missing"))?
                .parse::<u64>()
                .map_err(|_| new_error!("Recovery record marker generation is invalid"))?;
            let result = lines
                .next()
                .ok_or_else(|| new_error!("Recovery record result is missing"))?
                .to_owned();
            if lines.next().is_some() {
                return Err(new_error!("Recovery record has surplus fields"));
            }
            Ok(RecoveryState::Completed {
                key,
                message,
                repeat,
                worker,
                inner_sandbox_host,
                inner_host,
                guest_generation,
                marker_generation,
                result,
            })
        }
        _ => Err(new_error!("Recovery record state is invalid")),
    }
}

fn write_recovery_state(file: &mut (impl Write + Seek), state: &RecoveryState) -> Result<()> {
    let value = match state {
        RecoveryState::Empty => return Err(new_error!("Cannot write an empty recovery record")),
        RecoveryState::Started {
            key,
            message,
            repeat,
        } => format!("started\n{key}\n{message}\n{repeat}\n"),
        RecoveryState::Completed {
            key,
            message,
            repeat,
            worker,
            inner_sandbox_host,
            inner_host,
            guest_generation,
            marker_generation,
            result,
        } => format!(
            "completed\n{key}\n{message}\n{repeat}\n{worker}\n{inner_sandbox_host}\n{inner_host}\n{guest_generation}\n{marker_generation}\n{result}\n"
        ),
    };
    file.seek(SeekFrom::Start(0))?;
    file.write_all(value.as_bytes())?;
    file.flush()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn pathname_free_file() -> Result<std::fs::File> {
    use std::os::fd::FromRawFd;

    // SAFETY: memfd_create returns a new owned descriptor on success.
    let descriptor =
        unsafe { libc::memfd_create(c"hyperlight-nested-result".as_ptr(), libc::MFD_CLOEXEC) };
    if descriptor == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is the unique owned result of memfd_create.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(not(target_os = "linux"))]
fn pathname_free_file() -> Result<std::fs::File> {
    Ok(tempfile::tempfile()?)
}

fn assert_child_process_denied() -> Result<()> {
    fn check() -> Result<()> {
        let executable = std::env::current_exe()?;
        let error = match std::process::Command::new(executable)
            .arg("--nested-child-probe")
            .status()
        {
            Err(error) => error,
            Ok(status) => {
                return Err(new_error!(
                    "DenyChildProcesses allowed child creation with status {status}"
                ));
            }
        };
        #[cfg(target_os = "linux")]
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(new_error!(
                "Child creation failed with unexpected Linux error: {error}"
            ));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = error;
        Ok(())
    }

    check()?;
    std::thread::spawn(check)
        .join()
        .map_err(|_| new_error!("Nested child-denial probe thread panicked"))?
}

fn run_worker(startup: ProcessStartup) -> Result<()> {
    if startup.name()? != WORKER {
        return Err(new_error!("Unexpected nested-sandbox worker name"));
    }
    let backend = startup.vm_authority_backend()?;
    let export_policy = OsResourceExportPolicy::files(OsResourceRights::READ, MAX_PENDING_EXPORTS)?;
    let manifest = ProcessResourceManifest::new()
        .with_vm_authority(backend)?
        .with_file(OsResourceRights::READ)?
        .with_file(MARKER_RIGHTS)?
        .with_file_exports(export_policy)?;
    ProcessHostFunctions::run_with_resources(
        startup,
        [
            COMPOSE.erase(),
            COMPOSE_RECOVERABLE.erase(),
            EVIDENCE.erase(),
            CRASH_NON_IDEMPOTENT.erase(),
        ],
        manifest,
        move |resources, functions| {
            resources
                .take_vm_authority(backend)?
                .install_for_current_generation()?;
            let ids = resources.ids();
            let [guest_id, recovery_record_id] = ids.as_slice() else {
                return Err(new_error!(
                    "The nested worker requires guest and recovery-record resources"
                ));
            };
            let guest_generation = guest_id.generation();
            let marker_generation = recovery_record_id.generation();
            let mut guest = resources.take_file(*guest_id, OsResourceRights::READ)?;
            let recovery_record = Arc::new(Mutex::new(
                resources.take_file(*recovery_record_id, MARKER_RIGHTS)?,
            ));
            guest.seek(SeekFrom::Start(0))?;
            let mut guest_bytes = Vec::new();
            guest.read_to_end(&mut guest_bytes)?;
            let exporter = resources
                .exporter()
                .ok_or_else(|| new_error!("Nested worker export authority is missing"))?;
            let recovery_exporter = exporter.clone();
            let inner_host_pid = Arc::new(AtomicU32::new(0));
            let callback_pid = inner_host_pid.clone();
            let invocation = Arc::new(Mutex::new(None::<ExportInvocation>));
            let callback_invocation = invocation.clone();
            let callback_record = recovery_record.clone();
            let worker_pid = std::process::id();
            let evidence_worker_pid = Arc::new(AtomicU32::new(worker_pid));
            let inner_sandbox_host_pid = Arc::new(AtomicU32::new(0));
            let callback_sandbox_pid = inner_sandbox_host_pid.clone();
            let guest_len = guest_bytes.len();
            let inner = SandboxBuilder::from_bytes(guest_bytes)
                .host_function(
                    "NestedSandboxExport",
                    move |value: String| -> Result<String> {
                        let pid = std::process::id();
                        callback_pid.store(pid, Ordering::SeqCst);
                        let invocation = callback_invocation
                            .lock()
                            .map_err(|error| new_error!("Invocation lock failed: {error}"))?
                            .take()
                            .ok_or_else(|| new_error!("Nested export invocation is missing"))?;
                        if let ExportInvocation::Recoverable {
                            key,
                            message,
                            repeat,
                        } = invocation
                        {
                            let mut record = callback_record.lock().map_err(|error| {
                                new_error!("Recovery record lock failed: {error}")
                            })?;
                            write_recovery_state(
                                &mut *record,
                                &RecoveryState::Completed {
                                    key,
                                    message,
                                    repeat,
                                    worker: worker_pid,
                                    inner_sandbox_host: callback_sandbox_pid.load(Ordering::SeqCst),
                                    inner_host: pid,
                                    guest_generation,
                                    marker_generation,
                                    result: value.clone(),
                                },
                            )?;
                        }
                        export_value(&exporter, &value)?;
                        Ok(value)
                    },
                )
                .build()
                .map_err(|error| {
                    new_error!("Nested guest with {guest_len} bytes was rejected: {error}")
                })?;
            let inner = Arc::new(Mutex::new(inner));
            let compose_inner = inner.clone();
            let compose_invocation = invocation.clone();
            let compose_sandbox_pid = inner_sandbox_host_pid.clone();
            functions.bind(
                COMPOSE,
                move |message: String, repeat: u32| -> Result<String> {
                    validate_repeat(repeat)?;
                    assert_child_process_denied()?;
                    *compose_invocation
                        .lock()
                        .map_err(|error| new_error!("Invocation lock failed: {error}"))? =
                        Some(ExportInvocation::Ordinary);
                    let host_value = format!("process-host-function({message})");
                    compose_sandbox_pid.store(std::process::id(), Ordering::SeqCst);
                    compose_inner
                        .lock()
                        .map_err(|error| new_error!("Nested sandbox lock failed: {error}"))?
                        .call("NestedInnerCompose", (host_value, repeat))
                },
            )?;
            let recoverable_inner = inner.clone();
            let recoverable_invocation = invocation.clone();
            let recoverable_sandbox_pid = inner_sandbox_host_pid.clone();
            let completed_exported = Arc::new(Mutex::new(false));
            let recovery_completed_exported = completed_exported.clone();
            functions.bind(
                COMPOSE_RECOVERABLE,
                move |key: String, message: String, repeat: u32| -> Result<String> {
                    validate_record_field("invocation key", &key)?;
                    validate_record_field("message", &message)?;
                    validate_repeat(repeat)?;
                    assert_child_process_denied()?;
                    let state = {
                        let mut record = recovery_record
                            .lock()
                            .map_err(|error| new_error!("Recovery record lock failed: {error}"))?;
                        read_recovery_state(&mut *record)?
                    };
                    match state {
                        RecoveryState::Empty => {
                            let mut record = recovery_record.lock().map_err(|error| {
                                new_error!("Recovery record lock failed: {error}")
                            })?;
                            write_recovery_state(
                                &mut *record,
                                &RecoveryState::Started {
                                    key,
                                    message,
                                    repeat,
                                },
                            )?;
                            std::process::exit(86);
                        }
                        RecoveryState::Started {
                            key: recorded_key,
                            message: recorded_message,
                            repeat: recorded_repeat,
                        } if recorded_key == key
                            && recorded_message == message
                            && recorded_repeat == repeat =>
                        {
                            *recoverable_invocation
                                .lock()
                                .map_err(|error| new_error!("Invocation lock failed: {error}"))? =
                                Some(ExportInvocation::Recoverable {
                                    key,
                                    message: message.clone(),
                                    repeat,
                                });
                            let host_value = format!("process-host-function({message})");
                            recoverable_sandbox_pid.store(std::process::id(), Ordering::SeqCst);
                            recoverable_inner
                                .lock()
                                .map_err(|error| new_error!("Nested sandbox lock failed: {error}"))?
                                .call::<String>("NestedInnerCompose", (host_value, repeat))?;
                            std::process::exit(88);
                        }
                        RecoveryState::Completed {
                            key: recorded_key,
                            message: recorded_message,
                            repeat: recorded_repeat,
                            worker: _,
                            inner_sandbox_host: _,
                            inner_host: _,
                            guest_generation: _,
                            marker_generation: _,
                            result,
                        } if recorded_key == key
                            && recorded_message == message
                            && recorded_repeat == repeat =>
                        {
                            let mut exported =
                                recovery_completed_exported.lock().map_err(|error| {
                                    new_error!("Completed export lock failed: {error}")
                                })?;
                            if !*exported {
                                export_value(&recovery_exporter, &result)?;
                                *exported = true;
                            }
                            Ok(result)
                        }
                        _ => Err(new_error!(
                            "Recovery invocation does not match the provider-owned record"
                        )),
                    }
                },
            )?;
            let crash_inner = inner.clone();
            let crash_invocation = invocation.clone();
            let crash_sandbox_pid = inner_sandbox_host_pid.clone();
            functions.bind(
                CRASH_NON_IDEMPOTENT,
                move |message: String, repeat: u32| -> Result<String> {
                    validate_repeat(repeat)?;
                    *crash_invocation
                        .lock()
                        .map_err(|error| new_error!("Invocation lock failed: {error}"))? =
                        Some(ExportInvocation::Ordinary);
                    let host_value = format!("process-host-function({message})");
                    crash_sandbox_pid.store(std::process::id(), Ordering::SeqCst);
                    let _ = crash_inner
                        .lock()
                        .map_err(|error| new_error!("Nested sandbox lock failed: {error}"))?
                        .call::<String>("NestedInnerCompose", (host_value, repeat))?;
                    std::process::exit(87);
                },
            )?;
            functions.bind(EVIDENCE, move || -> Result<String> {
                let worker = evidence_worker_pid.load(Ordering::SeqCst);
                let inner_host = inner_host_pid.load(Ordering::SeqCst);
                let inner_sandbox_host = inner_sandbox_host_pid.load(Ordering::SeqCst);
                Ok(PidEvidence {
                    worker,
                    inner_sandbox_host,
                    inner_host,
                    guest_generation,
                    marker_generation,
                }
                .encode())
            })?;
            Ok(())
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
            "Nested function-worker VM authority is unavailable on this platform"
        ))
    }
}

fn configured_provider(guest: &std::path::Path) -> Result<(MeshProcessProvider, std::fs::File)> {
    let provider = MeshProcessProvider::discover().map_err(|error| {
        new_error!(
            "Process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    configure_provider(provider, guest)
}

fn configured_snapshot_provider(
    guest: &std::path::Path,
    layout: &std::path::Path,
) -> Result<(MeshProcessProvider, std::fs::File)> {
    let provider = MeshProcessProvider::discover_for_snapshot(layout).map_err(|error| {
        new_error!(
            "Snapshot process provider setup failed: {error}. See dev/process-isolation/QUICKSTART.md"
        )
    })?;
    configure_provider(provider, guest)
}

fn configure_provider(
    mut provider: MeshProcessProvider,
    guest: &std::path::Path,
) -> Result<(MeshProcessProvider, std::fs::File)> {
    provider.register_vm_authority(WORKER, backend()?)?;
    provider.register_file(WORKER, std::fs::File::open(guest)?, OsResourceRights::READ)?;
    let recovery_record = pathname_free_file()?;
    let recovery_verification = recovery_record.try_clone()?;
    provider.register_file(WORKER, recovery_record, MARKER_RIGHTS)?;
    provider.allow_file_exports(
        WORKER,
        OsResourceExportPolicy::files(OsResourceRights::READ, MAX_PENDING_EXPORTS)?,
    )?;
    Ok((provider, recovery_verification))
}

fn configured_builder(guest: &std::path::Path, provider: MeshProcessProvider) -> SandboxBuilder {
    let worker = HostFunctionProcess::new(ProcessOptions::for_provider(WORKER, profile()))
        .function(COMPOSE)
        .function(COMPOSE_RECOVERABLE)
        .function(EVIDENCE)
        .function(CRASH_NON_IDEMPOTENT);
    SandboxBuilder::from_file(guest)
        .mesh_process_provider(provider)
        .host_function_process(worker)
}

fn verify_call(
    sandbox: &mut hyperlight_host::MultiUseSandbox,
    provider: &MeshProcessProvider,
    message: &str,
    repeat: u32,
    print_diagnostics: bool,
) -> Result<CallEvidence> {
    let expected = expected(message, repeat);
    let actual = sandbox.call::<String>("NestedSandboxCompose", (message.to_owned(), repeat))?;
    if actual != expected {
        return Err(new_error!(
            "Nested sandbox returned '{actual}', expected '{expected}'"
        ));
    }
    let evidence = PidEvidence::parse(&sandbox.call::<String>("NestedSandboxEvidence", ())?)?;
    let reports = sandbox.process_reports();
    let worker = reports
        .iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Nested worker report is missing"))?;
    if worker.root_process_id <= 0 {
        return Err(new_error!("Nested worker report has an invalid process ID"));
    }
    if !report_contains_namespace_process(worker.root_process_id, evidence.worker)?
        || evidence.worker == std::process::id()
        || evidence.inner_sandbox_host != evidence.worker
        || evidence.inner_host != evidence.worker
    {
        return Err(new_error!(
            "Nested PID topology is invalid: parent={}, {evidence:?}",
            std::process::id()
        ));
    }
    if !worker.controls.iter().any(|outcome| {
        outcome.requested.control == ProcessControl::DenyChildProcesses
            && outcome.requested.required
    }) {
        return Err(new_error!(
            "DenyChildProcesses is absent from the worker report"
        ));
    }
    let mut exported = provider
        .take_exported_file(WORKER)?
        .ok_or_else(|| new_error!("Nested worker did not export its result object"))?;
    if exported.rights() != OsResourceRights::READ {
        return Err(new_error!(
            "Nested export rights were not reduced to read-only"
        ));
    }
    let resource_generation = exported.id().generation();
    if resource_generation != evidence.guest_generation
        || resource_generation != evidence.marker_generation
    {
        return Err(new_error!(
            "Nested guest, marker, and export capabilities have different generations"
        ));
    }
    let mut exported_value = String::new();
    exported.seek(SeekFrom::Start(0))?;
    exported.read_to_string(&mut exported_value)?;
    if exported_value != actual {
        return Err(new_error!(
            "Nested exported object differs from the returned value"
        ));
    }
    if print_diagnostics {
        println!(
            "NESTED_CALL message={message} repeat={repeat} result={actual} parent={} worker={} inner-sandbox-host={} inner-host={} generation={resource_generation} export-equal=true child-denied=true",
            std::process::id(),
            evidence.worker,
            evidence.inner_sandbox_host,
            evidence.inner_host,
        );
    }
    Ok(CallEvidence {
        pids: evidence,
        resource_generation,
    })
}

fn wait_for_inspection<R: BufRead, W: Write>(
    noninteractive: bool,
    stdin_is_terminal: bool,
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    if noninteractive {
        return Ok(());
    }
    if !stdin_is_terminal {
        return Err(new_error!(
            "Interactive demo input is not a terminal. Run with --noninteractive for CI or redirected input"
        ));
    }
    write!(
        output,
        "\nPress Enter to stop the nested topology and finish..."
    )?;
    output.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(new_error!(
            "Interactive demo input closed before Enter. Run with --noninteractive when no operator is present"
        ));
    }
    writeln!(output)?;
    Ok(())
}

fn run_demo(args: &[std::ffi::OsString]) -> Result<()> {
    let mut guest = None;
    let mut noninteractive = false;
    for argument in args {
        match argument.to_str() {
            Some("--noninteractive") => noninteractive = true,
            Some(value) if value.starts_with('-') => {
                return Err(new_error!("Unknown nested demo option '{value}'"));
            }
            Some(_) if guest.is_none() => guest = Some(std::path::Path::new(argument)),
            Some(value) => return Err(new_error!("Unexpected nested demo argument '{value}'")),
            None => return Err(new_error!("Nested demo arguments must be valid Unicode")),
        }
    }
    let guest =
        guest.ok_or_else(|| new_error!("Usage: nested_sandbox demo GUEST [--noninteractive]"))?;
    if !noninteractive && !std::io::stdin().is_terminal() {
        return Err(new_error!(
            "Interactive demo input is not a terminal. Run with --noninteractive for CI or redirected input"
        ));
    }
    let guest = std::fs::canonicalize(guest)
        .map_err(|error| new_error!("Nested guest canonicalization failed: {error}"))?;
    let (provider, _) = configured_provider(&guest)
        .map_err(|error| new_error!("Nested provider configuration failed: {error}"))?;
    let mut sandbox = configured_builder(&guest, provider.clone())
        .build()
        .map_err(|error| new_error!("Nested outer sandbox construction failed: {error}"))?;
    let call = verify_call(&mut sandbox, &provider, "compose", 2, false)?;
    let worker = sandbox
        .process_reports()
        .into_iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Nested worker report is missing"))?;

    println!();
    println!("Hyperlight nested sandbox demo");
    println!();
    println!("Topology");
    println!("  Application process {}", std::process::id());
    println!("    -> outer Hyperlight guest");
    println!(
        "       -> isolated host-function worker {}",
        worker.root_process_id
    );
    println!("          -> inner Hyperlight sandbox in the worker");
    println!();
    println!("Inner guest execution");
    println!("  1 inner guest-function call");
    println!("  2 co-located host-function callbacks");
    println!();
    println!("Result");
    println!("  {}", expected("compose", 2));
    println!();
    println!("Capability boundaries");
    println!("  PASS inner guest image supplied as a read-only file capability");
    println!("  PASS result exported as a read-only file capability");
    println!("  PASS undeclared child-process creation denied");
    println!(
        "  PASS guest, marker and result bound to generation {}",
        call.resource_generation
    );

    wait_for_inspection(
        noninteractive,
        std::io::stdin().is_terminal(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )?;
    let worker_root = worker.root_process_id;
    sandbox.shutdown()?;
    drop(sandbox);
    drop(provider);
    ensure_process_exited(worker_root)?;
    println!("  PASS nested worker and inner sandbox stopped cleanly");
    println!();
    println!("PASS nested sandbox composition");
    Ok(())
}

fn run_qualification(args: &[std::ffi::OsString]) -> Result<()> {
    let [guest, output] = args else {
        return Err(new_error!(
            "Usage: nested_sandbox GUEST NEW_OUTPUT_DIRECTORY"
        ));
    };
    let guest = std::fs::canonicalize(guest)
        .map_err(|error| new_error!("Nested guest canonicalization failed: {error}"))?;
    let output = std::path::Path::new(output);
    std::fs::create_dir(output)
        .map_err(|error| new_error!("Nested output directory creation failed: {error}"))?;

    let (provider, mut recovery_verification) = configured_provider(&guest)
        .map_err(|error| new_error!("Nested provider configuration failed: {error}"))?;
    let mut sandbox = configured_builder(&guest, provider.clone())
        .build()
        .map_err(|error| new_error!("Nested outer sandbox construction failed: {error}"))?;
    let first = verify_call(&mut sandbox, &provider, "compose", 1, true)?;
    let repeated = verify_call(&mut sandbox, &provider, "compose", 2, true)?;
    if repeated.pids != first.pids || repeated.resource_generation != first.resource_generation {
        return Err(new_error!(
            "Repeated calls changed the worker or resource generation"
        ));
    }
    println!(
        "Nested sandbox composition: outer guest -> process-bound worker -> inner Hyperlight sandbox in worker process; result={}",
        expected("compose", 2)
    );

    let snapshot = sandbox.snapshot()?;
    let layout = output.join("snapshot");
    let tag = OciTag::new("nested-sandbox")?;
    let digest = snapshot.save_with_process_provider(&layout, &tag, &provider)?;
    let before_restore = verify_call(&mut sandbox, &provider, "restore", 3, true)?;
    sandbox.restore(snapshot.clone())?;
    let after_restore = verify_call(&mut sandbox, &provider, "restore", 3, true)?;
    if after_restore != before_restore {
        return Err(new_error!(
            "In-place guest restore replaced the native worker or resource generation"
        ));
    }

    let recovery_key = "nested-recovery-1".to_owned();
    let recovery_message = "recovered".to_owned();
    let recovery_repeat = 2;
    let recovery_expected = expected(&recovery_message, recovery_repeat);
    let recovery = sandbox.call::<String>(
        "NestedSandboxComposeRecoverable",
        (
            recovery_key.clone(),
            recovery_message.clone(),
            recovery_repeat,
        ),
    )?;
    if recovery != recovery_expected {
        return Err(new_error!(
            "Recoverable nested composition returned '{recovery}', expected '{recovery_expected}'"
        ));
    }
    let completed = read_recovery_state(&mut recovery_verification)?;
    let RecoveryState::Completed {
        key: completed_key,
        message: completed_message,
        repeat: completed_repeat,
        worker: completed_worker,
        inner_sandbox_host: completed_sandbox_host,
        inner_host: completed_inner_host,
        guest_generation: completed_guest_generation,
        marker_generation: completed_marker_generation,
        result: completed_result,
    } = completed
    else {
        return Err(new_error!("Provider-owned recovery record is not complete"));
    };
    if completed_key != recovery_key
        || completed_message != recovery_message
        || completed_repeat != recovery_repeat
        || completed_result != recovery_expected
    {
        return Err(new_error!(
            "Provider-owned recovery record does not match the invocation"
        ));
    }
    if completed_worker == 0
        || completed_worker != completed_sandbox_host
        || completed_worker != completed_inner_host
        || completed_guest_generation != completed_marker_generation
        || completed_guest_generation == first.resource_generation
    {
        return Err(new_error!("Completed nested topology is invalid"));
    }
    let reports = sandbox.process_reports();
    let replacement = reports
        .iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Replacement worker report is missing"))?;
    if replacement.root_process_id <= 0 {
        return Err(new_error!(
            "Replacement worker report has an invalid process ID"
        ));
    }
    let replacement_root = replacement.root_process_id;
    let replacement_evidence =
        PidEvidence::parse(&sandbox.call::<String>("NestedSandboxEvidence", ())?)?;
    if !report_contains_namespace_process(replacement_root, replacement_evidence.worker)?
        || replacement_evidence.inner_sandbox_host != 0
        || replacement_evidence.inner_host != 0
        || replacement_evidence.guest_generation != replacement_evidence.marker_generation
        || replacement_evidence.guest_generation <= completed_guest_generation
    {
        return Err(new_error!("Replacement worker evidence is invalid"));
    }
    let mut recovery_export = provider
        .take_exported_file(WORKER)?
        .ok_or_else(|| new_error!("Recoverable nested call did not export its result"))?;
    if recovery_export.rights() != OsResourceRights::READ
        || recovery_export.id().generation() != replacement_evidence.guest_generation
    {
        return Err(new_error!(
            "Recoverable nested export rights or generation are invalid"
        ));
    }
    let mut recovery_export_value = String::new();
    recovery_export.seek(SeekFrom::Start(0))?;
    recovery_export.read_to_string(&mut recovery_export_value)?;
    if recovery_export_value != recovery_expected {
        return Err(new_error!(
            "Recoverable nested export differs from the final result"
        ));
    }
    let replay = sandbox.call::<String>(
        "NestedSandboxComposeRecoverable",
        (
            recovery_key.clone(),
            recovery_message.clone(),
            recovery_repeat,
        ),
    )?;
    if replay != recovery_expected {
        return Err(new_error!(
            "Completed nested replay returned a different result"
        ));
    }
    if provider.take_exported_file(WORKER)?.is_some() {
        return Err(new_error!(
            "Recoverable nested call exported more than once"
        ));
    }
    println!(
        "NESTED_RECOVERY result={recovery_expected} parent={} completed-worker={} completed-inner-sandbox-host={} completed-inner-host={} completed-generation={} replacement-worker={} delivery-generation={} export-equal=true deduplicated=true",
        std::process::id(),
        completed_worker,
        completed_sandbox_host,
        completed_inner_host,
        completed_guest_generation,
        replacement_evidence.worker,
        recovery_export.id().generation(),
    );

    drop(sandbox);
    drop(provider);
    ensure_process_exited(replacement_root)?;
    let loaded = Arc::new(Snapshot::checked_load(&layout, digest)?);
    let (fresh_provider, _fresh_recovery_verification) =
        configured_snapshot_provider(&guest, &layout)?;
    let mut fresh = SandboxBuilder::from_snapshot(loaded)
        .mesh_process_provider(fresh_provider.clone())
        .build()?;
    let reconstructed = verify_call(&mut fresh, &fresh_provider, "reconstructed", 2, true)?;
    let fresh_root = fresh
        .process_reports()
        .iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Reconstructed worker report is missing"))?
        .root_process_id;
    let non_idempotent = fresh.call::<String>(
        "NestedSandboxComposeCrashNonIdempotent",
        ("non-idempotent".to_owned(), 1_u32),
    );
    if !matches!(
        non_idempotent,
        Err(HyperlightError::GuestError(ErrorCode::HostFunctionError, ref message))
            if message.contains("execution is uncertain and replay is forbidden")
    ) {
        return Err(new_error!(
            "Non-idempotent crash did not fail closed without replay"
        ));
    }
    let final_root = fresh
        .process_reports()
        .iter()
        .find(|report| report.name == WORKER)
        .ok_or_else(|| new_error!("Final replacement worker report is missing"))?
        .root_process_id;
    if final_root <= 0 || final_root == fresh_root {
        return Err(new_error!(
            "Non-idempotent crash did not create a final replacement worker"
        ));
    }
    let final_evidence = PidEvidence::parse(&fresh.call::<String>("NestedSandboxEvidence", ())?)?;
    if !report_contains_namespace_process(final_root, final_evidence.worker)?
        || final_evidence.inner_sandbox_host != 0
        || final_evidence.inner_host != 0
        || final_evidence.guest_generation != final_evidence.marker_generation
        || final_evidence.guest_generation <= reconstructed.resource_generation
    {
        return Err(new_error!("Final replacement worker evidence is invalid"));
    }
    println!("NESTED_NON_IDEMPOTENT_CRASH=replay-forbidden");
    drop(fresh);
    ensure_process_exited(fresh_root)?;
    ensure_process_exited(final_root)?;
    if fresh_provider.take_exported_file(WORKER)?.is_some() {
        return Err(new_error!("Nested export residue remained after teardown"));
    }
    println!(
        "Nested sandbox verified: parent={}, worker={}, reconstructed={}",
        std::process::id(),
        completed_worker,
        reconstructed.pids.worker
    );
    Ok(())
}

fn run_controller() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--nested-child-probe"] {
        return Err(new_error!("Child probe unexpectedly executed"));
    }
    if args.first().is_some_and(|argument| argument == "demo") {
        return run_demo(&args[1..]);
    }
    run_qualification(&args)
}

fn main() -> Result<()> {
    // SAFETY: capture is the first operation, before threads or environment access.
    let startup = unsafe { ProcessStartup::capture() }?;
    if startup.is_none() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    }
    match startup {
        Some(startup) => run_worker(startup),
        None => run_controller(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_transform_has_two_visible_stages() {
        assert_eq!(
            expected("boom", 1),
            "inner-guest-function(process-host-function(boom))"
        );
        assert_eq!(
            expected("boom", 2),
            "inner-guest-function(process-host-function(boom),process-host-function(boom))"
        );
    }

    #[test]
    fn pid_evidence_round_trips_exactly() {
        let evidence = PidEvidence {
            worker: 17,
            inner_sandbox_host: 17,
            inner_host: 17,
            guest_generation: 9,
            marker_generation: 9,
        };
        assert_eq!(PidEvidence::parse(&evidence.encode()).unwrap(), evidence);
        assert!(PidEvidence::parse("worker=17").is_err());
        assert!(
            PidEvidence::parse(
                "worker=17;inner-sandbox-host=17;inner-host=17;guest-generation=9;marker-generation=9;extra=1"
            )
            .is_err()
        );
    }

    #[test]
    fn repeat_bounds_fail_closed() {
        assert!(validate_repeat(0).is_err());
        assert!(validate_repeat(1).is_ok());
        assert!(validate_repeat(64).is_ok());
        assert!(validate_repeat(65).is_err());
    }

    #[test]
    fn recovery_record_distinguishes_started_and_completed() {
        let mut record = std::io::Cursor::new(Vec::new());
        let started = RecoveryState::Started {
            key: "key-1".to_owned(),
            message: "boom".to_owned(),
            repeat: 2,
        };
        write_recovery_state(&mut record, &started).unwrap();
        assert_eq!(read_recovery_state(&mut record).unwrap(), started);
        let completed = RecoveryState::Completed {
            key: "key-1".to_owned(),
            message: "boom".to_owned(),
            repeat: 2,
            worker: 17,
            inner_sandbox_host: 17,
            inner_host: 17,
            guest_generation: 7,
            marker_generation: 7,
            result: expected("boom", 2),
        };
        write_recovery_state(&mut record, &completed).unwrap();
        assert_eq!(read_recovery_state(&mut record).unwrap(), completed);
    }

    #[test]
    fn noninteractive_demo_pause_returns_without_input() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        wait_for_inspection(true, false, &mut input, &mut output).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn interactive_demo_pause_requires_a_terminal() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert!(
            wait_for_inspection(false, false, &mut input, &mut output)
                .unwrap_err()
                .to_string()
                .contains("--noninteractive")
        );
    }
}
