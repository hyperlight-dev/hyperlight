// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Dedicated VM ownership and direct, lifecycle-supervised native dispatch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnType, ReturnValue,
};
use mesh::MeshPayload;
use mesh::rpc::{Rpc, RpcSend};
#[cfg(test)]
use mesh_process::ProcessConfig;
use tracing_core::LevelFilter;

use super::launch::{
    CleanupOwner, OwnedHost, PreparedProcess, ProcessCleanupError, ProcessGuard, ProcessLauncher,
    ProcessReport,
};
use super::program::{FunctionContractDefinition, ProcessTopologyDefinition, ProgramRole};
use super::{ProcessHostFunctions, ProcessStartup, runtime, transport};
use crate::hypervisor::{InterruptHandle, InterruptHandleInternal, InterruptHandleStateMachine};
use crate::sandbox::snapshot::{OciTag, Snapshot};
use crate::sandbox::uninitialized::{GuestBlob, GuestEnvironment};
use crate::sandbox::{LocalSandbox, PtRootFinder, SandboxConfiguration, SandboxStatus};
use crate::{GuestBinary, HostFunctions, HyperlightError, MultiUseSandbox, Result, new_error};

const VERSION: u32 = 4;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(MeshPayload)]
enum Request {
    #[mesh(1)]
    Call(Rpc<Vec<u8>, Reply<Vec<u8>>>),
    #[mesh(2)]
    Snapshot(Rpc<(), Reply<SnapshotImage>>),
    #[mesh(3)]
    Restore(Rpc<SnapshotImage, Reply<()>>),
    #[mesh(4)]
    LogLevel(Rpc<String, Reply<()>>),
    #[mesh(5)]
    Status(Rpc<(), u32>),
    // Wire commands must not depend on the executable's Cargo features.
    #[mesh(6)]
    Crashdump(Rpc<(), Reply<()>>),
    #[mesh(7)]
    Stop(Rpc<(), ()>),
}

#[derive(MeshPayload)]
enum Control {
    #[mesh(1)]
    Interrupt(Rpc<(), bool>),
    #[mesh(2)]
    Dropped(Rpc<(), bool>),
    #[cfg(gdb)]
    #[mesh(3)]
    DebugInterrupt(Rpc<(), bool>),
}

#[derive(MeshPayload)]
struct Reply<T> {
    result: std::result::Result<T, OperationError>,
    status: u32,
}

#[derive(Debug, MeshPayload)]
enum OperationError {
    Guest(u64, String),
    Aborted(u8, String),
    Cancelled,
    ExecutionAccess(u64),
    MemoryAccess(u64, u32, u32),
    HungHostFunction,
    CallInProgress,
    HostFunctionNotFound(String),
    UnsupportedInterface(String),
    GuestVersion {
        guest: String,
        host: String,
    },
    Poisoned,
    Unrecoverable,
    NoSnapshot,
    SnapshotFunctions {
        missing: Vec<String>,
        mismatches: Vec<String>,
    },
    ArgumentCount(usize, usize),
    AddOverflow(u64, u64),
    MemoryTooBig(usize, usize),
    MemoryTooSmall(usize, usize),
    MissingParameter,
    MissingLogField(String),
    LockFailed(String),
    NoHypervisor,
    UnexpectedParameter(Vec<u8>, String),
    UnexpectedReturn(Vec<u8>, String),
    VectorCapacity(usize, usize, i32),
    Message(String),
    Diagnostic(String),
}

impl TryFrom<HyperlightError> for OperationError {
    type Error = HyperlightError;

    fn try_from(error: HyperlightError) -> Result<Self> {
        if super::launch::has_cleanup_owner(&error) {
            return Err(error);
        }
        Ok(match error {
            HyperlightError::GuestError(code, message) => Self::Guest(code.into(), message),
            HyperlightError::GuestAborted(code, message) => Self::Aborted(code, message),
            HyperlightError::ExecutionCanceledByHost() => Self::Cancelled,
            HyperlightError::ExecutionAccessViolation(address) => Self::ExecutionAccess(address),
            HyperlightError::MemoryAccessViolation(address, access, flags) => {
                Self::MemoryAccess(address, access.bits(), flags.bits())
            }
            HyperlightError::GuestExecutionHungOnHostFunctionCall() => Self::HungHostFunction,
            HyperlightError::GuestFunctionCallAlreadyInProgress() => Self::CallInProgress,
            HyperlightError::HostFunctionNotFound(name) => Self::HostFunctionNotFound(name),
            HyperlightError::GuestInterfaceUnsupportedType(name) => {
                Self::UnsupportedInterface(name)
            }
            HyperlightError::GuestBinVersionMismatch {
                guest_bin_version,
                host_version,
            } => Self::GuestVersion {
                guest: guest_bin_version,
                host: host_version,
            },
            HyperlightError::PoisonedSandbox => Self::Poisoned,
            HyperlightError::UnrecoverableSandbox => Self::Unrecoverable,
            HyperlightError::NoMemorySnapshot => Self::NoSnapshot,
            HyperlightError::SnapshotHostFunctionMismatch {
                missing,
                signature_mismatches,
            } => Self::SnapshotFunctions {
                missing,
                mismatches: signature_mismatches,
            },
            HyperlightError::UnexpectedNoOfArguments(actual, expected) => {
                Self::ArgumentCount(actual, expected)
            }
            HyperlightError::CheckedAddOverflow(left, right) => Self::AddOverflow(left, right),
            HyperlightError::MemoryRequestTooBig(actual, limit) => {
                Self::MemoryTooBig(actual, limit)
            }
            HyperlightError::MemoryRequestTooSmall(actual, limit) => {
                Self::MemoryTooSmall(actual, limit)
            }
            HyperlightError::FailedToGetValueFromParameter() => Self::MissingParameter,
            HyperlightError::FieldIsMissingInGuestLogData(field) => Self::MissingLogField(field),
            HyperlightError::LockAttemptFailed(message) => Self::LockFailed(message),
            HyperlightError::NoHypervisorFound() => Self::NoHypervisor,
            HyperlightError::UnexpectedParameterValueType(value, expected) => {
                let call = FunctionCall::new(
                    String::new(),
                    Some(vec![value]),
                    FunctionCallType::Guest,
                    ReturnType::Void,
                );
                Self::UnexpectedParameter(transport::encode_function_call(&call)?, expected)
            }
            HyperlightError::UnexpectedReturnValueType(value, expected) => Self::UnexpectedReturn(
                transport::encode_function_result(&FunctionCallResult::new(Ok(value)))?,
                expected,
            ),
            HyperlightError::VectorCapacityIncorrect(capacity, length, size) => {
                Self::VectorCapacity(capacity, length, size)
            }
            HyperlightError::Error(message) => Self::Message(message),
            error @ HyperlightError::ProcessCleanup(_) => return Err(error),
            // Native errors and borrowed Rust type names have no portable representation.
            error @ (HyperlightError::AnyhowError(_)
            | HyperlightError::CStringConversionError(_)
            | HyperlightError::HyperlightVmError(_)
            | HyperlightError::IOError(_)
            | HyperlightError::IntConversionFailure(_)
            | HyperlightError::InvalidFlatBuffer(_)
            | HyperlightError::JsonConversionFailure(_)
            | HyperlightError::MetricNotFound(_)
            | HyperlightError::ParameterValueConversionFailure(_, _)
            | HyperlightError::PEFileProcessingFailure(_)
            | HyperlightError::RawPointerLessThanBaseAddress(_, _)
            | HyperlightError::RefCellBorrowFailed(_)
            | HyperlightError::RefCellMutBorrowFailed(_)
            | HyperlightError::ReturnValueConversionFailure(_, _)
            | HyperlightError::SharedMemory(_)
            | HyperlightError::SystemTimeError(_)
            | HyperlightError::TransportError(_)
            | HyperlightError::TryFromSliceError(_)
            | HyperlightError::UTF8StringConversionFailure(_)) => {
                Self::Diagnostic(error.to_string())
            }
            #[cfg(target_os = "windows")]
            error @ (HyperlightError::CrossBeamReceiveError(_)
            | HyperlightError::CrossBeamSendError(_)
            | HyperlightError::WindowsAPIError(_)) => Self::Diagnostic(error.to_string()),
            #[cfg(target_os = "linux")]
            error @ HyperlightError::VmmSysError(_) => Self::Diagnostic(error.to_string()),
        })
    }
}

impl OperationError {
    fn decode(self) -> Result<HyperlightError> {
        use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

        use crate::mem::memory_region::MemoryRegionFlags;
        Ok(match self {
            Self::Guest(code, message) => {
                let decoded = ErrorCode::from(code);
                if u64::from(decoded) != code {
                    return Err(new_error!("Invalid sandbox guest error code {code}"));
                }
                HyperlightError::GuestError(decoded, message)
            }
            Self::Aborted(code, message) => HyperlightError::GuestAborted(code, message),
            Self::Cancelled => HyperlightError::ExecutionCanceledByHost(),
            Self::ExecutionAccess(address) => HyperlightError::ExecutionAccessViolation(address),
            Self::MemoryAccess(address, access, flags) => HyperlightError::MemoryAccessViolation(
                address,
                MemoryRegionFlags::from_bits(access)
                    .ok_or_else(|| new_error!("Invalid sandbox access flags {access}"))?,
                MemoryRegionFlags::from_bits(flags)
                    .ok_or_else(|| new_error!("Invalid sandbox memory flags {flags}"))?,
            ),
            Self::HungHostFunction => HyperlightError::GuestExecutionHungOnHostFunctionCall(),
            Self::CallInProgress => HyperlightError::GuestFunctionCallAlreadyInProgress(),
            Self::HostFunctionNotFound(name) => HyperlightError::HostFunctionNotFound(name),
            Self::UnsupportedInterface(name) => {
                HyperlightError::GuestInterfaceUnsupportedType(name)
            }
            Self::GuestVersion { guest, host } => HyperlightError::GuestBinVersionMismatch {
                guest_bin_version: guest,
                host_version: host,
            },
            Self::Poisoned => HyperlightError::PoisonedSandbox,
            Self::Unrecoverable => HyperlightError::UnrecoverableSandbox,
            Self::NoSnapshot => HyperlightError::NoMemorySnapshot,
            Self::SnapshotFunctions {
                missing,
                mismatches,
            } => HyperlightError::SnapshotHostFunctionMismatch {
                missing,
                signature_mismatches: mismatches,
            },
            Self::ArgumentCount(actual, expected) => {
                HyperlightError::UnexpectedNoOfArguments(actual, expected)
            }
            Self::AddOverflow(left, right) => HyperlightError::CheckedAddOverflow(left, right),
            Self::MemoryTooBig(actual, limit) => {
                HyperlightError::MemoryRequestTooBig(actual, limit)
            }
            Self::MemoryTooSmall(actual, limit) => {
                HyperlightError::MemoryRequestTooSmall(actual, limit)
            }
            Self::MissingParameter => HyperlightError::FailedToGetValueFromParameter(),
            Self::MissingLogField(field) => HyperlightError::FieldIsMissingInGuestLogData(field),
            Self::LockFailed(message) => HyperlightError::LockAttemptFailed(message),
            Self::NoHypervisor => HyperlightError::NoHypervisorFound(),
            Self::UnexpectedParameter(bytes, expected) => {
                let call = transport::decode_function_call(bytes.as_slice())?;
                let mut parameters = call.parameters.unwrap_or_default();
                if parameters.len() != 1 {
                    return Err(new_error!("Invalid sandbox parameter error payload"));
                }
                HyperlightError::UnexpectedParameterValueType(parameters.remove(0), expected)
            }
            Self::UnexpectedReturn(bytes, expected) => {
                let value = transport::decode_function_result(bytes.as_slice())?
                    .into_inner()
                    .map_err(|_| new_error!("Invalid sandbox return error payload"))?;
                HyperlightError::UnexpectedReturnValueType(value, expected)
            }
            Self::VectorCapacity(capacity, length, size) => {
                HyperlightError::VectorCapacityIncorrect(capacity, length, size)
            }
            Self::Message(message) => HyperlightError::Error(message),
            Self::Diagnostic(message) => new_error!("Sandbox operation failed: {message}"),
        })
    }
}

fn status_code(status: SandboxStatus) -> u32 {
    match status {
        SandboxStatus::Ready => 0,
        SandboxStatus::Poisoned => 1,
        SandboxStatus::Unrecoverable => 2,
    }
}

fn decode_status(status: u32) -> Result<SandboxStatus> {
    Ok(match status {
        0 => SandboxStatus::Ready,
        1 => SandboxStatus::Poisoned,
        2 => SandboxStatus::Unrecoverable,
        _ => return Err(new_error!("Invalid sandbox status {status}")),
    })
}

#[derive(MeshPayload)]
pub(crate) enum SandboxSource {
    Binary(Vec<u8>),
    Snapshot(SnapshotImage),
}

/// Validated snapshot OCI files. Entries have no caller-chosen filesystem paths.
#[derive(MeshPayload)]
pub(crate) struct SnapshotImage {
    files: Vec<(String, Vec<u8>)>,
}

impl SnapshotImage {
    pub(crate) fn capture(snapshot: &Snapshot) -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        snapshot.save(temporary.path(), &OciTag::new("transfer")?)?;
        let mut files = Vec::new();
        collect_files(temporary.path(), temporary.path(), &mut files)?;
        Ok(Self { files })
    }

    fn restore(self) -> Result<Snapshot> {
        let temporary = tempfile::tempdir()?;
        let mut names = std::collections::BTreeSet::new();
        for (name, bytes) in self.files {
            let allowed = matches!(name.as_str(), "oci-layout" | "index.json")
                || name.strip_prefix("blobs/sha256/").is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if !allowed || !names.insert(name.clone()) {
                return Err(new_error!("Invalid or duplicate snapshot transfer entry"));
            }
            let destination = temporary.path().join(name);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(destination, bytes)?;
        }
        Snapshot::load(temporary.path(), OciTag::new("transfer")?)
    }
}

fn collect_files(
    root: &std::path::Path,
    directory: &std::path::Path,
    output: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if entry.file_type()?.is_file() {
            output.push((
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| new_error!("{error}"))?
                    .to_string_lossy()
                    .replace('\\', "/"),
                std::fs::read(entry.path())?,
            ));
        } else {
            return Err(new_error!("Unexpected snapshot transfer file type"));
        }
    }
    Ok(())
}

#[derive(MeshPayload)]
struct Configuration {
    scratch: u64,
    log_level: Option<String>,
    #[cfg(any(kvm, mshv3, hvf))]
    interrupt_retry_nanos: u64,
    #[cfg(target_os = "linux")]
    signal_offset: u8,
    #[cfg(target_arch = "x86_64")]
    msrs: Vec<u32>,
    #[cfg(crashdump)]
    crashdump: bool,
}

impl Configuration {
    fn capture(configuration: &SandboxConfiguration) -> Result<Self> {
        #[cfg(gdb)]
        if configuration.get_guest_debug_info().is_some() {
            return Err(new_error!(
                "Dedicated sandboxes require executable-local debugger configuration"
            ));
        }
        Ok(Self {
            scratch: configuration.get_scratch_size() as u64,
            log_level: configuration
                .get_max_guest_log_level()
                .map(|level| level.to_string()),
            #[cfg(any(kvm, mshv3, hvf))]
            interrupt_retry_nanos: configuration
                .get_interrupt_retry_delay()
                .as_nanos()
                .try_into()?,
            #[cfg(target_os = "linux")]
            signal_offset: configuration.get_interrupt_vcpu_sigrtmin_offset(),
            #[cfg(target_arch = "x86_64")]
            msrs: configuration.get_guest_msrs().to_vec(),
            #[cfg(crashdump)]
            crashdump: configuration.get_guest_core_dump(),
        })
    }

    fn restore(&self) -> Result<SandboxConfiguration> {
        let mut config = SandboxConfiguration::default();
        config.set_scratch_size(self.scratch.try_into()?);
        if let Some(level) = &self.log_level {
            config.set_max_guest_log_level(
                level
                    .parse()
                    .map_err(|error| new_error!("Invalid log level: {error}"))?,
            );
        }
        #[cfg(any(kvm, mshv3, hvf))]
        config.set_interrupt_retry_delay(Duration::from_nanos(self.interrupt_retry_nanos));
        #[cfg(target_os = "linux")]
        config.set_interrupt_vcpu_sigrtmin_offset(self.signal_offset)?;
        #[cfg(target_arch = "x86_64")]
        config
            .guest_msrs(&self.msrs)
            .map_err(|error| new_error!("{error}"))?;
        #[cfg(crashdump)]
        config.set_guest_core_dump(self.crashdump);
        Ok(config)
    }
}

#[derive(MeshPayload)]
pub(super) struct Bootstrap {
    version: u32,
    source: SandboxSource,
    config: Configuration,
    init_data: Option<(Vec<u8>, u32)>,
    topology: Vec<u8>,
    local_contracts: Vec<u8>,
    workers: Vec<transport::SupervisedConnection>,
    requests: mesh::Receiver<Request>,
    control: mesh::Receiver<Control>,
    ready: mesh::OneshotSender<std::result::Result<(), OperationError>>,
}

/// Executable-local bindings for one framework-launched sandbox.
///
/// The process contains exactly one VM. Construct bindings after capturing
/// [`ProcessStartup`], then transfer that one-shot startup value to [`Self::run`].
pub struct SandboxHost {
    functions: ProcessHostFunctions,
    pt_root_finder: Option<PtRootFinder>,
}

impl SandboxHost {
    /// Supplies trusted implementations compiled into this executable.
    pub fn new(functions: ProcessHostFunctions) -> Self {
        Self {
            functions,
            pt_root_finder: None,
        }
    }

    /// Supplies a callback that executes beside this process's VM.
    pub fn pt_root_finder(mut self, finder: PtRootFinder) -> Self {
        self.pt_root_finder = Some(finder);
        self
    }

    /// Serves one sandbox after the trusted launcher establishes containment.
    pub fn run(self, startup: ProcessStartup) -> Result<()> {
        mesh_process::run_mesh_host(
            startup.into_inner(),
            "hyperlight-sandbox",
            // OpenVMM requires anyhow at its callback boundary.
            async move |bootstrap| self.serve(bootstrap).await.map_err(anyhow::Error::new),
        )?;
        Err(new_error!("Sandbox-process bootstrap did not enter Mesh"))
    }

    async fn serve(self, mut bootstrap: Bootstrap) -> Result<()> {
        let initialized = self.initialize(&mut bootstrap).await;
        let mut sandbox = match initialized {
            Ok(sandbox) => sandbox,
            Err(error) => {
                let message = error.to_string();
                bootstrap.ready.send(Err(OperationError::try_from(error)?));
                return Err(new_error!("Sandbox initialization failed: {message}"));
            }
        };
        let interrupt = sandbox.interrupt_handle();
        let mut control = bootstrap.control;
        // Guest execution is synchronous. A separate consumer must remain able
        // to deliver interrupts while the request thread is inside the vCPU.
        let (mut control_context, mut cancel_control) = mesh::CancelContext::new().with_cancel();
        let interrupt_thread = std::thread::Builder::new()
            .name("hyperlight-sandbox-control".to_owned())
            .spawn(move || {
                futures_lite::future::block_on(async move {
                    while let Ok(Some(control)) =
                        control_context.until_cancelled(control.next()).await
                    {
                        match control {
                            Control::Interrupt(rpc) => rpc.handle_sync(|()| interrupt.kill()),
                            Control::Dropped(rpc) => rpc.handle_sync(|()| interrupt.dropped()),
                            #[cfg(gdb)]
                            Control::DebugInterrupt(rpc) => {
                                rpc.handle_sync(|()| interrupt.kill_from_debugger())
                            }
                        }
                    }
                })
            })?;
        bootstrap.ready.send(Ok(()));
        let result: Result<()> = async {
            while let Some(request) = bootstrap.requests.next().await {
                match request {
                    Request::Call(call) => {
                        call.handle_must_succeed(async |bytes| {
                            let result = (|| {
                                let call = transport::decode_function_call(bytes.as_slice())?;
                                if call.function_call_type() != FunctionCallType::Guest {
                                    return Err(new_error!("Sandbox received a non-guest call"));
                                }
                                sandbox.snapshot = None;
                                let value = sandbox.call_guest_function_by_name_no_reset(
                                    &call.function_name,
                                    call.expected_return_type,
                                    call.parameters.unwrap_or_default(),
                                )?;
                                transport::encode_function_result(&FunctionCallResult::new(Ok(
                                    value,
                                )))
                            })();
                            reply(&sandbox, result)
                        })
                        .await?
                    }
                    Request::Snapshot(rpc) => {
                        rpc.handle_must_succeed(async |()| {
                            let result = sandbox
                                .snapshot()
                                .and_then(|snapshot| SnapshotImage::capture(&snapshot));
                            reply(&sandbox, result)
                        })
                        .await?
                    }
                    Request::Restore(rpc) => {
                        rpc.handle_must_succeed(async |image| {
                            let result = image
                                .restore()
                                .and_then(|snapshot| sandbox.restore(Arc::new(snapshot)));
                            reply(&sandbox, result)
                        })
                        .await?
                    }
                    Request::LogLevel(rpc) => {
                        rpc.handle_must_succeed(async |level| {
                            let result = level
                                .parse()
                                .map_err(|error| new_error!("Invalid log level: {error}"))
                                .and_then(|level| sandbox.log_level(level));
                            reply(&sandbox, result)
                        })
                        .await?
                    }
                    Request::Status(rpc) => rpc.complete(status_code(sandbox.status())),
                    Request::Crashdump(rpc) => {
                        rpc.handle_must_succeed(async |()| {
                            #[cfg(crashdump)]
                            let result = sandbox.generate_crashdump();
                            #[cfg(not(crashdump))]
                            let result =
                                Err(new_error!("Sandbox executable does not support crashdumps"));
                            reply(&sandbox, result)
                        })
                        .await?
                    }
                    Request::Stop(rpc) => {
                        rpc.complete(());
                        break;
                    }
                }
            }
            // Dropping the VM invalidates the interrupt handle before process exit.
            drop(sandbox);
            Ok(())
        }
        .await;
        cancel_control.cancel();
        let joined = interrupt_thread.join();
        if joined.is_err() {
            tracing::error!("Sandbox interrupt consumer panicked");
        }
        result?;
        joined.map_err(|_| new_error!("Interrupt consumer panicked"))
    }

    async fn initialize(self, bootstrap: &mut Bootstrap) -> Result<LocalSandbox> {
        if bootstrap.version != VERSION {
            return Err(new_error!("Sandbox protocol version mismatch"));
        }
        let topology: ProcessTopologyDefinition = serde_json::from_slice(&bootstrap.topology)?;
        topology.validate()?;
        if topology.sandbox().is_none() {
            return Err(new_error!("Sandbox bootstrap has no sandbox placement"));
        }
        let required: Vec<FunctionContractDefinition> =
            serde_json::from_slice(&bootstrap.local_contracts)?;
        let actual: Vec<_> = self
            .functions
            .contracts
            .values()
            .map(FunctionContractDefinition::from_definition)
            .collect();
        if required != actual {
            return Err(new_error!(
                "Sandbox executable-local registration manifest mismatch"
            ));
        }
        #[cfg(target_os = "windows")]
        if !crate::is_hypervisor_present() {
            return Err(new_error!(
                "Sandbox-host WHP reports HypervisorPresent=false"
            ));
        }
        let mut functions = HostFunctions::default();
        for (name, entry) in self.functions.functions.into_iter() {
            functions.inner_mut().register_host_function(name, entry);
        }
        let route_owner = runtime::Runtime::remote();
        if bootstrap.workers.len() != topology.workers().len() {
            return Err(new_error!("Sandbox worker count does not match topology"));
        }
        for (connection, worker) in std::mem::take(&mut bootstrap.workers)
            .into_iter()
            .zip(topology.workers())
        {
            let routes = transport::register_supervised_routes(
                connection,
                worker.functions(),
                route_owner.clone(),
            )?;
            for (name, entry) in routes.into_iter() {
                if functions.inner().function_signature(&name).is_some() {
                    return Err(new_error!(
                        "Duplicate sandbox-local/process function '{name}'"
                    ));
                }
                functions.inner_mut().register_host_function(name, entry);
            }
        }
        functions.inner_mut().process_runtime = Some(route_owner);
        functions.inner_mut().process_topology = Some(Box::new(topology));
        let config = bootstrap.config.restore()?;
        let source = std::mem::replace(&mut bootstrap.source, SandboxSource::Binary(Vec::new()));
        let mut local = match source {
            SandboxSource::Binary(bytes) => {
                let init_data = bootstrap
                    .init_data
                    .as_ref()
                    .map(|(bytes, flags)| {
                        Ok::<_, HyperlightError>(GuestBlob {
                            data: bytes,
                            permissions: crate::mem::memory_region::MemoryRegionFlags::from_bits(
                                *flags,
                            )
                            .ok_or_else(|| new_error!("Invalid initial data permissions"))?,
                        })
                    })
                    .transpose()?;
                let environment = GuestEnvironment {
                    guest_binary: GuestBinary::Buffer(bytes),
                    init_data,
                };
                let mut uninitialized =
                    crate::UninitializedSandbox::new(environment, Some(config))?;
                uninitialized.host_funcs = Arc::new(Mutex::new(functions.into_inner()));
                uninitialized.evolve()?.into_local()?
            }
            SandboxSource::Snapshot(image) => {
                if bootstrap.init_data.is_some() {
                    return Err(new_error!(
                        "Snapshot reconstruction cannot replace init_data"
                    ));
                }
                LocalSandbox::from_snapshot(Arc::new(image.restore()?), functions, Some(config))?
            }
        };
        if let Some(finder) = self.pt_root_finder {
            local.set_pt_root_finder(finder);
        }
        Ok(local)
    }
}

fn reply<T>(sandbox: &LocalSandbox, result: Result<T>) -> Result<Reply<T>> {
    Ok(Reply {
        result: match result {
            Ok(value) => Ok(value),
            Err(error) => Err(OperationError::try_from(error)?),
        },
        status: status_code(sandbox.status()),
    })
}

pub(crate) struct SandboxProcess {
    requests: Option<mesh::Sender<Request>>,
    interrupt: Arc<RemoteInterrupt>,
    status: SandboxStatus,
    topology: ProcessTopologyDefinition,
    root: OwnedHost,
    _workers: Arc<runtime::Runtime>,
    supervisor: Option<transport::LifecycleSupervisor>,
    guard: Arc<dyn ProcessGuard>,
    report: ProcessReport,
    cleanup_complete: bool,
}

impl SandboxProcess {
    #[cfg(all(test, target_os = "windows"))]
    pub(crate) fn terminate_worker_for_test(&self, index: usize) -> Result<()> {
        self._workers.terminate_worker_for_test(index)
    }

    pub(crate) fn process_reports(&self) -> Vec<super::ProcessReport> {
        let mut reports = vec![self.report.clone()];
        reports.extend(self._workers.reports());
        reports
    }

    /// Prepares the whole topology before entering guest code. The caller validates
    /// every artifact first, and the launcher revalidates each replacement.
    pub(super) fn launch(
        definition: ProcessTopologyDefinition,
        launcher: Arc<dyn ProcessLauncher>,
        policy: runtime::RestartPolicy,
        source: SandboxSource,
        settings: &SandboxConfiguration,
        init_data: Option<(Vec<u8>, crate::mem::memory_region::MemoryRegionFlags)>,
        local_contracts: Vec<FunctionContractDefinition>,
    ) -> Result<MultiUseSandbox> {
        definition.validate()?;
        let sandbox = definition
            .sandbox()
            .ok_or_else(|| new_error!("Dedicated topology requires a sandbox owner"))?;
        let settings = Configuration::capture(settings)?;
        let prepared = launcher.prepare(ProgramRole::SandboxHost, sandbox)?;
        let owner = match runtime::Runtime::start_workers(definition.workers(), launcher, policy) {
            Ok(owner) => owner,
            Err(error) => {
                let deadline = Instant::now() + CONTROL_TIMEOUT;
                let terminated = prepared.guard.terminate_domain();
                let empty = prepared.guard.wait_empty(deadline);
                let release = if empty.is_ok() {
                    // This sandbox launch has not been submitted.
                    prepared.guard.release_resources(deadline)
                } else {
                    Err(new_error!(
                        "Unlaunched sandbox domain cleanup is unconfirmed"
                    ))
                };
                tracing::error!(
                    ?terminated,
                    ?empty,
                    ?release,
                    "Worker startup failed. Unlaunched sandbox cleanup attempted"
                );
                return Err(error);
            }
        };
        let result = Self::launch_ready(
            definition,
            prepared,
            owner.clone(),
            source,
            settings,
            init_data,
            local_contracts,
        );
        match result {
            Ok(process) => Ok(MultiUseSandbox::from_process(process)),
            Err(error) => {
                let cleanup = owner.stop();
                if cleanup.is_err() || super::launch::has_unconfirmed_launch(&error) {
                    tracing::error!(?cleanup, "Retaining sandbox startup cleanup ownership");
                    Err(ProcessCleanupError::retain(
                        error,
                        CleanupOwner::Runtime { _owner: owner },
                    ))
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Prepared launches are private transport qualification seams. Production
    /// callers must supply configurations from the confinement adapter.
    #[cfg(test)]
    pub(crate) fn launch_prepared(
        definition: ProcessTopologyDefinition,
        config: ProcessConfig,
        worker_launches: Vec<ProcessConfig>,
        source: SandboxSource,
        settings: &SandboxConfiguration,
        init_data: Option<(Vec<u8>, crate::mem::memory_region::MemoryRegionFlags)>,
        local_contracts: Vec<FunctionContractDefinition>,
    ) -> Result<MultiUseSandbox> {
        if worker_launches.len() != definition.workers().len() {
            return Err(new_error!(
                "Prepared launches do not match sandbox topology"
            ));
        }
        struct FixtureLauncher(Mutex<std::collections::VecDeque<ProcessConfig>>);
        impl ProcessLauncher for FixtureLauncher {
            fn prepare(
                &self,
                _: ProgramRole,
                _: &super::program::ProcessDefinition,
            ) -> Result<PreparedProcess> {
                Ok(PreparedProcess {
                    config: self
                        .0
                        .lock()
                        .unwrap()
                        .pop_front()
                        .ok_or_else(|| new_error!("Fixture has no replacement configuration"))?,
                    guard: Arc::new(runtime::TrustedFixtureGuard),
                    controls: vec![],
                    windows_policy: None,
                    resources: vec![],
                    export_authority: None,
                    resource_generation: None,
                })
            }
        }
        let configs = std::iter::once(config).chain(worker_launches).collect();
        Self::launch(
            definition,
            Arc::new(FixtureLauncher(Mutex::new(configs))),
            runtime::RestartPolicy::default(),
            source,
            settings,
            init_data,
            local_contracts,
        )
    }

    fn launch_ready(
        definition: ProcessTopologyDefinition,
        prepared: PreparedProcess,
        owner: Arc<runtime::Runtime>,
        source: SandboxSource,
        settings: Configuration,
        init_data: Option<(Vec<u8>, crate::mem::memory_region::MemoryRegionFlags)>,
        local_contracts: Vec<FunctionContractDefinition>,
    ) -> Result<Self> {
        let (workers, supervisor) =
            transport::supervised_connections(owner.clone(), definition.workers().len())?;
        let (requests, receive) = mesh::channel();
        let (control, controls) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let bootstrap = Bootstrap {
            version: VERSION,
            source,
            config: settings,
            init_data: init_data.map(|(bytes, flags)| (bytes, flags.bits())),
            topology: serde_json::to_vec(&definition)?,
            local_contracts: serde_json::to_vec(&local_contracts)?,
            workers,
            requests: receive,
            control: controls,
            ready,
        };
        let PreparedProcess {
            config,
            guard,
            controls,
            windows_policy,
            resources,
            export_authority,
            resource_generation: _,
        } = prepared;
        if !resources.is_empty() || export_authority.is_some() {
            return Err(new_error!(
                "Sandbox host processes cannot receive function-worker resources"
            ));
        }
        let root =
            futures_lite::future::block_on(owner.launch_sandbox(config, bootstrap, guard.clone()))?;
        let sandbox = definition.sandbox().unwrap();
        let report = ProcessReport {
            role: ProgramRole::SandboxHost,
            name: sandbox.name().to_owned(),
            program: sandbox.program().clone(),
            root_process_id: root.id(),
            controls,
            windows_policy,
        };
        let mut process = Self {
            requests: Some(requests),
            interrupt: Arc::new(RemoteInterrupt {
                control: Mutex::new(Some(control)),
                lost: AtomicBool::new(false),
                state: InterruptHandleStateMachine::new(),
            }),
            status: SandboxStatus::Ready,
            topology: definition,
            root,
            _workers: owner,
            supervisor: Some(supervisor),
            guard,
            report,
            cleanup_complete: false,
        };
        let result = futures_lite::future::block_on(
            mesh::CancelContext::new()
                .with_timeout(CONTROL_TIMEOUT)
                .until_cancelled(readiness),
        );
        match result {
            Ok(Ok(Ok(()))) => Ok(process),
            other => {
                let error = match other {
                    Ok(Ok(Err(error))) => error.decode().unwrap_or_else(|error| error),
                    other => new_error!("Sandbox readiness failed: {other:?}"),
                };
                if let Err(cleanup) = process.cleanup() {
                    tracing::error!(%cleanup, "Sandbox readiness cleanup is incomplete");
                    Err(ProcessCleanupError::retain(
                        error,
                        CleanupOwner::Sandbox {
                            _owner: Box::new(process),
                        },
                    ))
                } else {
                    Err(error)
                }
            }
        }
    }

    fn apply<T>(
        &mut self,
        response: std::result::Result<Reply<T>, mesh::rpc::RpcError>,
    ) -> Result<T> {
        match response {
            Ok(reply) => {
                self.status =
                    decode_status(reply.status).map_err(|error| self.protocol_error(error))?;
                match reply.result {
                    Ok(value) => Ok(value),
                    Err(error) => {
                        Err(error.decode().map_err(|error| self.protocol_error(error))?)
                    }
                }
            }
            Err(error) => {
                self.status = SandboxStatus::Unrecoverable;
                self.interrupt.lost.store(true, Ordering::Release);
                Err(new_error!("Sandbox process lost (terminal): {error}"))
            }
        }
    }

    fn protocol_error(&mut self, error: HyperlightError) -> HyperlightError {
        self.status = SandboxStatus::Unrecoverable;
        self.interrupt.lost.store(true, Ordering::Release);
        error
    }

    fn check_alive(&self) -> Result<()> {
        if self.interrupt.lost.load(Ordering::Acquire)
            || self.status.is_unrecoverable()
            || self._workers.is_poisoned()
        {
            Err(HyperlightError::UnrecoverableSandbox)
        } else {
            Ok(())
        }
    }

    pub(crate) fn call(
        &mut self,
        name: &str,
        output: ReturnType,
        args: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        self.check_alive()?;
        if self.status.is_poisoned() {
            return Err(HyperlightError::PoisonedSandbox);
        }
        let call = FunctionCall::new(name.to_owned(), Some(args), FunctionCallType::Guest, output);
        let result = futures_lite::future::block_on(
            self.requests
                .as_ref()
                .unwrap()
                .call(Request::Call, transport::encode_function_call(&call)?),
        );
        let bytes = self.apply(result)?;
        transport::decode_function_result(bytes.as_slice())?
            .into_inner()
            .map_err(|error| HyperlightError::GuestError(error.code, error.message))
    }

    pub(crate) fn snapshot(&mut self) -> Result<Arc<Snapshot>> {
        self.check_alive()?;
        let response = futures_lite::future::block_on(
            self.requests.as_ref().unwrap().call(Request::Snapshot, ()),
        );
        let mut snapshot = self.apply(response)?.restore()?;
        if snapshot.process_topology().is_none() {
            snapshot.set_process_topology(self.topology.clone())?;
        }
        snapshot.validate_process_topology(Some(&self.topology))?;
        Ok(Arc::new(snapshot))
    }

    pub(crate) fn restore(&mut self, snapshot: Arc<Snapshot>) -> Result<()> {
        self.check_alive()?;
        snapshot.validate_process_topology(Some(&self.topology))?;
        let image = SnapshotImage::capture(&snapshot)?;
        let response = futures_lite::future::block_on(
            self.requests
                .as_ref()
                .unwrap()
                .call(Request::Restore, image),
        );
        self.apply(response)
    }

    pub(crate) fn log_level(&mut self, level: LevelFilter) -> Result<()> {
        self.check_alive()?;
        let response = futures_lite::future::block_on(
            self.requests
                .as_ref()
                .unwrap()
                .call(Request::LogLevel, level.to_string()),
        );
        self.apply(response)
    }

    pub(crate) fn status(&self) -> SandboxStatus {
        if self.interrupt.lost.load(Ordering::Acquire) || self._workers.is_poisoned() {
            return SandboxStatus::Unrecoverable;
        }
        let Some(requests) = &self.requests else {
            return SandboxStatus::Unrecoverable;
        };
        match futures_lite::future::block_on(
            mesh::CancelContext::new()
                .with_timeout(CONTROL_TIMEOUT)
                .until_cancelled(requests.call(Request::Status, ())),
        ) {
            Ok(Ok(status)) => decode_status(status).unwrap_or_else(|error| {
                tracing::error!(%error, "Sandbox status protocol failed");
                self.interrupt.lost.store(true, Ordering::Release);
                SandboxStatus::Unrecoverable
            }),
            _ => {
                self.interrupt.lost.store(true, Ordering::Release);
                SandboxStatus::Unrecoverable
            }
        }
    }

    pub(crate) fn interrupt_handle(&self) -> Arc<dyn InterruptHandle> {
        self.interrupt.clone()
    }

    #[cfg(crashdump)]
    pub(crate) fn generate_crashdump(&mut self) -> Result<()> {
        self.check_alive()?;
        let response = futures_lite::future::block_on(
            self.requests.as_ref().unwrap().call(Request::Crashdump, ()),
        );
        self.apply(response)
    }
    pub(crate) fn cleanup(&mut self) -> Result<()> {
        if self.cleanup_complete {
            return Ok(());
        }
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        self.interrupt.lost.store(true, Ordering::Release);
        if let Ok(mut control) = self.interrupt.control.lock() {
            control.take();
        }
        if let Some(requests) = self.requests.take() {
            drop(requests.call(Request::Stop, ()));
        }
        // Cancellation unblocks lifecycle recovery before joining its owned thread.
        self.supervisor.take();
        let _ = futures_lite::future::block_on(
            mesh::CancelContext::new()
                .with_timeout(Duration::from_millis(250))
                .until_cancelled(self.root.wait_root()),
        );
        futures_lite::future::block_on(super::launch::cleanup_owned(
            &mut self.root,
            self.guard.as_ref(),
            deadline,
        ))?;
        self._workers.stop()?;
        self.cleanup_complete = true;
        Ok(())
    }
}

impl Drop for SandboxProcess {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(
                ?error,
                "Final sandbox cleanup incomplete. Dropping this cleanup owner"
            );
        }
    }
}

#[derive(Debug)]
struct RemoteInterrupt {
    control: Mutex<Option<mesh::Sender<Control>>>,
    lost: AtomicBool,
    state: InterruptHandleStateMachine,
}

impl RemoteInterrupt {
    fn request(&self, request: fn(Rpc<(), bool>) -> Control) -> bool {
        if self.lost.load(Ordering::Acquire) {
            return false;
        }
        let control = self.control.lock().ok().and_then(|control| control.clone());
        let Some(control) = control else { return false };
        match futures_lite::future::block_on(
            mesh::CancelContext::new()
                .with_timeout(CONTROL_TIMEOUT)
                .until_cancelled(control.call(request, ())),
        ) {
            Ok(Ok(interrupted)) => interrupted,
            _ => {
                self.lost.store(true, Ordering::Release);
                false
            }
        }
    }
}

impl InterruptHandleInternal for RemoteInterrupt {
    fn state(&self) -> &InterruptHandleStateMachine {
        &self.state
    }

    fn common_kill(&self) -> bool {
        self.request(Control::Interrupt)
    }
}

impl InterruptHandle for RemoteInterrupt {
    #[cfg(gdb)]
    fn kill_from_debugger(&self) -> bool {
        self.request(Control::DebugInterrupt)
    }

    fn dropped(&self) -> bool {
        if self.lost.load(Ordering::Acquire) {
            return true;
        }
        let dropped = self.request(Control::Dropped);
        dropped || self.lost.load(Ordering::Acquire)
    }
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
