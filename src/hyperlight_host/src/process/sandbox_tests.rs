// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

// These prepared launches qualify transport and VM APIs, not OS containment.
use super::*;
use crate::func::Registerable;
use crate::process::program::{
    LocalProgramStore, ProcessDefinition, ProgramConfig, ProgramRole, ProgramTarget,
};
use crate::process::{
    HostFunctionContract, Idempotency, ProcessControl, ProcessProfile, RequestedControl,
};

const PRINT: HostFunctionContract<(String,), i32> =
    HostFunctionContract::new("HostPrint", Idempotency::Idempotent);
const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::NonIdempotent);

fn fixture(name: &str) -> std::path::PathBuf {
    let path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "Build --example {name} with process-isolation before this test"
    );
    path
}

fn local_topology() -> ProcessTopologyDefinition {
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path());
    let artifact = store
        .package(
            &ProgramConfig {
                schema_version: 1,
                role: ProgramRole::SandboxHost,
                target: ProgramTarget::current(Default::default()),
                functions: Vec::new(),
            },
            &std::fs::read(fixture("sandbox_worker")).unwrap(),
        )
        .unwrap();
    let profile = ProcessProfile::new([RequestedControl {
        control: ProcessControl::DenyNetwork,
        required: true,
    }]);
    ProcessTopologyDefinition::new(
        Some(ProcessDefinition::new("sandbox", artifact, &profile, Vec::new()).unwrap()),
        Vec::new(),
    )
    .unwrap()
}

fn launch_local(topology: ProcessTopologyDefinition, source: SandboxSource) -> MultiUseSandbox {
    SandboxProcess::launch_prepared(
        topology,
        ProcessConfig::new("sandbox-test")
            .skip_worker_arg(true)
            .process_name(fixture("sandbox_worker"))
            .args(["--local-add"]),
        Vec::new(),
        source,
        &SandboxConfiguration::default(),
        None,
        vec![
            FunctionContractDefinition::from_contract(&ADD),
            FunctionContractDefinition::from_contract(&PRINT),
        ],
    )
    .unwrap()
}

fn source() -> SandboxSource {
    SandboxSource::Binary(std::fs::read(hyperlight_testing::simple_guest_as_pathbuf()).unwrap())
}

#[test]
fn dedicated_vm_calls_restore_guest_without_rewinding_native_callbacks() {
    let topology = local_topology();
    let mut sandbox = launch_local(topology.clone(), source());
    let pid: i32 = sandbox.call("PrintOutput", "pid".to_owned()).unwrap();
    assert_ne!(pid as u32, std::process::id());
    assert_eq!(sandbox.call::<i32>("Add", (10, 30)).unwrap(), 41);
    let snapshot = sandbox.snapshot().unwrap();
    assert_eq!(snapshot.process_topology(), Some(&topology));
    let before: i32 = sandbox.call("GetStatic", ()).unwrap();
    assert_eq!(sandbox.call::<i32>("AddToStatic", 7).unwrap(), before + 7);
    assert_eq!(sandbox.call::<i32>("Add", (10, 30)).unwrap(), 42);
    sandbox.restore(snapshot.clone()).unwrap();
    assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
    assert_eq!(sandbox.call::<i32>("Add", (10, 30)).unwrap(), 43);
    assert_eq!(
        sandbox
            .call::<i32>("PrintOutput", "pid".to_owned())
            .unwrap(),
        pid
    );
    let mut fresh = launch_local(
        topology,
        SandboxSource::Snapshot(SnapshotImage::capture(&snapshot).unwrap()),
    );
    assert_ne!(
        fresh.call::<i32>("PrintOutput", "pid".to_owned()).unwrap(),
        pid
    );
    assert_eq!(fresh.call::<i32>("Add", (10, 30)).unwrap(), 41);
    assert_eq!(fresh.call::<i32>("GetStatic", ()).unwrap(), before);
    assert!(sandbox.register_host_function("Late", || 1i32).is_err());
    assert!(
        sandbox
            .map_file_cow(std::path::Path::new("unused"), 0)
            .is_err()
    );
}

#[test]
fn dedicated_vm_interrupt_consumes_control_while_guest_runs() {
    let mut sandbox = launch_local(local_topology(), source());
    let snapshot = sandbox.snapshot().unwrap();
    let interrupt = sandbox.interrupt_handle();
    assert!(!interrupt.kill());
    assert!(!interrupt.dropped());
    let handle = interrupt.clone();
    let thread = std::thread::spawn(move || {
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(20));
            if handle.kill() {
                return true;
            }
        }
        false
    });
    let result = sandbox.call::<()>("Spin", ());
    assert!(thread.join().unwrap());
    assert!(
        matches!(result, Err(HyperlightError::ExecutionCanceledByHost())),
        "{result:?}"
    );
    assert!(sandbox.status().is_poisoned());
    assert!(matches!(
        sandbox.call::<i32>("EchoI32", 7),
        Err(HyperlightError::PoisonedSandbox)
    ));
    sandbox.restore(snapshot).unwrap();
    assert_eq!(sandbox.call::<i32>("EchoI32", 7).unwrap(), 7);
    drop(sandbox);
    assert!(interrupt.dropped());
}

#[test]
fn dedicated_vm_preserves_guest_error() {
    let bytes = std::fs::read(hyperlight_testing::simple_guest_as_pathbuf()).unwrap();
    let mut local = crate::SandboxBuilder::from_bytes(bytes.clone())
        .build()
        .unwrap();
    let mut dedicated = launch_local(local_topology(), SandboxSource::Binary(bytes));
    let local = local.call::<()>("MissingGuestFunction", ()).unwrap_err();
    let remote = dedicated
        .call::<()>("MissingGuestFunction", ())
        .unwrap_err();
    let HyperlightError::GuestError(local_code, local_message) = local else {
        panic!("Unexpected local error: {local:?}");
    };
    assert!(
        matches!(remote, HyperlightError::GuestError(code, ref message) if code == local_code && message == &local_message),
        "{remote:?}"
    );
}

#[test]
fn operation_errors_round_trip_with_portable_details() {
    use hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;

    use crate::mem::memory_region::MemoryRegionFlags as Flags;
    let errors = [
        HyperlightError::GuestError(ErrorCode::HostFunctionError, "guest detail".into()),
        HyperlightError::GuestAborted(255, "abort detail".into()),
        HyperlightError::ExecutionCanceledByHost(),
        HyperlightError::ExecutionAccessViolation(u64::MAX),
        HyperlightError::MemoryAccessViolation(0x1234, Flags::WRITE, Flags::READ | Flags::EXECUTE),
        HyperlightError::GuestExecutionHungOnHostFunctionCall(),
        HyperlightError::GuestFunctionCallAlreadyInProgress(),
        HyperlightError::HostFunctionNotFound("callback".into()),
        HyperlightError::GuestInterfaceUnsupportedType("type".into()),
        HyperlightError::GuestBinVersionMismatch {
            guest_bin_version: "guest".into(),
            host_version: "host".into(),
        },
        HyperlightError::PoisonedSandbox,
        HyperlightError::UnrecoverableSandbox,
        HyperlightError::NoMemorySnapshot,
        HyperlightError::SnapshotHostFunctionMismatch {
            missing: vec!["missing".into()],
            signature_mismatches: vec!["signature".into()],
        },
        HyperlightError::UnexpectedNoOfArguments(2, 3),
        HyperlightError::CheckedAddOverflow(u64::MAX, 1),
        HyperlightError::MemoryRequestTooBig(1024, 512),
        HyperlightError::MemoryRequestTooSmall(1, 512),
        HyperlightError::FailedToGetValueFromParameter(),
        HyperlightError::FieldIsMissingInGuestLogData("field".into()),
        HyperlightError::LockAttemptFailed("lock".into()),
        HyperlightError::NoHypervisorFound(),
        HyperlightError::UnexpectedParameterValueType(
            ParameterValue::ULong(u64::MAX),
            "Int".into(),
        ),
        HyperlightError::UnexpectedReturnValueType(ReturnValue::Void(()), "String".into()),
        HyperlightError::VectorCapacityIncorrect(32, 16, -1),
        HyperlightError::Error("operation detail".into()),
    ];
    for error in errors {
        let expected = format!("{error:?}");
        let bytes = mesh::OwnedMessage::new(OperationError::try_from(error).unwrap()).serialize();
        let decoded: OperationError = mesh::OwnedMessage::serialized(bytes).parse().unwrap();
        assert_eq!(format!("{:?}", decoded.decode().unwrap()), expected);
    }
    let error = HyperlightError::IOError(std::io::Error::other("native detail"));
    assert!(matches!(
        OperationError::try_from(error).unwrap().decode().unwrap(),
        HyperlightError::Error(message) if message.contains("native detail")
    ));
}

#[test]
fn operation_errors_reject_unknown_codes_flags_and_status() {
    for error in [
        OperationError::Guest(1, "unknown".into()),
        OperationError::Guest(u64::MAX, "unknown".into()),
        OperationError::MemoryAccess(1, 8, 1),
        OperationError::MemoryAccess(1, 1, 8),
        OperationError::UnexpectedParameter(vec![], "Int".into()),
        OperationError::UnexpectedReturn(vec![], "Int".into()),
    ] {
        let bytes = mesh::OwnedMessage::new(error).serialize();
        let decoded: OperationError = mesh::OwnedMessage::serialized(bytes).parse().unwrap();
        assert!(decoded.decode().is_err());
    }
    for status in [
        SandboxStatus::Ready,
        SandboxStatus::Poisoned,
        SandboxStatus::Unrecoverable,
    ] {
        assert_eq!(decode_status(status_code(status)).unwrap(), status);
    }
    assert!(decode_status(3).is_err());
    assert!(decode_status(u32::MAX).is_err());
}

#[test]
fn malformed_operation_reply_makes_sandbox_terminal() {
    for reply in [
        Reply {
            result: Ok(()),
            status: 3,
        },
        Reply {
            result: Err(OperationError::Guest(1, "unknown".into())),
            status: 0,
        },
        Reply {
            result: Err(OperationError::MemoryAccess(1, 8, 1)),
            status: 0,
        },
    ] {
        let mut process = SandboxProcess::launch_ready(
            local_topology(),
            PreparedProcess {
                config: ProcessConfig::new("invalid-reply-test")
                    .skip_worker_arg(true)
                    .process_name(fixture("sandbox_worker"))
                    .args(["--local-add"]),
                guard: Arc::new(runtime::TrustedFixtureGuard),
                controls: vec![],
                windows_policy: None,
                resources: vec![],
                export_authority: None,
                resource_generation: None,
            },
            runtime::Runtime::new().unwrap(),
            source(),
            Configuration::capture(&SandboxConfiguration::default()).unwrap(),
            None,
            vec![
                FunctionContractDefinition::from_contract(&ADD),
                FunctionContractDefinition::from_contract(&PRINT),
            ],
        )
        .unwrap();
        assert!(process.apply(Ok(reply)).is_err());
        assert_eq!(process.status, SandboxStatus::Unrecoverable);
        assert!(process.interrupt.lost.load(Ordering::Acquire));
        assert!(matches!(
            process.check_alive(),
            Err(HyperlightError::UnrecoverableSandbox)
        ));
        assert_eq!(process.status(), SandboxStatus::Unrecoverable);
    }
}

#[test]
fn operation_errors_cannot_consume_cleanup_ownership() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<HyperlightError>();
    assert_send_sync::<ProcessCleanupError>();
    for foreign_wrapper in [false, true] {
        let runtime = runtime::Runtime::new().unwrap();
        let weak = Arc::downgrade(&runtime);
        let error = ProcessCleanupError::retain(
            new_error!("original startup cause"),
            CleanupOwner::Runtime { _owner: runtime },
        );
        assert!(std::error::Error::source(&error).is_some());
        let error = if foreign_wrapper {
            // Simulates the mandatory foreign Mesh error boundary.
            HyperlightError::from(anyhow::Error::new(error))
        } else {
            error
        };
        let error = OperationError::try_from(error).unwrap_err();
        assert!(error.to_string().contains("original startup cause"));
        assert!(weak.upgrade().is_some());
        drop(error);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn sandbox_stop_and_crashdump_wire_tags_are_feature_independent() {
    #[derive(MeshPayload)]
    enum WireRequest {
        #[mesh(7)]
        Stop(Rpc<(), ()>),
        #[mesh(6)]
        Crashdump(Rpc<(), Reply<()>>),
    }

    let stop = mesh::OwnedMessage::new(Request::Stop(Rpc::detached(()))).serialize();
    let decoded: WireRequest = mesh::OwnedMessage::serialized(stop).parse().unwrap();
    assert!(matches!(decoded, WireRequest::Stop(_)));
    let stop = mesh::OwnedMessage::new(decoded).serialize();
    assert!(matches!(
        mesh::OwnedMessage::serialized(stop)
            .parse::<Request>()
            .unwrap(),
        Request::Stop(_)
    ));

    let crashdump = mesh::OwnedMessage::new(Request::Crashdump(Rpc::detached(()))).serialize();
    let decoded: WireRequest = mesh::OwnedMessage::serialized(crashdump).parse().unwrap();
    assert!(matches!(decoded, WireRequest::Crashdump(_)));
    let crashdump = mesh::OwnedMessage::new(decoded).serialize();
    assert!(matches!(
        mesh::OwnedMessage::serialized(crashdump)
            .parse::<Request>()
            .unwrap(),
        Request::Crashdump(_)
    ));
}

#[test]
fn sandbox_protocol_rejects_other_versions_before_initialization() {
    for version in [0, 1, 2, VERSION + 1, u32::MAX] {
        let (_, requests) = mesh::channel();
        let (_, control) = mesh::channel();
        let (ready, _) = mesh::oneshot();
        let mut bootstrap = Bootstrap {
            version,
            source: SandboxSource::Binary(vec![]),
            config: Configuration::capture(&SandboxConfiguration::default()).unwrap(),
            init_data: None,
            topology: vec![],
            local_contracts: vec![],
            workers: vec![],
            requests,
            control,
            ready,
        };
        let result = futures_lite::future::block_on(
            SandboxHost::new(ProcessHostFunctions::default()).initialize(&mut bootstrap),
        );
        assert!(
            matches!(result, Err(HyperlightError::Error(message)) if message == "Sandbox protocol version mismatch")
        );
    }
}

#[test]
fn dedicated_restore_preserves_typed_host_function_mismatch() {
    let topology = local_topology();
    let mut source =
        crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
            .host_function("OnlyInSnapshot", || 1i32)
            .build()
            .unwrap();
    let mut snapshot = source.snapshot().unwrap();
    drop(source);
    Arc::get_mut(&mut snapshot)
        .unwrap()
        .set_process_topology(topology.clone())
        .unwrap();
    let mut dedicated = launch_local(topology, self::source());
    let error = dedicated.restore(snapshot).unwrap_err();
    assert!(
        matches!(&error, HyperlightError::SnapshotHostFunctionMismatch { missing, .. }
        if missing.contains(&"OnlyInSnapshot".to_owned())),
        "{error:?}"
    );
    assert_eq!(dedicated.status(), SandboxStatus::Ready);
}

#[test]
fn transfer_rejects_paths_before_filesystem_use() {
    for path in [
        "../outside",
        "blobs/sha256/../outside",
        "C:/outside",
        "/outside",
    ] {
        let image = SnapshotImage {
            files: vec![(path.to_owned(), vec![])],
        };
        assert!(image.restore().is_err());
    }
}

// This launcher exercises the production topology/ownership path with ordinary
// Mesh children. Its recording guards are not OS confinement qualification.
struct DedicatedFixture {
    store: LocalProgramStore,
    args: Vec<std::ffi::OsString>,
    events: Arc<Mutex<Vec<String>>>,
    fail_empty: Arc<AtomicBool>,
    fail_sandbox_empty: Arc<AtomicBool>,
    guards: Mutex<Vec<std::sync::Weak<RecordingGuard>>>,
}

struct RecordingGuard {
    name: String,
    events: Arc<Mutex<Vec<String>>>,
    fail_empty: Arc<AtomicBool>,
}

impl ProcessGuard for RecordingGuard {
    fn start_launch(&self) {}

    fn release_resources(&self, _: Instant) -> Result<()> {
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(format!("release:{}", self.name));
        Ok(())
    }

    fn terminate_domain(&self) -> Result<()> {
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(format!("terminate:{}", self.name));
        Ok(())
    }

    fn wait_empty(&self, _: Instant) -> Result<()> {
        self.events
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(format!("empty:{}", self.name));
        if self.fail_empty.load(Ordering::Acquire) {
            return Err(new_error!("Fixture domain is not empty"));
        }
        Ok(())
    }
}

impl ProcessLauncher for DedicatedFixture {
    fn prepare(
        &self,
        role: ProgramRole,
        definition: &ProcessDefinition,
    ) -> Result<PreparedProcess> {
        let program = self.store.validate(
            definition.program(),
            &ProgramTarget::current(Default::default()),
        )?;
        assert_eq!(program.config().role, role);
        assert_eq!(program.config().functions, definition.functions());
        self.events
            .lock()
            .unwrap()
            .push(format!("prepare:{}", definition.name()));
        let mut config = ProcessConfig::new(definition.name())
            .skip_worker_arg(true)
            .process_name(fixture(if role == ProgramRole::SandboxHost {
                "sandbox_worker"
            } else {
                "process_worker"
            }));
        if role == ProgramRole::FunctionWorker {
            config = config.args(self.args.clone());
        }
        let guard = Arc::new(RecordingGuard {
            name: definition.name().to_owned(),
            events: self.events.clone(),
            fail_empty: if role == ProgramRole::SandboxHost {
                self.fail_sandbox_empty.clone()
            } else {
                self.fail_empty.clone()
            },
        });
        self.guards.lock().unwrap().push(Arc::downgrade(&guard));
        Ok(PreparedProcess {
            config,
            guard,
            controls: Vec::new(),
            windows_policy: None,
            resources: Vec::new(),
            export_authority: None,
            resource_generation: None,
        })
    }
}

fn dedicated_fixture(
    directory: &std::path::Path,
    mode: &str,
    idempotency: Idempotency,
) -> (ProcessTopologyDefinition, Arc<DedicatedFixture>) {
    let store = LocalProgramStore::new(directory.join("programs"));
    let contracts = vec![
        FunctionContractDefinition::from_contract(&HostFunctionContract::<(i32, i32), i32>::new(
            "HostAdd",
            idempotency,
        )),
        FunctionContractDefinition::from_contract(&HostFunctionContract::<(), u32>::new(
            "ProcessId",
            Idempotency::Idempotent,
        )),
    ];
    let profile = ProcessProfile::new([RequestedControl {
        control: ProcessControl::DenyNetwork,
        required: true,
    }]);
    let package = |role, functions, name| {
        store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role,
                    target: ProgramTarget::current(Default::default()),
                    functions,
                },
                &std::fs::read(fixture(name)).unwrap(),
            )
            .unwrap()
    };
    let sandbox = ProcessDefinition::new(
        "sandbox",
        package(ProgramRole::SandboxHost, vec![], "sandbox_worker"),
        &profile,
        vec![],
    )
    .unwrap();
    let worker = ProcessDefinition::new(
        "worker",
        package(
            ProgramRole::FunctionWorker,
            contracts.clone(),
            "process_worker",
        ),
        &profile,
        contracts,
    )
    .unwrap();
    let topology = ProcessTopologyDefinition::new(Some(sandbox), vec![worker]).unwrap();
    let mut args = if mode.is_empty() {
        vec![]
    } else {
        vec![mode.into(), directory.join("dispatches").into_os_string()]
    };
    match idempotency {
        Idempotency::Unspecified => args.push("unmarked".into()),
        Idempotency::NonIdempotent => args.push("non-idempotent".into()),
        Idempotency::Idempotent => {}
    }
    (
        topology,
        Arc::new(DedicatedFixture {
            store,
            args,
            events: Default::default(),
            fail_empty: Default::default(),
            fail_sandbox_empty: Default::default(),
            guards: Default::default(),
        }),
    )
}

#[test]
fn dedicated_startup_failure_retains_cleanup_owners() {
    struct Launcher {
        fixture: Arc<DedicatedFixture>,
        missing_executable: Option<std::path::PathBuf>,
    }
    impl ProcessLauncher for Launcher {
        fn prepare(
            &self,
            role: ProgramRole,
            definition: &ProcessDefinition,
        ) -> Result<PreparedProcess> {
            let mut prepared = self.fixture.prepare(role, definition)?;
            if role == ProgramRole::SandboxHost
                && let Some(path) = &self.missing_executable
            {
                prepared.config = prepared.config.process_name(path);
            }
            Ok(prepared)
        }
    }
    for missing_executable in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (topology, fixture) = dedicated_fixture(directory.path(), "", Idempotency::Idempotent);
        fixture.fail_empty.store(true, Ordering::Release);
        fixture.fail_sandbox_empty.store(true, Ordering::Release);
        let launcher = Arc::new(Launcher {
            fixture: fixture.clone(),
            missing_executable: missing_executable
                .then(|| directory.path().join("missing-sandbox")),
        });
        let error = SandboxProcess::launch(
            topology,
            launcher,
            runtime::RestartPolicy::default(),
            SandboxSource::Binary(vec![0]),
            &SandboxConfiguration::default(),
            None,
            vec![FunctionContractDefinition::from_contract(&PRINT)],
        )
        .expect_err("Invalid sandbox must fail startup");
        assert_eq!(fixture.guards.lock().unwrap().len(), 2);
        assert!(
            fixture
                .guards
                .lock()
                .unwrap()
                .iter()
                .all(|guard| guard.upgrade().is_some()),
            "Startup error lost a sandbox or worker cleanup owner: {error}"
        );
        assert!(
            !fixture
                .events
                .lock()
                .unwrap()
                .iter()
                .any(|event| event.starts_with("release:"))
        );
        fixture.fail_empty.store(false, Ordering::Release);
        fixture.fail_sandbox_empty.store(false, Ordering::Release);
        drop(error);
        for name in ["sandbox", "worker"] {
            assert_eq!(
                fixture
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == format!("release:{name}"))
                    .count(),
                1
            );
        }
        assert!(
            fixture
                .guards
                .lock()
                .unwrap()
                .iter()
                .all(|guard| guard.upgrade().is_none())
        );
    }
}

fn launch_dedicated(
    topology: ProcessTopologyDefinition,
    launcher: Arc<DedicatedFixture>,
    source: SandboxSource,
) -> MultiUseSandbox {
    SandboxProcess::launch(
        topology,
        launcher,
        runtime::RestartPolicy {
            max_restarts: 2,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
            ..Default::default()
        },
        source,
        &SandboxConfiguration::default(),
        None,
        vec![FunctionContractDefinition::from_contract(&PRINT)],
    )
    .unwrap()
}

fn dispatches(directory: &std::path::Path) -> usize {
    std::fs::read_to_string(directory.join("dispatches"))
        .unwrap()
        .lines()
        .count()
}

#[test]
fn dedicated_direct_guest_worker_recovery_and_snapshot_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let (topology, launcher) =
        dedicated_fixture(directory.path(), "--crash-once", Idempotency::Idempotent);
    let mut sandbox = launch_dedicated(topology.clone(), launcher.clone(), source());
    let initial = sandbox.process_reports();
    assert_eq!(initial.len(), 2);
    assert_eq!(initial[0].role, ProgramRole::SandboxHost);
    let snapshot = sandbox.snapshot().unwrap();
    assert_eq!(snapshot.process_topology(), Some(&topology));
    assert_eq!(sandbox.call::<i32>("Add", (10, 32)).unwrap(), 42);
    assert_eq!(dispatches(directory.path()), 2);
    let replacement = sandbox.process_reports();
    assert_eq!(initial[0].root_process_id, replacement[0].root_process_id);
    assert_ne!(initial[1].root_process_id, replacement[1].root_process_id);
    assert_eq!(sandbox.call::<i32>("Add", (2, 3)).unwrap(), 5);
    sandbox.restore(snapshot.clone()).unwrap();
    assert_eq!(
        sandbox.process_reports()[1].root_process_id,
        replacement[1].root_process_id
    );
    assert_eq!(sandbox.call::<i32>("Add", (4, 5)).unwrap(), 9);
    let mut reconstructed = launch_dedicated(
        topology,
        launcher.clone(),
        SandboxSource::Snapshot(SnapshotImage::capture(&snapshot).unwrap()),
    );
    assert_eq!(reconstructed.call::<i32>("Add", (20, 22)).unwrap(), 42);
    let fresh = reconstructed.process_reports();
    assert_ne!(fresh[0].root_process_id, replacement[0].root_process_id);
    assert_ne!(fresh[1].root_process_id, replacement[1].root_process_id);
    drop(sandbox);
    assert_eq!(reconstructed.call::<i32>("Add", (5, 6)).unwrap(), 11);
    drop(reconstructed);
    let events = launcher.events.lock().unwrap().clone();
    assert_eq!(
        &events[..7],
        [
            "prepare:sandbox",
            "prepare:worker",
            "terminate:worker",
            "terminate:worker",
            "empty:worker",
            "release:worker",
            "prepare:worker"
        ]
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| *event == "empty:sandbox")
            .count(),
        2
    );
}

#[test]
fn dedicated_ambiguous_nonidempotent_failure_recovers_only_next_call() {
    for idempotency in [Idempotency::Unspecified, Idempotency::NonIdempotent] {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = dedicated_fixture(directory.path(), "--crash-once", idempotency);
        let mut sandbox = launch_dedicated(topology, launcher, source());
        assert!(sandbox.call::<i32>("Add", (10, 32)).is_err());
        assert_eq!(dispatches(directory.path()), 1);
        assert!(sandbox.status().is_ready());
        assert_eq!(sandbox.call::<i32>("Add", (10, 32)).unwrap(), 42);
        assert_eq!(dispatches(directory.path()), 2);
    }
}

#[test]
fn dedicated_exhaustion_is_terminal_and_sibling_is_independent() {
    let bad = tempfile::tempdir().unwrap();
    let good = tempfile::tempdir().unwrap();
    let (topology, launcher) =
        dedicated_fixture(bad.path(), "--crash-always", Idempotency::Idempotent);
    let mut failing = launch_dedicated(topology, launcher, source());
    let (topology, launcher) = dedicated_fixture(good.path(), "", Idempotency::Idempotent);
    let mut healthy = launch_dedicated(topology, launcher, source());
    let snapshot = failing.snapshot().unwrap();
    assert!(failing.call::<i32>("Add", (1, 2)).is_err());
    assert_eq!(failing.status(), SandboxStatus::Unrecoverable);
    assert!(failing.restore(snapshot).is_err());
    assert!(failing.call::<i32>("EchoI32", 7).is_err());
    assert_eq!(dispatches(bad.path()), 3);
    assert_eq!(healthy.call::<i32>("Add", (1, 2)).unwrap(), 3);
    assert!(healthy.status().is_ready());
}

#[test]
fn dedicated_sandbox_host_loss_is_terminal_without_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (topology, launcher) = dedicated_fixture(directory.path(), "", Idempotency::Idempotent);
    let mut sandbox = launch_dedicated(topology, launcher.clone(), source());
    assert!(
        sandbox
            .call::<i32>("PrintOutput", "__exit_sandbox".to_owned())
            .is_err()
    );
    assert_eq!(sandbox.status(), SandboxStatus::Unrecoverable);
    assert!(sandbox.call::<i32>("Add", (1, 2)).is_err());
    let events = launcher.events.lock().unwrap().clone();
    assert_eq!(events, ["prepare:sandbox", "prepare:worker"]);
    drop(sandbox);
    let events = launcher.events.lock().unwrap().clone();
    assert!(events.iter().any(|event| event == "empty:sandbox"));
    assert!(events.iter().any(|event| event == "empty:worker"));
}

#[test]
fn dedicated_failed_domain_cleanup_forbids_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let (topology, launcher) =
        dedicated_fixture(directory.path(), "--crash-once", Idempotency::Idempotent);
    let mut sandbox = launch_dedicated(topology, launcher.clone(), source());
    launcher.fail_empty.store(true, Ordering::Release);
    assert!(sandbox.call::<i32>("Add", (1, 2)).is_err());
    assert_eq!(sandbox.status(), SandboxStatus::Unrecoverable);
    assert_eq!(dispatches(directory.path()), 1);
    let events = launcher.events.lock().unwrap().clone();
    assert_eq!(
        events,
        [
            "prepare:sandbox",
            "prepare:worker",
            "terminate:worker",
            "terminate:worker",
            "empty:worker"
        ]
    );
    launcher.fail_empty.store(false, Ordering::Release);
}

#[test]
fn dedicated_shutdown_reports_cleanup_failure() {
    let directory = tempfile::tempdir().unwrap();
    let (topology, launcher) = dedicated_fixture(directory.path(), "", Idempotency::Idempotent);
    let mut sandbox = launch_dedicated(topology, launcher.clone(), source());
    launcher.fail_empty.store(true, Ordering::Release);
    assert!(sandbox.shutdown().is_err());
    launcher.fail_empty.store(false, Ordering::Release);
    sandbox.shutdown().unwrap();
}
