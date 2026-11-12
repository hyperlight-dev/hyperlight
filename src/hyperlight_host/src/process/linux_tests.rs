// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::os::fd::{AsRawFd, FromRawFd};

use super::*;
use crate::process::program::{
    FunctionContractDefinition, LocalProgramStore, ProgramConfig, ProgramFile, ProgramTarget,
};
use crate::process::{
    HostFunctionContract, HostFunctionProcess, Idempotency, ProcessOptions, ProcessProfile,
    RequestedControl,
};

#[test]
fn unrestricted_preparation_does_not_require_delegated_linux_authority() {
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path().join("store"));
    let target = ProgramTarget::current(Default::default());
    let config = ProgramConfig {
        schema_version: 1,
        role: ProgramRole::SandboxHost,
        target: target.clone(),
        functions: Vec::new(),
    };
    let artifact = store.package(&config, b"native").unwrap();
    let definition = ProcessDefinition::new(
        "unrestricted",
        artifact.clone(),
        &ProcessProfile::unrestricted(),
        Vec::new(),
    )
    .unwrap();
    let validated = store.validate(&artifact, &target).unwrap();

    let prepared = prepare(
        ProgramRole::SandboxHost,
        &definition,
        &validated,
        None,
        Some("delegated authority unavailable"),
    )
    .unwrap();

    assert!(prepared.controls.is_empty());
}

#[test]
fn restricted_preparation_requires_delegated_linux_authority() {
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path().join("store"));
    let target = ProgramTarget::current(Default::default());
    let config = ProgramConfig {
        schema_version: 1,
        role: ProgramRole::SandboxHost,
        target: target.clone(),
        functions: Vec::new(),
    };
    let artifact = store.package(&config, b"native").unwrap();
    let definition = ProcessDefinition::new(
        "restricted",
        artifact.clone(),
        &ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]),
        Vec::new(),
    )
    .unwrap();
    let validated = store.validate(&artifact, &target).unwrap();

    let error = prepare(
        ProgramRole::SandboxHost,
        &definition,
        &validated,
        None,
        Some("delegated authority unavailable"),
    )
    .err()
    .expect("Restricted preparation must fail without delegated authority");

    assert!(
        error
            .to_string()
            .contains("delegated authority unavailable")
    );
}

#[test]
fn static_elf_needs_no_runtime_closure() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("static.c");
    let executable = directory.path().join("static");
    std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    assert!(
        std::process::Command::new("cc")
            .arg("-static")
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new(&executable)
            .status()
            .unwrap()
            .success()
    );
    assert!(super::runtime_closure(&executable).unwrap().is_empty());
}

#[test]
fn malformed_static_candidate_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("invalid");
    std::fs::write(&executable, b"not an ELF").unwrap();
    assert!(super::runtime_closure(&executable).is_err());
}

fn origin_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let library_source = directory.path().join("helper.c");
    let program_source = directory.path().join("program.c");
    let library = directory.path().join("liborigin_helper.so");
    let program = directory.path().join("origin-program");
    std::fs::write(&library_source, "int origin_helper(void) { return 42; }\n").unwrap();
    std::fs::write(
        &program_source,
        "extern int origin_helper(void); int main(void) { return origin_helper() != 42; }\n",
    )
    .unwrap();
    assert!(
        std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-Wl,-soname,liborigin_helper.so"])
            .arg(&library_source)
            .arg("-o")
            .arg(&library)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("cc")
            .arg(&program_source)
            .arg("-L")
            .arg(directory.path())
            .arg("-lorigin_helper")
            .arg("-Wl,-rpath,$ORIGIN")
            .arg("-o")
            .arg(&program)
            .status()
            .unwrap()
            .success()
    );
    (directory, program, library)
}

#[test]
fn origin_dependency_is_resolved_and_captured() {
    let (_directory, program, library) = origin_fixture();
    let expected = std::fs::read(library).unwrap();
    let files = super::runtime_closure(&program).unwrap();
    let captured = files
        .iter()
        .find(|file| file.image_path() == "/liborigin_helper.so")
        .unwrap();
    assert_eq!(captured.bytes(), expected);
}

#[test]
fn unresolved_origin_dependency_is_rejected() {
    let (_directory, program, library) = origin_fixture();
    std::fs::remove_file(library).unwrap();
    let error = super::runtime_closure(&program).unwrap_err();
    assert!(error.to_string().contains("not found"));
}

const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("HostAdd", Idempotency::Idempotent);
const PID: HostFunctionContract<(), u32> =
    HostFunctionContract::new("ProcessId", Idempotency::Idempotent);
const PRINT: HostFunctionContract<(String,), i32> =
    HostFunctionContract::new("HostPrint", Idempotency::Idempotent);

fn test_resources() -> (PathBuf, LinuxProcessResources) {
    let root =
        PathBuf::from(std::env::var_os("HYPERLIGHT_TEST_CGROUP_ROOT").expect("delegated root"));
    let helper = std::env::var_os("HYPERLIGHT_TEST_MINIJAIL").expect("explicit strict helper");
    let digest: [u8; 32] = hex::decode(
        std::env::var("HYPERLIGHT_TEST_MINIJAIL_SHA256").expect("trusted helper digest"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let resources = LinuxProcessResources::new(&root, helper, digest).unwrap();
    (root, resources)
}

fn runtime_files() -> Vec<ProgramFile> {
    let files: Vec<(String, PathBuf)> = serde_json::from_str(
        &std::env::var("HYPERLIGHT_TEST_RUNTIME_FILES").expect("explicit runtime-file manifest"),
    )
    .unwrap();
    files
        .into_iter()
        .map(|(image, source)| ProgramFile::new(image, fs::read(source).unwrap()).unwrap())
        .collect()
}

fn owned_domain(root: &Path, process_id: i32) -> PathBuf {
    let domains = fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("hyperlight-")
            {
                return None;
            }
            let path = entry.path();
            fs::read_to_string(path.join("cgroup.procs"))
                .unwrap()
                .lines()
                .any(|pid| pid.parse::<i32>().unwrap() == process_id)
                .then_some(path)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        domains.len(),
        1,
        "Reported root must belong to exactly one owned domain"
    );
    domains.into_iter().next().unwrap()
}

#[test]
#[ignore = "requires explicit native device probe and delegated driver"]
fn sandbox_host_hypervisor_access_diagnostics() {
    let output = probe_hypervisor_access(ProgramRole::SandboxHost);
    assert!(
        output.contains("KVM_ACCESS_OK"),
        "Sandbox-host KVM access failed"
    );
}

#[test]
#[ignore = "requires explicit native device probe and delegated driver"]
fn function_worker_has_no_hypervisor_device() {
    let output = probe_hypervisor_access(ProgramRole::FunctionWorker);
    assert!(
        output.contains("OPEN=-1 errno=2"),
        "Function worker can see the hypervisor device"
    );
    assert!(!output.contains("KVM_ACCESS_OK"));
}

fn probe_hypervisor_access(role: ProgramRole) -> String {
    probe_linux_access(role, "HYPERLIGHT_TEST_DEVICE_PROBE", false)
}

#[test]
#[ignore = "requires explicit child-process probe and delegated driver"]
fn child_process_syscalls_are_denied_in_existing_and_new_threads() {
    for role in [ProgramRole::FunctionWorker, ProgramRole::SandboxHost] {
        let output = probe_linux_access(role, "HYPERLIGHT_TEST_CHILD_PROCESS_PROBE", true);
        assert!(output.contains("CHILD_POLICY_OK"), "{role:?}: {output}");
        assert_eq!(
            output.matches("clone process denied").count(),
            9,
            "{output}"
        );
    }
}

#[test]
#[ignore = "requires child and baseline probes, strict helper, runtime files, device and delegated driver"]
fn ipc_and_keyring_isolation_apply_to_both_roles_without_child_policy() {
    let caller_ipc = fs::read_link("/proc/self/ns/ipc").unwrap();
    for role in [ProgramRole::FunctionWorker, ProgramRole::SandboxHost] {
        for (probe, deny_children) in [
            ("HYPERLIGHT_TEST_BASELINE_PROBE", false),
            ("HYPERLIGHT_TEST_CHILD_PROCESS_PROBE", true),
        ] {
            let output = probe_linux_access(role, probe, deny_children);
            assert!(output.contains("KEY_POLICY_OK"), "{role:?}: {output}");
            let workload_ipc = output
                .lines()
                .find_map(|line| line.strip_prefix("IPC_NAMESPACE="))
                .expect("probe IPC namespace identity");
            assert_ne!(Path::new(workload_ipc), caller_ipc.as_path(), "{output}");
            for syscall in ["keyctl", "add_key", "request_key"] {
                assert_eq!(
                    output.matches(&format!("{syscall} denied")).count(),
                    3,
                    "{role:?}: {output}"
                );
            }
        }
    }
}

#[test]
#[ignore = "requires explicit child-process probe, strict helper and delegated driver"]
fn invalid_seccomp_filter_fails_before_workload_and_cleans_domain() {
    for deny_children in [false, true] {
        check_invalid_seccomp_filter(deny_children);
    }
}

fn check_invalid_seccomp_filter(deny_children: bool) {
    let (root, resources) = test_resources();
    let before = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::BTreeSet<_>>();
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path().join("store"));
    let target = ProgramTarget::current(Default::default());
    let program = store
        .package_with_runtime(
            &ProgramConfig {
                schema_version: 1,
                role: ProgramRole::FunctionWorker,
                target: target.clone(),
                functions: vec![FunctionContractDefinition::from_contract(&PID)],
            },
            &fs::read(std::env::var_os("HYPERLIGHT_TEST_CHILD_PROCESS_PROBE").unwrap()).unwrap(),
            &runtime_files(),
        )
        .unwrap();
    let validated = store.validate(&program, &target).unwrap();
    let image = Image::stage(&resources, &validated, deny_children).unwrap();
    let staged_path = image.directory.path().to_owned();
    let filter = &image.process_filter;
    // A complete instruction without a terminating return reaches the kernel verifier.
    let mut invalid = Vec::from((libc::BPF_LD as u16).to_ne_bytes());
    invalid.extend_from_slice(&[0, 0]);
    invalid.extend_from_slice(&0_u32.to_ne_bytes());
    fs::set_permissions(filter, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(filter, invalid).unwrap();
    fs::set_permissions(filter, fs::Permissions::from_mode(0o400)).unwrap();
    let domain = Domain::create(&root).unwrap();
    domain
        .configure(&RequestedControl {
            control: ProcessControl::MemoryLimit(64 << 20),
            required: true,
        })
        .unwrap();
    let (output, writer) = Output::new("invalid-filter").unwrap();
    let capture_path = directory.path().join("helper-output");
    let capture = File::create(&capture_path).unwrap();
    let config = mesh_process::ProcessConfig::new_with_sandbox(
        "invalid-filter",
        Box::new(Profile {
            enrollment: domain.procs_fd(),
        }),
    )
    .process_name(&image.helper)
    .args(
        image
            .arguments(ProgramRole::FunctionWorker, &resources, true)
            .unwrap(),
    )
    .skip_worker_arg(true)
    .stdout(Some(capture.try_clone().unwrap()))
    .stderr(Some(capture));
    drop(writer);
    let guard = Arc::new(Guard {
        domain,
        image: Mutex::new(Some(image)),
        output,
        retain: AtomicBool::new(false),
    });
    futures_lite::future::block_on(async {
        let mesh = mesh_process::Mesh::new("invalid-filter".to_owned()).unwrap();
        match super::super::launch::launch_owned(
            &mesh,
            config,
            (),
            guard.clone(),
            mesh::CancelContext::new(),
            Duration::from_secs(5),
        )
        .await
        {
            Ok(mut child) => {
                let exit = mesh::CancelContext::new()
                    .with_timeout(Duration::from_secs(2))
                    .until_cancelled(child.wait_root())
                    .await;
                eprintln!("Invalid-filter root result: {exit:?}");
                super::super::launch::cleanup_owned(
                    &mut child,
                    guard.as_ref(),
                    Instant::now() + Duration::from_secs(10),
                )
                .await
                .unwrap();
            }
            Err(error) => {
                assert!(
                    !super::super::launch::has_cleanup_owner(&error),
                    "Unconfirmed invalid-filter cleanup: {error}"
                );
            }
        }
        mesh::CancelContext::new()
            .with_timeout(Duration::from_secs(10))
            .until_cancelled(mesh.shutdown())
            .await
            .unwrap();
    });
    let output = fs::read_to_string(capture_path).unwrap();
    assert!(output.contains("prctl(seccomp_filter) failed"), "{output}");
    assert!(!output.contains("WORKLOAD_EXECUTED"), "{output}");
    assert!(!staged_path.exists(), "Invalid-filter image retained");
    let after = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(before, after, "Invalid-filter domain retained");
}

fn probe_linux_access(role: ProgramRole, probe: &str, deny_children: bool) -> String {
    let (_, resources) = test_resources();
    let resources = resources
        .hypervisor_device(std::env::var_os("HYPERLIGHT_TEST_HYPERVISOR_DEVICE").unwrap())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path().join("store"));
    let target = ProgramTarget::current(Default::default());
    let executable = fs::read(std::env::var_os(probe).unwrap()).unwrap();
    let functions = if role == ProgramRole::FunctionWorker {
        vec![FunctionContractDefinition::from_contract(&PID)]
    } else {
        vec![]
    };
    let artifact = store
        .package_with_runtime(
            &ProgramConfig {
                schema_version: 1,
                role,
                target: target.clone(),
                functions: functions.clone(),
            },
            &executable,
            &runtime_files(),
        )
        .unwrap();
    let mut controls = vec![
        RequestedControl {
            control: ProcessControl::MemoryLimit(64 << 20),
            required: true,
        },
        RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        },
    ];
    if deny_children {
        controls.push(RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        });
    }
    let definition = ProcessDefinition::new(
        "device-probe",
        artifact.clone(),
        &ProcessProfile::new(controls),
        functions,
    )
    .unwrap();
    let validated = store.validate(&artifact, &target).unwrap();
    let mut prepared = prepare(role, &definition, &validated, Some(&resources), None).unwrap();
    let output_path = directory.path().join("device-output");
    let output = File::create(&output_path).unwrap();
    prepared.config = prepared
        .config
        .stdout(Some(output.try_clone().unwrap()))
        .stderr(Some(output));
    futures_lite::future::block_on(async {
        let mesh = mesh_process::Mesh::new("device-probe".to_owned()).unwrap();
        let mut root = super::super::launch::launch_owned(
            &mesh,
            prepared.config,
            (),
            prepared.guard.clone(),
            mesh::CancelContext::new(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let exited = mesh::CancelContext::new()
            .with_timeout(Duration::from_secs(10))
            .until_cancelled(root.wait_root())
            .await;
        let cleanup = super::super::launch::cleanup_owned(
            &mut root,
            prepared.guard.as_ref(),
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        let output = fs::read_to_string(&output_path).unwrap();
        eprintln!("{role:?} device probe: exit={exited:?} cleanup={cleanup:?}\n{output}");
        cleanup.unwrap();
        mesh::CancelContext::new()
            .with_timeout(Duration::from_secs(10))
            .until_cancelled(mesh.shutdown())
            .await
            .unwrap();
        output
    })
}

#[test]
fn helper_identity_is_verified_before_launch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("helper");
    fs::write(&path, b"helper").unwrap();
    assert!(LinuxProcessResources::new(directory.path(), &path, [0; 32]).is_err());
    let digest: [u8; 32] = Sha256::digest(b"helper").into();
    let resources = LinuxProcessResources::new(directory.path(), &path, digest).unwrap();
    fs::write(path, b"replacement").unwrap();
    assert!(matches!(
        &resources.helper,
        HelperSource::Captured(bytes) if &**bytes == b"helper"
    ));
    assert!(
        resources
            .installed_helper(directory.path().join("helper"))
            .is_err()
    );
}

#[test]
fn duplicate_controls_cannot_override_required_limits() {
    let profile = ProcessProfile::new([
        RequestedControl {
            control: ProcessControl::MemoryLimit(4096),
            required: true,
        },
        RequestedControl {
            control: ProcessControl::MemoryLimit(8192),
            required: false,
        },
    ]);
    assert!(profile.validate().is_err());
}

#[test]
fn syscall_filter_checks_native_abi_keys_and_optional_clone_flags() {
    fn evaluate(filter: &[u8], nr: u32, arch: u32, flags: u64) -> u32 {
        let mut accumulator = 0;
        let mut pc = 0;
        for _ in 0..filter.len() / 8 {
            let instruction = &filter[pc * 8..][..8];
            let code = u16::from_ne_bytes(instruction[..2].try_into().unwrap());
            let value = u32::from_ne_bytes(instruction[4..].try_into().unwrap());
            pc += 1;
            match code {
                0x20 => {
                    accumulator = match value {
                        0 => nr,
                        4 => arch,
                        16 => flags as u32,
                        _ => panic!("Unexpected seccomp_data offset"),
                    }
                }
                0x15 | 0x45 => {
                    let yes = if code == 0x15 {
                        accumulator == value
                    } else {
                        accumulator & value != 0
                    };
                    pc += usize::from(instruction[if yes { 2 } else { 3 }]);
                }
                0x06 => return value,
                _ => panic!("Unexpected BPF instruction"),
            }
        }
        panic!("Filter did not return");
    }

    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc000_00b7;
    let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    for deny_children in [false, true] {
        let filter = syscall_filter(deny_children);
        for nr in [libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key] {
            for flags in [0, u64::MAX] {
                assert_eq!(evaluate(&filter, nr as u32, arch, flags), denied);
            }
        }
        let child_result = if deny_children {
            denied
        } else {
            libc::SECCOMP_RET_ALLOW
        };
        for flags in [
            0,
            libc::SIGCHLD as u64,
            libc::CLONE_VM as u64,
            (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64,
            libc::CLONE_PARENT as u64,
            1 << 48,
        ] {
            assert_eq!(
                evaluate(&filter, libc::SYS_clone as u32, arch, flags),
                child_result
            );
            assert_eq!(
                evaluate(
                    &filter,
                    libc::SYS_clone as u32,
                    arch,
                    flags | libc::CLONE_THREAD as u64
                ),
                libc::SECCOMP_RET_ALLOW
            );
        }
        assert_eq!(
            evaluate(&filter, libc::SYS_clone3 as u32, arch, 0),
            if deny_children {
                libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
            } else {
                libc::SECCOMP_RET_ALLOW
            }
        );
        assert_eq!(
            evaluate(&filter, libc::SYS_getpid as u32, arch, 0),
            libc::SECCOMP_RET_ALLOW
        );
        for nr in [libc::SYS_clone, libc::SYS_keyctl, libc::SYS_getpid] {
            assert_eq!(
                evaluate(&filter, nr as u32, 0x4000_0003, u64::MAX),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
        #[cfg(target_arch = "x86_64")]
        {
            for nr in [libc::SYS_fork, libc::SYS_vfork] {
                assert_eq!(evaluate(&filter, nr as u32, arch, u64::MAX), child_result);
            }
            for nr in [
                libc::SYS_clone,
                libc::SYS_clone3,
                libc::SYS_keyctl,
                libc::SYS_add_key,
                libc::SYS_request_key,
                libc::SYS_getpid,
            ] {
                assert_eq!(
                    evaluate(&filter, nr as u32 | 0x4000_0000, arch, u64::MAX),
                    denied
                );
            }
        }
    }
}

#[test]
fn baseline_filter_and_namespaces_are_required_for_both_roles() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("helper");
    fs::write(&helper, b"helper").unwrap();
    let mut resources =
        LinuxProcessResources::new(directory.path(), &helper, Sha256::digest(b"helper").into())
            .unwrap();
    // Argument construction only. No hypervisor or namespace privileges are needed.
    resources.hypervisor_device = Some(PathBuf::from("/dev/null"));
    let store = LocalProgramStore::new(directory.path().join("store"));
    let target = ProgramTarget::current(Default::default());
    let artifact = store
        .package(
            &ProgramConfig {
                schema_version: 1,
                role: ProgramRole::FunctionWorker,
                target: target.clone(),
                functions: vec![FunctionContractDefinition::from_contract(&ADD)],
            },
            b"program",
        )
        .unwrap();
    let program = store.validate(&artifact, &target).unwrap();
    for requested in [false, true] {
        let image = Image::stage(&resources, &program, requested).unwrap();
        let filter = &image.process_filter;
        assert!(!filter.starts_with(&image.root));
        assert_eq!(fs::read(filter).unwrap(), syscall_filter(requested));
        assert_eq!(
            fs::metadata(filter).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(write_image_file(filter, b"replacement", 0o400).is_err());
        assert_eq!(fs::read(filter).unwrap(), syscall_filter(requested));
        for role in [ProgramRole::FunctionWorker, ProgramRole::SandboxHost] {
            for deny_network in [false, true] {
                let arguments = image.arguments(role, &resources, deny_network).unwrap();
                for required in ["-I", "-l", "-w", "--seccomp-bpf-binary"] {
                    assert_eq!(arguments.iter().filter(|arg| *arg == required).count(), 1);
                }
                assert!(arguments.windows(2).any(|args| {
                    args[0] == "--seccomp-bpf-binary" && args[1] == filter.to_str().unwrap()
                }));
            }
        }
    }
}

#[test]
#[ignore = "requires explicit helper, runtime image, test guest and delegated driver"]
fn guest_calls_production_linux_worker_and_reconstructs_snapshot() {
    check_guest_calls_and_snapshot("HYPERLIGHT_TEST_PROCESS_WORKER");
}

#[test]
#[ignore = "requires explicit child-policy worker, runtime image, guest and delegated driver"]
fn confined_rust_thread_calls_mesh_and_cannot_spawn_processes() {
    check_guest_calls_and_snapshot("HYPERLIGHT_TEST_CHILD_POLICY_WORKER");
}

fn check_guest_calls_and_snapshot(worker_image: &str) {
    let mut checkpoint = Instant::now();
    let mut timing = |step| {
        eprintln!("linux-production {step}: {:?}", checkpoint.elapsed());
        checkpoint = Instant::now();
    };
    let (root, resources) = test_resources();
    let worker = fs::read(std::env::var_os(worker_image).expect("built worker")).unwrap();
    let runtime_files = runtime_files();
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path());
    let target = ProgramTarget::current(Default::default());
    let artifact = store
        .package_with_runtime(
            &ProgramConfig {
                schema_version: 1,
                role: ProgramRole::FunctionWorker,
                target: target.clone(),
                functions: vec![
                    FunctionContractDefinition::from_contract(&ADD),
                    FunctionContractDefinition::from_contract(&PID),
                ],
            },
            &worker,
            &runtime_files,
        )
        .unwrap();
    timing("package");
    let profile = ProcessProfile::new([
        RequestedControl {
            control: ProcessControl::MemoryLimit(256 * 1024 * 1024),
            required: true,
        },
        RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: Duration::from_millis(50),
                period: Duration::from_millis(100),
            },
            required: true,
        },
        RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        },
        RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        },
    ]);
    let mut sandbox =
        crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
            .host_function_process(
                HostFunctionProcess::new(ProcessOptions::with_program_artifact(
                    "arithmetic",
                    artifact,
                    profile,
                ))
                .function(ADD)
                .function(PID),
            )
            .process_programs(store.clone(), target.clone())
            .linux_process_resources(resources.clone())
            .build()
            .unwrap();
    timing("initial-startup");
    assert_eq!(sandbox.call::<i32>("Add", (10_i32, 32_i32)).unwrap(), 42);
    timing("first-call");
    let reports = sandbox.process_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].controls.len(), 4);
    assert!(
        reports[0]
            .controls
            .iter()
            .all(|control| matches!(control.result, ControlResult::Applied { .. }))
    );
    let original = reports[0].root_process_id;
    let snapshot = sandbox.snapshot().unwrap();
    timing("snapshot");
    let mut restored = crate::SandboxBuilder::from_snapshot(snapshot.clone())
        .process_programs(store, target)
        .linux_process_resources(resources)
        .build()
        .unwrap();
    timing("reconstruction-startup");
    assert_ne!(original, restored.process_reports()[0].root_process_id);
    assert_eq!(restored.call::<i32>("Add", (20_i32, 22_i32)).unwrap(), 42);
    timing("reconstructed-call");
    sandbox.restore(snapshot).unwrap();
    timing("in-place-restore");
    assert_eq!(original, sandbox.process_reports()[0].root_process_id);
    assert_eq!(sandbox.call::<i32>("Add", (40_i32, 2_i32)).unwrap(), 42);
    timing("restored-call");
    drop(restored);
    timing("reconstructed-shutdown");
    drop(sandbox);
    timing("original-shutdown");
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("hyperlight-")
    }));
}

#[test]
#[ignore = "requires explicit sandbox/worker images, hypervisor device and delegated driver"]
fn confined_dedicated_vm_calls_worker_restores_and_fails_independently() {
    eprintln!("dedicated-qualification: preparing production images");
    let (root, resources) = test_resources();
    let resources = resources
        .hypervisor_device(
            std::env::var_os("HYPERLIGHT_TEST_HYPERVISOR_DEVICE")
                .expect("explicit hypervisor device"),
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = LocalProgramStore::new(directory.path());
    let target = ProgramTarget::current(Default::default());
    let files = runtime_files();
    let package = |role, variable, functions| {
        let bytes = fs::read(std::env::var_os(variable).expect("built process image")).unwrap();
        store
            .package_with_runtime(
                &ProgramConfig {
                    schema_version: 1,
                    role,
                    target: target.clone(),
                    functions,
                },
                &bytes,
                &files,
            )
            .unwrap()
    };
    let sandbox_program = package(
        ProgramRole::SandboxHost,
        "HYPERLIGHT_TEST_SANDBOX_WORKER",
        vec![FunctionContractDefinition::from_contract(&PRINT)],
    );
    let function_program = package(
        ProgramRole::FunctionWorker,
        "HYPERLIGHT_TEST_PROCESS_WORKER",
        vec![
            FunctionContractDefinition::from_contract(&ADD),
            FunctionContractDefinition::from_contract(&PID),
        ],
    );
    let profile = |memory| {
        ProcessProfile::new([
            RequestedControl {
                control: ProcessControl::MemoryLimit(memory),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            },
        ])
    };
    let mut sandbox =
        crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
            .sandbox_process(ProcessOptions::with_program_artifact(
                "dedicated-vm",
                sandbox_program,
                profile(512 << 20),
            ))
            .sandbox_host_function(PRINT)
            .host_function_process(
                HostFunctionProcess::new(ProcessOptions::with_program_artifact(
                    "arithmetic",
                    function_program,
                    profile(256 << 20),
                ))
                .function(ADD)
                .function(PID),
            )
            .process_programs(store.clone(), target.clone())
            .linux_process_resources(resources.clone())
            .build()
            .unwrap();
    eprintln!("dedicated-qualification: initial processes ready");
    let original = sandbox.process_reports();
    assert_eq!(original.len(), 2);
    assert_ne!(original[0].root_process_id, original[1].root_process_id);
    assert!(original.iter().all(|report| report.controls.len() == 3));
    assert!(original.iter().all(|report| {
        report
            .controls
            .iter()
            .all(|control| matches!(control.result, ControlResult::Applied { .. }))
    }));
    assert!(
        original
            .iter()
            .any(|report| report.role == ProgramRole::SandboxHost)
    );
    assert!(
        original
            .iter()
            .any(|report| report.role == ProgramRole::FunctionWorker)
    );
    for report in &original {
        let domain = owned_domain(&root, report.root_process_id);
        let expected = if report.role == ProgramRole::SandboxHost {
            512_u64 << 20
        } else {
            256_u64 << 20
        };
        assert_eq!(
            fs::read_to_string(domain.join("memory.max"))
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap(),
            expected
        );
        eprintln!(
            "dedicated-qualification: {:?} root={} domain={domain:?} memory={expected}",
            report.role, report.root_process_id
        );
    }
    let worker = original
        .iter()
        .find(|report| report.role == ProgramRole::FunctionWorker)
        .unwrap();
    assert!(worker.root_process_id > 0);
    // Pin the reported OS root before taking the ownership evidence used at injection.
    // SAFETY: pidfd_open takes a positive process ID and zero flags, with no pointers.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, worker.root_process_id, 0) };
    assert!(
        descriptor >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pidfd_open returned a fresh descriptor, transferred to this sole owner.
    let worker_pidfd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let worker_domain = owned_domain(&root, worker.root_process_id)
        .canonicalize()
        .unwrap();
    assert_eq!(
        worker_domain.parent().unwrap(),
        root.canonicalize().unwrap()
    );
    let worker_cgroup_file = format!("/proc/{}/cgroup", worker.root_process_id);
    let worker_cgroup = fs::read_to_string(&worker_cgroup_file).unwrap();
    let unified_path = worker_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap();
    assert_eq!(
        Path::new("/sys/fs/cgroup")
            .join(unified_path.trim_start_matches('/'))
            .canonicalize()
            .unwrap(),
        worker_domain,
        "Reported root must be enrolled in the exact captured task domain",
    );
    assert_eq!(sandbox.call::<i32>("Add", (10_i32, 32_i32)).unwrap(), 42);
    assert!(
        sandbox
            .call::<i32>("PrintOutput", "local callback".to_owned())
            .unwrap()
            > 0
    );
    let before = sandbox.call::<i32>("GetStatic", ()).unwrap();
    let snapshot = sandbox.snapshot().unwrap();
    assert_eq!(sandbox.call::<i32>("AddToStatic", 7).unwrap(), before + 7);
    sandbox.restore(snapshot.clone()).unwrap();
    assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
    assert_eq!(
        sandbox
            .process_reports()
            .iter()
            .map(|report| report.root_process_id)
            .collect::<Vec<_>>(),
        original
            .iter()
            .map(|report| report.root_process_id)
            .collect::<Vec<_>>()
    );
    eprintln!("dedicated-qualification: in-place snapshot restored in original processes");
    let mut sibling = crate::SandboxBuilder::from_snapshot(snapshot.clone())
        .process_programs(store, target)
        .linux_process_resources(resources)
        .build()
        .unwrap();
    let sibling_reports = sibling.process_reports();
    assert_eq!(sibling_reports.len(), 2);
    assert!(sibling_reports.iter().all(|report| {
        original
            .iter()
            .all(|old| old.root_process_id != report.root_process_id)
    }));
    assert_eq!(sibling.call::<i32>("Add", (20_i32, 22_i32)).unwrap(), 42);
    assert_eq!(sibling.call::<i32>("GetStatic", ()).unwrap(), before);
    eprintln!("dedicated-qualification: fresh sibling reconstructed");

    // Revalidate exact ownership and signal only the pinned root, never a recycled PID.
    assert_eq!(
        fs::read_to_string(&worker_cgroup_file).unwrap(),
        worker_cgroup
    );
    assert!(
        fs::read_to_string(worker_domain.join("cgroup.procs"))
            .unwrap()
            .lines()
            .any(|pid| pid.parse::<i32>().unwrap() == worker.root_process_id)
    );
    // SAFETY: the pidfd remains owned and live. A null siginfo uses SIGKILL with zero flags.
    let signaled = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            worker_pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    assert_eq!(
        signaled,
        0,
        "pidfd_send_signal: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(sandbox.call::<i32>("Add", (30_i32, 12_i32)).unwrap(), 42);
    let recovered = sandbox.process_reports();
    assert_eq!(recovered.len(), 2);
    for report in &recovered {
        let old = original.iter().find(|old| old.role == report.role).unwrap();
        if report.role == ProgramRole::FunctionWorker {
            assert_ne!(report.root_process_id, old.root_process_id);
            assert_ne!(owned_domain(&root, report.root_process_id), worker_domain);
        } else {
            assert_eq!(report.root_process_id, old.root_process_id);
        }
    }
    assert!(
        !worker_domain.exists(),
        "Recovery must remove the retired domain"
    );
    assert_eq!(sandbox.call::<i32>("GetStatic", ()).unwrap(), before);
    assert_eq!(sibling.call::<i32>("Add", (41_i32, 1_i32)).unwrap(), 42);
    assert_eq!(
        sibling
            .process_reports()
            .iter()
            .map(|report| report.root_process_id)
            .collect::<Vec<_>>(),
        sibling_reports
            .iter()
            .map(|report| report.root_process_id)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "dedicated-qualification: confined worker recovered without VM or sibling replacement"
    );

    assert!(
        sandbox
            .call::<i32>("PrintOutput", "__exit_sandbox".to_owned())
            .is_err()
    );
    assert!(sandbox.status().is_unrecoverable());
    assert!(sandbox.restore(snapshot).is_err());
    assert_eq!(sibling.call::<i32>("Add", (40_i32, 2_i32)).unwrap(), 42);
    assert!(
        sibling
            .call::<i32>("PrintOutput", "sibling remains ready".to_owned())
            .unwrap()
            > 0
    );
    eprintln!("dedicated-qualification: sandbox-host loss terminal, sibling still ready");
    drop(sandbox);
    assert_eq!(sibling.call::<i32>("Add", (39_i32, 3_i32)).unwrap(), 42);
    drop(sibling);
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("hyperlight-")
    }));
    eprintln!("dedicated-qualification: all owned cgroup leaves removed before harness exit");
}
