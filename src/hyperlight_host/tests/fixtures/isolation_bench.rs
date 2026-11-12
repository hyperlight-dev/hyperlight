// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! One explicit scenario per fresh release process:
//! `isolation_bench --config input.json [--allow-trusted-windows-sandbox-host]`.
//!
//! Input is a strict JSON `Config`. Counts are mandatory. `samples` is 1..=1000,
//! `warmup` is 0..=100 and `vm_starts` is 1..=16 in sequential mode.
//! Opt-in resident mode holds 1,2,4,8 independent VMs. Recovery faults one worker.
//! `work_directory` must not exist. Its parent must exist. Artifacts remain there.
//! Every input file carries a lowercase SHA-256. `source_fingerprint_sha256` hashes
//! compact UTF-8 JSON of the sorted map from source paths to their digests.
//! Unicode is literal, not ASCII-escaped.
//! This verifies listed source bytes, not their relationship to compiled binaries.
//! `controller_sha256` pins this executable. `machine` and `filesystem` are caller
//! descriptions, not measurements. Native dependencies are explicit image files.
//!
//! Scenarios: `legacy-local`, `calling-vm-local-functions`,
//! `calling-vm-separate-functions`, `separate-vm-local-functions`,
//! `separate-vm-separate-functions`. The first two use the identical local path.
//! Build `legacy-local` both with and without `process-isolation` for comparison.
//! Windows dedicated hosts require the CLI consent flag on every invocation.
//! Linux requires explicit delegated cgroup, pinned Minijail and device inputs.
//!
//! Output is one versioned JSON object on stdout. Any failure invalidates all
//! samples and exits nonzero. Durations are wall-clock nanoseconds. Resident and
//! recovery modes require an explicitly authorized external observer. Internal
//! startup phases and independent domain cleanup are not timed by this fixture.
//! String calls use RoundTripHostString/HostEchoString in every placement.
//! Controller size is not the footprint of a minimal enabled-unused consumer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use hyperlight_host::sandbox::snapshot::{OciTag, Snapshot};
use hyperlight_host::{MultiUseSandbox, Result, SandboxBuilder, new_error};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod isolation_bench_contracts;
use isolation_bench_contracts::{add, echo};

const SCHEMA: &str = "hyperlight-isolation-bench/v1";
const IO_BYTES: usize = 256 * 1024;

macro_rules! ensure {
    ($condition:expr, $($message:tt)*) => {
        if !$condition {
            return Err(new_error!($($message)*));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Scenario {
    LegacyLocal,
    CallingVmLocalFunctions,
    CallingVmSeparateFunctions,
    SeparateVmLocalFunctions,
    SeparateVmSeparateFunctions,
}

impl Scenario {
    fn dedicated(self) -> bool {
        matches!(
            self,
            Self::SeparateVmLocalFunctions | Self::SeparateVmSeparateFunctions
        )
    }

    fn remote_functions(self) -> bool {
        matches!(
            self,
            Self::CallingVmSeparateFunctions | Self::SeparateVmSeparateFunctions
        )
    }

    fn processes(self) -> bool {
        self.dedicated() || self.remote_functions()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFile {
    image_path: String,
    file: FileInput,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProgramInput {
    executable: FileInput,
    runtime_files: Vec<RuntimeFile>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxInput {
    delegated_cgroup: PathBuf,
    minijail: FileInput,
    hypervisor_device: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Measurement {
    #[default]
    Sequential,
    Resident {
        sandboxes: usize,
    },
    Recovery,
}

impl Measurement {
    fn validate(self, scenario: Scenario, vm_starts: usize) -> Result<()> {
        if self != Self::Sequential {
            ensure!(vm_starts == 1, "Observed modes require vm_starts=1");
        }
        match self {
            Self::Resident { sandboxes } => ensure!(
                [1, 2, 4, 8].contains(&sandboxes),
                "Resident sandbox count must be 1,2,4,8"
            ),
            Self::Recovery => ensure!(
                scenario.remote_functions(),
                "Recovery requires a separate function worker"
            ),
            Self::Sequential => {}
        }
        Ok(())
    }

    fn live_vms(self) -> usize {
        match self {
            Self::Resident { sandboxes } => sandboxes,
            _ => 1,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    measurement: Measurement,
    scenario: Scenario,
    samples: usize,
    warmup: usize,
    vm_starts: usize,
    payload_bytes: Vec<usize>,
    guest: FileInput,
    controller_sha256: String,
    source_files: Vec<FileInput>,
    source_fingerprint_sha256: String,
    source_revision: String,
    machine: String,
    filesystem: String,
    work_directory: PathBuf,
    worker: Option<ProgramInput>,
    sandbox_host: Option<ProgramInput>,
    os_dependencies: BTreeMap<String, String>,
    process_memory_bytes: u64,
    cpu_quota_us: Option<u64>,
    cpu_period_us: Option<u64>,
    linux: Option<LinuxInput>,
}

impl Config {
    fn validate(&self, consent: bool) -> Result<()> {
        self.measurement.validate(self.scenario, self.vm_starts)?;
        ensure!(!cfg!(debug_assertions), "Use a release build");
        ensure!(
            (1..=1000).contains(&self.samples),
            "samples must be 1..=1000"
        );
        ensure!(self.warmup <= 100, "warmup must be 0..=100");
        ensure!(
            (1..=16).contains(&self.vm_starts),
            "vm_starts must be 1..=16"
        );
        ensure!(
            !self.payload_bytes.is_empty()
                && self.payload_bytes.len() <= 4
                && self
                    .payload_bytes
                    .iter()
                    .all(|n| [0, 64, 4096, 65536].contains(n))
                && self.payload_bytes.iter().collect::<BTreeSet<_>>().len()
                    == self.payload_bytes.len(),
            "Choose unique payload sizes from 0, 64, 4096, 65536"
        );
        ensure!(
            !self.source_files.is_empty() && self.source_files.len() <= 4096,
            "Provide 1..=4096 source files"
        );
        ensure!(
            !self.machine.is_empty()
                && !self.filesystem.is_empty()
                && !self.source_revision.is_empty(),
            "Provenance descriptions must be explicit"
        );
        ensure!(
            !self.scenario.processes() || cfg!(feature = "process-isolation"),
            "This placement requires process-isolation"
        );
        ensure!(
            self.worker.is_some() == self.scenario.remote_functions()
                && self.sandbox_host.is_some() == self.scenario.dedicated(),
            "Supply exactly the native programs used by the selected scenario"
        );
        ensure!(
            !consent || (cfg!(target_os = "windows") && self.scenario.dedicated()),
            "Trusted consent is only valid for a dedicated Windows host"
        );
        ensure!(
            !cfg!(target_os = "windows") || !self.scenario.dedicated() || consent,
            "Dedicated Windows hosts require --allow-trusted-windows-sandbox-host"
        );
        ensure!(
            self.linux.is_some() == (cfg!(target_os = "linux") && self.scenario.processes()),
            "Linux process placement requires explicit Linux resources, other scenarios omit them"
        );
        if self.scenario.processes() {
            ensure!(
                (64 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.process_memory_bytes),
                "process_memory_bytes must be 64 MiB..=64 GiB"
            );
        }
        ensure!(
            matches!((self.cpu_quota_us, self.cpu_period_us), (None, None))
                || matches!((self.cpu_quota_us, self.cpu_period_us),
                    (Some(q), Some(p)) if q > 0 && p > 0 && q <= p),
            "Supply both CPU controls with 0 < quota <= period, or neither"
        );
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn verified_file(input: &FileInput) -> Result<Vec<u8>> {
    let bytes = std::fs::read(&input.path)
        .map_err(|error| new_error!("Reading {}: {error}", input.path.display()))?;
    ensure!(
        sha256(&bytes) == input.sha256,
        "SHA-256 mismatch: {}",
        input.path.display()
    );
    Ok(bytes)
}

fn verify_sources(config: &Config) -> Result<()> {
    let mut files = BTreeMap::new();
    for file in &config.source_files {
        verified_file(file)?;
        let name = file
            .path
            .to_str()
            .ok_or_else(|| new_error!("Source path must be UTF-8"))?;
        ensure!(
            files.insert(name, &file.sha256).is_none(),
            "Duplicate source path"
        );
    }
    ensure!(
        sha256(&serde_json::to_vec(&files)?) == config.source_fingerprint_sha256,
        "Source manifest fingerprint mismatch"
    );
    let executable = std::fs::read(std::env::current_exe()?)?;
    ensure!(
        sha256(&executable) == config.controller_sha256,
        "Controller SHA-256 mismatch"
    );
    Ok(())
}

fn surrogate_environment() -> Value {
    let initial = std::env::var("HYPERLIGHT_INITIAL_SURROGATES").ok();
    let maximum = std::env::var("HYPERLIGHT_MAX_SURROGATES").ok();
    let max = maximum
        .as_ref()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(512)
        .min(512);
    let count = initial
        .as_ref()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(max)
        .min(max);
    json!({
        "HYPERLIGHT_INITIAL_SURROGATES": initial,
        "HYPERLIGHT_MAX_SURROGATES": maximum,
        "calling_process_resolved_initial": count,
        "calling_process_resolved_max": max,
        "resolution": "production default/clamp formula, not an observed process count",
        "applies_to": "Windows calling-process VM only",
        "dedicated_windows_host_max": 0,
        "dedicated_windows_host_scope": "production launcher override, one VM per role",
        "mutated_by_harness": false,
        "RUST_LOG": std::env::var("RUST_LOG").ok(),
        "RUST_BACKTRACE": std::env::var("RUST_BACKTRACE").ok()
    })
}

fn unavailable(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

fn record(
    samples: &mut Vec<Value>,
    metric: &str,
    phase: &str,
    vm: usize,
    index: usize,
    payload: Option<usize>,
    start: Instant,
) {
    let duration = start.elapsed().as_nanos();
    samples.push(json!({
        "metric": metric, "phase": phase, "vm_index": vm, "sample_index": index,
        "payload_bytes": payload, "duration": duration,
        "unit": "ns"
    }));
}

#[cfg(feature = "process-isolation")]
mod placement {
    use hyperlight_host::process::program::{
        FunctionContractDefinition, LocalProgramStore, ProgramArtifact, ProgramConfig, ProgramFile,
        ProgramRole, ProgramTarget,
    };
    use hyperlight_host::process::{
        ControlResult, HostFunctionProcess, ProcessControl, ProcessOptions, ProcessProfile,
        RequestedControl, WindowsSandboxHostPolicy,
    };
    use isolation_bench_contracts::{ADD, ECHO};

    use super::*;

    pub struct Placement {
        pub store: LocalProgramStore,
        target: ProgramTarget,
        worker: Option<ProgramArtifact>,
        sandbox: Option<ProgramArtifact>,
        #[cfg(target_os = "linux")]
        resources: Option<hyperlight_host::process::LinuxProcessResources>,
    }

    fn definitions() -> Vec<FunctionContractDefinition> {
        vec![
            FunctionContractDefinition::from_contract(&ADD),
            FunctionContractDefinition::from_contract(&ECHO),
        ]
    }

    fn package(
        input: &ProgramInput,
        role: ProgramRole,
        config: &Config,
        store: &LocalProgramStore,
        target: &ProgramTarget,
        samples: &mut Vec<Value>,
    ) -> Result<ProgramArtifact> {
        let executable = verified_file(&input.executable)?;
        let mut runtime = input
            .runtime_files
            .iter()
            .map(|file| {
                ensure!(
                    file.image_path != "/isolation-bench-mode",
                    "Reserved image path"
                );
                ProgramFile::new(&file.image_path, verified_file(&file.file)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let functions = match role {
            ProgramRole::FunctionWorker => definitions(),
            ProgramRole::SandboxHost => {
                let mode: &[u8] = if config.scenario.remote_functions() {
                    b"remote"
                } else {
                    b"local"
                };
                runtime.push(ProgramFile::new("/isolation-bench-mode", mode.to_vec())?);
                if config.scenario.remote_functions() {
                    Vec::new()
                } else {
                    definitions()
                }
            }
        };
        let definition = ProgramConfig {
            schema_version: 1,
            role,
            target: target.clone(),
            functions,
        };
        let start = Instant::now();
        let artifact = store.package_with_runtime(&definition, &executable, &runtime)?;
        record(
            samples,
            &format!("package_{role:?}"),
            "preparation",
            0,
            0,
            None,
            start,
        );
        let start = Instant::now();
        store.validate(&artifact, target)?;
        record(
            samples,
            &format!("verify_package_{role:?}"),
            "preparation",
            0,
            0,
            None,
            start,
        );
        Ok(artifact)
    }

    fn controls(config: &Config, trusted: bool) -> ProcessProfile {
        let mut controls = vec![
            RequestedControl {
                control: ProcessControl::MemoryLimit(config.process_memory_bytes),
                required: true,
            },
            RequestedControl {
                control: ProcessControl::DenyNetwork,
                required: !trusted,
            },
            RequestedControl {
                control: ProcessControl::DenyChildProcesses,
                required: true,
            },
        ];
        if let (Some(quota), Some(period)) = (config.cpu_quota_us, config.cpu_period_us) {
            controls.push(RequestedControl {
                control: ProcessControl::CpuBudget {
                    quota: std::time::Duration::from_micros(quota),
                    period: std::time::Duration::from_micros(period),
                },
                required: true,
            });
        }
        ProcessProfile::new(controls)
    }

    impl Placement {
        pub fn prepare(config: &Config, samples: &mut Vec<Value>) -> Result<Self> {
            let store = LocalProgramStore::new(config.work_directory.join("programs"));
            let target = ProgramTarget::current(config.os_dependencies.clone());
            let worker = config
                .worker
                .as_ref()
                .map(|p| {
                    package(
                        p,
                        ProgramRole::FunctionWorker,
                        config,
                        &store,
                        &target,
                        samples,
                    )
                })
                .transpose()?;
            let sandbox = config
                .sandbox_host
                .as_ref()
                .map(|p| {
                    package(
                        p,
                        ProgramRole::SandboxHost,
                        config,
                        &store,
                        &target,
                        samples,
                    )
                })
                .transpose()?;
            #[cfg(target_os = "linux")]
            let resources = config
                .linux
                .as_ref()
                .map(|input| -> Result<_> {
                    let digest: [u8; 32] = hex::decode(&input.minijail.sha256)
                        .map_err(|error| new_error!("Invalid Minijail digest: {error}"))?
                        .try_into()
                        .map_err(|_| new_error!("Minijail SHA-256 must be 32 bytes"))?;
                    let resources = hyperlight_host::process::LinuxProcessResources::new(
                        &input.delegated_cgroup,
                        &input.minijail.path,
                        digest,
                    )?;
                    if config.scenario.dedicated() {
                        Ok(resources.hypervisor_device(
                            input.hypervisor_device.as_ref().ok_or_else(|| {
                                new_error!("Dedicated Linux VM needs explicit hypervisor_device")
                            })?,
                        )?)
                    } else {
                        ensure!(
                            input.hypervisor_device.is_none(),
                            "Function-only placement needs no device grant"
                        );
                        Ok(resources)
                    }
                })
                .transpose()?;
            Ok(Self {
                store,
                target,
                worker,
                sandbox,
                #[cfg(target_os = "linux")]
                resources,
            })
        }

        pub fn configure(
            &self,
            mut builder: SandboxBuilder,
            config: &Config,
            consent: bool,
        ) -> SandboxBuilder {
            if !config.scenario.processes() {
                return builder
                    .host_function("HostEchoString", echo)
                    .host_function("HostAdd", add);
            }
            builder = builder.process_programs(self.store.clone(), self.target.clone());
            #[cfg(target_os = "linux")]
            if let Some(resources) = &self.resources {
                builder = builder.linux_process_resources(resources.clone());
            }
            if let Some(program) = &self.sandbox {
                let mut options = ProcessOptions::with_program_artifact(
                    "bench-sandbox",
                    program.clone(),
                    controls(config, consent),
                );
                if consent {
                    options =
                        options.windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted);
                    builder = builder.allow_trusted_windows_sandbox_host();
                }
                builder = builder.sandbox_process(options);
                if !config.scenario.remote_functions() {
                    builder = builder
                        .sandbox_host_function(ECHO)
                        .sandbox_host_function(ADD);
                }
            }
            if let Some(program) = &self.worker {
                builder = builder.host_function_process(
                    HostFunctionProcess::new(ProcessOptions::with_program_artifact(
                        "bench-functions",
                        program.clone(),
                        controls(config, false),
                    ))
                    .function(ECHO)
                    .function(ADD),
                );
            }
            builder
        }

        pub fn artifacts(&self) -> Value {
            json!({
                "worker_manifest_sha256": self.worker.as_ref().map(|a| a.digest().to_string()),
                "sandbox_manifest_sha256": self.sandbox.as_ref().map(|a| a.digest().to_string()),
                "validation": "LocalProgramStore::validate verifies the complete packaged closure",
                "os_inventory": "caller-supplied exact inventory, not independently probed",
                "target": self.target
            })
        }
    }

    fn control(control: &ProcessControl) -> Value {
        match control {
            ProcessControl::MemoryLimit(bytes) => json!({"kind": "memory_limit", "bytes": bytes}),
            ProcessControl::CpuBudget { quota, period } => json!({
                "kind": "cpu_budget", "quota_ns": quota.as_nanos(), "period_ns": period.as_nanos()
            }),
            ProcessControl::DenyNetwork => json!({"kind": "deny_network"}),
            ProcessControl::DenyChildProcesses => json!({"kind": "deny_child_processes"}),
        }
    }

    pub fn reports(sandbox: &MultiUseSandbox) -> Value {
        Value::Array(sandbox.process_reports().iter().map(|report| {
            json!({
                "role": report.role, "name": report.name, "root_process_id": report.root_process_id,
                "isolation": report.effective_isolation(),
                "windows_cpu_rate_limit_percent": report.windows_cpu_rate_limit_percent(),
                "program_manifest_sha256": report.program.digest().to_string(),
                "controls": report.controls.iter().map(|outcome| {
                    let result = match &outcome.result {
                        ControlResult::Applied { effective, mechanism } => json!({
                            "status": "applied", "effective": control(effective), "mechanism": mechanism
                        }),
                        ControlResult::NotApplied { reason } => json!({
                            "status": "not_applied", "effective": null, "reason": reason
                        }),
                    };
                    json!({"requested": control(&outcome.requested.control), "required": outcome.requested.required, "result": result})
                }).collect::<Vec<_>>()
            })
        }).collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn all_placements_have_unique_callback_owners() {
            let directory = tempfile::tempdir().unwrap();
            let store = LocalProgramStore::new(directory.path());
            let target = ProgramTarget::current(Default::default());
            for scenario in [
                Scenario::LegacyLocal,
                Scenario::CallingVmLocalFunctions,
                Scenario::CallingVmSeparateFunctions,
                Scenario::SeparateVmLocalFunctions,
                Scenario::SeparateVmSeparateFunctions,
            ] {
                let config: Config = serde_json::from_value(json!({
                    "scenario": scenario, "samples": 1, "warmup": 0, "vm_starts": 1,
                    "payload_bytes": [64], "guest": {"path": "unused", "sha256": ""},
                    "controller_sha256": "", "source_files": [], "source_fingerprint_sha256": "",
                    "source_revision": "test", "machine": "test", "filesystem": "test",
                    "work_directory": directory.path(), "worker": null, "sandbox_host": null,
                    "os_dependencies": {}, "process_memory_bytes": 256 * 1024 * 1024,
                    "cpu_quota_us": null, "cpu_period_us": null, "linux": null,
                }))
                .unwrap();
                let package = |role, functions| {
                    store
                        .package(
                            &ProgramConfig {
                                schema_version: 1,
                                role,
                                target: target.clone(),
                                functions,
                            },
                            b"declaration-only-test",
                        )
                        .unwrap()
                };
                let placement = Placement {
                    store: store.clone(),
                    target: target.clone(),
                    worker: scenario
                        .remote_functions()
                        .then(|| package(ProgramRole::FunctionWorker, definitions())),
                    sandbox: scenario.dedicated().then(|| {
                        package(
                            ProgramRole::SandboxHost,
                            if scenario.remote_functions() {
                                vec![]
                            } else {
                                definitions()
                            },
                        )
                    }),
                    #[cfg(target_os = "linux")]
                    resources: None,
                };
                // Declaration capture neither launches these bytes nor qualifies confinement.
                let topology = placement
                    .configure(
                        SandboxBuilder::from_bytes(vec![]),
                        &config,
                        cfg!(target_os = "windows") && scenario.dedicated(),
                    )
                    .process_topology()
                    .unwrap();
                assert_eq!(topology.is_some(), scenario.processes());
                if let Some(topology) = topology {
                    assert_eq!(topology.sandbox().is_some(), scenario.dedicated());
                    assert_eq!(
                        topology.workers().len(),
                        usize::from(scenario.remote_functions())
                    );
                    for process in topology.sandbox().into_iter().chain(topology.workers()) {
                        let declaration = serde_json::to_value(process).unwrap();
                        let profile = declaration["profile"].as_array().unwrap();
                        let child_denial = profile
                            .iter()
                            .find(|request| request["control"] == "deny_child_processes")
                            .unwrap();
                        assert_eq!(child_denial["required"], true);
                        assert_eq!(profile[0]["required"], true);
                        assert_eq!(
                            profile[1]["required"],
                            !(cfg!(target_os = "windows") && process.name() == "bench-sandbox")
                        );
                    }
                    for worker in topology.workers() {
                        assert_eq!(worker.functions().len(), 2);
                        assert!(
                            worker
                                .functions()
                                .iter()
                                .all(|function| function.name() != "HostPrint")
                        );
                    }
                }
            }
        }
    }
}

#[cfg(feature = "process-isolation")]
use placement::Placement;

#[cfg(not(feature = "process-isolation"))]
struct Placement;

#[cfg(not(feature = "process-isolation"))]
impl Placement {
    fn prepare(_: &Config, _: &mut Vec<Value>) -> Result<Self> {
        Ok(Self)
    }

    fn configure(&self, builder: SandboxBuilder, _: &Config, _: bool) -> SandboxBuilder {
        builder
            .host_function("HostEchoString", echo)
            .host_function("HostAdd", add)
    }

    fn artifacts(&self) -> Value {
        json!({"worker_manifest_sha256": null, "sandbox_manifest_sha256": null})
    }
}

fn calls(
    config: &Config,
    sandbox: &mut MultiUseSandbox,
    vm: usize,
    samples: &mut Vec<Value>,
) -> Result<()> {
    let start = Instant::now();
    let value = sandbox.call::<i32>("Add", (17, 25))?;
    let elapsed = start.elapsed();
    ensure!(value == 42, "HostAdd returned {value}");
    samples.push(json!({
        "metric": "guest_Add", "phase": "first_invocation", "vm_index": vm,
        "sample_index": 0, "payload_bytes": null, "duration": elapsed.as_nanos(), "unit": "ns"
    }));
    for (phase, count) in [("warmup", config.warmup), ("sample", config.samples)] {
        for index in 0..count {
            let start = Instant::now();
            let value = sandbox.call::<i32>("Add", (17, 25))?;
            ensure!(value == 42, "HostAdd returned {value}");
            record(samples, "guest_Add", phase, vm, index, None, start);
        }
    }
    for &size in &config.payload_bytes {
        let payload = "x".repeat(size);
        for (phase, count) in [
            ("first_payload_invocation", 1),
            ("warmup", config.warmup),
            ("sample", config.samples),
        ] {
            for index in 0..count {
                let argument = payload.clone();
                let start = Instant::now();
                let value = sandbox.call::<String>("RoundTripHostString", argument)?;
                ensure!(
                    value == payload,
                    "HostEchoString returned a different payload"
                );
                record(
                    samples,
                    "guest_RoundTripHostString",
                    phase,
                    vm,
                    index,
                    Some(size),
                    start,
                );
            }
        }
    }
    Ok(())
}

fn process_reports(sandbox: &MultiUseSandbox) -> Value {
    #[cfg(feature = "process-isolation")]
    {
        placement::reports(sandbox)
    }
    #[cfg(not(feature = "process-isolation"))]
    {
        let _ = sandbox;
        json!([])
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationAck {
    sequence: usize,
    phase: String,
    observation: Value,
}

fn accept_ack(ack: ObservationAck, sequence: usize, phase: &str) -> Result<Value> {
    ensure!(
        ack.sequence == sequence && ack.phase == phase,
        "Observer acknowledged a different boundary"
    );
    ensure!(
        ack.observation["status"] == "ok"
            && ack.observation["schema"] == "hyperlight-isolation-observation/v1"
            && ack.observation["sequence"] == sequence
            && ack.observation["phase"] == phase
            && ack.observation["controller_identity"]["pid"] == std::process::id(),
        "Observer did not provide successful evidence"
    );
    Ok(ack.observation)
}

fn observe(
    config: &Config,
    observations: &mut Vec<Value>,
    phase: &str,
    processes: &Value,
) -> Result<()> {
    let sequence = observations.len();
    let path = config.work_directory.join(format!("event-{sequence}.json"));
    let temporary = path.with_extension("tmp");
    let event = json!({
        "schema": "hyperlight-isolation-boundary/v1", "sequence": sequence,
        "phase": phase, "controller_pid": std::process::id(),
        "measurement": config.measurement, "process_reports": processes,
    });
    {
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        output.write_all(&serde_json::to_vec(&event)?)?;
    }
    std::fs::rename(temporary, path)?;
    let ack = config.work_directory.join(format!("ack-{sequence}.json"));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::File::open(&ack) {
            Ok(file) => {
                use std::io::Read;
                let mut bytes = Vec::new();
                file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= 1024 * 1024,
                    "Observer acknowledgement exceeds 1MiB"
                );
                observations.push(accept_ack(
                    serde_json::from_slice(&bytes)?,
                    sequence,
                    phase,
                )?);
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ensure!(Instant::now() < deadline, "Observer timed out at {phase}");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn build_benchmark(
    config: &Config,
    consent: bool,
    guest: Vec<u8>,
    placement: &Placement,
) -> Result<MultiUseSandbox> {
    placement
        .configure(
            SandboxBuilder::from_bytes(guest).scratch_size(8 * 1024 * 1024),
            config,
            consent,
        )
        .build()
}

fn checked_add(sandbox: &mut MultiUseSandbox) -> Result<()> {
    ensure!(
        sandbox.call::<i32>("Add", (17, 25))? == 42,
        "HostAdd returned an invalid result"
    );
    Ok(())
}

enum ResidentCommand {
    Build,
    Start { start: Instant, end: Instant },
    Finish,
}

fn receive<T>(receiver: &mpsc::Receiver<T>) -> Result<T> {
    receiver
        .recv_timeout(Duration::from_secs(10))
        .map_err(|error| new_error!("Resident coordination failed: {error}"))
}

fn resident(
    config: &Config,
    consent: bool,
    guest: &[u8],
    report: &mut Value,
) -> Result<Vec<Value>> {
    let count = config.measurement.live_vms();
    let aborted = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let (ready, readiness) = mpsc::channel();
        let (done, completion) = mpsc::channel();
        let mut senders = Vec::new();
        let mut threads = Vec::new();
        for index in 0..count {
            let (sender, commands) = mpsc::channel();
            senders.push(sender);
            let ready = ready.clone();
            let done = done.clone();
            let aborted = &aborted;
            threads.push(scope.spawn(move || -> Result<()> {
                let run = || -> Result<()> {
                    ensure!(matches!(receive(&commands)?, ResidentCommand::Build), "Expected build command");
                    let mut owned = config.clone();
                    owned.work_directory = config.work_directory.join(format!("vm-{index}"));
                    std::fs::create_dir(&owned.work_directory)?;
                    let placement = Placement::prepare(&owned, &mut Vec::new())?;
                    let mut sandbox = build_benchmark(&owned, consent, guest.to_vec(), &placement)?;
                    for _ in 0..8 {
                        checked_add(&mut sandbox)?;
                    }
                    ready.send(Ok(json!({"vm_index": index, "stage": "resident",
                        "processes": process_reports(&sandbox), "artifacts": placement.artifacts()})))
                        .map_err(|error| new_error!("Readiness receiver lost: {error}"))?;
                    let ResidentCommand::Start { start, end } = receive(&commands)? else {
                        return Err(new_error!("Expected resident start"));
                    };
                    std::thread::sleep(start.saturating_duration_since(Instant::now()));
                    let mut calls = 0_u64;
                    while Instant::now() < end {
                        ensure!(!aborted.load(Ordering::Acquire), "Another resident sandbox failed");
                        checked_add(&mut sandbox)?;
                        calls += 1;
                    }
                    ensure!(calls > 0, "Resident window completed without a call");
                    done.send(Ok(json!({"vm_index": index, "completed_calls": calls,
                        "elapsed_ns": start.elapsed().as_nanos()})))
                        .map_err(|error| new_error!("Completion receiver lost: {error}"))?;
                    ensure!(matches!(receive(&commands)?, ResidentCommand::Finish), "Expected resident finish");
                    Ok(())
                };
                let result = run();
                if let Err(error) = &result {
                    aborted.store(true, Ordering::Release);
                    let _ = ready.send(Err(error.to_string()));
                    let _ = done.send(Err(error.to_string()));
                }
                result
            }));
        }
        drop(ready);
        drop(done);
        let mut observations = Vec::new();
        let result = (|| {
            observe(config, &mut observations, "reference", &json!([]))?;
            for sender in &senders {
                sender
                    .send(ResidentCommand::Build)
                    .map_err(|error| new_error!("{error}"))?;
            }
            let mut processes = Vec::new();
            for _ in 0..count {
                processes
                    .push(receive(&readiness)?.map_err(|error: String| new_error!("{error}"))?);
            }
            processes.sort_by_key(|value| value["vm_index"].as_u64());
            validate_resident_owners(&processes, count)?;
            report["artifacts"] = resident_artifacts(&processes);
            report["process_reports"] = json!(processes);
            observe(
                config,
                &mut observations,
                "warm_idle",
                &report["process_reports"],
            )?;
            observe(
                config,
                &mut observations,
                "active_start",
                &report["process_reports"],
            )?;
            let start = Instant::now() + Duration::from_millis(20);
            let end = start + Duration::from_secs(5);
            for sender in &senders {
                sender
                    .send(ResidentCommand::Start { start, end })
                    .map_err(|error| new_error!("{error}"))?;
            }
            let mut counters = Vec::new();
            for _ in 0..count {
                counters
                    .push(receive(&completion)?.map_err(|error: String| new_error!("{error}"))?);
            }
            let elapsed = start.elapsed().as_nanos();
            observe(
                config,
                &mut observations,
                "active_end",
                &report["process_reports"],
            )?;
            for sender in &senders {
                sender
                    .send(ResidentCommand::Finish)
                    .map_err(|error| new_error!("{error}"))?;
            }
            report["resident"] = json!({"sandbox_count": count, "window_ns": elapsed,
                "per_sandbox": counters, "warmup_calls_per_sandbox": 8,
                "workload": "serial guest Add(17,25), validate42 on every call"});
            Ok(Vec::new())
        })();
        aborted.store(true, Ordering::Release);
        drop(senders);
        let mut joined = Ok(());
        // Synchronous guest calls require the outer controller deadline and domain cleanup.
        for thread in threads {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => joined = Err(error),
                Err(_) => joined = Err(new_error!("Resident execution thread panicked")),
            }
        }
        report["observations"] = json!(observations);
        result.and_then(|value| joined.map(|()| value))
    })
}

fn resident_artifacts(reports: &[Value]) -> Value {
    json!({"per_sandbox": reports.iter().map(|report| json!({
        "vm_index": report["vm_index"], "artifacts": report["artifacts"]
    })).collect::<Vec<_>>()})
}

fn validate_resident_owners(reports: &[Value], count: usize) -> Result<()> {
    let mut indices = BTreeSet::new();
    let mut roots = BTreeSet::new();
    ensure!(reports.len() == count, "Incomplete resident readiness");
    for report in reports {
        let index = report["vm_index"]
            .as_u64()
            .ok_or_else(|| new_error!("Missing sandbox index"))?;
        ensure!(
            index < count as u64 && indices.insert(index),
            "Duplicate resident sandbox index"
        );
        for process in report["processes"]
            .as_array()
            .ok_or_else(|| new_error!("Missing process inventory"))?
        {
            let pid = process["root_process_id"]
                .as_i64()
                .ok_or_else(|| new_error!("Missing process identity"))?;
            ensure!(
                pid > 0 && roots.insert(pid),
                "Native process shared by resident sandboxes"
            );
        }
    }
    Ok(())
}

fn recovery(
    config: &Config,
    consent: bool,
    guest: Vec<u8>,
    report: &mut Value,
) -> Result<Vec<Value>> {
    let mut samples = Vec::new();
    let placement = Placement::prepare(config, &mut samples)?;
    report["artifacts"] = placement.artifacts();
    let mut sandbox = build_benchmark(config, consent, guest, &placement)?;
    for _ in 0..8 {
        checked_add(&mut sandbox)?;
    }
    let initial = sandbox.call::<i32>("GetStatic", ())?;
    let expected = initial
        .checked_add(7)
        .ok_or_else(|| new_error!("Guest state overflow"))?;
    ensure!(
        sandbox.call::<i32>("AddToStatic", 7)? == expected,
        "Pre-fault mutation failed"
    );
    ensure!(
        sandbox.call::<i32>("GetStatic", ())? == expected,
        "Pre-fault readback failed"
    );
    let before = process_reports(&sandbox);
    let mut observations = Vec::new();
    observe(
        config,
        &mut observations,
        "quiescent_fault",
        &json!([
            {"vm_index": 0, "stage": "before_fault", "processes": before}
        ]),
    )?;
    let start = Instant::now();
    checked_add(&mut sandbox)?;
    record(
        &mut samples,
        "worker_recovery_call",
        "sample",
        0,
        0,
        None,
        start,
    );
    ensure!(
        sandbox.call::<i32>("GetStatic", ())? == expected,
        "Recovery lost mutated guest state"
    );
    let after = process_reports(&sandbox);
    validate_replacement(&before, &after)?;
    let reports = json!([
        {"vm_index": 0, "stage": "before_fault", "processes": before},
        {"vm_index": 0, "stage": "after_fault", "processes": after}
    ]);
    observe(config, &mut observations, "recovered", &reports)?;
    report["process_reports"] = reports;
    report["observations"] = json!(observations);
    report["recovery"] = json!({"guest_state_before_mutation": initial,
        "guest_state_before_fault": expected, "guest_state_after_recovery": expected,
        "validated_result": 42, "faults": 1, "in_flight_at_fault": false});
    Ok(samples)
}

fn validate_replacement(before: &Value, after: &Value) -> Result<()> {
    let old = before
        .as_array()
        .ok_or_else(|| new_error!("Missing pre-fault inventory"))?;
    let new = after
        .as_array()
        .ok_or_else(|| new_error!("Missing replacement inventory"))?;
    ensure!(old.len() == new.len(), "Recovery changed process topology");
    let mut replacements = 0;
    for previous in old {
        let matches = new
            .iter()
            .filter(|next| next["role"] == previous["role"] && next["name"] == previous["name"])
            .collect::<Vec<_>>();
        ensure!(matches.len() == 1, "Recovery changed native ownership");
        let next = matches[0];
        ensure!(
            next["program_manifest_sha256"] == previous["program_manifest_sha256"],
            "Recovery changed program"
        );
        ensure!(
            next["root_process_id"].as_i64().is_some_and(|pid| pid > 0),
            "Invalid replacement identity"
        );
        if previous["role"] == "function_worker" {
            ensure!(
                next["root_process_id"] != previous["root_process_id"],
                "Worker was not replaced"
            );
            replacements += 1;
        } else {
            ensure!(
                next["root_process_id"] == previous["root_process_id"],
                "Unfaulted host was replaced"
            );
        }
        let controls = next["controls"]
            .as_array()
            .ok_or_else(|| new_error!("Missing replacement controls"))?;
        let old_controls = previous["controls"]
            .as_array()
            .ok_or_else(|| new_error!("Missing original controls"))?;
        ensure!(
            controls.len() == old_controls.len(),
            "Recovery changed control count"
        );
        ensure!(!controls.is_empty(), "No replacement control evidence");
        for (control, original) in controls.iter().zip(old_controls) {
            ensure!(
                control["requested"] == original["requested"]
                    && control["required"] == original["required"]
                    && control["result"]["status"] == original["result"]["status"]
                    && control["result"]["effective"] == original["result"]["effective"],
                "Recovery changed the effective policy"
            );
            ensure!(
                control["required"] != true || control["result"]["status"] == "applied",
                "Recovery omitted a required control"
            );
        }
    }
    ensure!(
        replacements == 1,
        "Recovery requires exactly one replacement worker"
    );
    Ok(())
}

fn measure(config: &Config, consent: bool, report: &mut Value) -> Result<Vec<Value>> {
    config.validate(consent)?;
    verify_sources(config)?;
    let guest = verified_file(&config.guest)?;
    std::fs::create_dir(&config.work_directory).map_err(|error| {
        new_error!("work_directory must be new with an existing parent: {error}")
    })?;
    if config.measurement != Measurement::Sequential {
        report["provenance_verified"] = json!(true);
        return match config.measurement {
            Measurement::Resident { .. } => resident(config, consent, &guest, report),
            Measurement::Recovery => recovery(config, consent, guest, report),
            Measurement::Sequential => unreachable!(),
        };
    }
    let mut samples = Vec::new();
    let placement = Placement::prepare(config, &mut samples)?;
    report["artifacts"] = placement.artifacts();
    report["provenance_verified"] = json!(true);
    let mut reports = Vec::new();
    let mut snapshots = Vec::new();
    for vm in 0..config.vm_starts {
        let builder = SandboxBuilder::from_bytes(guest.clone()).scratch_size(8 * 1024 * 1024);
        let builder = placement.configure(builder, config, consent);
        #[cfg(feature = "process-isolation")]
        {
            report["configured_topology"] = serde_json::to_value(builder.process_topology()?)?;
        }
        let start = Instant::now();
        let mut sandbox = builder.build()?;
        record(
            &mut samples,
            "builder_startup_total",
            if vm == 0 { "first_use" } else { "warm_process" },
            vm,
            0,
            None,
            start,
        );
        calls(config, &mut sandbox, vm, &mut samples)?;
        let state = sandbox.call::<i32>("GetStatic", ())?;
        let start = Instant::now();
        let snapshot = sandbox.snapshot()?;
        record(
            &mut samples,
            "snapshot_capture",
            "sample",
            vm,
            0,
            None,
            start,
        );
        ensure!(
            sandbox.call::<i32>("AddToStatic", 7)? == state + 7,
            "Guest state mutation failed"
        );
        let start = Instant::now();
        sandbox.restore(snapshot.clone())?;
        record(
            &mut samples,
            "snapshot_restore_in_place",
            "sample",
            vm,
            0,
            None,
            start,
        );
        ensure!(
            sandbox.call::<i32>("GetStatic", ())? == state,
            "Guest state was not restored"
        );
        ensure!(
            sandbox.call::<i32>("Add", (17, 25))? == 42,
            "Restored callback mismatch"
        );
        let path = config.work_directory.join(format!("snapshot-{vm}"));
        let tag = OciTag::new("bench")?;
        let start = Instant::now();
        #[cfg(feature = "process-isolation")]
        let digest = snapshot.save_with_programs(&path, &tag, &placement.store)?;
        #[cfg(not(feature = "process-isolation"))]
        let digest = snapshot.save(&path, &tag)?;
        record(
            &mut samples,
            "snapshot_export",
            "sample",
            vm,
            0,
            None,
            start,
        );
        let start = Instant::now();
        let loaded = Arc::new(Snapshot::load(&path, digest.clone())?);
        record(
            &mut samples,
            "snapshot_load_verify",
            "sample",
            vm,
            0,
            None,
            start,
        );
        snapshots
            .push(json!({"vm_index": vm, "path": path, "manifest_sha256": digest.to_string()}));
        reports.push(
            json!({"vm_index": vm, "stage": "original", "processes": process_reports(&sandbox)}),
        );
        let start = Instant::now();
        drop(sandbox);
        record(
            &mut samples,
            "sandbox_drop_return",
            "original",
            vm,
            0,
            None,
            start,
        );
        drop(snapshot);
        let builder = placement.configure(SandboxBuilder::from_snapshot(loaded), config, consent);
        let start = Instant::now();
        let mut fresh = builder.build()?;
        record(
            &mut samples,
            "snapshot_fresh_reconstruction",
            "sample",
            vm,
            0,
            None,
            start,
        );
        ensure!(
            fresh.call::<i32>("GetStatic", ())? == state,
            "Fresh guest state mismatch"
        );
        ensure!(
            fresh.call::<i32>("Add", (17, 25))? == 42,
            "Fresh callback mismatch"
        );
        ensure!(
            fresh.call::<String>("RoundTripHostString", "test".to_owned())? == "test",
            "Fresh string callback mismatch"
        );
        reports.push(
            json!({"vm_index": vm, "stage": "reconstructed", "processes": process_reports(&fresh)}),
        );
        let start = Instant::now();
        drop(fresh);
        record(
            &mut samples,
            "sandbox_drop_return",
            "reconstructed",
            vm,
            0,
            None,
            start,
        );
    }
    report["process_reports"] = json!(reports);
    report["snapshots"] = json!(snapshots);
    Ok(samples)
}

fn run() -> Result<(Value, bool)> {
    let mut args = std::env::args_os().skip(1);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--config")),
        "Usage: isolation_bench --config FILE [--allow-trusted-windows-sandbox-host]"
    );
    let path = args
        .next()
        .ok_or_else(|| new_error!("Missing config path"))?;
    let consent = match args.next() {
        None => false,
        Some(flag) if flag == "--allow-trusted-windows-sandbox-host" => true,
        Some(_) => return Err(new_error!("Unknown argument")),
    };
    ensure!(args.next().is_none(), "Unexpected trailing arguments");
    let config: Config = serde_json::from_slice(&std::fs::read(Path::new(&path))?)?;
    let mut report = json!({
        "schema": SCHEMA, "status": "preparing", "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "build": {
            "process_isolation": cfg!(feature = "process-isolation"),
            "debug_assertions": cfg!(debug_assertions),
            "package_version": env!("CARGO_PKG_VERSION"),
            "kvm": cfg!(feature = "kvm"), "mshv3": cfg!(feature = "mshv3"),
            "hvf": cfg!(feature = "hvf")
        },
        "scenario": config.scenario,
        "policy": if consent { "trusted-windows-sandbox-host; function-workers-appcontainer" }
            else if config.scenario.dedicated() && cfg!(target_os = "linux") { "confined-linux-sandbox-host; function-workers-minijail" }
            else if config.scenario.processes() && cfg!(target_os = "linux") { "calling-process-vm; function-workers-minijail" }
            else if config.scenario.processes() { "appcontainer-function-workers" } else { "local" },
        "trusted_windows_caller_consent": consent,
        "local_equivalence": "legacy-local and calling-vm-local-functions use identical builder/callback paths",
        "cross_platform_policy_equivalence": false,
        "controller_size_scope": "multiscenario controller executable, not minimal enabled-unused consumer footprint",
        "source_fingerprint_sha256": config.source_fingerprint_sha256,
        "config": config,
        "controller_pid": std::process::id(),
        "environment": surrogate_environment(),
        "cache_conditions": {
            "first_builder": "fresh process, filesystem cache not flushed",
            "later_builders": "warm in-process; each native role is freshly launched",
            "calls": "warm in-process after separately recorded first invocation and warmups",
            "input_reads": "provenance verification reads source and executable files before timing",
            "packaging": "new output store; input executable bytes already read",
            "filesystem": "caller description only, no cache eviction or filesystem probe"
        },
        "guest_layout": {"input_bytes": IO_BYTES, "output_bytes": IO_BYTES, "heap_bytes": 8 * 1024 * 1024, "scratch_bytes": 8 * 1024 * 1024},
        "execution": {"maximum_live_vms": config.measurement.live_vms(), "workers_per_vm": usize::from(config.scenario.remote_functions()),
            "native_state": "callbacks are stateless; only guest state is captured and restored",
            "shutdown": "drop-return wall time, not an independently verified domain-empty timestamp",
            "timing": "Instant wall time; payload allocation excluded; success validation precedes sample admission"},
        "unavailable": {
            "cpu_time": unavailable("Needs OS accounting for caller, VM surrogates, sandbox host and all workers"),
            "memory": unavailable("Sequential mode has no memory observer. Observed modes retain platform-specific samples, not cross-platform private/commit equivalence or unsampled peaks"),
            "density": unavailable("Needs an independently authorized bounded concurrent-VM experiment"),
            "scaling": unavailable("This harness is sequential with at most one VM"),
            "recovery": unavailable("Needs explicit fault injection and validated replay/cleanup outcomes"),
            "startup_internal_phases": unavailable("Needs production timestamps for confinement, process birth, transport and VM initialization"),
            "shutdown_domain_empty": unavailable("Public Drop has no fallible completion/evidence API"),
            "filesystem_cache_state": unavailable("Caches are not flushed or measured"),
            "native_host_state_restore": unavailable("Native callbacks are stateless and are reconstructed, not snapshotted"),
            "source_binary_binding": unavailable("Input digests verify listed source and executable bytes, not reproducible-build linkage"),
            "minimal_enabled_unused_footprint": unavailable("Requires a separately built minimal consumer without remote API references")
        },
        "provenance_verified": false, "configured_topology": null,
        "samples": [], "process_reports": [], "snapshots": [],
        "observations": [], "measurement": config.measurement
    });
    match measure(&config, consent, &mut report) {
        Ok(samples) => {
            report["samples"] = json!(samples);
            if matches!(config.measurement, Measurement::Resident { .. }) {
                report["unavailable"]
                    .as_object_mut()
                    .unwrap()
                    .remove("density");
                report["unavailable"]
                    .as_object_mut()
                    .unwrap()
                    .remove("scaling");
            }
            if config.measurement == Measurement::Recovery {
                report["unavailable"]
                    .as_object_mut()
                    .unwrap()
                    .remove("recovery");
            }
            report["status"] = json!("ok");
            Ok((report, true))
        }
        Err(error) => {
            report["status"] = json!("error");
            report["error"] = json!(format!("{error:#}"));
            report["samples"] = json!([]);
            Ok((report, false))
        }
    }
}

fn main() {
    let (report, success) = run().unwrap_or_else(|error| {
        (json!({"schema": SCHEMA, "status": "error", "error": format!("{error:#}"), "samples": []}), false)
    });
    match serde_json::to_string_pretty(&report) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("Cannot encode benchmark report: {error}");
            std::process::exit(1);
        }
    }
    if !success {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_mode_bounds_and_role_requirements() {
        for count in [1, 2, 4, 8] {
            assert!(
                Measurement::Resident { sandboxes: count }
                    .validate(Scenario::LegacyLocal, 1)
                    .is_ok()
            );
        }
        for count in [0, 3, 9, usize::MAX] {
            assert!(
                Measurement::Resident { sandboxes: count }
                    .validate(Scenario::LegacyLocal, 1)
                    .is_err()
            );
        }
        assert!(
            Measurement::Recovery
                .validate(Scenario::SeparateVmSeparateFunctions, 1)
                .is_ok()
        );
        assert!(
            Measurement::Recovery
                .validate(Scenario::SeparateVmLocalFunctions, 1)
                .is_err()
        );
        assert!(
            Measurement::Recovery
                .validate(Scenario::CallingVmSeparateFunctions, 2)
                .is_err()
        );
    }

    #[test]
    fn observer_acknowledgements_are_bound_to_successful_boundary() {
        let ack = |sequence, phase: &str, status: &str| ObservationAck {
            sequence,
            phase: phase.to_owned(),
            observation: json!({"schema": "hyperlight-isolation-observation/v1", "status": status,
                "sequence": sequence, "phase": phase, "controller_identity": {"pid": std::process::id()}}),
        };
        assert!(accept_ack(ack(1, "warm_idle", "ok"), 1, "warm_idle").is_ok());
        assert!(accept_ack(ack(0, "warm_idle", "ok"), 1, "warm_idle").is_err());
        assert!(accept_ack(ack(1, "active_end", "ok"), 1, "warm_idle").is_err());
        assert!(accept_ack(ack(1, "warm_idle", "error"), 1, "warm_idle").is_err());
        let mut invalid = ack(1, "warm_idle", "ok");
        invalid.observation["sequence"] = json!(0);
        assert!(accept_ack(invalid, 1, "warm_idle").is_err());
    }

    #[test]
    fn resident_readiness_requires_unique_sandboxes_and_native_owners() {
        let one = json!({"vm_index": 0, "processes": [{"root_process_id": 10}]});
        let two = json!({"vm_index": 1, "processes": [{"root_process_id": 11}]});
        assert!(validate_resident_owners(&[one.clone(), two], 2).is_ok());
        assert!(validate_resident_owners(std::slice::from_ref(&one), 2).is_err());
        assert!(validate_resident_owners(&[one.clone(), one.clone()], 2).is_err());
        assert!(
            validate_resident_owners(
                &[
                    one,
                    json!({"vm_index": 1, "processes": [{"root_process_id": 10}]})
                ],
                2
            )
            .is_err()
        );
    }

    #[test]
    fn resident_artifact_inventory_preserves_each_sandbox() {
        let reports = [
            json!({"vm_index": 0, "artifacts": {"worker_manifest_sha256": "one"}}),
            json!({"vm_index": 1, "artifacts": {"worker_manifest_sha256": "two"}}),
        ];
        assert_eq!(
            resident_artifacts(&reports),
            json!({"per_sandbox": reports})
        );
    }

    #[test]
    fn replacement_requires_new_worker_and_unchanged_applied_policy() {
        let process = |pid| {
            json!([{"role": "function_worker", "name": "worker",
            "program_manifest_sha256": "program", "root_process_id": pid,
            "controls": [{"requested": {"kind": "deny_child_processes"}, "required": true,
                "result": {"status": "applied", "effective": {"kind": "deny_child_processes"}}}]}])
        };
        assert!(validate_replacement(&process(1), &process(2)).is_ok());
        assert!(validate_replacement(&process(1), &process(1)).is_err());
        let mut invalid = process(2);
        invalid[0]["controls"][0]["result"]["status"] = json!("not_applied");
        assert!(validate_replacement(&process(1), &invalid).is_err());
        invalid[0]["controls"] = json!([]);
        assert!(validate_replacement(&process(1), &invalid).is_err());
    }

    #[test]
    fn dropped_coordinator_releases_waiting_execution_thread() {
        let (send, commands) = mpsc::channel::<ResidentCommand>();
        let thread = std::thread::spawn(move || receive(&commands));
        drop(send);
        assert!(thread.join().unwrap().is_err());
    }

    #[test]
    fn guest_callbacks_preserve_benchmark_payloads() {
        let guest = std::fs::read(hyperlight_testing::simple_guest_as_pathbuf()).unwrap();
        let mut sandbox = SandboxBuilder::from_bytes(guest)
            .input_data_size(IO_BYTES)
            .output_data_size(IO_BYTES)
            .heap_size(8 * 1024 * 1024)
            .scratch_size(8 * 1024 * 1024)
            .host_function("HostEchoString", echo)
            .host_function("HostAdd", add)
            .build()
            .unwrap();
        assert_eq!(sandbox.call::<i32>("Add", (17, 25)).unwrap(), 42);
        for size in [0, 64, 4096, 65536] {
            let payload = "x".repeat(size);
            assert_eq!(
                sandbox
                    .call::<String>("RoundTripHostString", payload.clone())
                    .unwrap(),
                payload,
            );
        }
    }
}
