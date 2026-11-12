// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use super::*;
use crate::SandboxBuilder;
use crate::func::Registerable;

const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("Add", Idempotency::Idempotent);

fn options(name: &str) -> ProcessOptions {
    let descriptor = serde_json::from_value(serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": format!("sha256:{}", "0".repeat(64)),
        "size": 1
    }))
    .unwrap();
    ProcessOptions::with_program_artifact(
        name,
        program::ProgramArtifact::from_descriptor(descriptor).unwrap(),
        ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]),
    )
}

#[test]
fn application_process_options_are_platform_neutral() {
    let options = ProcessOptions::for_provider(
        "arithmetic",
        ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]),
    );
    assert_eq!(options.name, "arithmetic");
    assert!(options.program.is_none());
}

#[test]
fn legacy_process_options_constructor_remains_source_compatible() {
    let options = options("arithmetic");
    let artifact = options.program.clone().unwrap();
    let compatible = ProcessOptions::new("arithmetic", artifact, options.profile.clone());
    assert!(compatible.program.is_some());
}

#[test]
fn shared_contract_matches_local_implementation() {
    let process = HostFunctionProcess::new(options("arithmetic")).function(ADD);
    let mut registrations = ProcessHostFunctions::default();
    registrations.bind(ADD, |a: i32, b: i32| a + b).unwrap();
    process.validate_registrations(&registrations).unwrap();
}

#[test]
fn duplicate_binding_preserves_original_signature() {
    let process = HostFunctionProcess::new(options("arithmetic")).function(ADD);
    let mut registrations = ProcessHostFunctions::default();
    registrations.bind(ADD, |a: i32, b: i32| a + b).unwrap();
    let duplicate = HostFunctionContract::<(), u64>::new("Add", Idempotency::Unspecified);
    assert!(registrations.bind(duplicate, || 7_u64).is_err());
    process.validate_registrations(&registrations).unwrap();
}

#[test]
fn signature_and_idempotency_must_match_exactly() {
    let expected = HostFunctionContract::<(i32, u64), i32>::new("Value", Idempotency::Idempotent);
    let process = HostFunctionProcess::new(options("values")).function(expected);
    let mismatches = [
        HostFunctionContract::<(u64, i32), i32>::new("Value", Idempotency::Idempotent).definition,
        HostFunctionContract::<(i32,), i32>::new("Value", Idempotency::Idempotent).definition,
        HostFunctionContract::<(i32, u64), u32>::new("Value", Idempotency::Idempotent).definition,
        HostFunctionContract::<(i32, u64), i32>::new("Value", Idempotency::NonIdempotent)
            .definition,
        HostFunctionContract::<(i32, u64), i32>::new("Value", Idempotency::Unspecified).definition,
    ];
    for mismatch in mismatches {
        let mut registrations = ProcessHostFunctions::default();
        registrations.contracts.insert(mismatch.name, mismatch);
        assert!(process.validate_registrations(&registrations).is_err());
    }
}

#[test]
fn missing_and_extra_registrations_fail() {
    let process = HostFunctionProcess::new(options("arithmetic")).function(ADD);
    let mut registrations = ProcessHostFunctions::default();
    assert!(process.validate_registrations(&registrations).is_err());
    registrations.bind(ADD, |a: i32, b: i32| a + b).unwrap();
    let extra = HostFunctionContract::<(), i32>::new("Extra", Idempotency::Unspecified);
    registrations.bind(extra, || 42).unwrap();
    assert!(process.validate_registrations(&registrations).is_err());
}

#[test]
fn duplicate_local_process_ownership_fails_before_loading_guest() {
    let result = SandboxBuilder::from_bytes([])
        .host_function("Add", |a: i32, b: i32| a + b)
        .host_function_process(HostFunctionProcess::new(options("arithmetic")).function(ADD))
        .build();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Duplicate local/process owner for 'Add'")
    );
}

#[test]
fn duplicate_process_ownership_fails_before_loading_guest() {
    let result = SandboxBuilder::from_bytes([])
        .host_function_process(HostFunctionProcess::new(options("first")).function(ADD))
        .host_function_process(HostFunctionProcess::new(options("second")).function(ADD))
        .build();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Duplicate host-function owner for 'Add'")
    );
}

#[test]
fn duplicate_function_in_one_process_fails() {
    let mut topology = Topology::default();
    topology.functions(
        HostFunctionProcess::new(options("arithmetic"))
            .function(ADD)
            .function(ADD),
    );
    assert!(topology.validate(&HostFunctions::default()).is_err());
}

#[test]
fn process_names_and_sandbox_placement_are_unique() {
    let mut topology = Topology::default();
    topology.sandbox(options("sandbox"));
    topology.functions(HostFunctionProcess::new(options("sandbox")).function(ADD));
    assert!(topology.validate(&HostFunctions::default()).is_err());

    let result = SandboxBuilder::from_bytes([])
        .sandbox_process(options("first"))
        .sandbox_process(options("second"))
        .build();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("only one process placement")
    );
}

#[test]
fn separate_sandboxes_can_use_the_same_contract() {
    for _ in 0..2 {
        let mut topology = Topology::default();
        topology.functions(HostFunctionProcess::new(options("arithmetic")).function(ADD));
        topology.validate(&HostFunctions::default()).unwrap();
    }
}

#[test]
fn local_overwrite_behavior_is_unchanged_with_feature_enabled() {
    let mut local = HostFunctions::empty();
    local.register_host_function("Value", || 1_i32).unwrap();
    local.register_host_function("Value", || 2_i32).unwrap();
    assert_eq!(local.into_iter().count(), 1);
}

#[test]
fn replay_needs_idempotency_or_proven_non_dispatch() {
    for idempotency in [
        Idempotency::Unspecified,
        Idempotency::NonIdempotent,
        Idempotency::Idempotent,
    ] {
        let contract = HostFunctionContract::<(), i32>::new("Value", idempotency);
        assert!(contract.permits_replay(DispatchOutcome::NotDispatched));
        assert_eq!(
            contract.permits_replay(DispatchOutcome::Uncertain),
            idempotency == Idempotency::Idempotent,
        );
    }
}

#[test]
fn invalid_profiles_fail_before_loading_guest() {
    for controls in [
        vec![],
        vec![RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: false,
        }],
        vec![RequestedControl {
            control: ProcessControl::MemoryLimit(0),
            required: true,
        }],
        vec![RequestedControl {
            control: ProcessControl::CpuBudget {
                quota: Duration::ZERO,
                period: Duration::from_millis(100),
            },
            required: true,
        }],
    ] {
        let profile = ProcessProfile::new(controls);
        assert!(profile.validate().is_err());
    }
}

#[test]
fn unrestricted_profile_is_valid_only_without_controls_or_limits() {
    let profile = ProcessProfile::unrestricted();
    profile.validate().unwrap();
    assert!(profile.is_unrestricted());

    let mut with_control = profile.clone();
    with_control.controls.push(RequestedControl {
        control: ProcessControl::DenyNetwork,
        required: true,
    });
    assert!(with_control.validate().is_err());

    assert!(
        ProcessProfile::unrestricted()
            .windows_cpu_rate_limit_percent(10)
            .is_err()
    );
}

#[test]
fn missing_mesh_provider_fails_before_loading_guest() {
    let result = SandboxBuilder::from_bytes([])
        .host_function_process(HostFunctionProcess::new(options("arithmetic")).function(ADD))
        .build();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires a MeshProcessProvider capability")
    );
}

#[test]
fn program_resolution_precedes_launch_and_guest_loading() {
    let directory = tempfile::tempdir().unwrap();
    let store = program::LocalProgramStore::new(directory.path());
    let target = program::ProgramTarget::current(Default::default());
    let process = HostFunctionProcess::new(options("arithmetic")).function(ADD);
    let expected = store
        .validate(process.options.program.as_ref().unwrap(), &target)
        .unwrap_err()
        .to_string();
    let error = SandboxBuilder::from_bytes([])
        .process_programs(store, target)
        .host_function_process(process)
        .build()
        .unwrap_err();
    assert_eq!(error.to_string(), expected);
}

#[test]
fn execution_target_must_describe_current_host() {
    let directory = tempfile::tempdir().unwrap();
    let mut target = program::ProgramTarget::current(Default::default());
    target.architecture = "foreign-host".to_owned();
    let error = SandboxBuilder::from_bytes([])
        .process_programs(program::LocalProgramStore::new(directory.path()), target)
        .host_function_process(HostFunctionProcess::new(options("arithmetic")).function(ADD))
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("must match the current host"));
}

#[test]
fn empty_process_metadata_is_rejected() {
    assert!(program::ProcessTopologyDefinition::new(None, Vec::new()).is_err());
    let definition: program::ProcessTopologyDefinition = serde_json::from_value(
        serde_json::json!({"schema_version": 1, "sandbox": null, "workers": []}),
    )
    .unwrap();
    assert!(definition.validate().is_err());
}

#[test]
fn configuration_capture_needs_no_program_store_or_guest_binary() {
    let builder = SandboxBuilder::from_bytes([])
        .host_function_process(HostFunctionProcess::new(options("arithmetic")).function(ADD));
    let captured = builder.process_topology().unwrap().unwrap();
    assert_eq!(captured.workers()[0].name(), "arithmetic");
    assert_eq!(
        captured.workers()[0].functions(),
        &[program::FunctionContractDefinition::from_contract(&ADD)]
    );
    assert!(
        SandboxBuilder::from_bytes([])
            .process_topology()
            .unwrap()
            .is_none()
    );
}

fn sandbox_definition(policy: WindowsSandboxHostPolicy) -> program::ProcessTopologyDefinition {
    let mut topology = Topology::default();
    topology.sandbox(options("sandbox").windows_sandbox_host_policy(policy));
    topology.definition().unwrap()
}

#[test]
fn missing_windows_policy_defaults_to_app_container() {
    let mut topology = Topology::default();
    topology.sandbox(options("sandbox"));
    topology.functions(HostFunctionProcess::new(options("worker")).function(ADD));
    let expected = topology.definition().unwrap();
    let mut json = serde_json::to_value(&expected).unwrap();
    json["sandbox"]
        .as_object_mut()
        .unwrap()
        .remove("windows_sandbox_host_policy");
    json["workers"][0]
        .as_object_mut()
        .unwrap()
        .remove("windows_sandbox_host_policy");
    let parsed: program::ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed, expected);
    for process in parsed.sandbox().into_iter().chain(parsed.workers()) {
        assert_eq!(
            process.windows_sandbox_host_policy(),
            WindowsSandboxHostPolicy::AppContainer
        );
    }
}

#[test]
fn trusted_windows_policy_round_trip_records_only_a_request() {
    let definition = sandbox_definition(WindowsSandboxHostPolicy::Trusted);
    let json = serde_json::to_value(&definition).unwrap();
    assert_eq!(json["sandbox"]["windows_sandbox_host_policy"], "trusted");
    let parsed: program::ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed, definition);
    let error = Topology::default()
        .configured_definition(Some(&parsed), &HostFunctions::default())
        .unwrap_err();
    assert!(error.to_string().contains("explicit runtime permission"));
    let error = Topology::default().resolve(parsed).err().unwrap();
    assert!(error.to_string().contains("explicit runtime permission"));
}

#[test]
fn trusted_remains_an_importable_enum_variant() {
    use WindowsSandboxHostPolicy::Trusted;

    let policy = Trusted;
    assert!(matches!(policy, Trusted));
}

#[test]
fn trusted_remains_available_through_a_variant_glob() {
    use WindowsSandboxHostPolicy::*;

    let policy = Trusted;
    assert!(matches!(policy, Trusted));
    assert!(!matches!(AppContainer, Trusted));
}

#[test]
fn duplicate_windows_cpu_rate_controls_fail_closed() {
    let profile = ProcessProfile::new([RequestedControl {
        control: ProcessControl::MemoryLimit(1),
        required: true,
    }])
    .windows_cpu_rate_limit_percent(50)
    .unwrap();
    assert!(
        profile
            .windows_cpu_rate_limit_percent(25)
            .unwrap_err()
            .to_string()
            .contains("duplicate Windows CPU rate")
    );
}

#[test]
fn windows_cpu_rate_supplements_a_required_process_control() {
    let profile = ProcessProfile::new([])
        .windows_cpu_rate_limit_percent(50)
        .unwrap();
    assert!(
        profile
            .validate()
            .unwrap_err()
            .to_string()
            .contains("supplements those controls")
    );
}

#[test]
fn windows_vm_host_policy_round_trip_and_one_step_builder() {
    let definition = sandbox_definition(WindowsSandboxHostPolicy::WindowsVmHost);
    let json = serde_json::to_value(&definition).unwrap();
    assert_eq!(json["sandbox"]["windows_sandbox_host_policy"], "trusted");
    let parsed: program::ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
    assert!(
        parsed
            .sandbox()
            .unwrap()
            .windows_sandbox_host_policy()
            .is_windows_vm_host()
    );
    let mut alias = serde_json::to_value(&definition).unwrap();
    alias["sandbox"]["windows_sandbox_host_policy"] = "windows_vm_host".into();
    let parsed_alias: program::ProcessTopologyDefinition = serde_json::from_value(alias).unwrap();
    assert_eq!(
        parsed_alias
            .sandbox()
            .unwrap()
            .windows_sandbox_host_policy(),
        WindowsSandboxHostPolicy::WindowsVmHost
    );
    let captured = SandboxBuilder::from_bytes([])
        .windows_vm_host_process(options("sandbox"))
        .process_topology();
    if cfg!(target_os = "windows") {
        assert_eq!(captured.unwrap(), Some(definition));
    } else {
        assert!(
            captured
                .unwrap_err()
                .to_string()
                .contains("supported only on Windows")
        );
    }
}

#[test]
fn compatibility_vm_host_names_still_compile_and_authorize() {
    let builder = SandboxBuilder::from_bytes([])
        .allow_trusted_windows_sandbox_host()
        .sandbox_process(
            options("sandbox").windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
        );
    let captured = builder.process_topology();
    if cfg!(target_os = "windows") {
        assert_eq!(
            captured.unwrap(),
            Some(sandbox_definition(WindowsSandboxHostPolicy::Trusted))
        );
    } else {
        assert!(captured.is_err());
    }
}

#[test]
fn declared_trusted_windows_host_requires_runtime_permission_before_launch() {
    let builder = SandboxBuilder::from_bytes([]).sandbox_process(
        options("sandbox").windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
    );
    let error = builder.process_topology().unwrap_err();
    assert!(error.to_string().contains("explicit runtime permission"));
    let error = builder.build().unwrap_err();
    assert!(error.to_string().contains("explicit runtime permission"));
}

#[test]
fn required_app_container_rejects_trusted_snapshot_placement() {
    let saved = sandbox_definition(WindowsSandboxHostPolicy::Trusted);
    let mut topology = Topology {
        allow_windows_vm_host: true,
        ..Default::default()
    };
    topology.sandbox(
        options("sandbox").windows_sandbox_host_policy(WindowsSandboxHostPolicy::AppContainer),
    );
    let error = topology
        .configured_definition(Some(&saved), &HostFunctions::default())
        .unwrap_err();
    assert!(error.to_string().contains("does not match placement"));
}

#[test]
fn permission_preserves_app_container_and_empty_placement() {
    let builder = SandboxBuilder::from_bytes([]).allow_trusted_windows_sandbox_host();
    assert!(builder.process_topology().unwrap().is_none());
    let captured = builder
        .sandbox_process(options("sandbox"))
        .process_topology()
        .unwrap()
        .unwrap();
    let expected = sandbox_definition(WindowsSandboxHostPolicy::AppContainer);
    assert_eq!(captured, expected);
    let topology = Topology {
        allow_windows_vm_host: true,
        ..Default::default()
    };
    assert_eq!(
        topology
            .configured_definition(Some(&expected), &HostFunctions::default())
            .unwrap(),
        Some(expected)
    );
}

#[test]
fn trusted_windows_worker_is_rejected_even_with_permission() {
    let error = SandboxBuilder::from_bytes([])
        .allow_trusted_windows_sandbox_host()
        .host_function_process(
            HostFunctionProcess::new(
                options("worker").windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
            )
            .function(ADD),
        )
        .build()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot be used by function workers")
    );

    let mut topology = Topology::default();
    topology.functions(HostFunctionProcess::new(options("worker")).function(ADD));
    let mut json = serde_json::to_value(topology.definition().unwrap()).unwrap();
    json["workers"][0]["windows_sandbox_host_policy"] = "trusted".into();
    let parsed: program::ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
    assert!(
        parsed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot be used by function workers")
    );
    let permitted = Topology {
        allow_windows_vm_host: true,
        ..Default::default()
    };
    assert!(
        permitted
            .resolve(parsed)
            .err()
            .unwrap()
            .to_string()
            .contains("cannot be used by function workers")
    );
}

#[cfg(target_os = "windows")]
#[test]
fn trusted_windows_snapshot_needs_permission_on_each_build() {
    let saved = sandbox_definition(WindowsSandboxHostPolicy::Trusted);
    let topology = Topology {
        allow_windows_vm_host: true,
        ..Default::default()
    };
    assert_eq!(
        topology
            .configured_definition(Some(&saved), &HostFunctions::default())
            .unwrap(),
        Some(saved.clone())
    );
    let error = topology.resolve(saved.clone()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("requires a MeshProcessProvider capability")
    );
    assert!(
        Topology::default()
            .configured_definition(Some(&saved), &HostFunctions::default())
            .is_err()
    );
    assert_eq!(
        SandboxBuilder::from_bytes([])
            .allow_trusted_windows_sandbox_host()
            .sandbox_process(
                options("sandbox").windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted)
            )
            .process_topology()
            .unwrap(),
        Some(saved)
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn trusted_windows_host_is_rejected_on_other_platforms() {
    let saved = sandbox_definition(WindowsSandboxHostPolicy::Trusted);
    let topology = Topology {
        allow_windows_vm_host: true,
        ..Default::default()
    };
    let error = topology
        .configured_definition(Some(&saved), &HostFunctions::default())
        .unwrap_err();
    assert!(error.to_string().contains("supported only on Windows"));
    let error = topology.resolve(saved).err().unwrap();
    assert!(error.to_string().contains("supported only on Windows"));
    let error = SandboxBuilder::from_bytes([])
        .allow_trusted_windows_sandbox_host()
        .sandbox_process(
            options("sandbox").windows_sandbox_host_policy(WindowsSandboxHostPolicy::Trusted),
        )
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("supported only on Windows"));
}
