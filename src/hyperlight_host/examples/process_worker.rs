// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::BTreeMap;

use hyperlight_host::process::program::{
    FunctionContractDefinition, ProcessDefinition, ProgramArtifact, ProgramConfig, ProgramRole,
    ProgramTarget,
};
use hyperlight_host::process::{
    HostFunctionContract, Idempotency, ProcessHostFunctions, ProcessProfile, ProcessStartup,
};
use hyperlight_host::{Result, new_error};

const ADD: HostFunctionContract<(i32, i32), i32> =
    HostFunctionContract::new("Add", Idempotency::Idempotent);
const CRASH: HostFunctionContract<(), ()> =
    HostFunctionContract::new("Crash", Idempotency::NonIdempotent);
const FAIL: HostFunctionContract<(), ()> =
    HostFunctionContract::new("Fail", Idempotency::NonIdempotent);
const PID: HostFunctionContract<(), u32> =
    HostFunctionContract::new("Pid", Idempotency::Idempotent);

fn main() -> Result<()> {
    // SAFETY: this is the process entry point and no threads or inherited-resource users exist.
    let startup = unsafe { ProcessStartup::capture() }?
        .ok_or_else(|| new_error!("Process worker was not launched by Mesh"))?;
    let artifact_hex = std::env::args_os()
        .nth(1)
        .ok_or_else(|| new_error!("Process worker artifact declaration is missing"))?;
    let artifact_json = hex::decode(artifact_hex.to_string_lossy().as_bytes())
        .map_err(|error| new_error!("Invalid process worker artifact declaration: {error}"))?;
    let artifact: ProgramArtifact = serde_json::from_slice(&artifact_json)?;
    let functions = vec![
        FunctionContractDefinition::from_contract(&ADD),
        FunctionContractDefinition::from_contract(&CRASH),
        FunctionContractDefinition::from_contract(&FAIL),
        FunctionContractDefinition::from_contract(&PID),
    ];
    let definition = ProcessDefinition::new(
        "worker",
        artifact,
        &ProcessProfile::unrestricted(),
        functions.clone(),
    )?;
    let config = ProgramConfig {
        schema_version: 1,
        role: ProgramRole::FunctionWorker,
        target: ProgramTarget::current(BTreeMap::new()),
        functions,
    };
    let mut registrations = ProcessHostFunctions::default();
    registrations.bind(ADD, |left, right| Ok(left + right))?;
    registrations.bind(CRASH, || -> Result<()> { std::process::exit(17) })?;
    registrations.bind(FAIL, || -> Result<()> { Err(new_error!("fixture error")) })?;
    registrations.bind(PID, || Ok(std::process::id()))?;
    registrations.run_declared(startup, &definition, &config)
}
