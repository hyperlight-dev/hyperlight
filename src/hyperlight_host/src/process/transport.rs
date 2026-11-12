// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use bytes::Bytes;
use futures::StreamExt;
use hyperlight_common::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
use hyperlight_common::flatbuffer_wrappers::function_types::{
    FunctionCallResult, ParameterValue, ReturnValue,
};
use hyperlight_common::flatbuffer_wrappers::{ExternalValueSink, ExternalValueSource};
use mesh::MeshPayload;
use mesh::rpc::{Rpc, RpcSend};

use super::program::FunctionContractDefinition;
use super::{FunctionDefinition, Idempotency, ProcessHostFunctions};
use crate::func::host_functions::TypeErasedHostFunction;
use crate::sandbox::host_funcs::FunctionEntry;
use crate::{HostFunctions, Result, new_error};

const PROTOCOL_VERSION: u32 = 2;

#[derive(Default)]
struct PackedExternalValues(Vec<Vec<u8>>);

impl<'a> ExternalValueSink<'a> for PackedExternalValues {
    fn push_bytes(&mut self, value: &'a [u8]) -> anyhow::Result<()> {
        self.0.push(value.to_vec());
        Ok(())
    }

    fn push_chunks(&mut self, value: &'a [Bytes]) -> anyhow::Result<()> {
        self.0.push(
            value
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect(),
        );
        Ok(())
    }
}

struct PackedExternalSource<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl ExternalValueSource for PackedExternalSource<'_> {
    fn take_bytes(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("process payload length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("process payload is truncated"))?
            .to_vec();
        self.offset = end;
        Ok(value)
    }

    fn take_chunks(&mut self, length: usize) -> anyhow::Result<Vec<Bytes>> {
        Ok(vec![Bytes::from(self.take_bytes(length)?)])
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        if self.offset != self.bytes.len() {
            anyhow::bail!("process payload contains unused external values");
        }
        Ok(())
    }
}

fn pack_control(control: &[u8], external_values: PackedExternalValues) -> Result<Vec<u8>> {
    let control_len = u32::try_from(control.len())
        .map_err(|_| new_error!("Process control payload is too large"))?;
    let external_len = external_values.0.iter().map(Vec::len).sum::<usize>();
    let mut payload = Vec::with_capacity(4 + control.len() + external_len);
    payload.extend_from_slice(&control_len.to_le_bytes());
    payload.extend_from_slice(control);
    for value in external_values.0 {
        payload.extend_from_slice(&value);
    }
    Ok(payload)
}

fn unpack_control(payload: &[u8]) -> Result<(&[u8], PackedExternalSource<'_>)> {
    let length = payload
        .get(..4)
        .ok_or_else(|| new_error!("Process payload is missing its control length"))?;
    let control_len = u32::from_le_bytes(length.try_into().expect("checked length")) as usize;
    let control_end = 4usize
        .checked_add(control_len)
        .ok_or_else(|| new_error!("Process control payload length overflow"))?;
    let control = payload
        .get(4..control_end)
        .ok_or_else(|| new_error!("Process control payload is truncated"))?;
    let external = payload
        .get(control_end..)
        .ok_or_else(|| new_error!("Process external payload is truncated"))?;
    Ok((
        control,
        PackedExternalSource {
            bytes: external,
            offset: 0,
        },
    ))
}

pub(super) fn encode_function_call(call: &FunctionCall) -> Result<Vec<u8>> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let mut external_values = PackedExternalValues::default();
    let control = call.encode(&mut builder, &mut external_values)?;
    pack_control(control, external_values)
}

pub(super) fn decode_function_call(payload: &[u8]) -> Result<FunctionCall> {
    let (control, mut external_values) = unpack_control(payload)?;
    Ok(FunctionCall::decode(control, &mut external_values)?)
}

pub(super) fn encode_function_result(result: &FunctionCallResult) -> Result<Vec<u8>> {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let mut external_values = PackedExternalValues::default();
    let control = result.encode(&mut builder, &mut external_values)?;
    pack_control(control, external_values)
}

pub(super) fn decode_function_result(payload: &[u8]) -> Result<FunctionCallResult> {
    let (control, mut external_values) = unpack_control(payload)?;
    Ok(FunctionCallResult::decode(control, &mut external_values)?)
}

#[derive(Debug, MeshPayload, PartialEq, Eq)]
struct WireContract {
    name: String,
    parameters: Vec<u32>,
    output: u32,
    idempotency: u32,
}

impl From<&FunctionDefinition> for WireContract {
    fn from(definition: &FunctionDefinition) -> Self {
        Self::from(&FunctionContractDefinition::from_definition(definition))
    }
}

impl From<&FunctionContractDefinition> for WireContract {
    fn from(definition: &FunctionContractDefinition) -> Self {
        Self {
            name: definition.name().to_owned(),
            parameters: definition
                .parameters()
                .iter()
                .map(|ty| ty.clone() as u32)
                .collect(),
            output: definition.output() as u32,
            idempotency: match definition.idempotency() {
                Idempotency::Unspecified => 0,
                Idempotency::NonIdempotent => 1,
                Idempotency::Idempotent => 2,
            },
        }
    }
}

#[derive(MeshPayload)]
pub(super) struct Bootstrap {
    version: u32,
    contracts: Vec<WireContract>,
    generation: u64,
    resource_declarations: Vec<super::resource::WireResourceDeclaration>,
    export_policy: Option<super::resource::WireExportPolicy>,
    validated: Option<mesh::OneshotSender<std::result::Result<(), String>>>,
    resources: mesh::Receiver<ResourceBootstrap>,
    requests: mesh::Receiver<Request>,
    ready: mesh::OneshotSender<std::result::Result<(), String>>,
}

#[derive(MeshPayload)]
pub(super) struct ResourceBootstrap {
    generation: u64,
    resources: Vec<super::resource::WireResource>,
    exports: Option<mesh::Sender<super::resource::ResourceExportRequest>>,
}

pub(super) struct PreparedBootstrap {
    pub(super) wire: Bootstrap,
    pub(super) delivery: ResourceDelivery,
}

pub(super) struct ResourceDelivery {
    validated: mesh::OneshotReceiver<std::result::Result<(), String>>,
    resources: mesh::Sender<ResourceBootstrap>,
}

impl ResourceDelivery {
    pub(super) async fn wait_validated(&mut self) -> Result<()> {
        (&mut self.validated)
            .await
            .map_err(|error| new_error!("Function-process validation channel failed: {error}"))?
            .map_err(|error| new_error!("Function-process manifest rejected: {error}"))
    }

    pub(super) fn send_resources(
        &self,
        generation: u64,
        resources: Vec<super::resource::WireResource>,
        exports: Option<mesh::Sender<super::resource::ResourceExportRequest>>,
    ) {
        self.resources.send(ResourceBootstrap {
            generation,
            resources,
            exports,
        });
    }
}

#[derive(MeshPayload)]
pub(super) enum Request {
    Call(Rpc<Vec<u8>, std::result::Result<Vec<u8>, String>>),
    Stop(Rpc<(), ()>),
}

#[derive(MeshPayload)]
pub(super) struct WorkerGeneration {
    number: u64,
    requests: mesh::Sender<Request>,
    contracts: Vec<WireContract>,
}

impl WorkerGeneration {
    pub(super) fn new(
        number: u64,
        requests: mesh::Sender<Request>,
        definitions: &[FunctionContractDefinition],
    ) -> Self {
        Self {
            number,
            requests,
            contracts: wire_contracts(definitions),
        }
    }
}

// No call name, arguments, return value, or replay permission crosses this channel.
#[derive(MeshPayload)]
enum LifecycleRequest {
    Refresh(Rpc<(usize, u64), std::result::Result<WorkerGeneration, String>>),
}

/// A direct worker endpoint and a separate parent-owned lifecycle capability.
#[derive(MeshPayload)]
pub(super) struct SupervisedConnection {
    initial: WorkerGeneration,
    lifecycle: mesh::Sender<LifecycleRequest>,
    worker_index: usize,
}

fn wire_contracts(definitions: &[FunctionContractDefinition]) -> Vec<WireContract> {
    canonicalize_wire_contracts(definitions.iter().map(WireContract::from).collect())
}

fn canonicalize_wire_contracts(mut contracts: Vec<WireContract>) -> Vec<WireContract> {
    contracts.sort_by(|left, right| left.name.cmp(&right.name));
    contracts
}

/// One-shot startup resources supplied by the trusted process launcher.
pub struct ProcessStartup(mesh_process::OwnedInvitation);

impl ProcessStartup {
    pub(super) fn into_inner(self) -> mesh_process::OwnedInvitation {
        self.0
    }

    /// Role supplied by the Mesh/PAL launch capability.
    pub fn role(&self) -> Result<super::program::ProgramRole> {
        match std::env::var("HYPERLIGHT_PROCESS_ROLE").as_deref() {
            Ok("sandbox") => Ok(super::program::ProgramRole::SandboxHost),
            Ok("worker") => Ok(super::program::ProgramRole::FunctionWorker),
            _ => Err(new_error!(
                "Mesh provider did not identify the process role"
            )),
        }
    }

    /// Logical process owner supplied by the Mesh/PAL launch capability.
    pub fn name(&self) -> Result<String> {
        let name = std::env::var("HYPERLIGHT_PROCESS_NAME")
            .map_err(|_| new_error!("Mesh provider did not identify the process owner"))?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(new_error!(
                "Mesh provider supplied an invalid process owner"
            ));
        }
        Ok(name)
    }

    /// Backend declared by the provider for this worker's VM authority.
    pub fn vm_authority_backend(&self) -> Result<super::VmBackend> {
        let value = std::env::var("HYPERLIGHT_VM_AUTHORITY_BACKEND")
            .map_err(|_| new_error!("Mesh provider did not declare VM authority"))?;
        super::VmBackend::from_environment_value(&value)
    }

    /// Captures worker startup resources, or returns `None` in an application role.
    ///
    /// # Safety
    ///
    /// Call once before threads, tracing or concurrent environment access.
    /// Inherited IPC resources must come from the trusted launcher and have no
    /// other owner or concurrent user. Do not spawn processes during capture.
    pub unsafe fn capture() -> Result<Option<Self>> {
        // SAFETY: the caller upholds the inherited-resource and environment contract.
        Ok(unsafe { mesh_process::OwnedInvitation::capture_from_environment() }?.map(Self))
    }
}

pub(super) fn bootstrap_with_resources(
    definitions: &[FunctionContractDefinition],
    generation: u64,
    resource_declarations: Vec<super::resource::WireResourceDeclaration>,
    export_policy: Option<super::resource::WireExportPolicy>,
    requests: mesh::Receiver<Request>,
    ready: mesh::OneshotSender<std::result::Result<(), String>>,
) -> PreparedBootstrap {
    let (validated, validation) = mesh::oneshot();
    let (resource_sender, resources) = mesh::channel();
    PreparedBootstrap {
        wire: Bootstrap {
            version: PROTOCOL_VERSION,
            contracts: wire_contracts(definitions),
            generation,
            resource_declarations,
            export_policy,
            validated: Some(validated),
            resources,
            requests,
            ready,
        },
        delivery: ResourceDelivery {
            validated: validation,
            resources: resource_sender,
        },
    }
}

#[cfg(test)]
fn bootstrap(
    definitions: &[FunctionContractDefinition],
    requests: mesh::Receiver<Request>,
    ready: mesh::OneshotSender<std::result::Result<(), String>>,
) -> PreparedBootstrap {
    bootstrap_with_resources(definitions, 1, vec![], None, requests, ready)
}

#[cfg(test)]
struct RemoteRoute {
    requests: mesh::Sender<Request>,
    definition: FunctionContractDefinition,
    _runtime: std::sync::Arc<super::runtime::Runtime>,
}

#[cfg(test)]
impl RemoteRoute {
    fn call(&self, parameters: Vec<ParameterValue>) -> Result<ReturnValue> {
        futures_lite::future::block_on(invoke(&self.requests, &self.definition, parameters))
    }
}

#[cfg(test)]
pub(super) async fn register_ready_routes(
    requests: mesh::Sender<Request>,
    readiness: mesh::OneshotReceiver<std::result::Result<(), String>>,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> Result<HostFunctions> {
    wait_ready(readiness).await?;
    let mut unique = std::collections::BTreeSet::new();
    for definition in definitions {
        if definition.name().is_empty() || !unique.insert(definition.name()) {
            return Err(new_error!("Duplicate or empty process function name"));
        }
    }
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let route = RemoteRoute {
            requests: requests.clone(),
            definition: definition.clone(),
            _runtime: runtime.clone(),
        };
        let function = TypeErasedHostFunction::new(move |parameters| route.call(parameters));
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function,
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    Ok(registrations)
}

pub(super) async fn wait_ready(
    readiness: mesh::OneshotReceiver<std::result::Result<(), String>>,
) -> Result<()> {
    mesh::CancelContext::new()
        .with_timeout(std::time::Duration::from_secs(30))
        .until_cancelled(readiness)
        .await
        .map_err(|error| new_error!("Function-process readiness timed out: {error}"))?
        .map_err(|error| new_error!("Function-process readiness failed: {error}"))?
        .map_err(|error| new_error!("Function-process manifest rejected: {error}"))?;
    Ok(())
}

pub(super) fn register_runtime_routes(
    worker_index: usize,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> HostFunctions {
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let owner = runtime.clone();
        let contract = definition.clone();
        let function = TypeErasedHostFunction::new(move |parameters| {
            let payload = encode_call(&contract, parameters)?;
            decode_response(&owner.invoke(worker_index, &contract, payload)?)
        });
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function,
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    registrations
}

/// Owns one lifecycle consumer for the sandbox. The thread never owns this guard.
pub(super) struct LifecycleSupervisor {
    runtime: std::sync::Arc<super::runtime::Runtime>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LifecycleSupervisor {
    fn drop(&mut self) {
        if let Err(error) = self.runtime.stop() {
            tracing::error!(%error, "Lifecycle supervisor cleanup failed");
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("Lifecycle supervisor panicked");
        }
    }
}

/// Call data flows directly from the VM to physical worker endpoints.
pub(super) fn supervised_connections(
    runtime: std::sync::Arc<super::runtime::Runtime>,
    count: usize,
) -> Result<(Vec<SupervisedConnection>, LifecycleSupervisor)> {
    if count == 0 {
        return Ok((
            Vec::new(),
            LifecycleSupervisor {
                runtime,
                thread: None,
            },
        ));
    }
    let (lifecycle, mut requests) = mesh::channel();
    let connections = (0..count)
        .map(|worker_index| {
            Ok(SupervisedConnection {
                initial: runtime.worker_generation(worker_index)?,
                lifecycle: lifecycle.clone(),
                worker_index,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut cancellation = runtime.cancellation();
    let owner = std::sync::Arc::downgrade(&runtime);
    let thread = std::thread::Builder::new()
        .name("hyperlight-function-lifecycle".to_owned())
        .spawn(move || {
            futures_lite::future::block_on(async move {
                while let Ok(Some(request)) = cancellation.until_cancelled(requests.next()).await {
                    match request {
                        LifecycleRequest::Refresh(refresh) => {
                            refresh.handle_sync(|(worker_index, generation)| {
                                owner
                                    .upgrade()
                                    .ok_or_else(|| new_error!("Function-process owner was dropped"))
                                    .and_then(|owner| {
                                        owner.refresh_worker(worker_index, generation)
                                    })
                                    .map_err(|error| error.to_string())
                            })
                        }
                    }
                }
            });
        })?;
    Ok((
        connections,
        LifecycleSupervisor {
            runtime,
            thread: Some(thread),
        },
    ))
}

struct SupervisedRoute {
    generation: std::sync::Mutex<WorkerGeneration>,
    lifecycle: mesh::Sender<LifecycleRequest>,
    contracts: Vec<WireContract>,
    runtime: std::sync::Arc<super::runtime::Runtime>,
    worker_index: usize,
}

impl SupervisedRoute {
    fn call(
        &self,
        contract: &FunctionContractDefinition,
        parameters: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        self.runtime.ensure_active()?;
        let payload = encode_call(contract, parameters)?;
        let mut generation = self
            .generation
            .lock()
            .map_err(|error| new_error!("Worker generation lock failed: {error}"))?;
        self.runtime.ensure_active()?;
        futures_lite::future::block_on(async {
            loop {
                self.runtime.ensure_active()?;
                // Only this VM-side route sends call data. The parent receives
                // generation numbers on a separate lifecycle-only endpoint.
                let response = self
                    .runtime
                    .cancellation()
                    .until_cancelled(generation.requests.call(Request::Call, payload.clone()))
                    .await
                    .map_err(|error| new_error!("Intentional function-process stop: {error}"))?;
                match response {
                    Ok(response) => {
                        return decode_response(&response.map_err(|error| {
                            new_error!("Host-function process call failed: {error}")
                        })?);
                    }
                    Err(error) => {
                        self.runtime.ensure_active()?;
                        let replacement = self
                            .runtime
                            .cancellation()
                            .until_cancelled(self.lifecycle.call(
                                LifecycleRequest::Refresh,
                                (self.worker_index, generation.number),
                            ))
                            .await
                            .map_err(|error| {
                                new_error!("Intentional function-process stop: {error}")
                            })?;
                        let replacement = match replacement {
                            Ok(Ok(replacement)) => replacement,
                            other => {
                                let cause = match other {
                                    Ok(Err(error)) => error,
                                    Err(error) => error.to_string(),
                                    _ => unreachable!(),
                                };
                                let error =
                                    format!("Function-process lifecycle recovery failed: {cause}");
                                tracing::error!(%error);
                                self.runtime.mark_poisoned_with_cause(error.clone());
                                return Err(new_error!("{error}"));
                            }
                        };
                        if replacement.number <= generation.number
                            || replacement.contracts != self.contracts
                        {
                            self.runtime.mark_poisoned();
                            return Err(new_error!(
                                "Function-process replacement generation or immutable manifest mismatch"
                            ));
                        }
                        *generation = replacement;
                        // No response is never proof of non-dispatch. This decision
                        // uses the VM's trusted, immutable registration only.
                        if contract.idempotency() != Idempotency::Idempotent {
                            return Err(new_error!(
                                "Host-function process disconnected; execution is uncertain and replay is forbidden: {error}"
                            ));
                        }
                    }
                }
            }
        })
    }
}

/// Installs direct calls and trusted replay logic inside the VM process.
pub(super) fn register_supervised_routes(
    connection: SupervisedConnection,
    definitions: &[FunctionContractDefinition],
    runtime: std::sync::Arc<super::runtime::Runtime>,
) -> Result<HostFunctions> {
    let contracts = wire_contracts(definitions);
    if connection.initial.contracts != contracts
        || contracts.iter().any(|contract| contract.name.is_empty())
        || contracts
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(new_error!(
            "Function-process initial immutable manifest mismatch"
        ));
    }
    let route = std::sync::Arc::new(SupervisedRoute {
        generation: std::sync::Mutex::new(connection.initial),
        lifecycle: connection.lifecycle,
        contracts,
        runtime: runtime.clone(),
        worker_index: connection.worker_index,
    });
    let mut registrations = HostFunctions::empty();
    for definition in definitions {
        let route = route.clone();
        let contract = definition.clone();
        registrations.inner_mut().register_host_function(
            definition.name().to_owned(),
            FunctionEntry {
                function: TypeErasedHostFunction::new(move |parameters| {
                    route.call(&contract, parameters)
                }),
                parameter_types: definition.parameters().into(),
                return_type: definition.output(),
            },
        );
    }
    registrations.inner_mut().process_runtime = Some(runtime);
    Ok(registrations)
}

fn encode_call(
    definition: &FunctionContractDefinition,
    parameters: Vec<ParameterValue>,
) -> Result<Vec<u8>> {
    let call = FunctionCall::new(
        definition.name().to_owned(),
        Some(parameters),
        FunctionCallType::Host,
        definition.output(),
    );
    encode_function_call(&call)
}

fn decode_response(response: &[u8]) -> Result<ReturnValue> {
    decode_function_result(response)?
        .into_inner()
        .map_err(|error| new_error!("Host-function process returned a guest error: {error:?}"))
}

#[cfg(test)]
async fn invoke(
    requests: &mesh::Sender<Request>,
    definition: &FunctionContractDefinition,
    parameters: Vec<ParameterValue>,
) -> Result<ReturnValue> {
    let response = requests
        .call(Request::Call, encode_call(definition, parameters)?)
        .await
        .map_err(|error| new_error!("Host-function process disconnected: {error}"))?
        .map_err(|error| new_error!("Host-function process call failed: {error}"))?;
    decode_response(&response)
}

impl ProcessHostFunctions {
    /// Serves registrations in a framework-launched function process.
    ///
    /// The launcher must establish containment before this executable starts.
    /// Capture startup resources before creating threads. The owned value can
    /// then be passed here after initialization.
    pub fn run(self, startup: ProcessStartup) -> Result<()> {
        let expected = self.contracts.values().map(WireContract::from).collect();
        Self::run_configured(
            startup,
            expected,
            super::ProcessResourceManifest::new(),
            move |resources, functions| {
                if !resources.is_empty() {
                    return Err(new_error!(
                        "Function process received resources without a resource-aware startup"
                    ));
                }
                *functions = self;
                Ok(())
            },
        )
    }

    /// Configures registrations after receiving process-scoped OS resources.
    pub fn run_with_resources(
        startup: ProcessStartup,
        contracts: impl IntoIterator<Item = super::ProcessHostFunctionContract>,
        manifest: super::ProcessResourceManifest,
        configure: impl FnOnce(&mut super::ProcessResources, &mut Self) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let expected = canonicalize_wire_contracts(
            contracts
                .into_iter()
                .map(|contract| {
                    WireContract::from(&FunctionContractDefinition::from_definition(
                        &contract.definition,
                    ))
                })
                .collect(),
        );
        Self::run_configured(startup, expected, manifest, configure)
    }

    fn run_configured(
        startup: ProcessStartup,
        expected: Vec<WireContract>,
        manifest: super::ProcessResourceManifest,
        configure: impl FnOnce(&mut super::ProcessResources, &mut Self) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        mesh_process::run_mesh_host(
            startup.into_inner(),
            "hyperlight-function",
            // OpenVMM requires anyhow at its callback boundary.
            async move |bootstrap| {
                Self::serve_configured(bootstrap, expected, manifest, configure)
                    .await
                    .map_err(anyhow::Error::new)
            },
        )?;
        Err(new_error!("Function-process bootstrap did not enter Mesh"))
    }

    async fn serve_configured(
        mut bootstrap: Bootstrap,
        expected: Vec<WireContract>,
        manifest: super::ProcessResourceManifest,
        configure: impl FnOnce(&mut super::ProcessResources, &mut Self) -> Result<()>,
    ) -> Result<()> {
        let validated = match bootstrap.validated.take() {
            Some(validated) => validated,
            None => {
                let error = new_error!("Function-process validation channel is missing");
                bootstrap.ready.send(Err(error.to_string()));
                return Err(error);
            }
        };
        let phase_one = if bootstrap.version != PROTOCOL_VERSION || bootstrap.contracts != expected
        {
            Err(new_error!(
                "Function-process protocol or registration manifest mismatch"
            ))
        } else {
            manifest.validate(
                bootstrap.generation,
                &bootstrap.resource_declarations,
                bootstrap.export_policy,
            )
        };
        if let Err(error) = phase_one {
            validated.send(Err(error.to_string()));
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        validated.send(Ok(()));
        let resource_bootstrap = match bootstrap.resources.next().await {
            Some(resources) => resources,
            None => {
                let error = new_error!("Function-process resource bootstrap channel closed");
                bootstrap.ready.send(Err(error.to_string()));
                return Err(error);
            }
        };
        if resource_bootstrap.generation != bootstrap.generation {
            let error = new_error!("Function-process resource bootstrap generation mismatch");
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        if let Err(error) = manifest.validate_payloads(
            &resource_bootstrap.resources,
            resource_bootstrap.exports.is_some(),
        ) {
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        let mut resources = match super::ProcessResources::from_wire(
            resource_bootstrap.resources,
            resource_bootstrap.exports,
            resource_bootstrap.generation,
            &bootstrap.resource_declarations,
        ) {
            Ok(resources) => resources,
            Err(error) => {
                bootstrap.ready.send(Err(error.to_string()));
                return Err(error);
            }
        };
        let mut functions = Self::default();
        if let Err(error) = configure(&mut resources, &mut functions) {
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        if !resources.is_empty() {
            let error = new_error!("Function process did not claim every transferred resource");
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        functions.serve(bootstrap).await
    }

    async fn serve(self, mut bootstrap: Bootstrap) -> Result<()> {
        let expected: Vec<_> = self.contracts.values().map(WireContract::from).collect();
        let phase_one = if bootstrap.version != PROTOCOL_VERSION || bootstrap.contracts != expected
        {
            Err(new_error!(
                "Function-process protocol or registration manifest mismatch"
            ))
        } else if bootstrap.validated.is_some() {
            super::ProcessResourceManifest::new().validate(
                bootstrap.generation,
                &bootstrap.resource_declarations,
                bootstrap.export_policy,
            )
        } else {
            Ok(())
        };
        if let Err(error) = phase_one {
            if let Some(validated) = bootstrap.validated.take() {
                validated.send(Err(error.to_string()));
            }
            bootstrap.ready.send(Err(error.to_string()));
            return Err(error);
        }
        if let Some(validated) = bootstrap.validated.take() {
            validated.send(Ok(()));
            let resource_bootstrap =
                bootstrap.resources.next().await.ok_or_else(|| {
                    new_error!("Function-process resource bootstrap channel closed")
                })?;
            let resources = super::ProcessResources::from_wire(
                resource_bootstrap.resources,
                resource_bootstrap.exports,
                resource_bootstrap.generation,
                &bootstrap.resource_declarations,
            )?;
            if !resources.is_empty() || resources.can_export() {
                return Err(new_error!(
                    "Function process received resources without a resource-aware startup"
                ));
            }
        }
        bootstrap.ready.send(Ok(()));
        while let Some(request) = bootstrap.requests.next().await {
            match request {
                Request::Call(call) => {
                    let (payload, call) = call.split();
                    let response = match self.dispatch(&payload) {
                        Ok(value) => Ok(value),
                        Err(error) if super::launch::has_cleanup_owner(&error) => {
                            return Err(error);
                        }
                        Err(error) => Err(error.to_string()),
                    };
                    call.complete(response);
                }
                Request::Stop(stop) => {
                    stop.complete(());
                    break;
                }
            }
        }
        Ok(())
    }

    fn dispatch(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let call = decode_function_call(payload)?;
        if call.function_call_type() != FunctionCallType::Host {
            return Err(new_error!("Function process received a non-host call"));
        }
        let definition = self
            .contracts
            .get(call.function_name.as_str())
            .ok_or_else(|| new_error!("Undeclared host function '{}'", call.function_name))?;
        if call.expected_return_type != definition.output {
            return Err(new_error!(
                "Return type mismatch for '{}'",
                call.function_name
            ));
        }
        let result = self
            .functions
            .inner()
            .call_host_function(&call.function_name, call.parameters.unwrap_or_default())?;
        encode_function_result(&FunctionCallResult::new(Ok(result)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::func::{ParameterTuple, SupportedReturnType};
    use crate::process::HostFunctionContract;

    mod process_contracts {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/process_contracts.rs"
        ));
    }
    use process_contracts::{ADD, PID};

    const ECHO: HostFunctionContract<(String,), String> =
        HostFunctionContract::new("HostEchoString", Idempotency::NonIdempotent);

    fn definitions() -> Vec<FunctionContractDefinition> {
        vec![
            FunctionContractDefinition::from_contract(&ADD),
            FunctionContractDefinition::from_contract(&PID),
        ]
    }

    // This trusted fixture qualifies transport, not OS containment.
    #[tokio::test]
    async fn mesh_child_validates_manifest_calls_and_shutdown() {
        run_fixture(false).await;
    }

    #[tokio::test]
    async fn guest_calls_mesh_child() {
        run_fixture(true).await;
    }

    #[tokio::test]
    async fn resource_worker_canonicalizes_reverse_contract_order() {
        let definitions = definitions();
        let (requests, worker_requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let mut prepared =
            bootstrap_with_resources(&definitions, 1, Vec::new(), None, worker_requests, ready);
        let expected = canonicalize_wire_contracts(
            [PID.erase(), ADD.erase()]
                .into_iter()
                .map(|contract| {
                    WireContract::from(&FunctionContractDefinition::from_definition(
                        &contract.definition,
                    ))
                })
                .collect(),
        );
        let worker = ProcessHostFunctions::serve_configured(
            prepared.wire,
            expected,
            super::super::ProcessResourceManifest::new(),
            |_resources, functions| {
                functions.bind(PID, std::process::id)?;
                functions.bind(ADD, |left, right| Ok(left + right))
            },
        );
        let controller = async move {
            prepared.delivery.wait_validated().await.unwrap();
            prepared.delivery.send_resources(1, Vec::new(), None);
            readiness.await.unwrap().unwrap();
            requests.call(Request::Stop, ()).await.unwrap();
        };
        let (worker, ()) = futures::future::join(worker, controller).await;
        worker.unwrap();
    }

    #[tokio::test]
    async fn resource_worker_rejects_duplicate_contract_names() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let configured = Arc::new(AtomicBool::new(false));
        let definitions = vec![FunctionContractDefinition::from_contract(&ADD)];
        let (_requests, worker_requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let mut prepared =
            bootstrap_with_resources(&definitions, 1, Vec::new(), None, worker_requests, ready);
        let expected = canonicalize_wire_contracts(
            [ADD.erase(), ADD.erase()]
                .into_iter()
                .map(|contract| {
                    WireContract::from(&FunctionContractDefinition::from_definition(
                        &contract.definition,
                    ))
                })
                .collect(),
        );
        let configured_for_worker = configured.clone();
        let worker = ProcessHostFunctions::serve_configured(
            prepared.wire,
            expected,
            super::super::ProcessResourceManifest::new(),
            move |_resources, _functions| {
                configured_for_worker.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        let controller = async move {
            assert!(prepared.delivery.wait_validated().await.is_err());
            assert!(readiness.await.unwrap().is_err());
        };
        let (worker, ()) = futures::future::join(worker, controller).await;
        assert!(
            worker
                .unwrap_err()
                .to_string()
                .contains("registration manifest mismatch")
        );
        assert!(!configured.load(Ordering::SeqCst));
    }

    fn fixture_path() -> std::path::PathBuf {
        let executable = std::env::current_exe().unwrap();
        let worker = executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples")
            .join(format!("process_worker{}", std::env::consts::EXE_SUFFIX));
        assert!(
            worker.is_file(),
            "Build the main-entry fixture with cargo build -p hyperlight-host --example process_worker --features process-isolation"
        );
        worker
    }

    fn fixture_config() -> mesh_process::ProcessConfig {
        mesh_process::ProcessConfig::new("function-test")
            .skip_worker_arg(true)
            .process_name(fixture_path())
    }

    fn file_resource_fixture_path() -> std::path::PathBuf {
        let executable = std::env::current_exe().unwrap();
        let worker = executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples")
            .join(format!(
                "process_file_resource{}",
                std::env::consts::EXE_SUFFIX
            ));
        assert!(
            worker.is_file(),
            "Build the resource fixture with cargo build -p hyperlight-host --example process_file_resource --features process-isolation"
        );
        worker
    }

    fn file_resource_fixture_config_with(
        rights: &str,
        exports: bool,
    ) -> mesh_process::ProcessConfig {
        mesh_process::ProcessConfig::new("file-resource-test")
            .skip_worker_arg(true)
            .process_name(file_resource_fixture_path())
            .env([
                (
                    std::ffi::OsString::from("HYPERLIGHT_PROCESS_ROLE"),
                    std::ffi::OsString::from("worker"),
                ),
                (
                    std::ffi::OsString::from("HYPERLIGHT_PROCESS_NAME"),
                    std::ffi::OsString::from("file-resource"),
                ),
                (
                    std::ffi::OsString::from("HYPERLIGHT_TEST_RESOURCE_RIGHTS"),
                    std::ffi::OsString::from(rights),
                ),
                (
                    std::ffi::OsString::from("HYPERLIGHT_TEST_RESOURCE_EXPORTS"),
                    std::ffi::OsString::from(if exports { "enabled" } else { "disabled" }),
                ),
            ])
    }

    fn file_resource_fixture_config_with_rights(rights: &str) -> mesh_process::ProcessConfig {
        file_resource_fixture_config_with(rights, false)
    }

    fn file_resource_fixture_config() -> mesh_process::ProcessConfig {
        file_resource_fixture_config_with("read-write", false)
    }

    struct RecoveryFixture {
        args: Vec<std::ffi::OsString>,
        prepares: std::sync::atomic::AtomicUsize,
        fail_reverification: bool,
        change_manifest: bool,
        store: super::super::program::LocalProgramStore,
        lifecycle: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail_cleanup: std::sync::Arc<std::sync::atomic::AtomicBool>,
        guards: std::sync::Mutex<Vec<std::sync::Weak<RecoveryFixtureGuard>>>,
    }

    // This guard observes ordering only. The main-entry fixture is explicitly trusted.
    struct RecoveryFixtureGuard {
        lifecycle: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail_cleanup: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl super::super::launch::ProcessGuard for RecoveryFixtureGuard {
        fn start_launch(&self) {}

        fn release_resources(&self, _: std::time::Instant) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("release");
            Ok(())
        }

        fn terminate_domain(&self) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("terminate");
            Ok(())
        }

        fn wait_empty(&self, _deadline: std::time::Instant) -> Result<()> {
            self.lifecycle
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push("empty");
            if self.fail_cleanup.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(new_error!("Test domain failed to become empty"));
            }
            Ok(())
        }
    }

    impl super::super::launch::ProcessLauncher for RecoveryFixture {
        fn prepare(
            &self,
            role: super::super::program::ProgramRole,
            definition: &super::super::program::ProcessDefinition,
        ) -> Result<super::super::launch::PreparedProcess> {
            use std::sync::atomic::Ordering;
            let attempt = self.prepares.fetch_add(1, Ordering::SeqCst);
            self.lifecycle.lock().unwrap().push("prepare");
            if attempt > 0 && self.fail_reverification {
                return Err(new_error!("Test program reverification rejected"));
            }
            // Even this explicitly trusted fixture checks the complete immutable
            // program manifest on every replacement.
            let topology = super::super::program::ProcessTopologyDefinition::new(
                None,
                vec![definition.clone()],
            )?;
            topology.validate_programs(
                &self.store,
                &super::super::program::ProgramTarget::current(Default::default()),
            )?;
            assert_eq!(role, super::super::program::ProgramRole::FunctionWorker);
            let mut args = self.args.clone();
            if attempt > 0 && self.change_manifest {
                args.push("non-idempotent".into());
            }
            let guard = std::sync::Arc::new(RecoveryFixtureGuard {
                lifecycle: self.lifecycle.clone(),
                fail_cleanup: self.fail_cleanup.clone(),
            });
            self.guards
                .lock()
                .unwrap()
                .push(std::sync::Arc::downgrade(&guard));
            Ok(super::super::launch::PreparedProcess {
                config: fixture_config().args(args),
                guard,
                controls: vec![],
                windows_policy: None,
                resources: vec![],
                export_authority: None,
                resource_generation: None,
            })
        }
    }

    fn recovery_fixture(
        directory: &std::path::Path,
        mode: &str,
        idempotency: Idempotency,
        fail_reverification: bool,
        change_manifest: bool,
    ) -> (
        super::super::program::ProcessTopologyDefinition,
        std::sync::Arc<RecoveryFixture>,
    ) {
        use super::super::program::*;
        use super::super::{ProcessControl, ProcessProfile, RequestedControl};
        let contract = HostFunctionContract::<(i32, i32), i32>::new("HostAdd", idempotency);
        let definitions = vec![
            FunctionContractDefinition::from_contract(&contract),
            FunctionContractDefinition::from_contract(&PID),
        ];
        let store = LocalProgramStore::new(directory.join("programs"));
        let program = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: ProgramTarget::current(Default::default()),
                    functions: definitions.clone(),
                },
                &std::fs::read(fixture_path()).unwrap(),
            )
            .unwrap();
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        }]);
        let topology = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("recovery-fixture", program, &profile, definitions).unwrap(),
            ],
        )
        .unwrap();
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
            std::sync::Arc::new(RecoveryFixture {
                args,
                prepares: std::sync::atomic::AtomicUsize::new(0),
                fail_reverification,
                change_manifest,
                store,
                lifecycle: Default::default(),
                fail_cleanup: Default::default(),
                guards: Default::default(),
            }),
        )
    }

    fn recovery_runtime(
        topology: &super::super::program::ProcessTopologyDefinition,
        launcher: std::sync::Arc<RecoveryFixture>,
    ) -> std::sync::Arc<super::super::runtime::Runtime> {
        super::super::runtime::Runtime::start_workers(
            topology.workers(),
            launcher,
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(4),
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn recovery_call(
        runtime: &super::super::runtime::Runtime,
        contract: &FunctionContractDefinition,
        parameters: Vec<ParameterValue>,
    ) -> Result<ReturnValue> {
        decode_response(&runtime.invoke(0, contract, encode_call(contract, parameters)?)?)
    }

    fn dispatch_count(directory: &std::path::Path) -> usize {
        std::fs::read_to_string(directory.join("dispatches"))
            .unwrap()
            .lines()
            .count()
    }

    #[test]
    fn recovery_replays_idempotent_actual_crash_with_new_root() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = recovery_runtime(&topology, launcher.clone());
        let initial_pid = runtime.reports()[0].root_process_id;
        let contract = &topology.workers()[0].functions()[0];
        // Exercise the synchronous route under an already-entered executor.
        futures::executor::block_on(async {
            let routes =
                register_runtime_routes(0, topology.workers()[0].functions(), runtime.clone());
            let result = routes
                .inner()
                .call_host_function(contract.name(), (10_i32, 32_i32).into_value())
                .unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
        });
        assert_ne!(initial_pid, runtime.reports()[0].root_process_id);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(dispatch_count(directory.path()), 2);
        assert!(!runtime.is_poisoned());
        let events = launcher.lifecycle.lock().unwrap().clone();
        assert_eq!(
            events,
            [
                "prepare",
                "terminate",
                "terminate",
                "empty",
                "release",
                "prepare"
            ]
        );
    }

    #[test]
    fn supervised_refresh_preserves_cleanup_failure_cause() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let owner = recovery_runtime(&topology, launcher.clone());
        let client = super::super::runtime::Runtime::new().unwrap();
        let (mut connections, _supervisor) = supervised_connections(owner.clone(), 1).unwrap();
        launcher
            .fail_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let routes = register_supervised_routes(
            connections.remove(0),
            topology.workers()[0].functions(),
            client.clone(),
        )
        .unwrap();
        let error = routes
            .inner()
            .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
            .unwrap_err();
        assert!(
            error.to_string().contains("lifecycle recovery failed"),
            "{error}"
        );
        let cause = client.poison_cause().unwrap();
        assert!(cause.contains("cleanup failed"), "{cause}");
        let owner_cause = owner.poison_cause().unwrap();
        assert!(cause.contains(&owner_cause), "{cause}");
        client.mark_poisoned();
        assert_eq!(client.poison_cause().as_deref(), Some(cause.as_str()));
    }

    #[test]
    fn recovery_retries_confirmed_cleaned_launch_failure() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct MissingOnce {
            launcher: Arc<RecoveryFixture>,
            missing: std::path::PathBuf,
        }
        impl ProcessLauncher for MissingOnce {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.launcher.prepare(role, definition)?;
                if self.launcher.prepares.load(Ordering::SeqCst) == 2 {
                    prepared.config = prepared.config.process_name(&self.missing);
                }
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            Arc::new(MissingOnce {
                launcher: launcher.clone(),
                missing: directory.path().join("missing-worker"),
            }),
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(4),
                ..Default::default()
            },
        )
        .unwrap();
        let initial_pid = runtime.reports()[0].root_process_id;
        let result = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        );
        assert!(
            result.is_ok(),
            "Confirmed-cleaned launch must be retryable: {result:?}"
        );
        assert_eq!(i32::try_from(result.unwrap()).unwrap(), 42);
        assert!(!runtime.is_poisoned());
        assert_ne!(initial_pid, runtime.reports()[0].root_process_id);
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 3);
        assert_eq!(dispatch_count(directory.path()), 2);
        assert!(
            launcher.guards.lock().unwrap()[..2]
                .iter()
                .all(|guard| guard.upgrade().is_none())
        );
        runtime.stop().unwrap();
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            3
        );
    }

    #[test]
    fn recovery_requires_empty_domain_before_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            false,
        );
        let runtime = recovery_runtime(&topology, launcher.clone());
        launcher
            .fail_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (1_i32, 2_i32).into_value(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup failed"), "{error}");
        assert!(runtime.is_poisoned());
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(dispatch_count(directory.path()), 1);
        let events = launcher.lifecycle.lock().unwrap().clone();
        assert_eq!(events, ["prepare", "terminate", "terminate", "empty"]);
    }

    #[test]
    fn recovery_regression_failed_stop_retains_cleanup_ownership() {
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let mut runtime = recovery_runtime(&topology, launcher.clone());
        let guard = launcher.guards.lock().unwrap()[0].clone();
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        assert!(
            std::sync::Arc::get_mut(&mut runtime)
                .unwrap()
                .shutdown()
                .is_err()
        );
        assert!(
            guard.upgrade().is_some(),
            "Failed cleanup lost its domain capability"
        );
        assert_eq!(runtime.reports().len(), 1);
        assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        std::sync::Arc::get_mut(&mut runtime)
            .unwrap()
            .shutdown()
            .unwrap();
        runtime.stop().unwrap();
        assert!(guard.upgrade().is_none());
        assert!(runtime.reports().is_empty());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recovery_regression_unready_replacement_retains_cleanup_ownership() {
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct FailReplacementCleanup(std::sync::Arc<RecoveryFixture>);
        impl ProcessLauncher for FailReplacementCleanup {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let prepared = self.0.prepare(role, definition)?;
                if self.0.prepares.load(Ordering::SeqCst) > 1 {
                    self.0.fail_cleanup.store(true, Ordering::SeqCst);
                }
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Idempotent,
            false,
            true,
        );
        let runtime = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            std::sync::Arc::new(FailReplacementCleanup(launcher.clone())),
            super::super::runtime::RestartPolicy {
                initial_backoff: Duration::from_millis(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value(),
            )
            .is_err()
        );
        assert!(runtime.is_poisoned());
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 2);
        assert_eq!(dispatch_count(directory.path()), 1);
        let guard = launcher.guards.lock().unwrap()[1].clone();
        assert!(
            guard.upgrade().is_some(),
            "Unready cleanup lost its domain capability"
        );
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        runtime.stop().unwrap();
        assert!(guard.upgrade().is_none());
        let lifecycle = launcher.lifecycle.lock().unwrap();
        assert_eq!(
            lifecycle
                .iter()
                .filter(|event| **event == "release")
                .count(),
            2,
            "{lifecycle:?}"
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn recovery_regression_stopped_route_never_enqueues() {
        use futures::FutureExt;

        let runtime = super::super::runtime::Runtime::remote();
        let (requests, mut calls) = mesh::channel();
        let (lifecycle, mut refreshes) = mesh::channel();
        let definitions = definitions();
        let routes = register_supervised_routes(
            SupervisedConnection {
                initial: WorkerGeneration::new(0, requests, &definitions),
                lifecycle,
                worker_index: 0,
            },
            &definitions,
            runtime.clone(),
        )
        .unwrap();
        runtime.stop().unwrap();
        assert!(
            routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .is_err()
        );
        assert!(
            calls.next().now_or_never().is_none(),
            "Stopped route enqueued a call"
        );
        assert!(refreshes.next().now_or_never().is_none());
        assert!(!runtime.is_poisoned());
    }

    #[test]
    fn recovery_regression_initial_readiness_failure_retries_cleanup() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        use super::super::launch::{PreparedProcess, ProcessGuard, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct RetryGuard {
            inner: Arc<dyn ProcessGuard>,
            fail_cleanup: Arc<AtomicBool>,
        }

        impl ProcessGuard for RetryGuard {
            fn start_launch(&self) {
                self.inner.start_launch();
            }
            fn terminate_domain(&self) -> Result<()> {
                self.inner.terminate_domain()
            }
            fn wait_empty(&self, deadline: Instant) -> Result<()> {
                let result = self.inner.wait_empty(deadline);
                self.fail_cleanup.store(false, Ordering::SeqCst);
                result
            }
            fn release_resources(&self, deadline: Instant) -> Result<()> {
                self.inner.release_resources(deadline)
            }
        }

        struct RetryLauncher(Arc<RecoveryFixture>);
        impl ProcessLauncher for RetryLauncher {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.0.prepare(role, definition)?;
                prepared.guard = Arc::new(RetryGuard {
                    inner: prepared.guard,
                    fail_cleanup: self.0.fail_cleanup.clone(),
                });
                Ok(prepared)
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let (topology, mut launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        Arc::get_mut(&mut launcher).unwrap().args = vec![
            "--crash-once".into(),
            directory.path().join("dispatches").into_os_string(),
            "non-idempotent".into(),
        ];
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        assert!(
            super::super::runtime::Runtime::start_workers(
                topology.workers(),
                Arc::new(RetryLauncher(launcher.clone())),
                Default::default(),
            )
            .is_err()
        );
        assert!(launcher.guards.lock().unwrap()[0].upgrade().is_none());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
        assert_eq!(launcher.prepares.load(Ordering::SeqCst), 1);
        assert!(!directory.path().join("dispatches").exists());
    }

    #[test]
    fn recovery_regression_unconfirmed_launch_survives_constructor_and_rpc_errors() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{ProcessDefinition, ProgramRole};

        struct MissingExecutable {
            launcher: Arc<RecoveryFixture>,
            missing: std::path::PathBuf,
            first: bool,
        }
        impl ProcessLauncher for MissingExecutable {
            fn prepare(
                &self,
                role: ProgramRole,
                definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                let mut prepared = self.launcher.prepare(role, definition)?;
                if self.first || self.launcher.prepares.load(Ordering::SeqCst) > 1 {
                    self.launcher.fail_cleanup.store(true, Ordering::SeqCst);
                    prepared.config = prepared.config.process_name(&self.missing);
                }
                Ok(prepared)
            }
        }

        for initial in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
            let result = super::super::runtime::Runtime::start_workers(
                topology.workers(),
                Arc::new(MissingExecutable {
                    launcher: launcher.clone(),
                    missing: directory.path().join("missing-worker"),
                    first: initial,
                }),
                super::super::runtime::RestartPolicy {
                    initial_backoff: Duration::from_millis(1),
                    ..Default::default()
                },
            );
            if initial {
                let error = result.err().expect("Missing initial executable must fail");
                let guard = launcher.guards.lock().unwrap()[0].clone();
                assert!(
                    guard.upgrade().is_some(),
                    "Constructor error lost pending launch ownership"
                );
                assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
                launcher.fail_cleanup.store(false, Ordering::SeqCst);
                drop(error);
                assert!(guard.upgrade().is_none());
            } else {
                let runtime = result.unwrap();
                let (connections, supervisor) = supervised_connections(runtime.clone(), 1).unwrap();
                let error = futures_lite::future::block_on(
                    connections[0]
                        .lifecycle
                        .call(LifecycleRequest::Refresh, (0, 0)),
                )
                .unwrap()
                .err()
                .expect("Missing replacement must fail");
                drop(error);
                let guard = launcher.guards.lock().unwrap()[1].clone();
                assert!(
                    guard.upgrade().is_some(),
                    "RPC error consumed pending launch ownership"
                );
                assert!(runtime.is_poisoned());
                launcher.fail_cleanup.store(false, Ordering::SeqCst);
                runtime.stop().unwrap();
                runtime.stop().unwrap();
                assert!(guard.upgrade().is_none());
                drop(supervisor);
            }
            assert_eq!(
                launcher
                    .lifecycle
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "release")
                    .count(),
                if initial { 1 } else { 2 }
            );
        }
    }

    #[test]
    fn local_guest_startup_failure_retains_worker_cleanup() {
        use std::sync::atomic::Ordering;

        for fail_cleanup in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
            let mut functions = HostFunctions::default();
            super::super::runtime::start_with_policy(
                topology,
                launcher.clone(),
                &mut functions,
                Default::default(),
            )
            .unwrap();
            launcher.fail_cleanup.store(fail_cleanup, Ordering::SeqCst);
            let error = crate::SandboxBuilder::from_bytes(vec![0])
                .started_process_functions(functions)
                .build()
                .expect_err("Malformed guest must fail after worker startup");
            let guard = launcher.guards.lock().unwrap()[0].clone();
            assert_eq!(
                super::super::launch::has_cleanup_owner(&error),
                fail_cleanup
            );
            assert_eq!(guard.upgrade().is_some(), fail_cleanup);
            assert_eq!(
                launcher.lifecycle.lock().unwrap().contains(&"release"),
                !fail_cleanup,
            );
            launcher.fail_cleanup.store(false, Ordering::SeqCst);
            drop(error);
            assert!(guard.upgrade().is_none());
            assert_eq!(
                launcher
                    .lifecycle
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "release")
                    .count(),
                1,
            );
        }
    }

    #[test]
    fn recovery_regression_failed_readiness_error_retains_runtime_until_drop() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let directory = tempfile::tempdir().unwrap();
        let (topology, mut launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        Arc::get_mut(&mut launcher).unwrap().args = vec![
            "--crash-once".into(),
            directory.path().join("dispatches").into_os_string(),
            "non-idempotent".into(),
        ];
        launcher.fail_cleanup.store(true, Ordering::SeqCst);
        let error = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            launcher.clone(),
            Default::default(),
        )
        .err()
        .expect("Readiness rejection must fail");
        let guard = launcher.guards.lock().unwrap()[0].clone();
        assert!(guard.upgrade().is_some());
        assert!(!launcher.lifecycle.lock().unwrap().contains(&"release"));
        launcher.fail_cleanup.store(false, Ordering::SeqCst);
        drop(error);
        assert!(guard.upgrade().is_none());
        assert_eq!(
            launcher
                .lifecycle
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "release")
                .count(),
            1
        );
    }

    #[test]
    fn recovery_prepares_every_program_before_launch_and_rolls_back_partial_startup() {
        for fail_validation in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                fail_validation,
                !fail_validation,
            );
            // Each fixture declares the same manifest. The second launch either
            // fails preparation or deliberately supplies a different manifest.
            let definition = topology.workers()[0].clone();
            let result = super::super::runtime::Runtime::start_workers(
                &[definition.clone(), definition],
                launcher.clone(),
                Default::default(),
            );
            assert!(result.is_err());
            let events = launcher.lifecycle.lock().unwrap().clone();
            if fail_validation {
                assert_eq!(events, ["prepare", "prepare"]);
            } else {
                assert_eq!(
                    events,
                    [
                        "prepare",
                        "prepare",
                        "terminate",
                        "terminate",
                        "empty",
                        "release",
                        "terminate",
                        "terminate",
                        "empty",
                        "release"
                    ]
                );
            }
            assert!(!directory.path().join("dispatches").exists());
        }
    }

    #[test]
    fn recovery_never_replays_ambiguous_unmarked_or_non_idempotent_calls() {
        for idempotency in [Idempotency::Unspecified, Idempotency::NonIdempotent] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "--crash-once", idempotency, false, false);
            let runtime = recovery_runtime(&topology, launcher.clone());
            let contract = &topology.workers()[0].functions()[0];
            let error =
                recovery_call(&runtime, contract, (10_i32, 32_i32).into_value()).unwrap_err();
            assert!(error.to_string().contains("replay is forbidden"), "{error}");
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                2
            );
            let result = recovery_call(&runtime, contract, (10_i32, 32_i32).into_value()).unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
            assert_eq!(dispatch_count(directory.path()), 2);
            assert!(!runtime.is_poisoned());
        }
    }

    #[test]
    fn recovery_can_dispatch_unmarked_call_after_proven_pre_enqueue_death() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-once",
            Idempotency::Unspecified,
            false,
            false,
        );
        // The test externally kills the idle root. The dispatch itself must not crash.
        std::fs::write(directory.path().join("dispatches"), b"").unwrap();
        let runtime = recovery_runtime(&topology, launcher.clone());
        runtime.terminate_fixture_root(0);
        let result = recovery_call(
            &runtime,
            &topology.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        )
        .unwrap();
        assert_eq!(i32::try_from(result).unwrap(), 42);
        assert_eq!(dispatch_count(directory.path()), 1);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[test]
    fn recovery_exhaustion_poisons_owner_without_affecting_sibling() {
        let failing_directory = tempfile::tempdir().unwrap();
        let healthy_directory = tempfile::tempdir().unwrap();
        let (failing, launcher) = recovery_fixture(
            failing_directory.path(),
            "--crash-always",
            Idempotency::Idempotent,
            false,
            false,
        );
        let (healthy, healthy_launcher) = recovery_fixture(
            healthy_directory.path(),
            "",
            Idempotency::Idempotent,
            false,
            false,
        );
        let failing_runtime = recovery_runtime(&failing, launcher.clone());
        let healthy_runtime = recovery_runtime(&healthy, healthy_launcher.clone());
        let healthy_pid = healthy_runtime.reports()[0].root_process_id;
        let contract = &failing.workers()[0].functions()[0];
        let error =
            recovery_call(&failing_runtime, contract, (1_i32, 2_i32).into_value()).unwrap_err();
        assert!(error.to_string().contains("budget exhausted"), "{error}");
        assert!(failing_runtime.is_poisoned());
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        assert_eq!(dispatch_count(failing_directory.path()), 4);
        assert!(recovery_call(&failing_runtime, contract, (1_i32, 2_i32).into_value()).is_err());
        assert_eq!(dispatch_count(failing_directory.path()), 4);
        let result = recovery_call(
            &healthy_runtime,
            &healthy.workers()[0].functions()[0],
            (10_i32, 32_i32).into_value(),
        )
        .unwrap();
        assert_eq!(i32::try_from(result).unwrap(), 42);
        assert_eq!(healthy_pid, healthy_runtime.reports()[0].root_process_id);
        assert!(!healthy_runtime.is_poisoned());
        assert_eq!(
            healthy_launcher
                .prepares
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn recovery_reverifies_program_and_exact_manifest_before_replay() {
        for change_manifest in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                !change_manifest,
                change_manifest,
            );
            let runtime = recovery_runtime(&topology, launcher.clone());
            let error = recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("budget exhausted"), "{error}");
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                4
            );
            assert_eq!(dispatch_count(directory.path()), 1);
            assert!(runtime.is_poisoned());
        }
    }

    #[test]
    fn recovery_intentional_shutdown_does_not_consume_restart_budget() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let mut runtime = recovery_runtime(&topology, launcher.clone());
        std::sync::Arc::get_mut(&mut runtime)
            .unwrap()
            .shutdown()
            .unwrap();
        assert!(
            recovery_call(
                &runtime,
                &topology.workers()[0].functions()[0],
                (1_i32, 2_i32).into_value()
            )
            .is_err()
        );
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(!runtime.is_poisoned());
    }

    #[test]
    fn recovery_exhaustion_is_terminal_only_for_owning_guest_sandbox() {
        use crate::sandbox::initialized_multi_use::SandboxStatus;
        let failing_directory = tempfile::tempdir().unwrap();
        let healthy_directory = tempfile::tempdir().unwrap();
        let build = |directory: &std::path::Path, mode| {
            let (topology, launcher) =
                recovery_fixture(directory, mode, Idempotency::Idempotent, false, false);
            let mut functions = HostFunctions::default();
            super::super::runtime::start_with_policy(
                topology,
                launcher,
                &mut functions,
                super::super::runtime::RestartPolicy {
                    initial_backoff: Duration::from_millis(1),
                    max_backoff: Duration::from_millis(4),
                    ..Default::default()
                },
            )
            .unwrap();
            // Production initializes the process runtime inside build(), after
            // collecting user functions. Install this trusted fixture at that seam.
            let mut sandbox = crate::UninitializedSandbox::new(
                crate::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_pathbuf()),
                None,
            )
            .unwrap();
            sandbox.host_funcs = std::sync::Arc::new(std::sync::Mutex::new(functions.into_inner()));
            sandbox.evolve().unwrap()
        };
        let mut failing = build(failing_directory.path(), "--crash-always");
        let mut healthy = build(healthy_directory.path(), "");
        let snapshot = failing.snapshot().unwrap();
        assert!(failing.call::<i32>("Add", (10_i32, 32_i32)).is_err());
        assert_eq!(failing.status(), SandboxStatus::Unrecoverable);
        assert!(failing.restore(snapshot).is_err());
        assert_eq!(healthy.call::<i32>("Add", (10_i32, 32_i32)).unwrap(), 42);
        assert!(healthy.status().is_ready());
        assert_eq!(dispatch_count(failing_directory.path()), 4);
    }

    #[test]
    fn recovery_direct_generation_refresh_and_cancels_blocked_native_call() {
        for mode in ["--crash-once", "--block-native"] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                mode,
                Idempotency::Idempotent,
                false,
                false,
            );
            let runtime = recovery_runtime(&topology, launcher.clone());
            let (mut connections, _supervisor) =
                supervised_connections(runtime.clone(), 1).unwrap();
            let connection = connections.remove(0);
            let connection =
                mesh::OwnedMessage::serialized(mesh::OwnedMessage::new(connection).serialize())
                    .parse::<SupervisedConnection>()
                    .unwrap();
            let client = super::super::runtime::Runtime::new().unwrap();
            let functions = register_supervised_routes(
                connection,
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            if mode == "--crash-once" {
                let result = functions
                    .inner()
                    .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                    .unwrap();
                assert_eq!(i32::try_from(result).unwrap(), 42);
                assert_eq!(dispatch_count(directory.path()), 2);
                assert_eq!(runtime.worker_generation(0).unwrap().number, 1);
                // Repeated refreshes for a stale generation reuse the verified
                // endpoint instead of consuming another restart.
                assert_eq!(runtime.refresh_worker(0, 0).unwrap().number, 1);
                assert_eq!(
                    launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                    2
                );
                client.stop().unwrap();
                runtime.stop().unwrap();
            } else {
                let pending = std::thread::spawn(move || {
                    functions
                        .inner()
                        .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                });
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !directory.path().join("dispatches").is_file() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "Worker never entered native call"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                let start = std::time::Instant::now();
                client.stop().unwrap();
                runtime.stop().unwrap();
                assert!(start.elapsed() < Duration::from_secs(35));
                assert!(pending.join().unwrap().is_err());
                assert_eq!(
                    launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                    1
                );
                assert!(!runtime.is_poisoned());
                assert!(!client.is_poisoned());
            }
        }
    }

    #[test]
    fn recovery_direct_routes_never_replay_ambiguous_unmarked_calls() {
        for idempotency in [Idempotency::Unspecified, Idempotency::NonIdempotent] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) =
                recovery_fixture(directory.path(), "--crash-once", idempotency, false, false);
            let owner = recovery_runtime(&topology, launcher.clone());
            let client = super::super::runtime::Runtime::new().unwrap();
            let (mut connections, _supervisor) = supervised_connections(owner.clone(), 1).unwrap();
            let routes = register_supervised_routes(
                connections.remove(0),
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            let error = routes
                .inner()
                .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                .unwrap_err();
            assert!(error.to_string().contains("replay is forbidden"), "{error}");
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                2
            );
            let result = routes
                .inner()
                .call_host_function("HostAdd", (10_i32, 32_i32).into_value())
                .unwrap();
            assert_eq!(i32::try_from(result).unwrap(), 42);
            assert_eq!(dispatch_count(directory.path()), 2);
            assert!(!client.is_poisoned());
            owner.stop().unwrap();
        }
    }

    #[test]
    fn recovery_direct_exhaustion_poisons_vm_without_parent_call_relay() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) = recovery_fixture(
            directory.path(),
            "--crash-always",
            Idempotency::Idempotent,
            false,
            false,
        );
        let owner = recovery_runtime(&topology, launcher.clone());
        let client = super::super::runtime::Runtime::new().unwrap();
        let (mut connections, _supervisor) = supervised_connections(owner.clone(), 1).unwrap();
        let routes = register_supervised_routes(
            connections.remove(0),
            topology.workers()[0].functions(),
            client.clone(),
        )
        .unwrap();
        assert!(
            routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .is_err()
        );
        assert!(owner.is_poisoned());
        assert!(client.is_poisoned());
        assert_eq!(dispatch_count(directory.path()), 4);
        assert_eq!(
            launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        owner.stop().unwrap();
    }

    #[test]
    fn recovery_idle_lifecycle_endpoint_does_not_keep_owner_alive() {
        let directory = tempfile::tempdir().unwrap();
        let (topology, launcher) =
            recovery_fixture(directory.path(), "", Idempotency::Idempotent, false, false);
        let owner = recovery_runtime(&topology, launcher);
        let (mut connections, supervisor) = supervised_connections(owner.clone(), 1).unwrap();
        let connection = connections.remove(0);
        let weak = std::sync::Arc::downgrade(&owner);
        drop(owner);
        drop(supervisor);
        assert!(weak.upgrade().is_none());
        let response = futures_lite::future::block_on(
            connection.lifecycle.call(LifecycleRequest::Refresh, (0, 0)),
        );
        assert!(response.is_err() || response.unwrap().is_err());
    }

    #[test]
    fn recovery_direct_routes_reject_changed_manifest_or_stale_generation_before_replay() {
        for change_manifest in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let (topology, launcher) = recovery_fixture(
                directory.path(),
                "--crash-once",
                Idempotency::Idempotent,
                false,
                false,
            );
            let owner = recovery_runtime(&topology, launcher.clone());
            let initial = owner.worker_generation(0).unwrap();
            let mut replacement = owner.worker_generation(0).unwrap();
            if change_manifest {
                replacement.number = 1;
                replacement.contracts[0].idempotency = 1;
            }
            let (lifecycle, mut receive) = mesh::channel();
            let responder = std::thread::spawn(move || {
                futures_lite::future::block_on(async move {
                    let LifecycleRequest::Refresh(refresh) = receive.next().await.unwrap();
                    refresh.handle_sync(|generation| {
                        assert_eq!(generation, (0, 0));
                        Ok(replacement)
                    });
                });
            });
            let client = super::super::runtime::Runtime::new().unwrap();
            let routes = register_supervised_routes(
                SupervisedConnection {
                    initial,
                    lifecycle,
                    worker_index: 0,
                },
                topology.workers()[0].functions(),
                client.clone(),
            )
            .unwrap();
            let error = routes
                .inner()
                .call_host_function("HostAdd", (1_i32, 2_i32).into_value())
                .unwrap_err();
            assert!(
                error.to_string().contains("immutable manifest mismatch"),
                "{error}"
            );
            assert!(client.is_poisoned());
            assert_eq!(dispatch_count(directory.path()), 1);
            assert_eq!(
                launcher.prepares.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            responder.join().unwrap();
            owner.stop().unwrap();
        }
    }

    #[test]
    fn snapshot_captures_runtime_owners_and_reconstructs_owned_signatures() {
        futures::executor::block_on(async {
            snapshot_roundtrip();
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn snapshot_runtime_progresses_with_blocked_tokio_reactor() {
        snapshot_roundtrip();
    }

    fn snapshot_roundtrip() {
        use super::super::program::{
            LocalProgramStore, ProcessDefinition, ProcessTopologyDefinition, ProgramConfig,
            ProgramRole, ProgramTarget,
        };
        use super::super::{ProcessControl, ProcessProfile, RequestedControl, runtime};
        use crate::func::Registerable;

        let directory = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(directory.path());
        let program = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: ProgramTarget::current(Default::default()),
                    functions: definitions(),
                },
                &std::fs::read(fixture_path()).unwrap(),
            )
            .unwrap();
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyNetwork,
            required: true,
        }]);
        // Prepared fixtures qualify routing and snapshots, not containment.
        let topology = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("arithmetic", program.clone(), &profile, definitions())
                    .unwrap(),
            ],
        )
        .unwrap();
        let launch = |definition| {
            let mut functions = HostFunctions::default();
            runtime::start_prepared(definition, vec![fixture_config()], &mut functions).unwrap();
            functions
        };
        let functions = launch(topology.clone());
        let mut uninitialized = crate::UninitializedSandbox::new(
            crate::GuestBinary::FilePath(hyperlight_testing::simple_guest_as_pathbuf()),
            None,
        )
        .unwrap();
        uninitialized.host_funcs =
            std::sync::Arc::new(std::sync::Mutex::new(functions.into_inner()));
        let mut sandbox = uninitialized.evolve().unwrap();
        let process_id = |sandbox: &crate::MultiUseSandbox| {
            u32::try_from(
                sandbox
                    .host_funcs
                    .lock()
                    .unwrap()
                    .call_host_function(PID.definition.name, Vec::new())
                    .unwrap(),
            )
            .unwrap()
        };
        let original_pid = process_id(&sandbox);
        let snapshot = sandbox.snapshot().unwrap();
        assert_eq!(snapshot.process_topology(), Some(&topology));
        assert!(
            crate::SandboxBuilder::from_snapshot(snapshot.clone())
                .build()
                .unwrap_err()
                .to_string()
                .contains("requires a MeshProcessProvider capability")
        );
        sandbox.restore(snapshot.clone()).unwrap();
        assert_eq!(process_id(&sandbox), original_pid);
        assert!(
            sandbox
                .register_host_function(ADD.definition.name, |a: i32, b: i32| a + b)
                .is_err()
        );
        assert_eq!(sandbox.call::<i32>("Add", (10, 32)).unwrap(), 42);

        let local_functions = || {
            let mut functions = HostFunctions::default();
            functions
                .register_host_function(ADD.definition.name, |a: i32, b: i32| a + b)
                .unwrap();
            functions
                .register_host_function(PID.definition.name, std::process::id)
                .unwrap();
            functions
        };
        assert!(
            crate::MultiUseSandbox::from_snapshot(snapshot.clone(), local_functions(), None)
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        assert!(
            crate::SandboxBuilder::from_snapshot(snapshot.clone())
                .host_functions(local_functions())
                .build()
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        let mut local =
            crate::SandboxBuilder::from_file(hyperlight_testing::simple_guest_as_pathbuf())
                .host_functions(local_functions())
                .build()
                .unwrap();
        assert!(
            local
                .restore(snapshot.clone())
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        assert!(local.status().is_ready());
        assert_eq!(local.call::<i32>("Add", (10, 32)).unwrap(), 42);

        let guest_only = local.snapshot().unwrap();
        assert!(guest_only.process_topology().is_none());
        sandbox.restore(guest_only).unwrap();
        assert_eq!(
            sandbox.snapshot().unwrap().process_topology(),
            Some(&topology)
        );
        assert_eq!(process_id(&sandbox), original_pid);
        assert_eq!(sandbox.call::<i32>("Add", (12, 30)).unwrap(), 42);

        let wrong_owner = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new("different-owner", program, &profile, definitions())
                    .unwrap(),
            ],
        )
        .unwrap();
        assert!(
            crate::MultiUseSandbox::from_snapshot(snapshot.clone(), launch(wrong_owner), None)
                .unwrap_err()
                .to_string()
                .contains("process topology")
        );
        let parsed = serde_json::from_slice(
            &serde_json::to_vec(snapshot.process_topology().unwrap()).unwrap(),
        )
        .unwrap();
        let mut restored =
            crate::MultiUseSandbox::from_snapshot(snapshot, launch(parsed), None).unwrap();
        assert_ne!(process_id(&restored), original_pid);
        assert_eq!(restored.call::<i32>("Add", (10, 32)).unwrap(), 42);
        assert_eq!(
            restored.snapshot().unwrap().process_topology(),
            Some(&topology)
        );
    }

    async fn run_fixture(with_guest: bool) {
        let runtime = super::super::runtime::Runtime::new().unwrap();
        let (send, requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let config = fixture_config();
        let bootstrap = bootstrap(&definitions(), requests, ready);
        let pid = runtime
            .launch(config, bootstrap, send.clone())
            .await
            .unwrap();
        let exchange = tokio::time::timeout(Duration::from_secs(30), async {
            let registrations =
                register_ready_routes(send.clone(), readiness, &definitions(), runtime.clone())
                    .await
                    .unwrap();
            let child_pid = call_fixture(&send, PID, ()).await.unwrap();
            assert_eq!(child_pid, u32::try_from(pid).unwrap());
            assert_ne!(child_pid, std::process::id());
            assert_eq!(call_fixture(&send, ADD, (10, 32)).await.unwrap(), 42);
            if with_guest {
                tokio::task::spawn_blocking(move || {
                    let mut sandbox = crate::SandboxBuilder::from_file(
                        hyperlight_testing::simple_guest_as_pathbuf(),
                    )
                    .host_functions(registrations)
                    .build()
                    .unwrap();
                    for i in 0_i32..10 {
                        assert_eq!(sandbox.call::<i32>("Add", (i, 32)).unwrap(), i + 32);
                    }
                })
                .await
                .unwrap();
            }
            send.call(Request::Stop, ()).await.unwrap();
        })
        .await;
        drop(send);
        drop(runtime);
        exchange.expect("Mesh child request timed out");
    }

    #[tokio::test]
    async fn mesh_bootstrap_transfers_owned_file_without_a_path() {
        use std::io::{Read, Seek, SeekFrom};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource.txt");
        std::fs::write(&path, b"host-content:").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut verification = file.try_clone().unwrap();
        std::fs::remove_file(&path).unwrap();

        let resource = super::super::resource::RegisteredResource::file(
            super::super::resource::ResourceId::new(7, 0, 1),
            file,
            super::super::OsResourceRights::READ | super::super::OsResourceRights::WRITE,
        );
        let definition = FunctionContractDefinition::from_contract(&ECHO);
        let runtime = super::super::runtime::Runtime::new().unwrap();
        let (send, requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        let declaration = resource.declaration(1);
        runtime
            .launch_with_resources(
                file_resource_fixture_config(),
                bootstrap_with_resources(
                    std::slice::from_ref(&definition),
                    1,
                    vec![declaration],
                    None,
                    requests,
                    ready,
                ),
                send.clone(),
                vec![resource],
                None,
            )
            .await
            .unwrap();
        readiness.await.unwrap().unwrap();
        let original = call_fixture(&send, ECHO, ("worker-write".to_owned(),))
            .await
            .unwrap();
        assert_eq!(original, "host-content:");
        verification.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = String::new();
        verification.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, "host-content:[generation=1]worker-write");
        send.call(Request::Stop, ()).await.unwrap();
    }

    #[tokio::test]
    async fn phase_one_rejection_does_not_invoke_resource_factory() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingFactory(Arc<AtomicUsize>);

        impl super::super::resource::LaunchResourceFactory for CountingFactory {
            fn create(
                &self,
                _generation: u64,
            ) -> Result<super::super::resource::NativeResourcePayload> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(super::super::resource::NativeResourcePayload::AuthorizationMarker)
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let resource = super::super::resource::RegisteredResource::typed(
            super::super::resource::ResourceId::new(12, 0, 0),
            super::super::resource::FIRST_TYPED_RESOURCE_KIND,
            b"marker".to_vec(),
            Arc::new(CountingFactory(calls.clone())),
        )
        .unwrap();
        let declaration = resource.declaration(1);
        let definition = FunctionContractDefinition::from_contract(&ECHO);
        let runtime = super::super::runtime::Runtime::new().unwrap();
        let (send, requests) = mesh::channel();
        let (ready, _readiness) = mesh::oneshot();
        let result = runtime
            .launch_with_resources(
                file_resource_fixture_config(),
                bootstrap_with_resources(
                    std::slice::from_ref(&definition),
                    1,
                    vec![declaration],
                    None,
                    requests,
                    ready,
                ),
                send,
                vec![resource],
                None,
            )
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_launch_burns_provider_generation_and_reinvokes_factory() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        use super::super::OsResourceRights;

        struct FailingFactory {
            read_write: std::fs::File,
            generations: Mutex<Vec<u64>>,
        }

        impl super::super::resource::LaunchResourceFactory for FailingFactory {
            fn create(
                &self,
                generation: u64,
            ) -> Result<super::super::resource::NativeResourcePayload> {
                let mut generations = self.generations.lock().unwrap();
                generations.push(generation);
                let attempt = generations.len();
                drop(generations);
                match attempt {
                    1 => Err(new_error!("Intentional resource factory failure")),
                    2 => Ok(super::super::resource::NativeResourcePayload::AuthorizationMarker),
                    _ => Ok(super::super::resource::NativeResourcePayload::File(
                        self.read_write.try_clone()?,
                    )),
                }
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("generation.txt");
        std::fs::write(&path, b"generation").unwrap();
        let factory = Arc::new(FailingFactory {
            read_write: std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
            generations: Mutex::new(Vec::new()),
        });
        let generation = Arc::new(AtomicU64::new(1));
        let definition = FunctionContractDefinition::from_contract(&ECHO);

        for expected in 1..=3 {
            let resource = super::super::resource::RegisteredResource::file_with_factory(
                super::super::resource::ResourceId::new(23, 0, 0),
                OsResourceRights::READ | OsResourceRights::WRITE,
                factory.clone(),
            );
            let declaration = resource.declaration(expected);
            let runtime = super::super::runtime::Runtime::new().unwrap();
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let result = runtime
                .launch_with_resources_generation(
                    file_resource_fixture_config(),
                    bootstrap_with_resources(
                        std::slice::from_ref(&definition),
                        expected,
                        vec![declaration],
                        None,
                        requests,
                        ready,
                    ),
                    send.clone(),
                    vec![resource],
                    None,
                    Some(generation.clone()),
                )
                .await;
            if expected == 1 {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("Intentional resource factory failure")
                );
            } else {
                result.unwrap();
                if expected == 2 {
                    // A rejected worker may exit before its readiness error is flushed.
                    if let Ok(readiness) = readiness.await {
                        assert!(readiness.is_err());
                    }
                } else {
                    readiness.await.unwrap().unwrap();
                    // The worker may exit before the transport flushes the Stop reply.
                    let _ = send.call(Request::Stop, ()).await;
                }
            }
        }
        assert_eq!(*factory.generations.lock().unwrap(), vec![1, 2, 3]);
        assert_eq!(generation.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn mesh_bootstrap_qualifies_file_rights_matrix() {
        use std::io::{Read, Seek, SeekFrom};

        for (name, rights, can_read, can_write) in [
            ("read", super::super::OsResourceRights::READ, true, false),
            ("write", super::super::OsResourceRights::WRITE, false, true),
            (
                "read-write",
                super::super::OsResourceRights::READ | super::super::OsResourceRights::WRITE,
                true,
                true,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("resource.txt");
            std::fs::write(&path, b"host-content:").unwrap();
            let verification = std::fs::File::open(&path).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(can_read)
                .write(can_write)
                .open(&path)
                .unwrap();
            std::fs::remove_file(&path).unwrap();
            let registered = super::super::resource::RegisteredResource::file(
                super::super::resource::ResourceId::new(8, 0, 1),
                file,
                rights,
            );
            let definition = FunctionContractDefinition::from_contract(&ECHO);
            let runtime = super::super::runtime::Runtime::new().unwrap();
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let declaration = registered.declaration(1);
            runtime
                .launch_with_resources(
                    file_resource_fixture_config_with_rights(name),
                    bootstrap_with_resources(
                        std::slice::from_ref(&definition),
                        1,
                        vec![declaration],
                        None,
                        requests,
                        ready,
                    ),
                    send.clone(),
                    vec![registered],
                    None,
                )
                .await
                .unwrap();
            readiness.await.unwrap().unwrap();
            let original = call_fixture(&send, ECHO, ("worker-write".to_owned(),))
                .await
                .unwrap();
            assert_eq!(original, if can_read { "host-content:" } else { "" });

            let mut verification = verification;
            verification.seek(SeekFrom::Start(0)).unwrap();
            let mut actual = String::new();
            verification.read_to_string(&mut actual).unwrap();
            assert_eq!(
                actual,
                if can_write {
                    "host-content:[generation=1]worker-write"
                } else {
                    "host-content:"
                }
            );
            send.call(Request::Stop, ()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn mesh_bootstrap_transfers_pathless_worker_file_to_parent() {
        use std::io::{Read, Seek, SeekFrom};
        use std::sync::{Arc, Mutex};

        use super::super::OsResourceRights;
        use super::super::resource::{
            ExportAuthority, ResourceExportSink, ResourceId, WireExportFile,
        };

        #[derive(Default)]
        struct Sink {
            files: Mutex<Vec<WireExportFile>>,
        }

        impl ResourceExportSink for Sink {
            fn begin_generation(&self, _process_name: &str, _generation: u64) -> Result<()> {
                Ok(())
            }

            fn accept_file(
                &self,
                _process_name: &str,
                generation: u64,
                file: WireExportFile,
            ) -> Result<ResourceId> {
                assert_eq!(generation, 1);
                let mut files = self.files.lock().unwrap();
                let slot = files.len() as u32;
                files.push(file);
                Ok(ResourceId::new(17, slot, generation))
            }

            fn end_generation(&self, _process_name: &str, _generation: u64) {}
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource.txt");
        std::fs::write(&path, b"host-content:").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        let registered = super::super::resource::RegisteredResource::file(
            ResourceId::new(16, 0, 1),
            file,
            OsResourceRights::READ | OsResourceRights::WRITE,
        );
        let sink = Arc::new(Sink::default());
        let authority = ExportAuthority::new(
            "file-resource".to_owned(),
            super::super::OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            sink.clone(),
        );
        let declaration = registered.declaration(1);
        let export_policy = authority.declaration();
        let definition = FunctionContractDefinition::from_contract(&ECHO);
        let runtime = super::super::runtime::Runtime::new().unwrap();
        let (send, requests) = mesh::channel();
        let (ready, readiness) = mesh::oneshot();
        runtime
            .launch_with_resources(
                file_resource_fixture_config_with("read-write", true),
                bootstrap_with_resources(
                    std::slice::from_ref(&definition),
                    1,
                    vec![declaration],
                    Some(export_policy),
                    requests,
                    ready,
                ),
                send.clone(),
                vec![registered],
                Some(authority),
            )
            .await
            .unwrap();
        readiness.await.unwrap().unwrap();
        let original = call_fixture(&send, ECHO, ("worker-write".to_owned(),))
            .await
            .unwrap();
        assert_eq!(original, "host-content:");
        send.call(Request::Stop, ()).await.unwrap();
        drop(runtime);

        let mut files = sink.files.lock().unwrap();
        let [exported] = files.as_mut_slice() else {
            panic!("worker must export exactly one file");
        };
        assert_eq!(exported.kind, 1);
        assert_eq!(exported.rights, OsResourceRights::READ.bits());
        exported.file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = String::new();
        exported.file.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, "host-content:[generation=1]worker-write");
    }

    #[test]
    fn replacement_receives_fresh_resource_and_export_generations() {
        use std::io::{Read, Seek, SeekFrom};
        use std::sync::{Arc, Mutex};

        use super::super::launch::{PreparedProcess, ProcessLauncher};
        use super::super::program::{
            FunctionContractDefinition, LocalProgramStore, ProcessDefinition,
            ProcessTopologyDefinition, ProgramConfig, ProgramRole, ProgramTarget,
        };
        use super::super::resource::{
            ExportAuthority, ResourceExportSink, ResourceId, WireExportFile,
        };
        use super::super::runtime::TrustedFixtureGuard;
        use super::super::{OsResourceRights, ProcessControl, ProcessProfile, RequestedControl};

        struct ResourceLauncher {
            resource: super::super::resource::RegisteredResource,
            export_authority: ExportAuthority,
        }

        impl ProcessLauncher for ResourceLauncher {
            fn prepare(
                &self,
                role: ProgramRole,
                _definition: &ProcessDefinition,
            ) -> Result<PreparedProcess> {
                assert_eq!(role, ProgramRole::FunctionWorker);
                Ok(PreparedProcess {
                    config: file_resource_fixture_config_with("read-write", true),
                    guard: Arc::new(TrustedFixtureGuard),
                    controls: vec![],
                    windows_policy: None,
                    resources: vec![self.resource.clone()],
                    export_authority: Some(self.export_authority.clone()),
                    resource_generation: None,
                })
            }
        }

        #[derive(Default)]
        struct Sink {
            files: Mutex<Vec<(u64, WireExportFile)>>,
        }

        impl ResourceExportSink for Sink {
            fn begin_generation(&self, _process_name: &str, _generation: u64) -> Result<()> {
                Ok(())
            }

            fn accept_file(
                &self,
                _process_name: &str,
                generation: u64,
                file: WireExportFile,
            ) -> Result<ResourceId> {
                let mut files = self.files.lock().unwrap();
                let slot = files.len() as u32;
                files.push((generation, file));
                Ok(ResourceId::new(19, slot, generation))
            }

            fn end_generation(&self, _process_name: &str, _generation: u64) {}
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource.txt");
        std::fs::write(&path, b"host-content:").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut verification = file.try_clone().unwrap();
        std::fs::remove_file(&path).unwrap();

        let definition = FunctionContractDefinition::from_contract(&ECHO);
        let store = LocalProgramStore::new(directory.path().join("programs"));
        let program = store
            .package(
                &ProgramConfig {
                    schema_version: 1,
                    role: ProgramRole::FunctionWorker,
                    target: ProgramTarget::current(Default::default()),
                    functions: vec![definition.clone()],
                },
                &std::fs::read(file_resource_fixture_path()).unwrap(),
            )
            .unwrap();
        let profile = ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        }]);
        let topology = ProcessTopologyDefinition::new(
            None,
            vec![
                ProcessDefinition::new(
                    "file-resource",
                    program,
                    &profile,
                    vec![definition.clone()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let sink = Arc::new(Sink::default());
        let launcher = Arc::new(ResourceLauncher {
            resource: super::super::resource::RegisteredResource::file(
                super::super::resource::ResourceId::new(9, 0, 1),
                file,
                OsResourceRights::READ | OsResourceRights::WRITE,
            ),
            export_authority: ExportAuthority::new(
                "file-resource".to_owned(),
                super::super::OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
                sink.clone(),
            ),
        });
        let runtime = super::super::runtime::Runtime::start_workers(
            topology.workers(),
            launcher,
            super::super::RestartPolicy {
                max_restarts: 5,
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(2),
                ..Default::default()
            },
        )
        .unwrap();

        let first = <String as SupportedReturnType>::from_value(
            recovery_call(&runtime, &definition, ("first".to_owned(),).into_value()).unwrap(),
        )
        .unwrap();
        assert_eq!(first, "host-content:");
        let mut expected = "host-content:[generation=1]first".to_owned();
        for generation in 2..=5 {
            runtime.terminate_fixture_root(0);
            let input = format!("call-{generation}");
            let previous = <String as SupportedReturnType>::from_value(
                recovery_call(&runtime, &definition, (input.clone(),).into_value()).unwrap(),
            )
            .unwrap();
            assert_eq!(previous, expected);
            expected.push_str(&format!("[generation={generation}]{input}"));
        }

        verification.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = String::new();
        verification.read_to_string(&mut actual).unwrap();
        assert_eq!(actual, expected);
        let mut exports = sink.files.lock().unwrap();
        assert_eq!(
            exports
                .iter()
                .map(|(generation, _)| *generation)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        for (generation, export) in exports.iter_mut() {
            export.file.seek(SeekFrom::Start(0)).unwrap();
            let mut result = String::new();
            export.file.read_to_string(&mut result).unwrap();
            assert!(result.contains(&format!("[generation={generation}]")));
        }
    }

    #[tokio::test]
    async fn owned_cleanup_reaps_blocked_startup_and_native_call() {
        for mode in ["--block-before-run", "--block-native"] {
            let mut runtime = super::super::runtime::Runtime::new().unwrap();
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("entered");
            let config = fixture_config().args([mode.into(), marker.clone().into_os_string()]);
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let start = std::time::Instant::now();
            let launch = runtime
                .launch(
                    config,
                    bootstrap(&definitions(), requests, ready),
                    send.clone(),
                )
                .await;
            if mode == "--block-before-run" {
                assert!(launch.is_err());
                assert!(marker.is_file());
                assert!(start.elapsed() < Duration::from_secs(40));
                continue;
            }
            launch.unwrap();
            let pending = if mode == "--block-native" {
                readiness.await.unwrap().unwrap();
                let call = FunctionCall::new(
                    ADD.definition.name.to_owned(),
                    Some((1_i32, 2_i32).into_value()),
                    FunctionCallType::Host,
                    ADD.definition.output,
                );
                Some(send.call(Request::Call, encode_function_call(&call).unwrap()))
            } else {
                None
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                while !marker.is_file() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("Child never entered the blocking operation");
            let start = std::time::Instant::now();
            // Cleanup must progress while both calling executors are blocked.
            futures::executor::block_on(async {
                std::sync::Arc::get_mut(&mut runtime)
                    .unwrap()
                    .shutdown()
                    .unwrap();
            });
            assert!(start.elapsed() < Duration::from_secs(40));
            if let Some(pending) = pending {
                assert!(pending.await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn owned_cleanup_rolls_back_partial_startup() {
        let mut runtime = super::super::runtime::Runtime::new().unwrap();
        let mut routes = Vec::new();
        for valid in [true, false] {
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let mut definitions = definitions();
            if !valid {
                definitions.pop();
            }
            let result = runtime
                .launch(
                    fixture_config(),
                    bootstrap(&definitions, requests, ready),
                    send.clone(),
                )
                .await
                .map(|_| ());
            if !valid {
                assert!(result.is_err());
                continue;
            }
            result.unwrap();
            let result =
                register_ready_routes(send, readiness, &definitions, runtime.clone()).await;
            routes.push(result.unwrap());
        }
        drop(routes);
        futures::executor::block_on(async {
            std::sync::Arc::get_mut(&mut runtime)
                .unwrap()
                .shutdown()
                .unwrap();
        });
    }

    async fn call_fixture<A: ParameterTuple, O: SupportedReturnType>(
        send: &mesh::Sender<Request>,
        contract: HostFunctionContract<A, O>,
        parameters: A,
    ) -> Result<O> {
        let value = invoke(
            send,
            &FunctionContractDefinition::from_contract(&contract),
            parameters.into_value(),
        )
        .await?;
        Ok(O::from_value(value)?)
    }

    #[test]
    fn mesh_transports_registered_call_and_stop() {
        futures::executor::block_on(async {
            let contract =
                HostFunctionContract::<(i32, i32), i32>::new("Add", Idempotency::Idempotent);
            let mut functions = ProcessHostFunctions::default();
            functions.bind(contract, |a: i32, b: i32| a + b).unwrap();
            let (send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let mut bootstrap = bootstrap(
                std::slice::from_ref(&FunctionContractDefinition::from_contract(&contract)),
                requests,
                ready,
            );
            // Encode/decode exercises transferable endpoints, not only local messages.
            let wire =
                mesh::OwnedMessage::serialized(mesh::OwnedMessage::new(bootstrap.wire).serialize())
                    .parse()
                    .unwrap();
            let client = async {
                bootstrap.delivery.wait_validated().await.unwrap();
                bootstrap.delivery.send_resources(1, vec![], None);
                readiness.await.unwrap().unwrap();
                let call = FunctionCall::new(
                    "Add".to_owned(),
                    Some((10_i32, 32_i32).into_value()),
                    FunctionCallType::Host,
                    <i32 as SupportedReturnType>::TYPE,
                );
                let response = send
                    .call(Request::Call, encode_function_call(&call).unwrap())
                    .await
                    .unwrap()
                    .unwrap();
                let value = decode_function_result(response.as_slice())
                    .unwrap()
                    .into_inner()
                    .unwrap();
                assert_eq!(<i32 as SupportedReturnType>::from_value(value).unwrap(), 42);
                send.call(Request::Stop, ()).await.unwrap();
            };
            let (result, ()) = futures::join!(functions.serve(wire), client);
            result.unwrap();
        });
    }

    #[test]
    fn manifest_mismatch_never_reports_ready() {
        futures::executor::block_on(async {
            let functions = ProcessHostFunctions::default();
            let (_send, requests) = mesh::channel();
            let (ready, readiness) = mesh::oneshot();
            let mut bootstrap = bootstrap(&[], requests, ready);
            bootstrap.wire.version = PROTOCOL_VERSION + 1;
            let result = futures::join!(
                functions.serve(bootstrap.wire),
                bootstrap.delivery.wait_validated()
            );
            assert!(result.0.is_err());
            assert!(result.1.is_err());
            assert!(readiness.await.unwrap().is_err());
        });
    }

    #[test]
    fn malformed_calls_do_not_execute_implementation() {
        let mut functions = ProcessHostFunctions::default();
        functions
            .bind(
                HostFunctionContract::<(), i32>::new("Fail", Idempotency::Unspecified),
                || -> i32 { panic!("invalid call reached user code") },
            )
            .unwrap();
        assert!(functions.dispatch(&[]).is_err());
        for (name, kind, result, parameters) in [
            (
                "Fail",
                FunctionCallType::Guest,
                <i32 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Unknown",
                FunctionCallType::Host,
                <i32 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Fail",
                FunctionCallType::Host,
                <u64 as SupportedReturnType>::TYPE,
                None,
            ),
            (
                "Fail",
                FunctionCallType::Host,
                <i32 as SupportedReturnType>::TYPE,
                Some((7_i32,).into_value()),
            ),
        ] {
            let call = FunctionCall::new(name.to_owned(), parameters, kind, result);
            assert!(
                functions
                    .dispatch(&encode_function_call(&call).unwrap())
                    .is_err()
            );
        }
    }
}
