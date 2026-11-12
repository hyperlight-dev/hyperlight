// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Process placement declarations validated before guest initialization.
//!
//! Restricted process launching requires a supported containment backend.
//! [`ProcessProfile::unrestricted`] intentionally applies no process controls
//! and runs both native process roles with the caller's permissions. It cannot
//! be combined with controls or platform limits.
//!
//! macOS supports unrestricted profiles only. The pinned Mesh API does not
//! expose its owned-root API there, so each process receives a dedicated Mesh
//! whose shutdown owns that root's cleanup. Restricted macOS profiles fail
//! before process spawn.
//!
//! # Windows VM hosts
//!
//! AppContainer is the default. Windows Hypervisor Platform access can require
//! the VM-owning sandbox host to run as an ordinary non-elevated process outside
//! AppContainer. The VM host retains process separation and job limits, but has
//! no AppContainer filesystem or network boundary. Function workers remain in
//! separate AppContainers.
//!
//! Applications select and authorize that boundary in one operation:
//!
//! ```no_run
//! use hyperlight_host::{SandboxBuilder, process::ProcessOptions};
//! # fn configure(builder: SandboxBuilder, options: ProcessOptions) -> SandboxBuilder {
//! builder.windows_vm_host_process(options)
//! # }
//! ```
//!
//! Every fresh reconstruction needs caller authorization. Snapshot metadata and
//! program digests cannot grant it. Required network denial fails for a Windows
//! VM host. Optional network denial is reported as not applied.
//!
//! A separate Windows sandbox-host runs one VM with surrogates disabled.
//! Calling-process defaults and environment remain unchanged.
//!
//! # Cleanup limits
//!
//! Replacement and resource release require confirmed original-root completion
//! and an empty confinement domain. Failed cleanup retains ownership while the
//! sandbox, runtime or ownership-carrying startup error remains alive.
//!
//! Final-owner Drop performs bounded best-effort cleanup and logs failures.
//! If completion remains unconfirmed, that owner can disappear without leaving
//! a retry capability. Windows kill-on-close requests termination but does not
//! prove domain emptiness. Linux has no equivalent lifetime guarantee, so
//! descendants or resources can remain. macOS cleanup owns one dedicated Mesh,
//! not an independent descendant process domain. Resource deletion failure after
//! proven emptiness can leave files or profiles without implying a running
//! process. Failed cleanup is not reported as successful release.
//!
//! # Errors
//!
//! Enabling `process-isolation` adds [`crate::HyperlightError::ProcessCleanup`]
//! to the exhaustive public error enum. Feature-enabled matches must handle it.
//! The feature-disabled enum is unchanged. The error retains cleanup ownership
//! and exposes the original diagnostic through its source chain.
//!
//! Dedicated sandbox replies preserve portable guest, cancellation, memory,
//! argument and snapshot errors. Native/backend errors and borrowed Rust type
//! names use diagnostic errors. Cleanup capabilities stay with their owner and
//! cannot travel in operation replies. Both executables require the same private
//! protocol version.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::marker::PhantomData;
use std::time::Duration;

use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterType, ReturnType};

use crate::func::{HostFunction, ParameterTuple, SupportedReturnType};
use crate::{HostFunctions, Result, new_error};

#[cfg(target_os = "windows")]
const WINDOWS_VM_HOST_MECHANISM: &str = "Ordinary non-elevated Windows VM host";
const WINDOWS_CPU_RATE_MECHANISM: &str = "Windows Job Object hard CPU rate: ";

mod launch;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_domain;
#[cfg(target_os = "linux")]
mod linux_output;
#[cfg(target_os = "macos")]
mod macos;
pub mod program;
mod provider;
mod resource;
mod runtime;
mod sandbox;
mod transport;
mod vm_authority;
#[cfg(target_os = "windows")]
mod windows;

pub use launch::{
    ControlOutcome, ControlResult, ProcessCleanupError, ProcessReport, WindowsProcessPolicyReport,
};
#[cfg(target_os = "linux")]
pub use linux::LinuxProcessResources;
pub use provider::MeshProcessProvider;
#[allow(unused_imports)]
pub(crate) use resource::{
    ClaimedTypedResource, FIRST_TYPED_RESOURCE_KIND, LaunchResourceFactory, NativeResourcePayload,
    NativeResourceValidator,
};
pub use resource::{
    ExportedFile, OsResourceExportPolicy, OsResourceKind, OsResourceRights,
    ProcessResourceExporter, ProcessResourceManifest, ProcessResources, ResourceId,
    TransferredFile,
};
pub use runtime::RestartPolicy;
pub(crate) use runtime::Runtime as ProcessRuntime;
pub use sandbox::SandboxHost;
pub(crate) use sandbox::{SandboxProcess, SandboxSource, SnapshotImage};
pub use transport::ProcessStartup;
#[cfg(target_os = "windows")]
pub use vm_authority::VmHostAuthorization;
pub use vm_authority::{VmAuthority, VmBackend};
pub(crate) use vm_authority::{current_vm_backend, take_installed_for_vm};

/// Requested Windows sandbox-host containment. Runtime permission is separate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WindowsSandboxHostPolicy {
    /// Requires AppContainer containment.
    #[default]
    AppContainer,
    /// Runs a VM-owning sandbox host outside AppContainer on Windows.
    ///
    /// This is compatible with Windows Hypervisor Platform. Job and resource
    /// limits remain. There is no AppContainer filesystem or network boundary.
    /// Function workers and non-Windows hosts cannot use this.
    Trusted,
}

impl serde::Serialize for WindowsSandboxHostPolicy {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(match self {
            Self::AppContainer => "app_container",
            Self::Trusted => "trusted",
        })
    }
}

impl<'de> serde::Deserialize<'de> for WindowsSandboxHostPolicy {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <String as serde::Deserialize>::deserialize(deserializer)?.as_str() {
            "app_container" => Ok(Self::AppContainer),
            "trusted" => Ok(Self::Trusted),
            "windows_vm_host" => Ok(Self::Trusted),
            value => Err(serde::de::Error::unknown_variant(
                value,
                &["app_container", "trusted", "windows_vm_host"],
            )),
        }
    }
}

impl WindowsSandboxHostPolicy {
    /// Plain-language name for the legacy [`Self::Trusted`] variant.
    #[allow(non_upper_case_globals)]
    pub const WindowsVmHost: Self = Self::Trusted;

    pub(crate) fn is_windows_vm_host(self) -> bool {
        self == Self::Trusted
    }
}

/// A trusted declaration about repeating a function's effects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Idempotency {
    /// No replay permission has been declared.
    #[default]
    Unspecified,
    /// Repeating an executed call can change its effects.
    NonIdempotent,
    /// The implementation permits replay after an uncertain execution outcome.
    Idempotent,
}

/// Shared guest ABI and replay metadata, independent of process placement.
#[derive(Debug)]
pub struct HostFunctionContract<Args, Output> {
    definition: FunctionDefinition,
    types: PhantomData<fn(Args) -> Output>,
}

impl<A, O> Copy for HostFunctionContract<A, O> {}

impl<A, O> Clone for HostFunctionContract<A, O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: ParameterTuple, O: SupportedReturnType> HostFunctionContract<A, O> {
    /// The declaration must come from trusted registration, not guest input.
    pub const fn new(name: &'static str, idempotency: Idempotency) -> Self {
        Self {
            definition: FunctionDefinition {
                name,
                parameters: A::TYPE,
                output: O::TYPE,
                idempotency,
            },
            types: PhantomData,
        }
    }

    /// Erases Rust parameter types for pre-resource bootstrap validation.
    pub const fn erase(self) -> ProcessHostFunctionContract {
        ProcessHostFunctionContract {
            definition: self.definition,
        }
    }

    /// A possibly executed call may replay only with explicit idempotency.
    pub fn permits_replay(&self, outcome: DispatchOutcome) -> bool {
        outcome == DispatchOutcome::NotDispatched
            || self.definition.idempotency == Idempotency::Idempotent
    }
}

/// Type-erased trusted host-function declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessHostFunctionContract {
    definition: FunctionDefinition,
}

/// What the dispatcher can establish about a failed call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// The dispatcher has proof the call was never dispatched.
    NotDispatched,
    /// Execution may have occurred, including when an acknowledgment is missing.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FunctionDefinition {
    name: &'static str,
    parameters: &'static [ParameterType],
    output: ReturnType,
    idempotency: Idempotency,
}

/// An OS-enforced process restriction, separate from guest VM sizing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessControl {
    /// A hard accounted memory budget in bytes.
    MemoryLimit(u64),
    /// An enforced CPU-time budget per scheduling period.
    CpuBudget {
        /// CPU time available during each period.
        quota: Duration,
        /// Scheduling period.
        period: Duration,
    },
    /// Deny network access.
    DenyNetwork,
    /// Deny creating child processes.
    DenyChildProcesses,
}

/// One requested control and whether omission prevents startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedControl {
    /// The requested restriction.
    pub control: ProcessControl,
    /// Required controls must be enforceable before guest initialization.
    pub required: bool,
}

/// Immutable process-wide restrictions once assigned to a process.
#[derive(Clone, Debug)]
pub struct ProcessProfile {
    controls: Vec<RequestedControl>,
    windows_cpu_rate_limit_percent: Option<u8>,
    unrestricted: bool,
}

impl ProcessProfile {
    /// Empty profiles are rejected rather than launching an unrestricted process.
    pub fn new(controls: impl IntoIterator<Item = RequestedControl>) -> Self {
        Self {
            controls: controls.into_iter().collect(),
            windows_cpu_rate_limit_percent: None,
            unrestricted: false,
        }
    }

    /// Runs as the caller with no process restrictions.
    pub fn unrestricted() -> Self {
        Self {
            controls: Vec::new(),
            windows_cpu_rate_limit_percent: None,
            unrestricted: true,
        }
    }

    /// Whether this profile intentionally requests no process restrictions.
    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    /// Adds a Windows Job Object CPU cap to a profile with required controls.
    ///
    /// The percentage is aggregate processor capacity available to the host.
    /// Other platforms reject this Windows-specific profile setting.
    pub fn windows_cpu_rate_limit_percent(mut self, percent: u8) -> Result<Self> {
        if self.unrestricted {
            return Err(new_error!(
                "Unrestricted process profiles cannot include platform limits"
            ));
        }
        if self.windows_cpu_rate_limit_percent.is_some() {
            return Err(new_error!(
                "A process profile contains duplicate Windows CPU rate controls"
            ));
        }
        if !(1..=100).contains(&percent) {
            return Err(new_error!("CPU rate limit must be 1 through 100 percent"));
        }
        self.windows_cpu_rate_limit_percent = Some(percent);
        Ok(self)
    }

    pub(crate) fn windows_cpu_rate_percent(&self) -> Option<u8> {
        self.windows_cpu_rate_limit_percent
    }

    fn validate(&self) -> Result<()> {
        if self.unrestricted {
            if !self.controls.is_empty() || self.windows_cpu_rate_limit_percent.is_some() {
                return Err(new_error!(
                    "Unrestricted process profiles cannot include controls or platform limits"
                ));
            }
            return Ok(());
        }
        if !self.controls.iter().any(|control| control.required) {
            return Err(new_error!(
                "A process profile needs a required process control; the Windows CPU rate setting supplements those controls"
            ));
        }
        let mut kinds = std::collections::HashSet::new();
        for request in &self.controls {
            if !kinds.insert(std::mem::discriminant(&request.control)) {
                return Err(new_error!("A process profile contains duplicate controls"));
            }
            match &request.control {
                ProcessControl::MemoryLimit(0) => {
                    return Err(new_error!("A process memory limit must be nonzero"));
                }
                ProcessControl::CpuBudget { quota, period }
                    if quota.is_zero() || period.is_zero() =>
                {
                    return Err(new_error!("CPU quota and period must be nonzero"));
                }
                _ => {}
            }
        }
        if matches!(self.windows_cpu_rate_limit_percent, Some(0 | 101..)) {
            return Err(new_error!("CPU rate limit must be 1 through 100 percent"));
        }
        Ok(())
    }
}

/// Immutable program identity and restrictions for one sandbox-owned process.
#[derive(Clone, Debug)]
pub struct ProcessOptions {
    name: String,
    program: Option<program::ProgramArtifact>,
    profile: ProcessProfile,
    windows_sandbox_host_policy: WindowsSandboxHostPolicy,
}

impl ProcessOptions {
    /// Uses a prepackaged program for this process placement.
    pub fn new(
        name: impl Into<String>,
        program: program::ProgramArtifact,
        profile: ProcessProfile,
    ) -> Self {
        Self {
            name: name.into(),
            program: Some(program),
            profile,
            windows_sandbox_host_policy: WindowsSandboxHostPolicy::default(),
        }
    }

    /// Requests provider-owned program packaging for this process placement.
    pub fn for_provider(name: impl Into<String>, profile: ProcessProfile) -> Self {
        Self {
            name: name.into(),
            program: None,
            profile,
            windows_sandbox_host_policy: WindowsSandboxHostPolicy::default(),
        }
    }

    /// Supplies a prepackaged program for qualification or custom embedders.
    ///
    /// This is an explicit alias for [`Self::new`]. Normal applications should
    /// use [`Self::for_provider`] and let the
    /// [`MeshProcessProvider`] own program packaging.
    pub fn with_program_artifact(
        name: impl Into<String>,
        program: program::ProgramArtifact,
        profile: ProcessProfile,
    ) -> Self {
        Self::new(name, program, profile)
    }

    /// Records a containment request. A Windows VM host also needs builder permission.
    pub fn windows_sandbox_host_policy(mut self, policy: WindowsSandboxHostPolicy) -> Self {
        self.windows_sandbox_host_policy = policy;
        self
    }

    /// Selects the ordinary non-elevated Windows VM-host boundary.
    ///
    /// Use [`crate::SandboxBuilder::windows_vm_host_process`] to authorize and
    /// configure a new VM host in one operation.
    pub fn windows_vm_host(mut self) -> Self {
        self.windows_sandbox_host_policy = WindowsSandboxHostPolicy::Trusted;
        self
    }

    fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.chars().any(char::is_control) {
            return Err(new_error!(
                "Process name must be nonempty and contain no control characters"
            ));
        }
        self.profile.validate()
    }
}

/// Functions that share one process and its authority.
#[derive(Debug)]
pub struct HostFunctionProcess {
    options: ProcessOptions,
    functions: Vec<FunctionDefinition>,
}

impl HostFunctionProcess {
    /// Each configured instance belongs to one sandbox, never a global pool.
    pub fn new(options: ProcessOptions) -> Self {
        Self {
            options,
            functions: Vec::new(),
        }
    }

    /// Assigns a shared contract to this process.
    pub fn function<A: ParameterTuple, O: SupportedReturnType>(
        mut self,
        contract: HostFunctionContract<A, O>,
    ) -> Self {
        self.functions.push(contract.definition);
        self
    }

    /// Checks executable-local registrations without executing implementations.
    pub fn validate_registrations(&self, registrations: &ProcessHostFunctions) -> Result<()> {
        self.options.validate()?;
        let mut expected = BTreeMap::new();
        for definition in &self.functions {
            insert_definition(&mut expected, *definition)?;
        }
        if expected != registrations.contracts {
            return Err(new_error!(
                "Host-function contracts do not match process '{}'",
                self.options.name
            ));
        }
        Ok(())
    }
}

/// Executable-local implementations for one declared process manifest.
pub struct ProcessHostFunctions {
    functions: HostFunctions,
    contracts: BTreeMap<&'static str, FunctionDefinition>,
}

impl Default for ProcessHostFunctions {
    fn default() -> Self {
        Self {
            functions: HostFunctions::empty(),
            contracts: BTreeMap::new(),
        }
    }
}

impl ProcessHostFunctions {
    /// Duplicate registration fails without replacing the original binding.
    pub fn bind<A: ParameterTuple, O: SupportedReturnType>(
        &mut self,
        contract: HostFunctionContract<A, O>,
        implementation: impl Into<HostFunction<O, A>>,
    ) -> Result<()> {
        use crate::func::Registerable;

        if contract.definition.name.is_empty() {
            return Err(new_error!("A host-function name must be nonempty"));
        }
        if self.contracts.contains_key(contract.definition.name) {
            return Err(new_error!(
                "Duplicate host-function owner for '{}'",
                contract.definition.name
            ));
        }
        self.functions
            .register_host_function(contract.definition.name, implementation)?;
        insert_definition(&mut self.contracts, contract.definition)
    }
}

fn insert_definition(
    definitions: &mut BTreeMap<&'static str, FunctionDefinition>,
    definition: FunctionDefinition,
) -> Result<()> {
    if definition.name.is_empty() {
        return Err(new_error!("A host-function name must be nonempty"));
    }
    match definitions.entry(definition.name) {
        Entry::Occupied(_) => Err(new_error!(
            "Duplicate host-function owner for '{}'",
            definition.name
        )),
        Entry::Vacant(entry) => {
            entry.insert(definition);
            Ok(())
        }
    }
}

#[derive(Default)]
pub(crate) struct Topology {
    sandbox: Option<ProcessOptions>,
    sandbox_functions: Vec<FunctionDefinition>,
    functions: Vec<HostFunctionProcess>,
    duplicate_sandbox: bool,
    pub(crate) provider: Option<MeshProcessProvider>,
    pub(crate) programs: Option<(program::LocalProgramStore, program::ProgramTarget)>,
    pub(crate) restart_policy: RestartPolicy,
    pub(crate) allow_windows_vm_host: bool,
    #[cfg(target_os = "linux")]
    pub(crate) linux_resources: Option<LinuxProcessResources>,
}

impl Topology {
    pub(crate) fn definition(&self) -> Result<program::ProcessTopologyDefinition> {
        let sandbox = self
            .sandbox
            .as_ref()
            .map(|options| {
                let functions = self
                    .sandbox_functions
                    .iter()
                    .map(program::FunctionContractDefinition::from_definition)
                    .collect::<Vec<_>>();
                program::ProcessDefinition::new(
                    &options.name,
                    self.resolve_program(
                        &options.name,
                        program::ProgramRole::SandboxHost,
                        &functions,
                        options.program.as_ref(),
                    )?,
                    &options.profile,
                    functions,
                )
                .map(|definition| {
                    definition.with_windows_sandbox_host_policy(options.windows_sandbox_host_policy)
                })
            })
            .transpose()?;
        let workers = self
            .functions
            .iter()
            .map(|worker| {
                let functions = worker
                    .functions
                    .iter()
                    .map(program::FunctionContractDefinition::from_definition)
                    .collect::<Vec<_>>();
                program::ProcessDefinition::new(
                    &worker.options.name,
                    self.resolve_program(
                        &worker.options.name,
                        program::ProgramRole::FunctionWorker,
                        &functions,
                        worker.options.program.as_ref(),
                    )?,
                    &worker.options.profile,
                    functions,
                )
                .map(|definition| {
                    definition.with_windows_sandbox_host_policy(
                        worker.options.windows_sandbox_host_policy,
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        program::ProcessTopologyDefinition::new(sandbox, workers)
    }

    pub(crate) fn configured_definition(
        &self,
        expected: Option<&program::ProcessTopologyDefinition>,
        local: &HostFunctions,
    ) -> Result<Option<program::ProcessTopologyDefinition>> {
        self.validate(local)?;
        let declared = if self.sandbox.is_some() || !self.functions.is_empty() {
            Some(self.definition()?)
        } else {
            None
        };
        let definition = match (expected, declared) {
            (Some(expected), Some(declared)) if expected != &declared => {
                return Err(new_error!(
                    "Snapshot process topology does not match placement"
                ));
            }
            (_, Some(declared)) => declared,
            (Some(expected), None) => expected.clone(),
            (None, None) => return Ok(None),
        };
        for function in definition
            .sandbox()
            .into_iter()
            .chain(definition.workers())
            .flat_map(|process| process.functions())
        {
            if local.inner().function_signature(function.name()).is_some() {
                return Err(new_error!(
                    "Snapshot process topology conflicts with local host function '{}'",
                    function.name()
                ));
            }
        }
        self.authorize(&definition)?;
        Ok(Some(definition))
    }

    fn authorize(&self, definition: &program::ProcessTopologyDefinition) -> Result<()> {
        definition.validate()?;
        if definition
            .sandbox()
            .is_some_and(|sandbox| sandbox.windows_sandbox_host_policy().is_windows_vm_host())
        {
            if !self.allow_windows_vm_host {
                return Err(new_error!(
                    "Windows VM host requires explicit runtime permission. Use \
                     SandboxBuilder::windows_vm_host_process for a new sandbox or \
                     SandboxBuilder::allow_windows_vm_host when loading a snapshot"
                ));
            }
            if !cfg!(target_os = "windows") {
                return Err(new_error!(
                    "Windows VM host process placement is supported only on Windows"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn resolve(
        self,
        definition: program::ProcessTopologyDefinition,
    ) -> Result<ResolvedTopology> {
        self.authorize(&definition)?;
        let provider = self.provider()?;
        let launcher = provider.launcher(&definition)?;
        Ok(ResolvedTopology {
            definition,
            launcher,
            policy: self.restart_policy,
        })
    }

    fn provider(&self) -> Result<MeshProcessProvider> {
        if let Some(provider) = &self.provider {
            return Ok(provider.clone());
        }
        if let Some((store, target)) = &self.programs {
            let provider = MeshProcessProvider::from_local_programs(store.clone(), target.clone())?;
            #[cfg(target_os = "linux")]
            let provider = match &self.linux_resources {
                Some(resources) => provider.with_linux_resources(resources.clone())?,
                None => provider,
            };
            return Ok(provider);
        }
        Err(new_error!(
            "Process placement requires a MeshProcessProvider capability"
        ))
    }

    fn resolve_program(
        &self,
        name: &str,
        role: program::ProgramRole,
        functions: &[program::FunctionContractDefinition],
        artifact: Option<&program::ProgramArtifact>,
    ) -> Result<program::ProgramArtifact> {
        match artifact {
            Some(artifact) => Ok(artifact.clone()),
            None => self
                .provider()?
                .resolve_program(name, role, functions, None),
        }
    }

    pub(crate) fn sandbox(&mut self, process: ProcessOptions) {
        self.duplicate_sandbox |= self.sandbox.is_some();
        self.sandbox = Some(process);
    }

    pub(crate) fn functions(&mut self, process: HostFunctionProcess) {
        self.functions.push(process);
    }

    pub(crate) fn sandbox_function<A: ParameterTuple, O: SupportedReturnType>(
        &mut self,
        contract: HostFunctionContract<A, O>,
    ) {
        self.sandbox_functions.push(contract.definition);
    }

    pub(crate) fn validate(&self, local: &HostFunctions) -> Result<()> {
        if self.duplicate_sandbox {
            return Err(new_error!("A sandbox can have only one process placement"));
        }
        let mut process_names = std::collections::BTreeSet::new();
        if self.sandbox.is_none() && !self.sandbox_functions.is_empty() {
            return Err(new_error!(
                "Sandbox-host contracts require dedicated sandbox placement"
            ));
        }
        if let Some(sandbox) = &self.sandbox {
            sandbox.validate()?;
            process_names.insert(sandbox.name.as_str());
        }
        let mut functions = BTreeMap::new();
        for definition in &self.sandbox_functions {
            insert_definition(&mut functions, *definition)?;
        }
        for process in &self.functions {
            process.options.validate()?;
            if !process_names.insert(process.options.name.as_str()) {
                return Err(new_error!(
                    "Duplicate process name '{}'",
                    process.options.name
                ));
            }
            if process.functions.is_empty() {
                return Err(new_error!(
                    "Host-function process '{}' has no functions",
                    process.options.name
                ));
            }
            for definition in &process.functions {
                insert_definition(&mut functions, *definition)?;
                if local.inner().function_signature(definition.name).is_some() {
                    return Err(new_error!(
                        "Duplicate local/process owner for '{}'",
                        definition.name
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct ResolvedTopology {
    definition: program::ProcessTopologyDefinition,
    launcher: std::sync::Arc<dyn launch::ProcessLauncher>,
    policy: RestartPolicy,
}

impl ResolvedTopology {
    pub(crate) fn start_local(self, local: &mut HostFunctions) -> Result<()> {
        runtime::start_with_policy(self.definition, self.launcher, local, self.policy)
    }

    pub(crate) fn start_sandbox(
        self,
        source: SandboxSource,
        settings: &crate::sandbox::SandboxConfiguration,
        init_data: Option<(Vec<u8>, crate::mem::memory_region::MemoryRegionFlags)>,
    ) -> Result<crate::MultiUseSandbox> {
        let contracts = self
            .definition
            .sandbox()
            .ok_or_else(|| new_error!("Missing sandbox process placement"))?
            .functions()
            .to_vec();
        SandboxProcess::launch(
            self.definition,
            self.launcher,
            self.policy,
            source,
            settings,
            init_data,
            contracts,
        )
    }
}

#[cfg(test)]
mod tests;
