// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Mesh/PAL process-placement authority.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::launch::{ConfiguredLauncher, ProcessLauncher};
use super::program::{
    FunctionContractDefinition, LocalProgramStore, ProcessTopologyDefinition, ProgramArtifact,
    ProgramConfig, ProgramFile, ProgramRole, ProgramTarget,
};
use super::resource::{
    ExportAuthority, ExportedFile, LaunchResourceFactory, OsResourceExportPolicy, OsResourceRights,
    RegisteredResource, ResourceExportSink, ResourceId, WireExportFile,
    validate_file_contains_rights, validate_file_rights,
};
use crate::{Result, new_error};

pub(super) const MAX_PROGRAM_BYTES: u64 = 256 * 1024 * 1024;

/// Mesh-owned authority for packaging and launching constrained native processes.
///
/// Applications pass this opaque capability to [`crate::SandboxBuilder`].
/// Platform confinement details and host authority do not enter snapshots.
#[derive(Clone)]
pub struct MeshProcessProvider {
    inner: Arc<Provider>,
}

pub(super) struct Provider {
    store: LocalProgramStore,
    target: ProgramTarget,
    current_program: Option<ProgramSource>,
    programs: std::collections::BTreeMap<String, ProgramSource>,
    resource_session: u128,
    next_resource_slot: AtomicU32,
    pub(super) resource_generation: Arc<AtomicU64>,
    pub(super) resources: std::collections::BTreeMap<String, Vec<RegisteredResource>>,
    exports: Mutex<ExportState>,
    #[cfg(target_os = "linux")]
    linux: Option<super::LinuxProcessResources>,
    #[cfg(target_os = "linux")]
    linux_discovery_error: Option<String>,
    _temporary_store: Option<Arc<tempfile::TempDir>>,
}

#[derive(Default)]
struct ExportState {
    policies: std::collections::BTreeMap<String, OsResourceExportPolicy>,
    pending: std::collections::BTreeMap<String, std::collections::VecDeque<ExportedFile>>,
    active_generations: std::collections::BTreeMap<String, u64>,
    last_generations: std::collections::BTreeMap<String, u64>,
}

struct ProgramSource {
    executable: Vec<u8>,
    _runtime_files: Vec<ProgramFile>,
    _captured_executable: PathBuf,
    #[cfg(target_os = "linux")]
    _capture_root: PathBuf,
    _capture: tempfile::TempDir,
}

#[derive(Debug)]
pub(super) struct CapturedFile {
    pub bytes: Vec<u8>,
    pub permissions: std::fs::Permissions,
}

impl std::fmt::Debug for MeshProcessProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshProcessProvider")
            .field("target", &self.inner.target)
            .finish_non_exhaustive()
    }
}

impl MeshProcessProvider {
    /// Discovers the current host's Mesh/PAL process-placement capability.
    ///
    /// Linux restricted profiles require operator-delegated authority. macOS
    /// accepts unrestricted profiles and rejects restricted profiles.
    pub fn discover() -> Result<Self> {
        Self::discover_with_store(None)
    }

    /// Reauthorizes a loaded snapshot against the current host.
    ///
    /// `layout` supplies immutable program artifacts only. Host authority is
    /// discovered again and is never taken from the snapshot.
    pub fn discover_for_snapshot(layout: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::discover_with_store(Some(LocalProgramStore::new(layout.as_ref())))
    }

    fn discover_with_store(store: Option<LocalProgramStore>) -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        {
            let snapshot_store = store.is_some();
            let (store, temporary_store) = match store {
                Some(store) => (store, None),
                None => {
                    let directory = Arc::new(
                        tempfile::Builder::new()
                            .prefix("hyperlight-mesh-programs-")
                            .tempdir()?,
                    );
                    (LocalProgramStore::new(directory.path()), Some(directory))
                }
            };
            let current_program = (!snapshot_store)
                .then(|| {
                    let executable = std::env::current_exe().map_err(|error| {
                        new_error!("Mesh provider cannot locate this executable: {error}")
                    })?;
                    program_source(&executable)
                })
                .transpose()?;
            #[cfg(target_os = "linux")]
            let (linux, linux_discovery_error) = match super::linux::discover_provider() {
                Ok(resources) => (Some(resources), None),
                Err(error) => (None, Some(error.to_string())),
            };
            Ok(Self {
                inner: Arc::new(Provider {
                    store,
                    target: ProgramTarget::current(Default::default()),
                    current_program,
                    programs: Default::default(),
                    resource_session: uuid::Uuid::new_v4().as_u128(),
                    next_resource_slot: AtomicU32::new(0),
                    resource_generation: Arc::new(AtomicU64::new(1)),
                    resources: Default::default(),
                    exports: Default::default(),
                    #[cfg(target_os = "linux")]
                    linux,
                    #[cfg(target_os = "linux")]
                    linux_discovery_error,
                    _temporary_store: temporary_store,
                }),
            })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            let _ = store;
            Err(new_error!(
                "Mesh process placement is unavailable on this host"
            ))
        }
    }

    /// Builds a provider from explicit local resources for qualification or embedders.
    pub fn from_local_programs(store: LocalProgramStore, target: ProgramTarget) -> Result<Self> {
        {
            if target != ProgramTarget::current(target.os_dependencies.clone()) {
                return Err(new_error!(
                    "Program execution target must match the current host"
                ));
            }
            Ok(Self {
                inner: Arc::new(Provider {
                    store,
                    target,
                    current_program: None,
                    programs: Default::default(),
                    resource_session: uuid::Uuid::new_v4().as_u128(),
                    next_resource_slot: AtomicU32::new(0),
                    resource_generation: Arc::new(AtomicU64::new(1)),
                    resources: Default::default(),
                    exports: Default::default(),
                    #[cfg(target_os = "linux")]
                    linux: None,
                    #[cfg(target_os = "linux")]
                    linux_discovery_error: Some(
                        "Linux process resources were not configured".to_owned(),
                    ),
                    _temporary_store: None,
                }),
            })
        }
    }

    /// Adds explicit Linux launch authority for qualification or custom embedders.
    #[cfg(target_os = "linux")]
    pub fn with_linux_resources(mut self, resources: super::LinuxProcessResources) -> Result<Self> {
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Configure Linux resources before cloning the provider"))?;
        provider.linux = Some(resources);
        provider.linux_discovery_error = None;
        Ok(self)
    }

    /// Registers a dedicated executable while the provider owns its packaging.
    ///
    /// The logical name must match the corresponding [`super::ProcessOptions`].
    pub fn with_program(
        mut self,
        name: impl Into<String>,
        executable: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        if self.inner._temporary_store.is_none() {
            return Err(new_error!(
                "A snapshot provider cannot package new native programs"
            ));
        }
        let name = name.into();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(new_error!(
                "Provider program name must be nonempty and contain no control characters"
            ));
        }
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider programs before cloning the provider"))?;
        if provider.programs.contains_key(&name) {
            return Err(new_error!("Duplicate provider program '{name}'"));
        }
        let source = program_source(executable.as_ref())?;
        provider.programs.insert(name, source);
        Ok(self)
    }

    /// Moves an already-open file capability into one function worker.
    ///
    /// The resource belongs to this provider session. It is not stored in
    /// snapshots and must be registered again for reconstruction.
    #[allow(deprecated)]
    pub fn register_file(
        &mut self,
        process_name: impl Into<String>,
        file: File,
        rights: OsResourceRights,
    ) -> Result<()> {
        validate_file_rights(&file, rights)?;
        let process_name = process_name.into();
        if process_name.is_empty() || process_name.chars().any(char::is_control) {
            return Err(new_error!(
                "Resource process name must be nonempty and contain no control characters"
            ));
        }
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register process resources before cloning the provider"))?;
        let slot = provider
            .next_resource_slot
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slot| {
                slot.checked_add(1)
            })
            .map_err(|_| new_error!("Too many process resources"))?;
        let resources = provider.resources.entry(process_name).or_default();
        let id = ResourceId::new(provider.resource_session, slot, 0);
        resources.push(RegisteredResource::file(id, file, rights));
        Ok(())
    }

    /// Authorizes one function worker generation to create one VM.
    ///
    /// Linux opens a fresh backend device descriptor after each generation is
    /// reserved. Windows transfers an authenticated no-handle authorization
    /// marker and selects the ordinary same-user principal for this worker.
    pub fn register_vm_authority(
        &mut self,
        process_name: impl Into<String>,
        backend: super::VmBackend,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        let device = self
            .inner
            .linux
            .as_ref()
            .and_then(|resources| resources.vm_authority_device(backend))
            .map(std::path::Path::to_owned)
            .ok_or_else(|| new_error!("Linux VM authority device is unavailable"))?;
        let (metadata, factory) = super::vm_authority::registration(
            backend,
            #[cfg(target_os = "linux")]
            device,
        )?;
        self.register_typed(
            process_name,
            super::vm_authority::VM_AUTHORITY_RESOURCE_KIND,
            metadata,
            factory,
        )
    }

    #[allow(dead_code, deprecated)]
    pub(crate) fn register_typed(
        &mut self,
        process_name: impl Into<String>,
        kind: u32,
        metadata: Vec<u8>,
        factory: Arc<dyn LaunchResourceFactory>,
    ) -> Result<()> {
        let process_name = process_name.into();
        if process_name.is_empty() || process_name.chars().any(char::is_control) {
            return Err(new_error!(
                "Resource process name must be nonempty and contain no control characters"
            ));
        }
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register process resources before cloning the provider"))?;
        let slot = provider
            .next_resource_slot
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slot| {
                slot.checked_add(1)
            })
            .map_err(|_| new_error!("Too many process resources"))?;
        let id = ResourceId::new(provider.resource_session, slot, 0);
        let resource = RegisteredResource::typed(id, kind, metadata, factory)?;
        provider
            .resources
            .entry(process_name)
            .or_default()
            .push(resource);
        Ok(())
    }

    /// Authorizes bounded file-capability exports from one function worker.
    pub fn allow_file_exports(
        &mut self,
        process_name: impl Into<String>,
        policy: OsResourceExportPolicy,
    ) -> Result<()> {
        let process_name = process_name.into();
        if process_name.is_empty() || process_name.chars().any(char::is_control) {
            return Err(new_error!(
                "Export process name must be nonempty and contain no control characters"
            ));
        }
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Configure resource exports before cloning the provider"))?;
        let policies = &mut provider
            .exports
            .get_mut()
            .map_err(|error| new_error!("Resource export lock failed: {error}"))?
            .policies;
        if policies.contains_key(&process_name) {
            return Err(new_error!(
                "Duplicate resource export policy for '{process_name}'"
            ));
        }
        policies.insert(process_name, policy);
        Ok(())
    }

    /// Takes the oldest pending file exported by one function worker.
    pub fn take_exported_file(&self, process_name: &str) -> Result<Option<ExportedFile>> {
        let mut exports = self
            .inner
            .exports
            .lock()
            .map_err(|error| new_error!("Resource export lock failed: {error}"))?;
        Ok(exports
            .pending
            .get_mut(process_name)
            .and_then(std::collections::VecDeque::pop_front))
    }

    /// Adds one verified runtime file to the default application executable.
    ///
    /// Use this for application-local files that automatic platform discovery
    /// cannot identify. The image path is relative to the staged program root.
    #[cfg(target_os = "windows")]
    pub fn with_runtime_file(
        mut self,
        image_path: impl AsRef<std::path::Path>,
        source: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let files = runtime_files(image_path.as_ref(), source.as_ref())?;
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider runtime files before cloning it"))?;
        let program = provider.current_program.as_mut().ok_or_else(|| {
            new_error!("This provider cannot add files to the application program")
        })?;
        for file in files {
            add_runtime_file(program, file)?;
        }
        Ok(self)
    }

    /// Adds one verified runtime file to a named dedicated executable.
    #[cfg(target_os = "windows")]
    pub fn with_program_runtime_file(
        mut self,
        name: &str,
        image_path: impl AsRef<std::path::Path>,
        source: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        let files = runtime_files(image_path.as_ref(), source.as_ref())?;
        let provider = Arc::get_mut(&mut self.inner)
            .ok_or_else(|| new_error!("Register provider runtime files before cloning it"))?;
        let program = provider
            .programs
            .get_mut(name)
            .ok_or_else(|| new_error!("Unknown provider program '{name}'"))?;
        for file in files {
            add_runtime_file(program, file)?;
        }
        Ok(self)
    }

    pub(crate) fn resolve_program(
        &self,
        name: &str,
        role: ProgramRole,
        functions: &[FunctionContractDefinition],
        artifact: Option<&ProgramArtifact>,
    ) -> Result<ProgramArtifact> {
        if let Some(artifact) = artifact {
            self.inner.store.validate(artifact, &self.inner.target)?;
            return Ok(artifact.clone());
        }
        let source = self
            .inner
            .programs
            .get(name)
            .or(self.inner.current_program.as_ref())
            .ok_or_else(|| {
                new_error!("This MeshProcessProvider requires an explicit program artifact")
            })?;
        #[cfg(target_os = "linux")]
        let runtime_files =
            super::linux::runtime_closure_in(&source._captured_executable, &source._capture_root)
                .map_err(|error| {
                new_error!("Mesh provider cannot package native program '{name}': {error}")
            })?;
        #[cfg(target_os = "windows")]
        let runtime_files =
            super::windows::runtime_closure(&source.executable, &source._runtime_files).map_err(
                |error| new_error!("Mesh provider cannot package native program '{name}': {error}"),
            )?;
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let runtime_files = source._runtime_files.clone();
        self.inner.store.package_with_runtime(
            &ProgramConfig {
                schema_version: 1,
                role,
                target: self.inner.target.clone(),
                functions: functions.to_vec(),
            },
            &source.executable,
            &runtime_files,
        )
    }

    pub(super) fn launcher(
        &self,
        definition: &ProcessTopologyDefinition,
    ) -> Result<Arc<dyn ProcessLauncher>> {
        definition.validate_programs(&self.inner.store, &self.inner.target)?;
        validate_resource_owners(
            &self.inner.resources,
            definition.workers().iter().map(|worker| worker.name()),
        )?;
        validate_resource_owners(
            &self
                .inner
                .exports
                .lock()
                .map_err(|error| new_error!("Resource export lock failed: {error}"))?
                .policies,
            definition.workers().iter().map(|worker| worker.name()),
        )?;
        #[cfg(target_os = "windows")]
        let authorized_workers = {
            let mut authorized = std::collections::BTreeSet::new();
            for (name, resources) in &self.inner.resources {
                let mut backends = Vec::new();
                for resource in resources {
                    let (kind, metadata) = resource.kind_and_metadata();
                    if let Some(backend) = super::vm_authority::registered_backend(kind, metadata)?
                    {
                        backends.push(backend);
                    }
                }
                if backends.is_empty() {
                    continue;
                }
                if backends != [super::VmBackend::Whp] {
                    return Err(new_error!(
                        "Windows worker VM authorization must contain exactly one WHP marker"
                    ));
                }
                authorized.insert(name.clone());
            }
            authorized
        };
        Ok(Arc::new(ConfiguredLauncher {
            store: self.inner.store.clone(),
            target: self.inner.target.clone(),
            #[cfg(target_os = "windows")]
            windows: super::windows::WindowsPrincipals::new(definition, &authorized_workers)?,
            #[cfg(target_os = "linux")]
            linux: self.inner.linux.clone(),
            #[cfg(target_os = "linux")]
            linux_discovery_error: self.inner.linux_discovery_error.clone(),
            _provider: self.inner.clone(),
        }))
    }
}

impl Provider {
    pub(super) fn export_authority(
        self: &Arc<Self>,
        process_name: &str,
    ) -> Result<Option<ExportAuthority>> {
        let exports = self
            .exports
            .lock()
            .map_err(|error| new_error!("Resource export lock failed: {error}"))?;
        Ok(exports
            .policies
            .get(process_name)
            .copied()
            .map(|policy| ExportAuthority::new(process_name.to_owned(), policy, self.clone())))
    }
}

impl ResourceExportSink for Provider {
    fn begin_generation(&self, process_name: &str, generation: u64) -> Result<()> {
        if generation == 0 {
            return Err(new_error!("Resource export generation is invalid"));
        }
        let mut exports = self
            .exports
            .lock()
            .map_err(|error| new_error!("Resource export lock failed: {error}"))?;
        if !exports.policies.contains_key(process_name) {
            return Err(new_error!("Resource export is not authorized"));
        }
        if exports.active_generations.contains_key(process_name) {
            return Err(new_error!("Resource export generation is already active"));
        }
        if exports
            .last_generations
            .get(process_name)
            .is_some_and(|last| generation <= *last)
        {
            return Err(new_error!("Resource export generation is stale"));
        }
        exports.pending.remove(process_name);
        exports
            .last_generations
            .insert(process_name.to_owned(), generation);
        exports
            .active_generations
            .insert(process_name.to_owned(), generation);
        Ok(())
    }

    #[allow(deprecated)]
    fn accept_file(
        &self,
        process_name: &str,
        generation: u64,
        file: WireExportFile,
    ) -> Result<ResourceId> {
        if generation == 0 || file.kind != 1 {
            return Err(new_error!("Resource export kind or generation is invalid"));
        }
        let rights = OsResourceRights::from_bits(file.rights)
            .filter(|rights| !rights.is_empty())
            .ok_or_else(|| new_error!("Resource export rights are invalid"))?;
        validate_file_contains_rights(&file.file, rights)?;
        let mut exports = self
            .exports
            .lock()
            .map_err(|error| new_error!("Resource export lock failed: {error}"))?;
        let policy = exports
            .policies
            .get(process_name)
            .copied()
            .ok_or_else(|| new_error!("Resource export is not authorized"))?;
        if exports.active_generations.get(process_name) != Some(&generation) {
            return Err(new_error!("Resource export generation is stale"));
        }
        if !policy.rights().contains(rights) {
            return Err(new_error!("Resource export rights exceed policy"));
        }
        if exports
            .pending
            .get(process_name)
            .is_some_and(|pending| pending.len() >= policy.max_pending())
        {
            return Err(new_error!("Resource export quota is exhausted"));
        }
        let slot = self
            .next_resource_slot
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |slot| {
                slot.checked_add(1)
            })
            .map_err(|_| new_error!("Resource export slots are exhausted"))?;
        let id = ResourceId::new(self.resource_session, slot, generation);
        exports
            .pending
            .entry(process_name.to_owned())
            .or_default()
            .push_back(ExportedFile::new(id, file.file, rights));
        Ok(id)
    }

    fn end_generation(&self, process_name: &str, generation: u64) {
        let Ok(mut exports) = self.exports.lock() else {
            tracing::error!("Resource export lock failed while ending generation");
            return;
        };
        if exports.active_generations.get(process_name) == Some(&generation) {
            exports.active_generations.remove(process_name);
            exports.pending.remove(process_name);
        }
    }
}

impl MeshProcessProvider {
    pub(crate) fn export_programs(
        &self,
        topology: &ProcessTopologyDefinition,
        destination: &LocalProgramStore,
    ) -> Result<()> {
        self.inner.store.export(&topology.programs(), destination)
    }
}

fn validate_resource_owners<'a, V>(
    resources: &std::collections::BTreeMap<String, V>,
    workers: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let workers: std::collections::BTreeSet<_> = workers.into_iter().collect();
    for process_name in resources.keys() {
        if !workers.contains(process_name.as_str()) {
            return Err(new_error!(
                "Process resource owner '{process_name}' is not a function worker"
            ));
        }
    }
    Ok(())
}

fn program_source(executable: &std::path::Path) -> Result<ProgramSource> {
    program_source_with(executable, |_| {})
}

fn program_source_with(
    executable: &Path,
    capture_hook: impl FnMut(CaptureStage),
) -> Result<ProgramSource> {
    let source = std::fs::canonicalize(executable).map_err(|error| {
        new_error!(
            "Mesh provider cannot resolve native program '{}': {error}",
            executable.display()
        )
    })?;
    let captured = capture_file_with(&source, capture_hook).map_err(|error| {
        new_error!(
            "Mesh provider cannot read native program '{}': {error}",
            source.display()
        )
    })?;
    let capture = tempfile::Builder::new()
        .prefix("hyperlight-program-capture-")
        .tempdir()?;
    #[cfg(target_os = "linux")]
    let capture_root = capture.path().join("root");
    #[cfg(target_os = "linux")]
    let captured_executable = {
        let relative = source
            .strip_prefix(Path::new("/"))
            .map_err(|_| new_error!("Native Linux program path must be absolute"))?;
        capture_root.join(relative)
    };
    #[cfg(not(target_os = "linux"))]
    let captured_executable = capture.path().join(
        source
            .file_name()
            .ok_or_else(|| new_error!("Native program path has no file name"))?,
    );
    #[cfg(target_os = "linux")]
    let capture_boundary = &capture_root;
    #[cfg(not(target_os = "linux"))]
    let capture_boundary = capture.path();
    if !captured_executable.starts_with(capture_boundary) {
        return Err(new_error!(
            "Captured native program path escaped provider-owned storage"
        ));
    }
    std::fs::create_dir_all(
        captured_executable
            .parent()
            .ok_or_else(|| new_error!("Captured native program has no parent directory"))?,
    )?;
    std::fs::write(&captured_executable, &captured.bytes)?;
    std::fs::set_permissions(&captured_executable, captured.permissions)?;
    #[cfg(target_os = "linux")]
    super::linux::capture_origin_dependencies(
        &captured.bytes,
        source.parent(),
        captured_executable
            .parent()
            .ok_or_else(|| new_error!("Captured native program has no parent directory"))?,
        &capture_root,
    )?;
    #[cfg(target_os = "linux")]
    let runtime_files = Vec::new();
    #[cfg(target_os = "windows")]
    let runtime_files =
        super::windows::capture_adjacent_dependencies(&captured.bytes, source.parent())?;
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let runtime_files = Vec::new();
    Ok(ProgramSource {
        executable: captured.bytes,
        _runtime_files: runtime_files,
        _captured_executable: captured_executable,
        #[cfg(target_os = "linux")]
        _capture_root: capture_root,
        _capture: capture,
    })
}

#[cfg(target_os = "windows")]
fn runtime_files(image_path: &Path, source: &Path) -> Result<Vec<ProgramFile>> {
    if image_path.is_absolute()
        || image_path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(new_error!(
            "Provider runtime image path must be relative and remain below the program root"
        ));
    }
    let image_path = format!("/{}", image_path.to_string_lossy().replace('\\', "/"));
    let captured = capture_file(source).map_err(|error| {
        new_error!(
            "Mesh provider cannot read runtime file '{}': {error}",
            source.display()
        )
    })?;
    Ok(vec![ProgramFile::new(image_path, captured.bytes)?])
}

pub(super) fn capture_file(path: &Path) -> Result<CapturedFile> {
    capture_file_with(path, |_| {})
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureStage {
    Opened,
    Read,
}

fn capture_file_with(path: &Path, capture_hook: impl FnMut(CaptureStage)) -> Result<CapturedFile> {
    capture_file_with_limit(path, MAX_PROGRAM_BYTES, capture_hook)
}

fn capture_file_with_limit(
    path: &Path,
    limit: u64,
    mut capture_hook: impl FnMut(CaptureStage),
) -> Result<CapturedFile> {
    let file = File::open(path)?;
    let permissions = file.metadata()?.permissions();
    capture_hook(CaptureStage::Opened);
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    capture_hook(CaptureStage::Read);
    if bytes.len() as u64 > limit {
        return Err(new_error!(
            "Native program file '{}' exceeds the 256 MiB limit",
            path.display()
        ));
    }
    Ok(CapturedFile { bytes, permissions })
}

#[cfg(target_os = "windows")]
fn add_runtime_file(program: &mut ProgramSource, file: ProgramFile) -> Result<()> {
    if program._runtime_files.len() >= 128 {
        return Err(new_error!(
            "Windows native program dependency closure exceeds 128 DLLs"
        ));
    }
    if program._runtime_files.iter().any(|existing| {
        existing
            .image_path()
            .eq_ignore_ascii_case(file.image_path())
    }) {
        return Err(new_error!(
            "Duplicate provider runtime image path '{}'",
            file.image_path()
        ));
    }
    program
        ._runtime_files
        .iter()
        .try_fold(program.executable.len(), |total, existing| {
            total.checked_add(existing.bytes().len())
        })
        .and_then(|total| total.checked_add(file.bytes().len()))
        .filter(|total| *total as u64 <= MAX_PROGRAM_BYTES)
        .ok_or_else(|| new_error!("Native program and runtime files exceed the 256 MiB limit"))?;
    program._runtime_files.push(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use super::*;
    use crate::process::ProcessResources;

    fn provider(packaging: bool) -> MeshProcessProvider {
        let directory = Arc::new(tempfile::tempdir().unwrap());
        MeshProcessProvider {
            inner: Arc::new(Provider {
                store: LocalProgramStore::new(directory.path()),
                target: ProgramTarget::current(Default::default()),
                current_program: None,
                programs: Default::default(),
                resource_session: uuid::Uuid::new_v4().as_u128(),
                next_resource_slot: AtomicU32::new(0),
                resource_generation: Arc::new(AtomicU64::new(1)),
                resources: Default::default(),
                exports: Default::default(),
                #[cfg(target_os = "linux")]
                linux: None,
                #[cfg(target_os = "linux")]
                linux_discovery_error: Some(
                    "Linux process resources were not configured".to_owned(),
                ),
                _temporary_store: packaging.then_some(directory),
            }),
        }
    }

    #[cfg(target_os = "windows")]
    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[cfg(target_os = "windows")]
    fn pe_fixture(imports: &[String], is_dll: bool) -> Vec<u8> {
        const PE: usize = 0x80;
        const OPTIONAL: usize = PE + 24;
        const SECTION: usize = OPTIONAL + 0xf0;
        const RAW: usize = 0x200;
        const RVA: u32 = 0x1000;
        let descriptors = (imports.len() + 1) * 20;
        let iat = descriptors.next_multiple_of(8);
        let names = iat + 8;
        let data_size = names + imports.iter().map(|name| name.len() + 1).sum::<usize>();
        let raw_size = data_size.next_multiple_of(0x200);
        let mut bytes = vec![0_u8; RAW + raw_size];
        bytes[..2].copy_from_slice(b"MZ");
        write_u32(&mut bytes, 0x3c, PE as u32);
        bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
        write_u16(&mut bytes, PE + 4, 0x8664);
        write_u16(&mut bytes, PE + 6, 1);
        write_u16(&mut bytes, PE + 20, 0xf0);
        write_u16(&mut bytes, PE + 22, if is_dll { 0x2022 } else { 0x0022 });
        write_u16(&mut bytes, OPTIONAL, 0x20b);
        write_u32(&mut bytes, OPTIONAL + 20, RVA);
        write_u64(&mut bytes, OPTIONAL + 24, 0x140000000);
        write_u32(&mut bytes, OPTIONAL + 32, 0x1000);
        write_u32(&mut bytes, OPTIONAL + 36, 0x200);
        write_u16(&mut bytes, OPTIONAL + 40, 6);
        write_u16(&mut bytes, OPTIONAL + 48, 6);
        write_u32(&mut bytes, OPTIONAL + 56, 0x2000);
        write_u32(&mut bytes, OPTIONAL + 60, RAW as u32);
        write_u16(&mut bytes, OPTIONAL + 68, 3);
        write_u32(&mut bytes, OPTIONAL + 108, 16);
        write_u32(&mut bytes, OPTIONAL + 120, RVA);
        write_u32(&mut bytes, OPTIONAL + 124, descriptors as u32);
        bytes[SECTION..SECTION + 6].copy_from_slice(b".rdata");
        write_u32(&mut bytes, SECTION + 8, data_size as u32);
        write_u32(&mut bytes, SECTION + 12, RVA);
        write_u32(&mut bytes, SECTION + 16, raw_size as u32);
        write_u32(&mut bytes, SECTION + 20, RAW as u32);
        write_u32(&mut bytes, SECTION + 36, 0x40000040);
        let mut name_offset = names;
        for (index, name) in imports.iter().enumerate() {
            let descriptor = RAW + index * 20;
            write_u32(&mut bytes, descriptor, RVA + iat as u32);
            write_u32(&mut bytes, descriptor + 12, RVA + name_offset as u32);
            write_u32(&mut bytes, descriptor + 16, RVA + iat as u32);
            bytes[RAW + name_offset..RAW + name_offset + name.len()]
                .copy_from_slice(name.as_bytes());
            name_offset += name.len() + 1;
        }
        bytes
    }

    #[cfg(target_os = "windows")]
    fn exe_fixture(imports: &[String]) -> Vec<u8> {
        pe_fixture(imports, false)
    }

    #[cfg(target_os = "windows")]
    fn dll_fixture(imports: &[String]) -> Vec<u8> {
        pe_fixture(imports, true)
    }

    #[cfg(target_os = "windows")]
    fn packaged_program(
        provider: &MeshProcessProvider,
        name: &str,
    ) -> Result<super::super::program::ValidatedProgram> {
        use super::super::{
            HostFunctionContract, HostFunctionProcess, Idempotency, ProcessControl, ProcessOptions,
            ProcessProfile, RequestedControl,
        };
        let contract = HostFunctionContract::<(), i32>::new("Fixture", Idempotency::Idempotent);
        let topology = crate::SandboxBuilder::from_bytes([])
            .mesh_process_provider(provider.clone())
            .host_function_process(
                HostFunctionProcess::new(ProcessOptions::for_provider(
                    name,
                    ProcessProfile::new([RequestedControl {
                        control: ProcessControl::DenyNetwork,
                        required: true,
                    }]),
                ))
                .function(contract),
            )
            .process_topology()?
            .unwrap();
        provider
            .inner
            .store
            .validate(topology.workers()[0].program(), &provider.inner.target)
    }

    #[test]
    fn duplicate_named_program_is_rejected() {
        let executable = std::env::current_exe().unwrap();
        let provider = provider(true).with_program("worker", &executable).unwrap();
        let error = provider.with_program("worker", executable).unwrap_err();
        assert!(error.to_string().contains("Duplicate provider program"));
    }

    #[test]
    fn file_resources_are_provider_owned_and_session_scoped() {
        let mut provider = provider(false);
        provider
            .register_file(
                "worker",
                tempfile::tempfile().unwrap(),
                OsResourceRights::READ | OsResourceRights::WRITE,
            )
            .unwrap();
        provider
            .register_file(
                "worker",
                tempfile::tempfile().unwrap(),
                OsResourceRights::READ | OsResourceRights::WRITE,
            )
            .unwrap();
        provider
            .register_file(
                "sibling",
                tempfile::tempfile().unwrap(),
                OsResourceRights::READ | OsResourceRights::WRITE,
            )
            .unwrap();
        let first = provider.inner.resources["worker"][0].id;
        let second = provider.inner.resources["worker"][1].id;
        let sibling = provider.inner.resources["sibling"][0].id;
        assert_ne!(first, second);
        assert_ne!(first, sibling);
        assert_eq!(provider.inner.resources["worker"].len(), 2);

        let mut cloned = provider.clone();
        assert!(
            cloned
                .register_file(
                    "worker",
                    tempfile::tempfile().unwrap(),
                    OsResourceRights::READ | OsResourceRights::WRITE,
                )
                .unwrap_err()
                .to_string()
                .contains("before cloning")
        );
    }

    #[test]
    fn typed_resource_facade_is_available_to_internal_adapters() {
        struct MarkerFactory;

        impl crate::process::LaunchResourceFactory for MarkerFactory {
            fn create(&self, _generation: u64) -> Result<crate::process::NativeResourcePayload> {
                Ok(crate::process::NativeResourcePayload::AuthorizationMarker)
            }
        }

        struct MarkerValidator;

        impl crate::process::NativeResourceValidator for MarkerValidator {
            fn validate(
                &self,
                metadata: &[u8],
                payload: &crate::process::NativeResourcePayload,
            ) -> Result<()> {
                if metadata == b"vm-authority"
                    && matches!(
                        payload,
                        crate::process::NativeResourcePayload::AuthorizationMarker
                    )
                {
                    Ok(())
                } else {
                    Err(new_error!("Typed resource marker mismatch"))
                }
            }
        }

        let kind = crate::process::FIRST_TYPED_RESOURCE_KIND;
        let mut provider = provider(false);
        provider
            .register_typed(
                "worker",
                kind,
                b"vm-authority".to_vec(),
                Arc::new(MarkerFactory),
            )
            .unwrap();
        crate::process::ProcessResourceManifest::new()
            .with_typed(kind, b"vm-authority".to_vec(), Arc::new(MarkerValidator))
            .unwrap();
        let resource = &provider.inner.resources["worker"][0];
        assert!(matches!(
            resource.instantiate(1).unwrap().payload,
            crate::process::NativeResourcePayload::AuthorizationMarker
        ));
    }

    #[test]
    fn resource_owner_must_be_a_declared_function_worker() {
        let mut provider = provider(false);
        provider
            .register_file(
                "missing-worker",
                tempfile::tempfile().unwrap(),
                OsResourceRights::READ | OsResourceRights::WRITE,
            )
            .unwrap();
        let error =
            validate_resource_owners(&provider.inner.resources, std::iter::empty()).unwrap_err();
        assert!(error.to_string().contains("is not a function worker"));
    }

    #[test]
    fn export_policy_is_bounded_and_provider_owned() {
        let mut provider = provider(false);
        provider
            .allow_file_exports(
                "worker",
                OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            )
            .unwrap();
        provider.inner.begin_generation("worker", 7).unwrap();
        let first = provider
            .inner
            .accept_file(
                "worker",
                7,
                WireExportFile {
                    kind: 1,
                    rights: OsResourceRights::READ.bits(),
                    file: tempfile::tempfile().unwrap(),
                },
            )
            .unwrap();
        assert!(
            provider
                .inner
                .accept_file(
                    "worker",
                    7,
                    WireExportFile {
                        kind: 1,
                        rights: OsResourceRights::READ.bits(),
                        file: tempfile::tempfile().unwrap(),
                    },
                )
                .unwrap_err()
                .to_string()
                .contains("quota")
        );
        let mut exported = provider.take_exported_file("worker").unwrap().unwrap();
        assert_eq!(exported.id(), first);
        assert_eq!(exported.rights(), OsResourceRights::READ);
        assert_eq!(
            exported.write_all(b"denied").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(
            provider
                .inner
                .begin_generation("worker", 8)
                .unwrap_err()
                .to_string()
                .contains("already active")
        );
        provider.inner.end_generation("worker", 7);
        provider.inner.begin_generation("worker", 8).unwrap();
        let second = provider
            .inner
            .accept_file(
                "worker",
                8,
                WireExportFile {
                    kind: 1,
                    rights: OsResourceRights::READ.bits(),
                    file: tempfile::tempfile().unwrap(),
                },
            )
            .unwrap();
        provider.inner.end_generation("worker", 8);
        assert!(
            provider
                .inner
                .begin_generation("worker", 1)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
        assert_ne!(first, second);
    }

    #[test]
    fn export_policy_rejects_unauthorized_metadata_and_rights() {
        let mut provider = provider(false);
        provider
            .allow_file_exports(
                "worker",
                OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            )
            .unwrap();
        provider.inner.begin_generation("worker", 1).unwrap();
        for (process, generation, kind, rights, expected) in [
            (
                "missing",
                1,
                1,
                OsResourceRights::READ.bits(),
                "not authorized",
            ),
            ("worker", 0, 1, OsResourceRights::READ.bits(), "invalid"),
            ("worker", 1, 99, OsResourceRights::READ.bits(), "invalid"),
            ("worker", 1, 1, u32::MAX, "invalid"),
            (
                "worker",
                1,
                1,
                OsResourceRights::WRITE.bits(),
                "exceed policy",
            ),
        ] {
            let error = provider
                .inner
                .accept_file(
                    process,
                    generation,
                    WireExportFile {
                        kind,
                        rights,
                        file: tempfile::tempfile().unwrap(),
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
        assert!(provider.take_exported_file("worker").unwrap().is_none());
    }

    #[test]
    fn mesh_export_channel_preserves_worker_source() {
        let mut provider = provider(false);
        provider
            .allow_file_exports(
                "worker",
                OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            )
            .unwrap();
        let authority = provider.inner.export_authority("worker").unwrap().unwrap();
        let (sender, handler) = authority.start(13).unwrap();
        let resources = ProcessResources::from_wire(vec![], Some(sender), 13, &[]).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"worker result").unwrap();
        resources
            .export_file(&source, OsResourceRights::READ)
            .unwrap();
        source.write_all(b" retained").unwrap();
        let mut exported = provider.take_exported_file("worker").unwrap().unwrap();
        drop(resources);
        let mut handler = handler;
        handler.stop();
        handler
            .join(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();

        let mut contents = String::new();
        exported.seek(SeekFrom::Start(0)).unwrap();
        exported.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "worker result retained");
    }

    #[test]
    fn snapshot_provider_cannot_package_programs() {
        let error = provider(false)
            .with_program("worker", std::env::current_exe().unwrap())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot package new native programs")
        );
    }

    #[test]
    fn program_bytes_are_captured_before_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory
            .path()
            .join(std::env::current_exe().unwrap().file_name().unwrap());
        let original = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(&source, &original).unwrap();
        let mut permissions = std::fs::metadata(&source).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&source, permissions).unwrap();
        let replacement = b"replacement".to_vec();
        let captured = program_source_with(&source, |stage| {
            if stage == CaptureStage::Opened {
                let opened = directory.path().join("opened");
                std::fs::rename(&source, opened).unwrap();
                std::fs::write(&source, &replacement).unwrap();
            }
        })
        .unwrap();
        assert_eq!(captured.executable, original);
        assert!(
            std::fs::metadata(&captured._captured_executable)
                .unwrap()
                .permissions()
                .readonly()
        );
        assert_eq!(std::fs::read(source).unwrap(), replacement);
    }

    #[test]
    fn program_capture_survives_source_removal_after_read() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory
            .path()
            .join(std::env::current_exe().unwrap().file_name().unwrap());
        let original = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        std::fs::write(&source, &original).unwrap();
        let captured = program_source_with(&source, |stage| {
            if stage == CaptureStage::Read {
                std::fs::remove_file(&source).unwrap();
            }
        })
        .unwrap();
        assert_eq!(captured.executable, original);
        assert!(!source.exists());
    }

    #[test]
    fn bounded_capture_rejects_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("oversized");
        std::fs::write(&source, [0_u8; 17]).unwrap();
        let error = capture_file_with_limit(&source, 16, |_| {}).unwrap_err();
        assert!(error.to_string().contains("exceeds the 256 MiB limit"));
    }

    #[cfg(target_os = "linux")]
    fn relative_from_current(path: &Path) -> PathBuf {
        let current = std::env::current_dir().unwrap();
        let from = current.components().collect::<Vec<_>>();
        let to = path.components().collect::<Vec<_>>();
        let common = from
            .iter()
            .zip(&to)
            .take_while(|(left, right)| left == right)
            .count();
        std::iter::repeat_n(
            std::path::Component::ParentDir.as_os_str(),
            from.len() - common,
        )
        .chain(to[common..].iter().map(|component| component.as_os_str()))
        .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cloned_provider_rejects_linux_resource_configuration() {
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("minijail");
        std::fs::write(&helper, b"helper").unwrap();
        let resources = super::super::LinuxProcessResources::new(
            directory.path(),
            &helper,
            Sha256::digest(b"helper").into(),
        )
        .unwrap();
        let provider = provider(false);
        let _clone = provider.clone();
        let error = provider.with_linux_resources(resources).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Configure Linux resources before cloning")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_origin_dependency_context() {
        let directory = tempfile::tempdir().unwrap();
        let library_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let library = directory.path().join("libprovider_origin.so");
        let program = directory.path().join("origin-program");
        std::fs::write(
            &library_source,
            "int provider_origin(void) { return 42; }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_origin(void); int main(void) { return provider_origin() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_origin.so"])
                .arg(&library_source)
                .arg("-o")
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(directory.path())
                .arg("-lprovider_origin")
                .arg("-Wl,-rpath,$ORIGIN")
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected = std::fs::read(&library).unwrap();
        let relative_program = relative_from_current(&program);
        assert!(
            relative_program
                .components()
                .any(|component| { component == std::path::Component::ParentDir })
        );
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_file(program).unwrap();
        std::fs::remove_file(library).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        assert_eq!(
            files
                .iter()
                .find(|file| file.image_path() == "/libprovider_origin.so")
                .unwrap()
                .bytes(),
            expected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_origin_lists_and_inherited_rpath() {
        let directory = tempfile::tempdir().unwrap();
        let libraries = directory.path().join("lib");
        std::fs::create_dir(&libraries).unwrap();
        let leaf_source = directory.path().join("leaf.c");
        let helper_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let leaf = libraries.join("libprovider_leaf.so");
        let helper = libraries.join("libprovider_helper.so");
        let program = directory.path().join("origin-program");
        std::fs::write(&leaf_source, "int provider_leaf(void) { return 42; }\n").unwrap();
        std::fs::write(
            &helper_source,
            "extern int provider_leaf(void); int provider_helper(void) { return provider_leaf(); }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_helper(void); int main(void) { return provider_helper() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_leaf.so"])
                .arg(&leaf_source)
                .arg("-o")
                .arg(&leaf)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_helper.so"])
                .arg(&helper_source)
                .arg("-L")
                .arg(&libraries)
                .arg("-lprovider_leaf")
                .arg("-o")
                .arg(&helper)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(&libraries)
                .arg("-lprovider_helper")
                .arg("-Wl,--disable-new-dtags,-rpath,$ORIGIN/missing:$ORIGIN/lib")
                .arg("-Wl,-rpath-link")
                .arg(&libraries)
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected_helper = std::fs::read(&helper).unwrap();
        let expected_leaf = std::fs::read(&leaf).unwrap();
        let relative_program = relative_from_current(&program);
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_file(program).unwrap();
        std::fs::remove_file(helper).unwrap();
        std::fs::remove_file(leaf).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        let files = files
            .iter()
            .map(|file| (file.image_path(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(files["/lib/libprovider_helper.so"], expected_helper);
        assert_eq!(files["/lib/libprovider_leaf.so"], expected_leaf);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn program_source_preserves_parent_origin_layout() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("bin");
        let lib = directory.path().join("lib");
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(&lib).unwrap();
        let library_source = directory.path().join("helper.c");
        let program_source_path = directory.path().join("program.c");
        let library = lib.join("libprovider_parent.so");
        let program = bin.join("origin-program");
        std::fs::write(
            &library_source,
            "int provider_parent(void) { return 42; }\n",
        )
        .unwrap();
        std::fs::write(
            &program_source_path,
            "extern int provider_parent(void); int main(void) { return provider_parent() != 42; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("cc")
                .args(["-shared", "-fPIC", "-Wl,-soname,libprovider_parent.so"])
                .arg(&library_source)
                .arg("-o")
                .arg(&library)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cc")
                .arg(&program_source_path)
                .arg("-L")
                .arg(&lib)
                .arg("-lprovider_parent")
                .arg("-Wl,-rpath,$ORIGIN/../lib")
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let expected = std::fs::read(&library).unwrap();
        let relative_program = relative_from_current(&program);
        assert!(
            relative_program
                .components()
                .filter(|component| *component == std::path::Component::ParentDir)
                .count()
                >= 2
        );
        let source = program_source(&relative_program).unwrap();
        assert!(
            source
                ._captured_executable
                .starts_with(&source._capture_root)
        );
        std::fs::remove_dir_all(directory.path()).unwrap();
        assert!(
            std::process::Command::new(&source._captured_executable)
                .status()
                .unwrap()
                .success()
        );
        let files = super::super::linux::runtime_closure_in(
            &source._captured_executable,
            &source._capture_root,
        )
        .unwrap();
        assert_eq!(
            files
                .iter()
                .find(|file| file.image_path() == "/lib/libprovider_parent.so")
                .unwrap()
                .bytes(),
            expected
        );
        let captured_executable = source._captured_executable.clone();
        let capture_root = source._capture_root.clone();
        drop(source);
        assert!(!captured_executable.exists());
        assert!(!capture_root.exists());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn explicit_runtime_file_uses_relative_image_path() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("helper.dll");
        std::fs::write(&runtime, b"dll").unwrap();
        let provider = provider(true);
        let source = program_source(&std::env::current_exe().unwrap()).unwrap();
        let provider = MeshProcessProvider {
            inner: Arc::new(Provider {
                current_program: Some(source),
                ..Arc::try_unwrap(provider.inner).ok().unwrap()
            }),
        }
        .with_runtime_file("bin/helper.dll", &runtime)
        .unwrap();
        let file = &provider
            .inner
            .current_program
            .as_ref()
            .unwrap()
            ._runtime_files[0];
        assert_eq!(file.image_path(), "/bin/helper.dll");
        assert_eq!(file.bytes(), b"dll");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_packages_adjacent_dll() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let program_bytes = exe_fixture(&["helper.dll".to_owned()]);
        let helper_bytes = dll_fixture(&[]);
        std::fs::write(&program, program_bytes).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files().len(), 1);
        assert_eq!(packaged.runtime_files()[0].image_path(), "/helper.dll");
        assert_eq!(packaged.runtime_files()[0].bytes(), helper_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_uses_captured_program_after_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let original = exe_fixture(&[]);
        std::fs::write(&program, &original).unwrap();
        let provider = provider(true).with_program("worker", &program).unwrap();
        std::fs::write(&program, b"replacement").unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.executable(), original);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_uses_captured_dll_after_source_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let original = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &original).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        std::fs::write(&helper, b"replacement").unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files()[0].bytes(), original);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_packages_transitive_adjacent_dlls() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        let leaf = directory.path().join("leaf.dll");
        let helper_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        let files = packaged
            .runtime_files()
            .iter()
            .map(|file| (file.image_path(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(files["/helper.dll"], helper_bytes);
        assert_eq!(files["/leaf.dll"], leaf_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_prefers_private_dll_over_system32_fallback() {
        let system32 =
            std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32");
        let known = super::super::windows::known_dlls().unwrap();
        let collision = std::fs::read_dir(system32)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .find(|name| {
                name.to_ascii_lowercase().ends_with(".dll")
                    && !known.contains(&name.to_ascii_lowercase())
            })
            .expect("System32 must contain a non-KnownDLL fallback");
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let private = directory.path().join(&collision);
        let leaf = directory.path().join("leaf.dll");
        let private_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(std::slice::from_ref(&collision))).unwrap();
        std::fs::write(&private, &private_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        let files = packaged
            .runtime_files()
            .iter()
            .map(|file| (file.image_path().to_ascii_lowercase(), file.bytes()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            files[&format!("/{}", collision.to_ascii_lowercase())],
            private_bytes
        );
        assert_eq!(files["/leaf.dll"], leaf_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_missing_dll_during_placement() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        std::fs::write(&program, exe_fixture(&["missing.dll".to_owned()])).unwrap();
        let provider = provider(true).with_program("worker", program).unwrap();
        let error = packaged_program(&provider, "worker").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("missing.dll"));
        assert!(message.contains("with_program_runtime_file"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_repairs_missing_dll_with_explicit_declaration() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("declared-helper.bin");
        let helper_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        let provider = provider(true)
            .with_program("worker", program)
            .unwrap()
            .with_program_runtime_file("worker", "helper.dll", helper)
            .unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files()[0].image_path(), "/helper.dll");
        assert_eq!(packaged.runtime_files()[0].bytes(), helper_bytes);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_validates_transitive_explicit_dlls() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.bin");
        let leaf = directory.path().join("leaf.bin");
        let helper_bytes = dll_fixture(&["leaf.dll".to_owned()]);
        let leaf_bytes = dll_fixture(&[]);
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, &helper_bytes).unwrap();
        std::fs::write(&leaf, &leaf_bytes).unwrap();
        let provider = provider(true)
            .with_program("worker", program)
            .unwrap()
            .with_program_runtime_file("worker", "helper.dll", helper)
            .unwrap()
            .with_program_runtime_file("worker", "leaf.dll", leaf)
            .unwrap();
        let packaged = packaged_program(&provider, "worker").unwrap();
        assert_eq!(packaged.runtime_files().len(), 2);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_excessive_import_count() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let imports = (0..129)
            .map(|index| format!("x{index:03}.dll"))
            .collect::<Vec<_>>();
        std::fs::write(&program, exe_fixture(&imports)).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("exceeds 128 DLLs"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_dll_as_program() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        std::fs::write(&program, dll_fixture(&[])).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("marked as a DLL"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_executable_as_runtime_dll() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let helper = directory.path().join("helper.dll");
        std::fs::write(&program, exe_fixture(&["helper.dll".to_owned()])).unwrap();
        std::fs::write(&helper, exe_fixture(&[])).unwrap();
        let error = provider(true).with_program("worker", program).unwrap_err();
        assert!(error.to_string().contains("not marked as a DLL"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn public_provider_rejects_excessive_explicit_runtime_files() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program.exe");
        let runtime = directory.path().join("runtime.dll");
        std::fs::write(&program, exe_fixture(&[])).unwrap();
        std::fs::write(&runtime, dll_fixture(&[])).unwrap();
        let mut provider = provider(true).with_program("worker", program).unwrap();
        for index in 0..128 {
            provider = provider
                .with_program_runtime_file("worker", format!("runtime-{index:03}.dll"), &runtime)
                .unwrap();
        }
        let error = provider
            .with_program_runtime_file("worker", "runtime-128.dll", runtime)
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 128 DLLs"));
    }
}
