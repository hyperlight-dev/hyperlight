// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use mesh::MeshPayload;
use mesh::rpc::{Rpc, RpcSend};

use crate::{Result, new_error};

/// Opaque identity for one provider-owned OS resource.
#[derive(Clone, Copy, Debug, MeshPayload, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId {
    session_high: u64,
    session_low: u64,
    slot: u32,
    generation: u64,
}

/// Policy for file capabilities exported by one worker.
#[derive(Clone, Copy, Debug)]
pub struct OsResourceExportPolicy {
    rights: OsResourceRights,
    max_pending: usize,
}

/// Resource declarations accepted by a resource-aware process worker.
#[derive(Clone, Default)]
pub struct ProcessResourceManifest {
    resources: Vec<ExpectedResource>,
    exports: Option<OsResourceExportPolicy>,
}

#[derive(Clone)]
struct ExpectedResource {
    kind: u32,
    metadata: Vec<u8>,
    validator: Option<Arc<dyn NativeResourceValidator>>,
}

pub(crate) trait NativeResourceValidator: Send + Sync {
    fn validate(&self, metadata: &[u8], payload: &NativeResourcePayload) -> Result<()>;
}

impl ProcessResourceManifest {
    /// Creates an empty resource manifest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one file capability with exactly these declared rights.
    pub fn with_file(mut self, rights: OsResourceRights) -> Result<Self> {
        validate_rights(rights)?;
        self.resources.push(ExpectedResource {
            kind: FILE_RESOURCE_KIND,
            metadata: rights.bits().to_ne_bytes().to_vec(),
            validator: None,
        });
        Ok(self)
    }

    /// Allows worker-to-parent file exports under this exact policy.
    pub fn with_file_exports(mut self, policy: OsResourceExportPolicy) -> Result<Self> {
        if self.exports.replace(policy).is_some() {
            return Err(new_error!("Resource export policy is duplicated"));
        }
        Ok(self)
    }

    pub(super) fn validate(
        &self,
        generation: u64,
        declarations: &[WireResourceDeclaration],
        exports: Option<WireExportPolicy>,
    ) -> Result<()> {
        validate_declarations(generation, declarations)?;
        if let Some(exports) = exports {
            exports.validate()?;
        }
        let actual = declarations
            .iter()
            .map(|declaration| ExpectedResource {
                kind: declaration.kind,
                metadata: declaration.metadata.clone(),
                validator: None,
            })
            .collect::<Vec<_>>();
        if actual.len() != self.resources.len()
            || actual
                .iter()
                .zip(&self.resources)
                .any(|(actual, expected)| {
                    actual.kind != expected.kind || actual.metadata != expected.metadata
                })
        {
            return Err(new_error!("Process resource declaration mismatch"));
        }
        if exports != self.exports.map(WireExportPolicy::from) {
            return Err(new_error!("Process resource export policy mismatch"));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn with_typed(
        mut self,
        kind: u32,
        metadata: Vec<u8>,
        validator: Arc<dyn NativeResourceValidator>,
    ) -> Result<Self> {
        if kind < FIRST_TYPED_RESOURCE_KIND {
            return Err(new_error!("Typed process resource kind is reserved"));
        }
        self.resources.push(ExpectedResource {
            kind,
            metadata,
            validator: Some(validator),
        });
        Ok(self)
    }

    pub(super) fn validate_payloads(
        &self,
        resources: &[WireResource],
        has_exporter: bool,
    ) -> Result<()> {
        if resources.len() != self.resources.len() || has_exporter != self.exports.is_some() {
            return Err(new_error!(
                "Process resource payload count or authority mismatch"
            ));
        }
        for (resource, expected) in resources.iter().zip(&self.resources) {
            match (expected.kind, &expected.validator, &resource.payload) {
                (FILE_RESOURCE_KIND, None, NativeResourcePayload::File(_)) => {}
                (FILE_RESOURCE_KIND, _, _) => {
                    return Err(new_error!("Process file resource payload mismatch"));
                }
                (_, Some(validator), payload) => {
                    validator.validate(&expected.metadata, payload)?;
                }
                _ => return Err(new_error!("Typed process resource has no validator")),
            }
        }
        Ok(())
    }
}

impl OsResourceExportPolicy {
    /// Allows file exports with at most these rights and pending objects.
    pub fn files(rights: OsResourceRights, max_pending: usize) -> Result<Self> {
        validate_rights(rights)?;
        if max_pending == 0 {
            return Err(new_error!("A resource export quota must be nonzero"));
        }
        Ok(Self {
            rights,
            max_pending,
        })
    }

    pub(super) fn rights(self) -> OsResourceRights {
        self.rights
    }

    pub(super) fn max_pending(self) -> usize {
        self.max_pending
    }
}

impl ResourceId {
    pub(super) fn new(session: u128, slot: u32, generation: u64) -> Self {
        Self {
            session_high: (session >> 64) as u64,
            session_low: session as u64,
            slot,
            generation,
        }
    }

    /// Returns the worker generation that owns this identity.
    pub fn generation(self) -> u64 {
        self.generation
    }
}

/// Type of an OS object transferred into a process worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OsResourceKind {
    /// An already-open file object.
    File,
}

bitflags::bitflags! {
    /// Operations authorized for a transferred OS resource.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OsResourceRights: u32 {
        /// Read bytes from the object.
        const READ = 1 << 0;
        /// Write bytes to the object.
        const WRITE = 1 << 1;
    }
}

pub(super) const FILE_RESOURCE_KIND: u32 = 1;
pub(crate) const FIRST_TYPED_RESOURCE_KIND: u32 = 0x100;

pub(crate) trait LaunchResourceFactory: Send + Sync {
    fn create(&self, generation: u64) -> Result<NativeResourcePayload>;
}

#[derive(Clone)]
pub(crate) struct RegisteredResource {
    pub id: ResourceId,
    kind: u32,
    metadata: Vec<u8>,
    factory: Arc<dyn LaunchResourceFactory>,
}

impl RegisteredResource {
    pub(super) fn file(id: ResourceId, file: File, rights: OsResourceRights) -> Self {
        Self {
            id,
            kind: FILE_RESOURCE_KIND,
            metadata: rights.bits().to_ne_bytes().to_vec(),
            factory: Arc::new(FileResourceFactory { file, rights }),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn typed(
        id: ResourceId,
        kind: u32,
        metadata: Vec<u8>,
        factory: Arc<dyn LaunchResourceFactory>,
    ) -> Result<Self> {
        if kind < FIRST_TYPED_RESOURCE_KIND {
            return Err(new_error!("Typed process resource kind is reserved"));
        }
        Ok(Self {
            id,
            kind,
            metadata,
            factory,
        })
    }

    pub(super) fn declaration(&self, generation: u64) -> WireResourceDeclaration {
        WireResourceDeclaration {
            session_high: self.id.session_high,
            session_low: self.id.session_low,
            slot: self.id.slot,
            generation,
            kind: self.kind,
            metadata: self.metadata.clone(),
        }
    }

    pub(crate) fn kind_and_metadata(&self) -> (u32, &[u8]) {
        (self.kind, &self.metadata)
    }

    #[cfg(test)]
    pub(super) fn file_with_factory(
        id: ResourceId,
        rights: OsResourceRights,
        factory: Arc<dyn LaunchResourceFactory>,
    ) -> Self {
        Self {
            id,
            kind: FILE_RESOURCE_KIND,
            metadata: rights.bits().to_ne_bytes().to_vec(),
            factory,
        }
    }

    pub(super) fn instantiate(&self, generation: u64) -> Result<WireResource> {
        if generation == 0 {
            return Err(new_error!("Process resource generation is invalid"));
        }
        let payload = self.factory.create(generation)?;
        Ok(WireResource {
            session_high: self.id.session_high,
            session_low: self.id.session_low,
            slot: self.id.slot,
            generation,
            kind: self.kind,
            metadata: self.metadata.clone(),
            payload,
        })
    }
}

struct FileResourceFactory {
    file: File,
    rights: OsResourceRights,
}

impl LaunchResourceFactory for FileResourceFactory {
    fn create(&self, _generation: u64) -> Result<NativeResourcePayload> {
        Ok(NativeResourcePayload::File(duplicate_file(
            &self.file,
            self.rights,
        )?))
    }
}

#[derive(Clone, Debug, MeshPayload, PartialEq, Eq)]
pub(super) struct WireResourceDeclaration {
    pub(super) session_high: u64,
    pub(super) session_low: u64,
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) kind: u32,
    pub(super) metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug, MeshPayload, PartialEq, Eq)]
pub(super) struct WireExportPolicy {
    rights: u32,
    max_pending: u64,
}

impl From<OsResourceExportPolicy> for WireExportPolicy {
    fn from(policy: OsResourceExportPolicy) -> Self {
        Self {
            rights: policy.rights.bits(),
            max_pending: policy.max_pending as u64,
        }
    }
}

impl WireExportPolicy {
    fn validate(self) -> Result<()> {
        let rights = OsResourceRights::from_bits(self.rights)
            .ok_or_else(|| new_error!("Resource export rights are invalid"))?;
        validate_rights(rights)?;
        if self.max_pending == 0 || usize::try_from(self.max_pending).is_err() {
            return Err(new_error!("Resource export quota is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, MeshPayload)]
pub(crate) enum NativeResourcePayload {
    File(File),
    #[cfg(unix)]
    Descriptor(std::os::fd::OwnedFd),
    #[cfg(windows)]
    Handle(std::os::windows::io::OwnedHandle),
    AuthorizationMarker,
}

#[derive(Debug, MeshPayload)]
pub(super) struct WireResource {
    pub(super) session_high: u64,
    pub(super) session_low: u64,
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) kind: u32,
    pub(super) metadata: Vec<u8>,
    pub(super) payload: NativeResourcePayload,
}

#[derive(Debug, MeshPayload)]
pub(super) struct WireExportFile {
    pub(super) kind: u32,
    pub(super) rights: u32,
    pub(super) file: File,
}

#[derive(MeshPayload)]
pub(super) enum ResourceExportRequest {
    File(Rpc<WireExportFile, std::result::Result<ResourceId, String>>),
}

pub(super) trait ResourceExportSink: Send + Sync {
    fn begin_generation(&self, process_name: &str, generation: u64) -> Result<()>;

    fn accept_file(
        &self,
        process_name: &str,
        generation: u64,
        file: WireExportFile,
    ) -> Result<ResourceId>;

    fn end_generation(&self, process_name: &str, generation: u64);
}

pub(super) struct ExportHandler {
    stop: Option<futures::channel::oneshot::Sender<()>>,
    completion: std::sync::mpsc::Receiver<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct ExportGenerationGuard {
    sink: Arc<dyn ResourceExportSink>,
    process_name: String,
    generation: u64,
    completed: std::sync::mpsc::Sender<()>,
}

impl Drop for ExportGenerationGuard {
    fn drop(&mut self) {
        self.sink
            .end_generation(&self.process_name, self.generation);
        let _ = self.completed.send(());
    }
}

impl ExportHandler {
    pub(super) fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    pub(super) fn join(&mut self, deadline: std::time::Instant) -> Result<()> {
        let timeout = deadline.saturating_duration_since(std::time::Instant::now());
        match self.completion.recv_timeout(timeout) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(new_error!("Resource export handler cleanup timed out"));
            }
        }
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            return Err(new_error!("Resource export handler panicked"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ExportAuthority {
    process_name: String,
    policy: OsResourceExportPolicy,
    sink: Arc<dyn ResourceExportSink>,
}

impl ExportAuthority {
    pub(super) fn new(
        process_name: String,
        policy: OsResourceExportPolicy,
        sink: Arc<dyn ResourceExportSink>,
    ) -> Self {
        Self {
            process_name,
            policy,
            sink,
        }
    }

    pub(super) fn declaration(&self) -> WireExportPolicy {
        self.policy.into()
    }

    pub(super) fn start(
        self,
        generation: u64,
    ) -> Result<(mesh::Sender<ResourceExportRequest>, ExportHandler)> {
        use futures::{FutureExt, StreamExt};

        self.sink.begin_generation(&self.process_name, generation)?;
        let (sender, mut requests) = mesh::channel();
        let (stop, stopped) = futures::channel::oneshot::channel();
        let (completed, completion) = std::sync::mpsc::channel();
        let process_name = self.process_name;
        let sink = self.sink;
        let cleanup_process_name = process_name.clone();
        let cleanup_sink = sink.clone();
        let thread = match std::thread::Builder::new()
            .name("hyperlight-resource-exports".to_owned())
            .spawn(move || {
                let _cleanup = ExportGenerationGuard {
                    sink: sink.clone(),
                    process_name: process_name.clone(),
                    generation,
                    completed,
                };
                futures_lite::future::block_on(async move {
                    let stopped = stopped.fuse();
                    futures::pin_mut!(stopped);
                    loop {
                        futures::select! {
                            request = requests.next().fuse() => {
                                let Some(request) = request else {
                                    break;
                                };
                                match request {
                                    ResourceExportRequest::File(request) => {
                                        request.handle_sync(|file| {
                                            sink.accept_file(&process_name, generation, file)
                                                .map_err(|error| error.to_string())
                                        });
                                    }
                                }
                            }
                            _ = stopped => break,
                        }
                    }
                });
            }) {
            Ok(thread) => thread,
            Err(error) => {
                cleanup_sink.end_generation(&cleanup_process_name, generation);
                return Err(new_error!(
                    "Resource export thread creation failed: {error}"
                ));
            }
        };
        Ok((
            sender,
            ExportHandler {
                stop: Some(stop),
                completion,
                thread: Some(thread),
            },
        ))
    }
}

impl WireResource {
    fn into_entry(self) -> Result<(ResourceId, ResourceEntry)> {
        let payload = match (self.kind, self.payload) {
            (FILE_RESOURCE_KIND, NativeResourcePayload::File(file)) => {
                let rights = self
                    .metadata
                    .as_slice()
                    .try_into()
                    .ok()
                    .and_then(|bytes: [u8; 4]| {
                        OsResourceRights::from_bits(u32::from_ne_bytes(bytes))
                    })
                    .filter(|rights| !rights.is_empty())
                    .ok_or_else(|| new_error!("Process file resource rights are invalid"))?;
                ResourceEntryPayload::File { file, rights }
            }
            (FILE_RESOURCE_KIND, _) => {
                return Err(new_error!("Process file resource payload is invalid"));
            }
            (kind, payload) if kind >= FIRST_TYPED_RESOURCE_KIND => ResourceEntryPayload::Typed {
                metadata: self.metadata,
                payload,
            },
            _ => return Err(new_error!("Process resource has an unknown kind")),
        };
        Ok((
            ResourceId {
                session_high: self.session_high,
                session_low: self.session_low,
                slot: self.slot,
                generation: self.generation,
            },
            ResourceEntry {
                kind: self.kind,
                payload,
            },
        ))
    }
}

struct ResourceEntry {
    kind: u32,
    payload: ResourceEntryPayload,
}

enum ResourceEntryPayload {
    File {
        file: File,
        rights: OsResourceRights,
    },
    #[allow(dead_code)]
    Typed {
        metadata: Vec<u8>,
        payload: NativeResourcePayload,
    },
}

#[allow(dead_code)]
pub(crate) struct ClaimedTypedResource {
    pub metadata: Vec<u8>,
    pub payload: NativeResourcePayload,
}

/// OS resources delivered to one process-worker generation.
pub struct ProcessResources {
    entries: BTreeMap<ResourceId, ResourceEntry>,
    generation: Option<u64>,
    exporter: Option<mesh::Sender<ResourceExportRequest>>,
}

/// Cloneable authority for exporting bounded OS resources to the calling host.
#[derive(Clone)]
pub struct ProcessResourceExporter {
    exporter: mesh::Sender<ResourceExportRequest>,
}

impl ProcessResourceExporter {
    /// Exports a restricted duplicate of an owned file to the calling host.
    pub fn export_file(&self, file: &File, rights: OsResourceRights) -> Result<ResourceId> {
        send_file_export(&self.exporter, file, rights)
    }
}

impl ProcessResources {
    pub(super) fn from_wire(
        resources: Vec<WireResource>,
        exporter: Option<mesh::Sender<ResourceExportRequest>>,
        generation: u64,
        declarations: &[WireResourceDeclaration],
    ) -> Result<Self> {
        if generation == 0 {
            return Err(new_error!("Process resource generation is invalid"));
        }
        let actual_declarations = resources
            .iter()
            .map(|resource| WireResourceDeclaration {
                session_high: resource.session_high,
                session_low: resource.session_low,
                slot: resource.slot,
                generation: resource.generation,
                kind: resource.kind,
                metadata: resource.metadata.clone(),
            })
            .collect::<Vec<_>>();
        if actual_declarations != declarations {
            return Err(new_error!(
                "Transferred process resources do not match accepted declarations"
            ));
        }
        let mut entries = BTreeMap::new();
        let mut scope = None;
        for resource in resources {
            let (id, entry) = resource.into_entry()?;
            if id.generation != generation {
                return Err(new_error!("Process resource generation mismatch"));
            }
            let current_scope = (id.session_high, id.session_low, id.generation);
            if scope
                .replace(current_scope)
                .is_some_and(|scope| scope != current_scope)
            {
                return Err(new_error!(
                    "Process resources do not share one session generation"
                ));
            }
            if entries.insert(id, entry).is_some() {
                return Err(new_error!("Process resource identity is duplicated"));
            }
        }
        super::vm_authority::capture_declared_process_context(generation, declarations)?;
        Ok(Self {
            entries,
            generation: Some(generation),
            exporter,
        })
    }

    /// Returns the resources available to this worker generation.
    pub fn ids(&self) -> Vec<ResourceId> {
        self.entries.keys().copied().collect()
    }

    /// Returns this worker's resource generation.
    pub fn generation(&self) -> Option<u64> {
        self.generation
    }

    /// Returns whether this worker may request resource exports.
    pub fn can_export(&self) -> bool {
        self.exporter.is_some()
    }

    /// Returns export authority that can be retained by bound host functions.
    pub fn exporter(&self) -> Option<ProcessResourceExporter> {
        self.exporter
            .as_ref()
            .cloned()
            .map(|exporter| ProcessResourceExporter { exporter })
    }

    /// Exports a restricted duplicate of an owned file to the calling host.
    pub fn export_file(&self, file: &File, rights: OsResourceRights) -> Result<ResourceId> {
        let exporter = self
            .exporter
            .as_ref()
            .ok_or_else(|| new_error!("This worker has no resource export authority"))?;
        send_file_export(exporter, file, rights)
    }

    /// Takes an owned file capability with at least `required` rights.
    pub fn take_file(
        &mut self,
        id: ResourceId,
        required: OsResourceRights,
    ) -> Result<TransferredFile> {
        if required.is_empty() || OsResourceRights::from_bits(required.bits()).is_none() {
            return Err(new_error!("Requested process resource rights are invalid"));
        }
        let entry = self
            .entries
            .get(&id)
            .ok_or_else(|| new_error!("Unknown or stale process resource"))?;
        if entry.kind != FILE_RESOURCE_KIND {
            return Err(new_error!("Process resource kind mismatch"));
        }
        let ResourceEntryPayload::File { rights, .. } = &entry.payload else {
            return Err(new_error!("Process file resource payload mismatch"));
        };
        if !rights.contains(required) {
            return Err(new_error!("Process resource rights are insufficient"));
        }
        let entry = self
            .entries
            .remove(&id)
            .expect("validated process resource must remain present");
        let ResourceEntryPayload::File { file, rights } = entry.payload else {
            unreachable!("validated file resource payload must remain present");
        };
        Ok(TransferredFile { file, rights })
    }

    #[allow(dead_code)]
    pub(crate) fn take_typed(
        &mut self,
        id: ResourceId,
        expected_kind: u32,
    ) -> Result<ClaimedTypedResource> {
        if expected_kind < FIRST_TYPED_RESOURCE_KIND {
            return Err(new_error!("Typed process resource kind is reserved"));
        }
        let entry = self
            .entries
            .get(&id)
            .ok_or_else(|| new_error!("Unknown or stale process resource"))?;
        if entry.kind != expected_kind {
            return Err(new_error!("Process resource kind mismatch"));
        }
        let entry = self
            .entries
            .remove(&id)
            .expect("validated process resource must remain present");
        let ResourceEntryPayload::Typed { metadata, payload } = entry.payload else {
            return Err(new_error!("Typed process resource payload mismatch"));
        };
        Ok(ClaimedTypedResource { metadata, payload })
    }

    pub(crate) fn unique_typed_id(&self, expected_kind: u32) -> Result<ResourceId> {
        let mut ids = self
            .entries
            .iter()
            .filter_map(|(id, entry)| (entry.kind == expected_kind).then_some(*id));
        let id = ids
            .next()
            .ok_or_else(|| new_error!("Required typed process resource is missing"))?;
        if ids.next().is_some() {
            return Err(new_error!("Typed process resource is duplicated"));
        }
        Ok(id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn send_file_export(
    exporter: &mesh::Sender<ResourceExportRequest>,
    file: &File,
    rights: OsResourceRights,
) -> Result<ResourceId> {
    validate_rights(rights)?;
    let file = duplicate_file_for_export(file, rights)?;
    futures_lite::future::block_on(exporter.call(
        ResourceExportRequest::File,
        WireExportFile {
            kind: 1,
            rights: rights.bits(),
            file,
        },
    ))
    .map_err(|error| new_error!("Resource export channel failed: {error}"))?
    .map_err(|error| new_error!("Resource export denied: {error}"))
}

/// Rights-gated owned file received from the calling process.
pub struct TransferredFile {
    file: File,
    rights: OsResourceRights,
}

impl TransferredFile {
    /// Rights carried by this capability.
    pub fn rights(&self) -> OsResourceRights {
        self.rights
    }

    fn require(&self, right: OsResourceRights) -> io::Result<()> {
        if self.rights.contains(right) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transferred resource right is missing",
            ))
        }
    }
}

impl Read for TransferredFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.require(OsResourceRights::READ)?;
        self.file.read(buffer)
    }
}

impl Write for TransferredFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.require(OsResourceRights::WRITE)?;
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.require(OsResourceRights::WRITE)?;
        self.file.flush()
    }
}

impl Seek for TransferredFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self
            .rights
            .intersects(OsResourceRights::READ | OsResourceRights::WRITE)
        {
            self.file.seek(position)
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "transferred resource has no seek-capable right",
            ))
        }
    }
}

/// Rights-gated file capability exported from a worker.
pub struct ExportedFile {
    id: ResourceId,
    file: TransferredFile,
}

impl ExportedFile {
    pub(super) fn new(id: ResourceId, file: File, rights: OsResourceRights) -> Self {
        Self {
            id,
            file: TransferredFile { file, rights },
        }
    }

    /// Provider-session identity assigned to this export.
    pub fn id(&self) -> ResourceId {
        self.id
    }

    /// Rights granted to the calling host.
    pub fn rights(&self) -> OsResourceRights {
        self.file.rights()
    }
}

impl Read for ExportedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Write for ExportedFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for ExportedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

pub(super) fn validate_file_rights(file: &File, rights: OsResourceRights) -> Result<()> {
    validate_rights(rights)?;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        // SAFETY: fcntl reads flags from a live descriptor without retaining it.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let mode = flags & libc::O_ACCMODE;
        let native = match mode {
            libc::O_RDONLY => OsResourceRights::READ,
            libc::O_WRONLY => OsResourceRights::WRITE,
            libc::O_RDWR => OsResourceRights::READ | OsResourceRights::WRITE,
            _ => return Err(new_error!("File resource has an unknown access mode")),
        };
        if rights != native {
            return Err(new_error!(
                "Linux file resource rights must match the descriptor access mode"
            ));
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::ptr::null_mut;

        use windows_sys::Win32::Foundation::DuplicateHandle;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut duplicate = null_mut();
        let access = (if rights.contains(OsResourceRights::READ) {
            FILE_GENERIC_READ
        } else {
            0
        }) | (if rights.contains(OsResourceRights::WRITE) {
            FILE_GENERIC_WRITE
        } else {
            0
        });
        // SAFETY: Source and target processes are live. The output is adopted on success.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.as_raw_handle(),
                GetCurrentProcess(),
                &mut duplicate,
                access,
                0,
                0,
            )
        } == 0
        {
            return Err(new_error!(
                "File resource does not grant requested access: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: DuplicateHandle returned one owned handle.
        drop(unsafe { OwnedHandle::from_raw_handle(duplicate) });
    }

    Ok(())
}

fn validate_rights(rights: OsResourceRights) -> Result<()> {
    if rights.is_empty() || OsResourceRights::from_bits(rights.bits()).is_none() {
        return Err(new_error!("A process resource needs valid nonempty rights"));
    }
    Ok(())
}

fn validate_declarations(generation: u64, declarations: &[WireResourceDeclaration]) -> Result<()> {
    const MAX_RESOURCES: usize = 64;
    const MAX_METADATA: usize = 4096;

    if generation == 0 {
        return Err(new_error!("Process resource generation is invalid"));
    }
    if declarations.len() > MAX_RESOURCES {
        return Err(new_error!("Process resource declaration quota is exceeded"));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut session = None;
    for declaration in declarations {
        if declaration.generation != generation {
            return Err(new_error!(
                "Process resource declaration generation mismatch"
            ));
        }
        if declaration.metadata.len() > MAX_METADATA {
            return Err(new_error!(
                "Process resource declaration metadata is too large"
            ));
        }
        let current_session = (declaration.session_high, declaration.session_low);
        if session
            .replace(current_session)
            .is_some_and(|session| session != current_session)
        {
            return Err(new_error!(
                "Process resource declarations do not share one provider session"
            ));
        }
        if !ids.insert((
            declaration.session_high,
            declaration.session_low,
            declaration.slot,
            declaration.generation,
        )) {
            return Err(new_error!(
                "Process resource declaration identity is duplicated"
            ));
        }
        match declaration.kind {
            FILE_RESOURCE_KIND => {
                let bytes: [u8; 4] = declaration
                    .metadata
                    .as_slice()
                    .try_into()
                    .map_err(|_| new_error!("Process file resource metadata is invalid"))?;
                let rights = OsResourceRights::from_bits(u32::from_ne_bytes(bytes))
                    .ok_or_else(|| new_error!("Process file resource rights are invalid"))?;
                validate_rights(rights)?;
            }
            FIRST_TYPED_RESOURCE_KIND.. => {}
            _ => return Err(new_error!("Process resource kind is unknown")),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn duplicate_file(file: &File, rights: OsResourceRights) -> Result<File> {
    validate_file_rights(file, rights)?;
    Ok(file.try_clone()?)
}

#[cfg(windows)]
fn duplicate_file(file: &File, rights: OsResourceRights) -> Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut duplicate = null_mut();
    let access = (if rights.contains(OsResourceRights::READ) {
        FILE_GENERIC_READ
    } else {
        0
    }) | (if rights.contains(OsResourceRights::WRITE) {
        FILE_GENERIC_WRITE
    } else {
        0
    });
    // SAFETY: Source and target processes are live. The output is adopted on success.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            file.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            access,
            0,
            0,
        )
    } == 0
    {
        return Err(new_error!(
            "File resource duplication failed: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: DuplicateHandle returned one owned file handle.
    Ok(unsafe { File::from_raw_handle(duplicate) })
}

#[cfg(unix)]
fn duplicate_file_for_export(file: &File, rights: OsResourceRights) -> Result<File> {
    validate_file_contains_rights(file, rights)?;
    Ok(file.try_clone()?)
}

#[cfg(windows)]
fn duplicate_file_for_export(file: &File, rights: OsResourceRights) -> Result<File> {
    duplicate_file(file, rights)
}

pub(super) fn validate_file_contains_rights(file: &File, rights: OsResourceRights) -> Result<()> {
    validate_rights(rights)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        // SAFETY: fcntl reads flags from a live descriptor without retaining it.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags == -1 {
            return Err(io::Error::last_os_error().into());
        }
        let mode = flags & libc::O_ACCMODE;
        if rights.contains(OsResourceRights::READ) && mode == libc::O_WRONLY {
            return Err(new_error!("File export does not grant read access"));
        }
        if rights.contains(OsResourceRights::WRITE) && mode == libc::O_RDONLY {
            return Err(new_error!("File export does not grant write access"));
        }
    }
    #[cfg(windows)]
    {
        drop(duplicate_file(file, rights)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[cfg(windows)]
    fn object_handle_count(file: &File) -> u32 {
        use std::os::windows::io::AsRawHandle;

        #[repr(C)]
        #[derive(Default)]
        struct ObjectBasicInformation {
            attributes: u32,
            granted_access: u32,
            handle_count: u32,
            pointer_count: u32,
            paged_pool_charge: u32,
            non_paged_pool_charge: u32,
            reserved: [u32; 3],
            name_info_size: u32,
            type_info_size: u32,
            security_descriptor_size: u32,
            creation_time: i64,
        }

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(
                handle: *mut std::ffi::c_void,
                information_class: u32,
                information: *mut std::ffi::c_void,
                information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        let mut information = ObjectBasicInformation::default();
        let mut length = 0;
        // SAFETY: The live file handle and writable fixed-size output buffer are valid.
        let status = unsafe {
            NtQueryObject(
                file.as_raw_handle(),
                0,
                (&mut information as *mut ObjectBasicInformation).cast(),
                std::mem::size_of::<ObjectBasicInformation>() as u32,
                &mut length,
            )
        };
        assert!(status >= 0, "NtQueryObject failed with status {status:#x}");
        information.handle_count
    }

    struct MarkerFactory {
        calls: Arc<AtomicUsize>,
    }

    struct MarkerValidator;

    impl NativeResourceValidator for MarkerValidator {
        fn validate(&self, metadata: &[u8], payload: &NativeResourcePayload) -> Result<()> {
            if metadata != b"backend=marker"
                || !matches!(payload, NativeResourcePayload::AuthorizationMarker)
            {
                return Err(new_error!("Typed marker resource is invalid"));
            }
            Ok(())
        }
    }

    impl LaunchResourceFactory for MarkerFactory {
        fn create(&self, _generation: u64) -> Result<NativeResourcePayload> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NativeResourcePayload::AuthorizationMarker)
        }
    }

    fn wire_file(id: ResourceId, kind: u32, rights: u32, file: File) -> WireResource {
        WireResource {
            session_high: id.session_high,
            session_low: id.session_low,
            slot: id.slot,
            generation: id.generation,
            kind,
            metadata: rights.to_ne_bytes().to_vec(),
            payload: NativeResourcePayload::File(file),
        }
    }

    fn process_resources(
        resources: Vec<WireResource>,
        exporter: Option<mesh::Sender<ResourceExportRequest>>,
        generation: u64,
    ) -> Result<ProcessResources> {
        let declarations = resources
            .iter()
            .map(|resource| WireResourceDeclaration {
                session_high: resource.session_high,
                session_low: resource.session_low,
                slot: resource.slot,
                generation: resource.generation,
                kind: resource.kind,
                metadata: resource.metadata.clone(),
            })
            .collect::<Vec<_>>();
        ProcessResources::from_wire(resources, exporter, generation, &declarations)
    }

    #[test]
    fn rejects_stale_generation_and_missing_rights() {
        let file = tempfile::tempfile().unwrap();
        let id = ResourceId::new(7, 3, 11);
        let mut resources = process_resources(
            vec![wire_file(
                id,
                FILE_RESOURCE_KIND,
                OsResourceRights::READ.bits(),
                file,
            )],
            None,
            id.generation,
        )
        .unwrap();
        let stale = ResourceId {
            generation: id.generation - 1,
            ..id
        };
        assert!(resources.take_file(stale, OsResourceRights::READ).is_err());
        assert!(resources.take_file(id, OsResourceRights::WRITE).is_err());
        assert!(resources.take_file(id, OsResourceRights::empty()).is_err());
        assert!(resources.take_file(id, OsResourceRights::READ).is_ok());
    }

    #[test]
    fn typed_resource_requires_exact_kind_and_is_consumed_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let id = ResourceId::new(9, 4, 0);
        let registered = RegisteredResource::typed(
            id,
            FIRST_TYPED_RESOURCE_KIND,
            b"backend=marker".to_vec(),
            Arc::new(MarkerFactory {
                calls: calls.clone(),
            }),
        )
        .unwrap();
        let declaration = registered.declaration(7);
        ProcessResourceManifest::new()
            .with_typed(
                FIRST_TYPED_RESOURCE_KIND,
                b"backend=marker".to_vec(),
                Arc::new(MarkerValidator),
            )
            .unwrap()
            .validate(7, std::slice::from_ref(&declaration), None)
            .unwrap();
        let wire = registered.instantiate(7).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        ProcessResourceManifest::new()
            .with_typed(
                FIRST_TYPED_RESOURCE_KIND,
                b"backend=marker".to_vec(),
                Arc::new(MarkerValidator),
            )
            .unwrap()
            .validate_payloads(std::slice::from_ref(&wire), false)
            .unwrap();
        let mut resources =
            ProcessResources::from_wire(vec![wire], None, 7, std::slice::from_ref(&declaration))
                .unwrap();
        let actual_id = ResourceId {
            generation: 7,
            ..id
        };
        assert!(
            resources
                .take_typed(actual_id, FIRST_TYPED_RESOURCE_KIND + 1)
                .is_err()
        );
        let claimed = resources
            .take_typed(actual_id, FIRST_TYPED_RESOURCE_KIND)
            .unwrap();
        assert_eq!(claimed.metadata, b"backend=marker");
        assert!(matches!(
            claimed.payload,
            NativeResourcePayload::AuthorizationMarker
        ));
        assert!(
            resources
                .take_typed(actual_id, FIRST_TYPED_RESOURCE_KIND)
                .is_err()
        );
    }

    #[test]
    fn typed_payload_validation_rejects_missing_surplus_and_wrong_metadata() {
        let manifest = ProcessResourceManifest::new()
            .with_typed(
                FIRST_TYPED_RESOURCE_KIND,
                b"backend=marker".to_vec(),
                Arc::new(MarkerValidator),
            )
            .unwrap();
        assert!(manifest.validate_payloads(&[], false).is_err());

        let resource = WireResource {
            session_high: 1,
            session_low: 2,
            slot: 0,
            generation: 3,
            kind: FIRST_TYPED_RESOURCE_KIND,
            metadata: b"backend=marker".to_vec(),
            payload: NativeResourcePayload::AuthorizationMarker,
        };
        let surplus = WireResource {
            session_high: 1,
            session_low: 2,
            slot: 1,
            generation: 3,
            kind: FIRST_TYPED_RESOURCE_KIND,
            metadata: b"backend=marker".to_vec(),
            payload: NativeResourcePayload::AuthorizationMarker,
        };
        assert!(
            manifest
                .validate_payloads(&[resource, surplus], false)
                .is_err()
        );

        let declaration = WireResourceDeclaration {
            session_high: 1,
            session_low: 2,
            slot: 0,
            generation: 3,
            kind: FIRST_TYPED_RESOURCE_KIND,
            metadata: b"backend=wrong".to_vec(),
        };
        assert!(
            manifest
                .validate(3, std::slice::from_ref(&declaration), None)
                .is_err()
        );
    }

    #[test]
    fn rejected_typed_native_payload_is_closed() {
        let manifest = ProcessResourceManifest::new()
            .with_typed(
                FIRST_TYPED_RESOURCE_KIND,
                b"backend=marker".to_vec(),
                Arc::new(MarkerValidator),
            )
            .unwrap();

        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, OwnedFd};

            let descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
            let raw = descriptor.as_raw_fd();
            let resources = vec![WireResource {
                session_high: 1,
                session_low: 2,
                slot: 0,
                generation: 3,
                kind: FIRST_TYPED_RESOURCE_KIND,
                metadata: b"backend=marker".to_vec(),
                payload: NativeResourcePayload::Descriptor(descriptor),
            }];
            assert!(manifest.validate_payloads(&resources, false).is_err());
            drop(resources);
            // SAFETY: fcntl only probes whether the stale numeric descriptor remains live.
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::OwnedHandle;

            let source = tempfile::tempfile().unwrap();
            let baseline_handles = object_handle_count(&source);
            let handle: OwnedHandle = source.try_clone().unwrap().into();
            let resources = vec![WireResource {
                session_high: 1,
                session_low: 2,
                slot: 0,
                generation: 3,
                kind: FIRST_TYPED_RESOURCE_KIND,
                metadata: b"backend=marker".to_vec(),
                payload: NativeResourcePayload::Handle(handle),
            }];
            assert!(manifest.validate_payloads(&resources, false).is_err());
            drop(resources);
            assert_eq!(object_handle_count(&source), baseline_handles);
        }
    }

    #[test]
    fn wrapper_enforces_declared_rights() {
        let mut file = TransferredFile {
            file: tempfile::tempfile().unwrap(),
            rights: OsResourceRights::READ,
        };
        assert_eq!(
            file.write_all(b"denied").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn export_requires_authority_without_consuming_source() {
        let resources = process_resources(vec![], None, 1).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        source.write_all(b"retained").unwrap();
        assert!(
            resources
                .export_file(&source, OsResourceRights::READ)
                .unwrap_err()
                .to_string()
                .contains("no resource export authority")
        );
        source.write_all(b"-writable").unwrap();
    }

    #[test]
    fn export_policy_rejects_empty_rights_and_zero_quota() {
        assert!(OsResourceExportPolicy::files(OsResourceRights::empty(), 1).is_err());
        assert!(OsResourceExportPolicy::files(OsResourceRights::READ, 0).is_err());
    }

    #[test]
    fn denied_export_closes_duplicate_and_preserves_source() {
        #[cfg(unix)]
        use std::sync::atomic::{AtomicI64, Ordering};

        struct RejectingSink {
            #[cfg(unix)]
            raw: AtomicI64,
        }

        impl ResourceExportSink for RejectingSink {
            fn begin_generation(&self, _process_name: &str, _generation: u64) -> Result<()> {
                Ok(())
            }

            fn accept_file(
                &self,
                _process_name: &str,
                _generation: u64,
                file: WireExportFile,
            ) -> Result<ResourceId> {
                #[cfg(unix)]
                {
                    use std::os::fd::AsRawFd;
                    self.raw
                        .store(file.file.as_raw_fd().into(), Ordering::SeqCst);
                }
                #[cfg(windows)]
                {
                    let _ = &file;
                }
                Err(new_error!("policy denial"))
            }

            fn end_generation(&self, _process_name: &str, _generation: u64) {}
        }

        let sink = Arc::new(RejectingSink {
            #[cfg(unix)]
            raw: AtomicI64::new(-1),
        });
        let authority = ExportAuthority::new(
            "worker".to_owned(),
            OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            sink.clone(),
        );
        let (sender, mut handler) = authority.start(1).unwrap();
        let resources = process_resources(vec![], Some(sender), 1).unwrap();
        let mut source = tempfile::tempfile().unwrap();
        #[cfg(windows)]
        let baseline_handles = object_handle_count(&source);
        assert!(
            resources
                .export_file(&source, OsResourceRights::READ)
                .unwrap_err()
                .to_string()
                .contains("policy denial")
        );
        source.write_all(b"source retained").unwrap();
        drop(resources);
        handler.stop();
        handler
            .join(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();

        #[cfg(unix)]
        {
            let raw = sink.raw.load(Ordering::SeqCst);
            // SAFETY: fcntl only probes whether the stale numeric descriptor remains live.
            assert_eq!(unsafe { libc::fcntl(raw as i32, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
        #[cfg(windows)]
        {
            assert_eq!(object_handle_count(&source), baseline_handles);
        }
    }

    #[test]
    fn export_handler_stops_while_remote_sender_remains_open() {
        struct Sink;

        impl ResourceExportSink for Sink {
            fn begin_generation(&self, _process_name: &str, _generation: u64) -> Result<()> {
                Ok(())
            }

            fn accept_file(
                &self,
                _process_name: &str,
                _generation: u64,
                _file: WireExportFile,
            ) -> Result<ResourceId> {
                unreachable!()
            }

            fn end_generation(&self, _process_name: &str, _generation: u64) {}
        }

        let authority = ExportAuthority::new(
            "worker".to_owned(),
            OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            Arc::new(Sink),
        );
        let (sender, mut handler) = authority.start(1).unwrap();
        handler.stop();
        handler
            .join(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();
        drop(sender);
    }

    #[test]
    fn export_handler_panic_ends_generation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PanickingSink {
            ended: AtomicBool,
        }

        impl ResourceExportSink for PanickingSink {
            fn begin_generation(&self, _process_name: &str, _generation: u64) -> Result<()> {
                Ok(())
            }

            fn accept_file(
                &self,
                _process_name: &str,
                _generation: u64,
                _file: WireExportFile,
            ) -> Result<ResourceId> {
                panic!("intentional export handler panic")
            }

            fn end_generation(&self, _process_name: &str, _generation: u64) {
                self.ended.store(true, Ordering::SeqCst);
            }
        }

        let sink = Arc::new(PanickingSink {
            ended: AtomicBool::new(false),
        });
        let authority = ExportAuthority::new(
            "worker".to_owned(),
            OsResourceExportPolicy::files(OsResourceRights::READ, 1).unwrap(),
            sink.clone(),
        );
        let (sender, mut handler) = authority.start(1).unwrap();
        let resources = process_resources(vec![], Some(sender), 1).unwrap();
        assert!(
            resources
                .export_file(&tempfile::tempfile().unwrap(), OsResourceRights::READ)
                .is_err()
        );
        assert!(
            handler
                .join(std::time::Instant::now() + std::time::Duration::from_secs(1))
                .unwrap_err()
                .to_string()
                .contains("panicked")
        );
        assert!(sink.ended.load(Ordering::SeqCst));
    }

    #[test]
    fn exported_file_closes_native_object_when_dropped() {
        #[cfg(unix)]
        let exported = ExportedFile::new(
            ResourceId::new(21, 0, 1),
            tempfile::tempfile().unwrap(),
            OsResourceRights::READ,
        );
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            let raw = exported.file.file.as_raw_fd();
            drop(exported);
            // SAFETY: fcntl only probes whether the stale numeric descriptor remains live.
            assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
        #[cfg(windows)]
        {
            let source = tempfile::tempfile().unwrap();
            let baseline_handles = object_handle_count(&source);
            let exported = ExportedFile::new(
                ResourceId::new(21, 0, 1),
                source.try_clone().unwrap(),
                OsResourceRights::READ,
            );
            drop(exported);
            assert_eq!(object_handle_count(&source), baseline_handles);
        }
    }

    #[test]
    fn rejects_mixed_resource_generations() {
        let first = ResourceId::new(7, 0, 1);
        let second = ResourceId::new(7, 1, 2);
        let result = process_resources(
            vec![
                wire_file(
                    first,
                    FILE_RESOURCE_KIND,
                    (OsResourceRights::READ | OsResourceRights::WRITE).bits(),
                    tempfile::tempfile().unwrap(),
                ),
                wire_file(
                    second,
                    FILE_RESOURCE_KIND,
                    (OsResourceRights::READ | OsResourceRights::WRITE).bits(),
                    tempfile::tempfile().unwrap(),
                ),
            ],
            None,
            1,
        );
        let error = match result {
            Ok(_) => panic!("mixed generations must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("generation mismatch"));
    }

    #[test]
    fn rejects_invalid_wire_metadata() {
        for (kind, rights, generation, expected) in [
            (99, OsResourceRights::READ.bits(), 1, "unknown kind"),
            (1, u32::MAX, 1, "rights are invalid"),
            (1, OsResourceRights::READ.bits(), 0, "generation mismatch"),
        ] {
            let result = process_resources(
                vec![wire_file(
                    ResourceId::new(7, 0, generation),
                    kind,
                    rights,
                    tempfile::tempfile().unwrap(),
                )],
                None,
                generation.max(1),
            );
            let error = match result {
                Ok(_) => panic!("invalid wire metadata must fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected), "{expected}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_requires_declared_rights_to_match_descriptor_access() {
        let file = tempfile::tempfile().unwrap();
        assert!(
            validate_file_rights(&file, OsResourceRights::READ)
                .unwrap_err()
                .to_string()
                .contains("must match")
        );
        validate_file_rights(&file, OsResourceRights::READ | OsResourceRights::WRITE).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_duplicate_reduces_native_file_access() {
        let source = tempfile::tempfile().unwrap();
        let mut duplicate = duplicate_file(&source, OsResourceRights::READ).unwrap();
        assert!(duplicate.write_all(b"denied").is_err());
    }

    fn registered_file() -> RegisteredResource {
        RegisteredResource::file(
            ResourceId::new(7, 0, 1),
            tempfile::tempfile().unwrap(),
            OsResourceRights::READ | OsResourceRights::WRITE,
        )
    }

    #[cfg(unix)]
    #[test]
    fn wire_duplicate_closes_descriptor_when_dropped() {
        use std::os::fd::AsRawFd;

        let registered = registered_file();
        let wire = registered.instantiate(1).unwrap();
        let NativeResourcePayload::File(file) = &wire.payload else {
            panic!("file registration must create a file payload");
        };
        let raw = file.as_raw_fd();
        drop(wire);

        // SAFETY: fcntl only probes whether the numeric descriptor remains live.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[cfg(windows)]
    #[test]
    fn wire_duplicate_closes_handle_when_dropped() {
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, GetHandleInformation};

        let registered = registered_file();
        let wire = registered.instantiate(1).unwrap();
        let NativeResourcePayload::File(file) = &wire.payload else {
            panic!("file registration must create a file payload");
        };
        let raw = file.as_raw_handle();
        drop(wire);

        let mut flags = 0;
        // SAFETY: GetHandleInformation only probes the stale numeric handle value.
        assert_eq!(unsafe { GetHandleInformation(raw, &mut flags) }, 0);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_INVALID_HANDLE as i32)
        );
    }
}
