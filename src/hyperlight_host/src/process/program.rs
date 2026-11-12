// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Immutable native program identities and an offline OCI layout store.
//!
//! Packaging is explicit. Validation reads the complete local closure and returns
//! owned bytes, never a mutable executable path. Launchers must preserve those
//! bytes and enforce process restrictions before execution.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageIndex, ImageIndexBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::sandbox::snapshot::OciDigest;
use crate::sandbox::snapshot::file::config::{ParameterTypeRepr, ReturnTypeRepr};
use crate::sandbox::snapshot::file::digest::{Digest256, oci_digest, verify_blob_bytes};
use crate::sandbox::snapshot::file::fsutil::{
    put_blob_if_absent, read_bounded, reject_symlink, replace_file_atomic,
};
use crate::{Result, new_error};

/// Config schema for a single native executable with host-provided OS dependencies.
pub const PROGRAM_CONFIG_V1: &str = "application/vnd.hyperlight.program.config.v1+json";
/// Raw native executable bytes. This layer is not a filesystem archive.
pub const PROGRAM_EXECUTABLE_V1: &str = "application/vnd.hyperlight.program.executable.v1";
/// Raw immutable runtime-file bytes. This layer is not a filesystem archive.
pub const PROGRAM_RUNTIME_FILE_V1: &str = "application/vnd.hyperlight.program.runtime-file.v1";
/// Absolute image path authenticated by the enclosing manifest digest.
pub const PROGRAM_IMAGE_PATH: &str = "io.hyperlight.program.image-path";

const MAX_JSON_SIZE: u64 = 1024 * 1024;
const MAX_EXECUTABLE_SIZE: u64 = 256 * 1024 * 1024;

/// Owned runtime content at a normalized absolute image path, never a host path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramFile {
    image_path: String,
    bytes: Vec<u8>,
}

impl ProgramFile {
    /// Rejects noncanonical paths, reserved trees and oversized content.
    pub fn new(image_path: impl Into<String>, bytes: Vec<u8>) -> Result<Self> {
        let image_path = image_path.into();
        validate_image_path(&image_path)?;
        add_file_size(0, bytes.len() as u64)?;
        Ok(Self { image_path, bytes })
    }

    /// Path in the program image namespace.
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Immutable content for protected staging.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A manifest descriptor, independent of any store location or mutable tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Descriptor", into = "Descriptor")]
pub struct ProgramArtifact(Descriptor);

impl ProgramArtifact {
    /// Checks identity syntax without accessing a store.
    pub fn from_descriptor(descriptor: Descriptor) -> Result<Self> {
        check_descriptor(&descriptor, &MediaType::ImageManifest, MAX_JSON_SIZE)?;
        Ok(Self(descriptor))
    }

    /// The immutable root of the manifest/config/executable/runtime closure.
    pub fn descriptor(&self) -> &Descriptor {
        &self.0
    }

    /// Canonical sha256 manifest identity.
    pub fn digest(&self) -> OciDigest {
        // The constructor and serde conversion validate the same grammar.
        OciDigest::from_oci_spec_digest(self.0.digest())
    }
}

impl TryFrom<Descriptor> for ProgramArtifact {
    type Error = crate::HyperlightError;

    fn try_from(value: Descriptor) -> Result<Self> {
        Self::from_descriptor(value)
    }
}

impl From<ProgramArtifact> for Descriptor {
    fn from(value: ProgramArtifact) -> Self {
        value.0
    }
}

/// Native program entrypoint protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRole {
    /// Runs the sandbox and its guest.
    SandboxHost,
    /// Runs a declared group of host functions.
    FunctionWorker,
}

/// Exact runtime requirements, supplied by the packager and checked by the host.
///
/// Dependency versions are exact strings, not ranges. The launcher supplies a
/// trusted inventory of available OS dependencies. These declarations do not
/// install dependencies or attest to the inventory's accuracy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramTarget {
    /// Rust OS name, such as `windows`, `linux`, or `macos`.
    pub os: String,
    /// Rust architecture name, such as `x86_64` or `aarch64`.
    pub architecture: String,
    /// ABI environment, such as `msvc`, `gnu`, `musl`, or `darwin`.
    pub environment: String,
    /// Host-provided runtime libraries or OS contracts and their exact versions.
    pub os_dependencies: BTreeMap<String, String>,
}

impl ProgramTarget {
    /// Uses the compiling host's platform and an explicitly verified OS inventory.
    pub fn current(os_dependencies: BTreeMap<String, String>) -> Self {
        let environment = if cfg!(target_env = "msvc") {
            "msvc"
        } else if cfg!(target_env = "gnu") {
            "gnu"
        } else if cfg!(target_env = "musl") {
            "musl"
        } else if cfg!(target_os = "macos") {
            "darwin"
        } else {
            "unknown"
        };
        Self {
            os: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            environment: environment.into(),
            os_dependencies,
        }
    }

    fn validate(&self) -> Result<()> {
        let valid_platform = matches!(
            (self.os.as_str(), self.environment.as_str()),
            ("windows", "msvc") | ("linux", "gnu" | "musl") | ("macos", "darwin")
        ) && matches!(self.architecture.as_str(), "x86_64" | "aarch64");
        if !valid_platform {
            return Err(new_error!("Unsupported native program target"));
        }
        for (name, version) in &self.os_dependencies {
            if name.trim().is_empty()
                || version.trim().is_empty()
                || name.chars().any(char::is_control)
                || version.chars().any(char::is_control)
            {
                return Err(new_error!(
                    "OS dependency names and versions must be explicit"
                ));
            }
        }
        Ok(())
    }

    fn require_available(&self, available: &Self) -> Result<()> {
        self.validate()?;
        available.validate()?;
        if self.os != available.os
            || self.architecture != available.architecture
            || self.environment != available.environment
        {
            return Err(new_error!("Native program target does not match runtime"));
        }
        for (name, version) in &self.os_dependencies {
            if available.os_dependencies.get(name) != Some(version) {
                return Err(new_error!(
                    "Missing OS dependency {} at version {}",
                    name,
                    version
                ));
            }
        }
        Ok(())
    }
}

/// Versioned native program definition, committed by the manifest digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramConfig {
    /// Currently `1`.
    pub schema_version: u32,
    /// Protocol exposed by this native executable.
    pub role: ProgramRole,
    /// Platform and OS dependencies required before execution.
    pub target: ProgramTarget,
    /// Exact worker contracts exported by this executable, including idempotency.
    pub functions: Vec<FunctionContractDefinition>,
}

impl ProgramConfig {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(new_error!(
                "Unsupported native program schema {}",
                self.schema_version
            ));
        }
        self.target.validate()?;
        if self.role == ProgramRole::FunctionWorker && self.functions.is_empty() {
            return Err(new_error!("Native program role and contracts disagree"));
        }
        let mut names = BTreeSet::new();
        for function in &self.functions {
            if function.name.is_empty() || !names.insert(&function.name) {
                return Err(new_error!("Duplicate or empty native program contract"));
            }
        }
        Ok(())
    }
}

/// Verified owned content, suitable for a launcher's protected staging area.
#[derive(Debug)]
pub struct ValidatedProgram {
    artifact: ProgramArtifact,
    config: ProgramConfig,
    executable: Vec<u8>,
    runtime_files: Vec<ProgramFile>,
}

impl ValidatedProgram {
    /// Identity verified against the complete local closure.
    pub fn artifact(&self) -> &ProgramArtifact {
        &self.artifact
    }

    /// Verified requirements and program role.
    pub fn config(&self) -> &ProgramConfig {
        &self.config
    }

    /// Executable content. Launchers must not reopen the original store path.
    pub fn executable(&self) -> &[u8] {
        &self.executable
    }

    /// Verified explicit runtime content. No host files are resolved.
    pub fn runtime_files(&self) -> &[ProgramFile] {
        &self.runtime_files
    }
}

/// An explicitly selected filesystem OCI layout. It never contacts a registry.
#[derive(Clone, Debug)]
pub struct LocalProgramStore {
    root: PathBuf,
}

struct Closure {
    config: ProgramConfig,
    blobs: Vec<(Descriptor, Vec<u8>)>,
}

impl LocalProgramStore {
    /// Selects a store without creating it or reading any files.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { root: path.into() }
    }

    /// Explicitly packages one executable. Shared blobs are content-deduplicated.
    pub fn package(&self, config: &ProgramConfig, executable: &[u8]) -> Result<ProgramArtifact> {
        self.package_with_runtime(config, executable, &[])
    }

    /// Packages an executable and explicit runtime files within one aggregate byte limit.
    pub fn package_with_runtime(
        &self,
        config: &ProgramConfig,
        executable: &[u8],
        runtime_files: &[ProgramFile],
    ) -> Result<ProgramArtifact> {
        config.validate()?;
        if executable.is_empty() || executable.len() as u64 > MAX_EXECUTABLE_SIZE {
            return Err(new_error!(
                "Native executable size is outside the supported bounds"
            ));
        }
        validate_image_paths(runtime_files.iter().map(|file| file.image_path()))?;
        let mut total = executable.len() as u64;
        for file in runtime_files {
            total = add_file_size(total, file.bytes.len() as u64)?;
        }
        let config_bytes = json_bytes(config)?;
        let config_descriptor = descriptor(PROGRAM_CONFIG_V1.into(), &config_bytes)?;
        let executable_descriptor = descriptor(PROGRAM_EXECUTABLE_V1.into(), executable)?;
        let mut layers = vec![executable_descriptor];
        for file in runtime_files {
            let mut layer = descriptor(PROGRAM_RUNTIME_FILE_V1.into(), &file.bytes)?;
            layer.set_annotations(Some(
                [(PROGRAM_IMAGE_PATH.to_owned(), file.image_path.clone())]
                    .into_iter()
                    .collect(),
            ));
            layers.push(layer);
        }
        let manifest = ImageManifestBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::Other(PROGRAM_CONFIG_V1.into()))
            .config(config_descriptor.clone())
            .layers(layers.clone())
            .build()
            .map_err(|e| new_error!("Invalid program manifest: {}", e))?;
        let manifest_bytes = json_bytes(&manifest)?;
        let artifact = ProgramArtifact::from_descriptor(descriptor(
            MediaType::ImageManifest,
            &manifest_bytes,
        )?)?;
        let mut blobs = vec![(config_descriptor, config_bytes)];
        blobs.push((layers[0].clone(), executable.to_vec()));
        blobs.extend(
            layers
                .into_iter()
                .skip(1)
                .zip(runtime_files)
                .map(|(layer, file)| (layer, file.bytes.clone())),
        );
        blobs.push((artifact.0.clone(), manifest_bytes));
        self.write_blobs(&blobs)?;
        self.publish_descriptor(&artifact)?;
        Ok(artifact)
    }

    /// Validates all local blobs and runtime requirements without executing code.
    pub fn validate(
        &self,
        artifact: &ProgramArtifact,
        available: &ProgramTarget,
    ) -> Result<ValidatedProgram> {
        let closure = self.read_closure(artifact)?;
        closure.config.target.require_available(available)?;
        let mut layers = closure.blobs.into_iter().skip(2);
        let (_, executable) = layers
            .next()
            .ok_or_else(|| new_error!("Native executable layer is missing"))?;
        let runtime_files = layers
            .map(|(desc, bytes)| ProgramFile::new(runtime_image_path(&desc)?, bytes))
            .collect::<Result<Vec<_>>>()?;
        Ok(ValidatedProgram {
            artifact: artifact.clone(),
            config: closure.config,
            executable,
            runtime_files,
        })
    }

    /// Copies complete verified closures to another layout, once per manifest.
    ///
    /// No target compatibility is required for export. The destination may be
    /// transported to another OS. Execution still requires `validate`.
    pub fn export(
        &self,
        artifacts: &[ProgramArtifact],
        destination: &LocalProgramStore,
    ) -> Result<()> {
        let mut seen = BTreeMap::new();
        for artifact in artifacts {
            if let Some(previous) =
                seen.insert(artifact.digest().to_string(), artifact.descriptor())
            {
                if previous != artifact.descriptor() {
                    return Err(new_error!(
                        "Conflicting descriptors for one native program digest"
                    ));
                }
            } else {
                let closure = self.read_closure(artifact)?;
                destination.write_blobs(&closure.blobs)?;
                destination.publish_descriptor(artifact)?;
            }
        }
        Ok(())
    }

    fn read_closure(&self, artifact: &ProgramArtifact) -> Result<Closure> {
        self.check_layout()?;
        let manifest_bytes =
            self.read_blob(&artifact.0, &MediaType::ImageManifest, MAX_JSON_SIZE)?;
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| new_error!("Invalid native program manifest JSON: {}", e))?;
        let config_media = MediaType::Other(PROGRAM_CONFIG_V1.into());
        if manifest.schema_version() != SCHEMA_VERSION
            || manifest.media_type().as_ref() != Some(&MediaType::ImageManifest)
            || manifest.artifact_type().as_ref() != Some(&config_media)
            || manifest.subject().is_some()
            || manifest.layers().is_empty()
        {
            return Err(new_error!("Unsupported native program manifest shape"));
        }
        // Check all declared sizes and paths before allocating any file content.
        let mut total = 0;
        for (index, layer) in manifest.layers().iter().enumerate() {
            let media = if index == 0 {
                PROGRAM_EXECUTABLE_V1
            } else {
                PROGRAM_RUNTIME_FILE_V1
            };
            check_descriptor(layer, &media.into(), MAX_EXECUTABLE_SIZE)?;
            total = add_file_size(total, layer.size())?;
        }
        let paths = manifest.layers()[1..]
            .iter()
            .map(runtime_image_path)
            .collect::<Result<Vec<_>>>()?;
        validate_image_paths(paths.into_iter())?;
        let config_bytes = self.read_blob(manifest.config(), &config_media, MAX_JSON_SIZE)?;
        let config: ProgramConfig = serde_json::from_slice(&config_bytes)
            .map_err(|e| new_error!("Invalid native program config JSON: {}", e))?;
        config.validate()?;
        let mut blobs = vec![
            (artifact.0.clone(), manifest_bytes),
            (manifest.config().clone(), config_bytes),
        ];
        for layer in manifest.layers() {
            let bytes = self.read_blob(layer, layer.media_type(), MAX_EXECUTABLE_SIZE)?;
            blobs.push((layer.clone(), bytes));
        }
        Ok(Closure { config, blobs })
    }

    fn read_blob(&self, desc: &Descriptor, media: &MediaType, limit: u64) -> Result<Vec<u8>> {
        let digest = check_descriptor(desc, media, limit)?;
        let bytes = read_bounded(&self.blobs_dir().join(digest_hex(&digest)), desc.size())?;
        if bytes.len() as u64 != desc.size() {
            return Err(new_error!("Native program blob size mismatch"));
        }
        verify_blob_bytes("native program", &bytes, digest_hex(&digest))?;
        Ok(bytes)
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs").join("sha256")
    }

    fn check_directories(&self) -> Result<()> {
        for path in [&self.root, &self.root.join("blobs"), &self.blobs_dir()] {
            reject_symlink(path)?;
        }
        Ok(())
    }

    fn check_layout(&self) -> Result<()> {
        self.check_directories()?;
        let bytes = read_bounded(&self.root.join("oci-layout"), MAX_JSON_SIZE)?;
        let marker: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| new_error!("Invalid program OCI layout marker: {}", e))?;
        if marker["imageLayoutVersion"] != "1.0.0" {
            return Err(new_error!("Unsupported program OCI layout version"));
        }
        Ok(())
    }

    fn write_blobs(&self, blobs: &[(Descriptor, Vec<u8>)]) -> Result<()> {
        self.check_directories()?;
        if self
            .root
            .join("oci-layout")
            .try_exists()
            .map_err(|e| new_error!("{}", e))?
        {
            self.check_layout()?;
        } else if self.root.exists()
            && std::fs::read_dir(&self.root)
                .map_err(|e| new_error!("{}", e))?
                .next()
                .is_some()
        {
            return Err(new_error!(
                "Program store is not an empty directory or OCI layout"
            ));
        }
        std::fs::create_dir_all(self.blobs_dir()).map_err(|e| new_error!("{}", e))?;
        for (desc, bytes) in blobs {
            let hash = Digest256::from_bytes(bytes);
            if desc.digest().to_string() != format!("sha256:{}", hash.hex)
                || desc.size() != bytes.len() as u64
            {
                return Err(new_error!("Program export descriptor mismatch"));
            }
            put_blob_if_absent(&self.blobs_dir(), &hash, bytes)?;
        }
        replace_file_atomic(
            &self.root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
    }

    fn publish_descriptor(&self, artifact: &ProgramArtifact) -> Result<()> {
        let index_path = self.root.join("index.json");
        let mut manifests = if index_path.try_exists().map_err(|e| new_error!("{}", e))? {
            let bytes = read_bounded(&index_path, MAX_JSON_SIZE)?;
            let index: ImageIndex = serde_json::from_slice(&bytes)
                .map_err(|e| new_error!("Invalid OCI program index: {}", e))?;
            if index.schema_version() != SCHEMA_VERSION
                || index
                    .media_type()
                    .as_ref()
                    .is_some_and(|m| m != &MediaType::ImageIndex)
            {
                return Err(new_error!("Unsupported OCI program index"));
            }
            index.manifests().to_vec()
        } else {
            Vec::new()
        };
        if !manifests.iter().any(|d| d == &artifact.0) {
            manifests.push(artifact.0.clone());
        }
        let index = ImageIndexBuilder::default()
            .schema_version(SCHEMA_VERSION)
            .media_type(MediaType::ImageIndex)
            .manifests(manifests)
            .build()
            .map_err(|e| new_error!("Invalid OCI program index: {}", e))?;
        replace_file_atomic(&index_path, &json_bytes(&index)?)
    }
}

fn check_descriptor(desc: &Descriptor, media: &MediaType, limit: u64) -> Result<OciDigest> {
    let digest: OciDigest = desc.digest().to_string().parse()?;
    if desc.media_type() != media
        || (desc.size() == 0 && media != &MediaType::Other(PROGRAM_RUNTIME_FILE_V1.into()))
        || desc.size() > limit
    {
        return Err(new_error!(
            "Unsupported native program descriptor media type or size"
        ));
    }
    if desc.urls().as_ref().is_some_and(|v| !v.is_empty()) || desc.data().is_some() {
        return Err(new_error!(
            "Native program descriptors must use local content blobs"
        ));
    }
    Ok(digest)
}

fn add_file_size(total: u64, size: u64) -> Result<u64> {
    total
        .checked_add(size)
        .filter(|total| *total <= MAX_EXECUTABLE_SIZE)
        .ok_or_else(|| new_error!("Native program aggregate file size exceeds limit"))
}

fn runtime_image_path(desc: &Descriptor) -> Result<&str> {
    desc.annotations()
        .as_ref()
        .and_then(|annotations| annotations.get(PROGRAM_IMAGE_PATH))
        .map(String::as_str)
        .ok_or_else(|| new_error!("Runtime file is missing its image path annotation"))
}

fn validate_image_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path[1..]
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
        || matches!(
            path.split('/').nth(1),
            Some("program" | "proc" | "sys" | "dev")
        )
    {
        return Err(new_error!("Invalid or reserved runtime image path"));
    }
    Ok(())
}

fn validate_image_paths<'a>(paths: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for path in paths {
        validate_image_path(path)?;
        if !seen.insert(path) {
            return Err(new_error!("Duplicate runtime image path"));
        }
    }
    for path in &seen {
        for (index, _) in path.match_indices('/').skip(1) {
            if seen.contains(&path[..index]) {
                return Err(new_error!("Conflicting runtime file and directory paths"));
            }
        }
    }
    Ok(())
}

fn digest_hex(digest: &OciDigest) -> &str {
    &digest.as_str()["sha256:".len()..]
}

fn descriptor(media: MediaType, bytes: &[u8]) -> Result<Descriptor> {
    DescriptorBuilder::default()
        .media_type(media)
        .digest(oci_digest(&Digest256::from_bytes(bytes))?)
        .size(bytes.len() as u64)
        .build()
        .map_err(|e| new_error!("Invalid program descriptor: {}", e))
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|e| new_error!("Invalid program JSON: {}", e))?;
    if bytes.len() as u64 > MAX_JSON_SIZE {
        return Err(new_error!("Native program JSON exceeds size limit"));
    }
    Ok(bytes)
}

/// Owned contract metadata. It contains no executable callbacks or replay state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionContractDefinition {
    name: String,
    parameters: Vec<ParameterTypeRepr>,
    output: ReturnTypeRepr,
    idempotency: IdempotencyDefinition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdempotencyDefinition {
    Unspecified,
    NonIdempotent,
    Idempotent,
}

impl FunctionContractDefinition {
    pub(super) fn from_definition(definition: &super::FunctionDefinition) -> Self {
        Self {
            name: definition.name.to_owned(),
            parameters: definition.parameters.iter().map(Into::into).collect(),
            output: (&definition.output).into(),
            idempotency: match definition.idempotency {
                super::Idempotency::Unspecified => IdempotencyDefinition::Unspecified,
                super::Idempotency::NonIdempotent => IdempotencyDefinition::NonIdempotent,
                super::Idempotency::Idempotent => IdempotencyDefinition::Idempotent,
            },
        }
    }

    /// Captures a trusted typed declaration without invoking its implementation.
    pub fn from_contract<A, O>(contract: &super::HostFunctionContract<A, O>) -> Self {
        Self::from_definition(&contract.definition)
    }

    /// Function name owned by this program.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Declared guest ABI parameter types.
    pub fn parameters(&self) -> Vec<super::ParameterType> {
        self.parameters.iter().copied().map(Into::into).collect()
    }

    /// Declared guest ABI result type.
    pub fn output(&self) -> super::ReturnType {
        self.output.into()
    }

    /// Trusted replay classification, not a replay instruction.
    pub fn idempotency(&self) -> super::Idempotency {
        match self.idempotency {
            IdempotencyDefinition::Unspecified => super::Idempotency::Unspecified,
            IdempotencyDefinition::NonIdempotent => super::Idempotency::NonIdempotent,
            IdempotencyDefinition::Idempotent => super::Idempotency::Idempotent,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ControlDefinition {
    MemoryLimit(u64),
    CpuBudget { quota: Duration, period: Duration },
    DenyNetwork,
    DenyChildProcesses,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequirement {
    control: ControlDefinition,
    required: bool,
}

impl From<&super::RequestedControl> for ControlRequirement {
    fn from(request: &super::RequestedControl) -> Self {
        Self {
            control: match request.control {
                super::ProcessControl::MemoryLimit(bytes) => ControlDefinition::MemoryLimit(bytes),
                super::ProcessControl::CpuBudget { quota, period } => {
                    ControlDefinition::CpuBudget { quota, period }
                }
                super::ProcessControl::DenyNetwork => ControlDefinition::DenyNetwork,
                super::ProcessControl::DenyChildProcesses => ControlDefinition::DenyChildProcesses,
            },
            required: request.required,
        }
    }
}

/// Definition of one owned process, including programs that have never started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessDefinition {
    name: String,
    program: ProgramArtifact,
    #[serde(default, skip_serializing_if = "is_false")]
    unrestricted: bool,
    profile: Vec<ControlRequirement>,
    functions: Vec<FunctionContractDefinition>,
    #[serde(default)]
    windows_sandbox_host_policy: super::WindowsSandboxHostPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windows_cpu_rate_limit_percent: Option<u8>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ProcessDefinition {
    /// Copies declarations only. No store access or native process is needed.
    pub fn new(
        name: impl Into<String>,
        program: ProgramArtifact,
        profile: &super::ProcessProfile,
        mut functions: Vec<FunctionContractDefinition>,
    ) -> Result<Self> {
        profile.validate()?;
        functions.sort_by(|a, b| a.name.cmp(&b.name));
        let definition = Self {
            name: name.into(),
            program,
            unrestricted: profile.is_unrestricted(),
            profile: profile.controls.iter().map(Into::into).collect(),
            functions,
            windows_sandbox_host_policy: super::WindowsSandboxHostPolicy::default(),
            windows_cpu_rate_limit_percent: profile.windows_cpu_rate_percent(),
        };
        definition.validate()?;
        Ok(definition)
    }

    /// Records a containment request without granting runtime permission.
    pub fn with_windows_sandbox_host_policy(
        mut self,
        policy: super::WindowsSandboxHostPolicy,
    ) -> Self {
        self.windows_sandbox_host_policy = policy;
        self
    }

    /// Requested containment, independent of runtime authorization.
    pub fn windows_sandbox_host_policy(&self) -> super::WindowsSandboxHostPolicy {
        self.windows_sandbox_host_policy
    }

    /// Stable process owner name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Immutable OCI program identity.
    pub fn program(&self) -> &ProgramArtifact {
        &self.program
    }

    /// Declared OS restrictions, for the launcher's enforcement decision.
    pub fn profile(&self) -> super::ProcessProfile {
        let mut profile = super::ProcessProfile::new(self.profile.iter().map(|request| {
            super::RequestedControl {
                control: match request.control {
                    ControlDefinition::MemoryLimit(bytes) => {
                        super::ProcessControl::MemoryLimit(bytes)
                    }
                    ControlDefinition::CpuBudget { quota, period } => {
                        super::ProcessControl::CpuBudget { quota, period }
                    }
                    ControlDefinition::DenyNetwork => super::ProcessControl::DenyNetwork,
                    ControlDefinition::DenyChildProcesses => {
                        super::ProcessControl::DenyChildProcesses
                    }
                },
                required: request.required,
            }
        }));
        profile.unrestricted = self.unrestricted;
        profile.windows_cpu_rate_limit_percent = self.windows_cpu_rate_limit_percent;
        profile
    }

    /// Contracts owned by this worker. Empty for a dedicated sandbox host.
    pub fn functions(&self) -> &[FunctionContractDefinition] {
        &self.functions
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(new_error!("A process definition needs a name"));
        }
        self.profile().validate()?;
        let mut names = BTreeSet::new();
        for function in &self.functions {
            if function.name.is_empty() || !names.insert(&function.name) {
                return Err(new_error!("Duplicate or empty process function name"));
            }
        }
        Ok(())
    }
}

/// Versioned definition-only topology. Local callbacks use snapshot rebinding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessTopologyDefinition {
    schema_version: u32,
    sandbox: Option<ProcessDefinition>,
    workers: Vec<ProcessDefinition>,
}

impl ProcessTopologyDefinition {
    #[cfg(test)]
    pub(crate) fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Checks exact ownership without opening any referenced program.
    pub fn new(
        sandbox: Option<ProcessDefinition>,
        mut workers: Vec<ProcessDefinition>,
    ) -> Result<Self> {
        workers.sort_by(|a, b| a.name.cmp(&b.name));
        let processes = sandbox.iter().chain(&workers);
        let schema_version = if processes.clone().any(|process| process.unrestricted) {
            3
        } else if processes
            .clone()
            .any(|process| process.windows_cpu_rate_limit_percent.is_some())
        {
            2
        } else {
            1
        };
        let definition = Self {
            schema_version,
            sandbox,
            workers,
        };
        definition.validate()?;
        Ok(definition)
    }
}

impl ProcessTopologyDefinition {
    /// Dedicated sandbox-host definition, when configured.
    pub fn sandbox(&self) -> Option<&ProcessDefinition> {
        self.sandbox.as_ref()
    }

    /// Function worker definitions, including workers with no executions.
    pub fn workers(&self) -> &[ProcessDefinition] {
        &self.workers
    }

    /// Unique immutable programs required by this topology.
    pub fn programs(&self) -> Vec<ProgramArtifact> {
        let mut seen = BTreeSet::new();
        self.sandbox
            .iter()
            .chain(self.workers.iter())
            .filter(|p| seen.insert(p.program.digest().to_string()))
            .map(|p| p.program.clone())
            .collect()
    }

    /// Validates untrusted parsed declarations without resolving artifacts.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.schema_version, 1..=3) {
            return Err(new_error!("Unsupported process topology schema"));
        }
        let has_cpu_rate = self
            .sandbox
            .iter()
            .chain(&self.workers)
            .any(|process| process.windows_cpu_rate_limit_percent.is_some());
        if self.schema_version == 1 && has_cpu_rate {
            return Err(new_error!(
                "Process topology schema 1 cannot contain a Windows CPU rate limit"
            ));
        }
        let has_unrestricted = self
            .sandbox
            .iter()
            .chain(&self.workers)
            .any(|process| process.unrestricted);
        if self.schema_version < 3 && has_unrestricted {
            return Err(new_error!(
                "Process topology schema before 3 cannot contain unrestricted profiles"
            ));
        }
        if self.sandbox.is_none() && self.workers.is_empty() {
            return Err(new_error!("A process topology must declare a process"));
        }
        let mut programs = BTreeMap::new();
        for process in self.sandbox.iter().chain(&self.workers) {
            if let Some(previous) = programs.insert(
                process.program.digest().to_string(),
                process.program.descriptor(),
            ) && previous != process.program.descriptor()
            {
                return Err(new_error!(
                    "Conflicting descriptors for one native program digest"
                ));
            }
        }
        let mut processes = BTreeSet::new();
        let mut functions = BTreeSet::new();
        if let Some(sandbox) = &self.sandbox {
            sandbox.validate()?;
            for function in &sandbox.functions {
                if !functions.insert(&function.name) {
                    return Err(new_error!("Duplicate sandbox-host function owner"));
                }
            }
            processes.insert(&sandbox.name);
        }
        for worker in &self.workers {
            worker.validate()?;
            if worker.windows_sandbox_host_policy.is_windows_vm_host() {
                return Err(new_error!(
                    "Windows VM-host policy cannot be used by function workers"
                ));
            }
            if !processes.insert(&worker.name) || worker.functions.is_empty() {
                return Err(new_error!(
                    "Duplicate process owner or empty function worker"
                ));
            }
            for function in &worker.functions {
                if !functions.insert(&function.name) {
                    return Err(new_error!("Duplicate process function owner"));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_host_functions(
        &self,
        host_functions: &hyperlight_common::flatbuffer_wrappers::host_function_details::HostFunctionDetails,
    ) -> Result<()> {
        self.validate()?;
        for function in self
            .sandbox
            .iter()
            .chain(&self.workers)
            .flat_map(|owner| &owner.functions)
        {
            let matched = host_functions
                .host_functions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|f| f.function_name == function.name);
            let matches = matched.is_some_and(|f| {
                let parameters: Vec<_> = f
                    .parameter_types
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(ParameterTypeRepr::from)
                    .collect();
                parameters == function.parameters
                    && ReturnTypeRepr::from(&f.return_type) == function.output
            });
            if !matches {
                return Err(new_error!(
                    "Snapshot lacks process contract '{}'",
                    function.name
                ));
            }
        }
        Ok(())
    }

    /// Verifies every program's closure, target requirements and declared role.
    pub fn validate_programs(
        &self,
        store: &LocalProgramStore,
        available: &ProgramTarget,
    ) -> Result<()> {
        self.validate()?;
        for (process, role) in self
            .sandbox
            .iter()
            .map(|p| (p, ProgramRole::SandboxHost))
            .chain(
                self.workers
                    .iter()
                    .map(|p| (p, ProgramRole::FunctionWorker)),
            )
        {
            let validated = store.validate(&process.program, available)?;
            if validated.config.role != role {
                return Err(new_error!(
                    "Program role does not match process '{}'",
                    process.name
                ));
            }
            let mut actual = validated.config.functions;
            actual.sort_by(|a, b| a.name.cmp(&b.name));
            let mut expected = process.functions.clone();
            expected.sort_by(|a, b| a.name.cmp(&b.name));
            if actual != expected {
                return Err(new_error!(
                    "Program contracts do not match process '{}'",
                    process.name
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{
        HostFunctionContract, Idempotency, ProcessControl, ProcessProfile, RequestedControl,
    };

    fn config() -> ProgramConfig {
        ProgramConfig {
            schema_version: 1,
            role: ProgramRole::SandboxHost,
            target: ProgramTarget::current(BTreeMap::new()),
            functions: Vec::new(),
        }
    }

    fn profile() -> ProcessProfile {
        ProcessProfile::new([RequestedControl {
            control: ProcessControl::DenyChildProcesses,
            required: true,
        }])
    }

    fn worker_contract() -> FunctionContractDefinition {
        FunctionContractDefinition::from_contract(&HostFunctionContract::<(i32,), i32>::new(
            "Worker",
            Idempotency::NonIdempotent,
        ))
    }

    fn blob_path(store: &LocalProgramStore, desc: &Descriptor) -> PathBuf {
        store
            .blobs_dir()
            .join(desc.digest().to_string().strip_prefix("sha256:").unwrap())
    }

    fn replace_manifest(
        store: &LocalProgramStore,
        artifact: &ProgramArtifact,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> ProgramArtifact {
        let mut manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(blob_path(store, artifact.descriptor())).unwrap(),
        )
        .unwrap();
        mutate(&mut manifest);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let desc = descriptor(MediaType::ImageManifest, &bytes).unwrap();
        std::fs::write(blob_path(store, &desc), bytes).unwrap();
        ProgramArtifact::from_descriptor(desc).unwrap()
    }

    #[test]
    fn package_validate_export_and_deduplicate_closure() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(source.path());
        let dest = LocalProgramStore::new(destination.path());
        let first = store.package(&config(), b"native program fixture").unwrap();
        let mut worker = config();
        worker.role = ProgramRole::FunctionWorker;
        worker.functions.push(worker_contract());
        let second = store.package(&worker, b"native program fixture").unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_eq!(
            first,
            store.package(&config(), b"native program fixture").unwrap()
        );
        assert_eq!(std::fs::read_dir(store.blobs_dir()).unwrap().count(), 5);
        store
            .export(&[first.clone(), first.clone(), second.clone()], &dest)
            .unwrap();
        assert_eq!(std::fs::read_dir(dest.blobs_dir()).unwrap().count(), 5);
        let validated = dest.validate(&first, &config().target).unwrap();
        assert_eq!(validated.executable(), b"native program fixture");
        assert_eq!(validated.artifact(), &first);
        assert_eq!(validated.config(), &config());
        assert!(validated.runtime_files().is_empty());
        assert_eq!(
            dest.validate(&second, &worker.target).unwrap().config(),
            &worker
        );
        let json = serde_json::to_vec(&first).unwrap();
        assert_eq!(
            serde_json::from_slice::<ProgramArtifact>(&json).unwrap(),
            first
        );
    }

    #[test]
    fn runtime_files_round_trip_export_and_share_blobs_across_manifests() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(source.path());
        let dest = LocalProgramStore::new(destination.path());
        let files = vec![
            ProgramFile::new("/lib/loader.so", b"shared runtime".to_vec()).unwrap(),
            ProgramFile::new("/lib/alias.so", b"shared runtime".to_vec()).unwrap(),
            ProgramFile::new("/etc/runtime.conf", b"configuration".to_vec()).unwrap(),
            ProgramFile::new("/etc/empty", Vec::new()).unwrap(),
        ];
        let first = store
            .package_with_runtime(&config(), b"native", &files)
            .unwrap();
        let mut worker = config();
        worker.role = ProgramRole::FunctionWorker;
        worker.functions.push(worker_contract());
        let second = store
            .package_with_runtime(&worker, b"native", &files)
            .unwrap();
        assert_ne!(first.digest(), second.digest());
        store
            .export(&[first.clone(), second.clone(), first.clone()], &dest)
            .unwrap();
        // Two manifests, two configs, one executable, three runtime blobs.
        assert_eq!(std::fs::read_dir(store.blobs_dir()).unwrap().count(), 8);
        assert_eq!(std::fs::read_dir(dest.blobs_dir()).unwrap().count(), 8);
        let validated = dest.validate(&first, &config().target).unwrap();
        assert_eq!(validated.runtime_files(), files);
        assert_eq!(validated.runtime_files()[0].image_path(), "/lib/loader.so");
        assert_eq!(validated.runtime_files()[0].bytes(), b"shared runtime");
        assert_eq!(
            dest.validate(&second, &worker.target)
                .unwrap()
                .runtime_files(),
            files
        );
        drop(source);
        drop(destination);
        assert_eq!(validated.runtime_files(), files);
    }

    #[test]
    fn runtime_blobs_require_presence_digest_and_size_for_validation_and_export() {
        let dir = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let dest = LocalProgramStore::new(destination.path());
        let files = [ProgramFile::new("/lib/runtime.so", b"runtime".to_vec()).unwrap()];
        let artifact = store
            .package_with_runtime(&config(), b"native", &files)
            .unwrap();
        let closure = store.read_closure(&artifact).unwrap();
        let path = blob_path(&store, &closure.blobs[3].0);
        for corrupt in [b"tampered".as_slice(), b"runtimE", b""] {
            std::fs::write(&path, corrupt).unwrap();
            assert!(store.validate(&artifact, &config().target).is_err());
            assert!(
                store
                    .export(std::slice::from_ref(&artifact), &dest)
                    .is_err()
            );
        }
        std::fs::remove_file(path).unwrap();
        assert!(store.validate(&artifact, &config().target).is_err());
        assert!(store.export(&[artifact], &dest).is_err());
    }

    #[test]
    fn runtime_annotations_are_required_and_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let files = [ProgramFile::new("/lib/runtime.so", b"runtime".to_vec()).unwrap()];
        let artifact = store
            .package_with_runtime(&config(), b"native", &files)
            .unwrap();
        let missing = replace_manifest(&store, &artifact, |v| {
            v["layers"][1]
                .as_object_mut()
                .unwrap()
                .remove("annotations");
        });
        assert!(store.validate(&missing, &config().target).is_err());
        for field in ["urls", "data", "mediaType"] {
            let changed = replace_manifest(&store, &artifact, |v| {
                v["layers"][1][field] = match field {
                    "urls" => serde_json::json!(["https://example.invalid/runtime"]),
                    "data" => "cnVudGltZQ==".into(),
                    _ => PROGRAM_EXECUTABLE_V1.into(),
                };
            });
            assert!(store.validate(&changed, &config().target).is_err());
        }
        let renamed = replace_manifest(&store, &artifact, |v| {
            v["layers"][1]["annotations"][PROGRAM_IMAGE_PATH] = "/lib/renamed.so".into();
        });
        assert_ne!(renamed.digest(), artifact.digest());
        // Even a valid path change must authenticate against a new manifest identity.
        std::fs::copy(
            blob_path(&store, renamed.descriptor()),
            blob_path(&store, artifact.descriptor()),
        )
        .unwrap();
        assert!(store.validate(&artifact, &config().target).is_err());
    }

    #[test]
    fn rejects_runtime_path_attacks_and_collisions_in_packaging_and_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let files = [
            ProgramFile::new("/lib/a", vec![1]).unwrap(),
            ProgramFile::new("/lib/b", vec![2]).unwrap(),
        ];
        let artifact = store
            .package_with_runtime(&config(), b"native", &files)
            .unwrap();
        for path in [
            "",
            "/",
            "relative",
            "//lib/a",
            "/lib//a",
            "/lib/a/",
            "/./a",
            "/lib/../a",
            "/lib/\0a",
            "/lib\\a",
            "C:/lib/a",
            "/C:/lib/a",
            "https://host/a",
            "/https://host/a",
            "/program",
            "/program/child",
            "/proc",
            "/proc/self/mem",
            "/sys",
            "/sys/kernel",
            "/dev",
            "/dev/null",
        ] {
            assert!(ProgramFile::new(path, vec![1]).is_err(), "{path:?}");
            let changed = replace_manifest(&store, &artifact, |v| {
                v["layers"][1]["annotations"][PROGRAM_IMAGE_PATH] = path.into();
            });
            assert!(
                store.validate(&changed, &config().target).is_err(),
                "{path:?}"
            );
        }
        for (first, second) in [("/lib/a", "/lib/a"), ("/lib", "/lib/a"), ("/lib/a", "/lib")] {
            let collision = [
                ProgramFile::new(first, vec![1]).unwrap(),
                ProgramFile::new(second, vec![2]).unwrap(),
            ];
            assert!(
                store
                    .package_with_runtime(&config(), b"native", &collision)
                    .is_err()
            );
            let changed = replace_manifest(&store, &artifact, |v| {
                v["layers"][1]["annotations"][PROGRAM_IMAGE_PATH] = first.into();
                v["layers"][2]["annotations"][PROGRAM_IMAGE_PATH] = second.into();
            });
            assert!(store.validate(&changed, &config().target).is_err());
        }
        assert!(ProgramFile::new("/program-data", vec![1]).is_ok());
        assert!(ProgramFile::new("/device/file", vec![1]).is_ok());
    }

    #[test]
    fn aggregate_file_size_is_checked_before_reading_content() {
        assert_eq!(
            add_file_size(MAX_EXECUTABLE_SIZE - 1, 1).unwrap(),
            MAX_EXECUTABLE_SIZE
        );
        assert!(add_file_size(MAX_EXECUTABLE_SIZE, 1).is_err());
        assert!(add_file_size(1, u64::MAX).is_err());
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let files = [ProgramFile::new("/lib/runtime.so", vec![1]).unwrap()];
        let artifact = store
            .package_with_runtime(&config(), b"native", &files)
            .unwrap();
        let changed = replace_manifest(&store, &artifact, |v| {
            v["layers"][0]["size"] = (MAX_EXECUTABLE_SIZE - 1).into();
            v["layers"][1]["size"] = 2.into();
        });
        // Neither declared size matches its tiny blob. The aggregate check runs first.
        let error = store.validate(&changed, &config().target).unwrap_err();
        assert!(error.to_string().contains("aggregate file size"), "{error}");
    }

    #[test]
    fn validated_executable_is_independent_of_mutable_store_paths() {
        let source = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(source.path());
        let artifact = store.package(&config(), b"native program fixture").unwrap();
        let validated = store.validate(&artifact, &config().target).unwrap();
        drop(source);
        assert_eq!(validated.executable(), b"native program fixture");
        assert!(store.validate(&artifact, &config().target).is_err());
    }

    #[test]
    fn runtime_requires_exact_platform_and_declared_os_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let mut cfg = config();
        cfg.target
            .os_dependencies
            .insert("system-runtime".into(), "1.2".into());
        let artifact = store.package(&cfg, b"native").unwrap();
        assert!(store.validate(&artifact, &config().target).is_err());
        let mut available = cfg.target.clone();
        available
            .os_dependencies
            .insert("system-runtime".into(), "1.3".into());
        assert!(store.validate(&artifact, &available).is_err());
        available = cfg.target.clone();
        available.architecture = if cfg.target.architecture == "x86_64" {
            "aarch64"
        } else {
            "x86_64"
        }
        .into();
        assert!(store.validate(&artifact, &available).is_err());
        available = cfg.target.clone();
        available.environment = "unsupported".into();
        assert!(store.validate(&artifact, &available).is_err());
        assert!(store.validate(&artifact, &cfg.target).is_ok());
    }

    #[test]
    fn verifies_every_blob_digest_size_and_presence() {
        for position in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let store = LocalProgramStore::new(dir.path());
            let artifact = store.package(&config(), b"native").unwrap();
            let closure = store.read_closure(&artifact).unwrap();
            let (desc, original) = &closure.blobs[position];
            let path = blob_path(&store, desc);
            let mut corrupted = original.clone();
            corrupted[0] ^= 1;
            std::fs::write(&path, &corrupted).unwrap();
            assert!(
                store.validate(&artifact, &config().target).is_err(),
                "digest {position}"
            );
            std::fs::write(&path, &original[..original.len() - 1]).unwrap();
            assert!(
                store.validate(&artifact, &config().target).is_err(),
                "size {position}"
            );
            std::fs::remove_file(&path).unwrap();
            assert!(
                store.validate(&artifact, &config().target).is_err(),
                "missing {position}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_closure_and_remote_descriptors() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let artifact = store.package(&config(), b"native").unwrap();
        let mutations: [fn(&mut serde_json::Value); 9] = [
            |v| v["schemaVersion"] = 7.into(),
            |v| v["artifactType"] = "unknown".into(),
            |v| v["config"]["mediaType"] = "unknown".into(),
            |v| v["layers"][0]["mediaType"] = "unknown".into(),
            |v| v["layers"][0]["size"] = 0.into(),
            |v| v["layers"][0]["digest"] = "sha256:../../outside".into(),
            |v| v["layers"][0]["urls"] = serde_json::json!(["https://example.invalid/program"]),
            |v| v["layers"][0]["data"] = "eA==".into(),
            |v| {
                let extra = v["config"].clone();
                v["layers"].as_array_mut().unwrap().push(extra);
            },
        ];
        for mutate in mutations {
            let changed = replace_manifest(&store, &artifact, mutate);
            assert!(store.validate(&changed, &config().target).is_err());
        }
        let mut identity = serde_json::to_value(&artifact).unwrap();
        identity["digest"] = "latest".into();
        assert!(serde_json::from_value::<ProgramArtifact>(identity).is_err());
    }

    #[test]
    fn declarations_round_trip_without_store_or_started_programs() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let mut cfg = config();
        cfg.role = ProgramRole::FunctionWorker;
        cfg.functions.push(worker_contract());
        let artifact = store.package(&cfg, b"native").unwrap();
        let worker = ProcessDefinition::new("worker", artifact, &profile(), cfg.functions).unwrap();
        let definition = ProcessTopologyDefinition::new(None, vec![worker.clone()]).unwrap();
        drop(dir);
        let json = serde_json::to_vec(&definition).unwrap();
        let parsed: ProcessTopologyDefinition = serde_json::from_slice(&json).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed, definition);
        assert_eq!(parsed.workers()[0], worker);
        assert!(parsed.validate_programs(&store, &config().target).is_err());
        assert!(ProcessTopologyDefinition::new(None, vec![worker.clone(), worker]).is_err());
    }

    #[test]
    fn unrestricted_declarations_use_schema_three_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let mut cfg = config();
        cfg.role = ProgramRole::FunctionWorker;
        cfg.functions.push(worker_contract());
        let artifact = store.package(&cfg, b"native").unwrap();
        let worker = ProcessDefinition::new(
            "worker",
            artifact,
            &super::super::ProcessProfile::unrestricted(),
            cfg.functions,
        )
        .unwrap();
        let definition = ProcessTopologyDefinition::new(None, vec![worker]).unwrap();

        assert_eq!(definition.schema_version(), 3);
        let json = serde_json::to_value(&definition).unwrap();
        assert_eq!(json["workers"][0]["unrestricted"], true);
        let parsed: ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
        assert!(parsed.workers()[0].profile().is_unrestricted());
        assert_eq!(parsed, definition);
    }

    #[test]
    fn older_topology_schema_rejects_unrestricted_processes() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let mut cfg = config();
        cfg.role = ProgramRole::FunctionWorker;
        cfg.functions.push(worker_contract());
        let artifact = store.package(&cfg, b"native").unwrap();
        let worker = ProcessDefinition::new(
            "worker",
            artifact,
            &super::super::ProcessProfile::unrestricted(),
            cfg.functions,
        )
        .unwrap();
        let definition = ProcessTopologyDefinition::new(None, vec![worker]).unwrap();
        let mut json = serde_json::to_value(definition).unwrap();
        json["schema_version"] = 2.into();

        let parsed: ProcessTopologyDefinition = serde_json::from_value(json).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn unrestricted_process_rejects_serialized_controls() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let mut cfg = config();
        cfg.role = ProgramRole::FunctionWorker;
        cfg.functions.push(worker_contract());
        let artifact = store.package(&cfg, b"native").unwrap();
        let unrestricted = ProcessDefinition::new(
            "worker",
            artifact.clone(),
            &super::super::ProcessProfile::unrestricted(),
            cfg.functions.clone(),
        )
        .unwrap();
        let restricted =
            ProcessDefinition::new("worker", artifact, &profile(), cfg.functions).unwrap();
        let mut json = serde_json::to_value(unrestricted).unwrap();
        json["profile"] = serde_json::to_value(restricted).unwrap()["profile"].clone();

        let parsed: ProcessDefinition = serde_json::from_value(json).unwrap();
        assert!(parsed.validate().is_err());
    }

    #[test]
    fn validates_program_roles_contracts_and_idempotency() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalProgramStore::new(dir.path());
        let artifact = store.package(&config(), b"native").unwrap();
        let worker =
            ProcessDefinition::new("worker", artifact, &profile(), vec![worker_contract()])
                .unwrap();
        let topology = ProcessTopologyDefinition::new(None, vec![worker]).unwrap();
        assert!(
            topology
                .validate_programs(&store, &config().target)
                .is_err()
        );

        let mut cfg = config();
        cfg.role = ProgramRole::FunctionWorker;
        cfg.functions.push(worker_contract());
        let artifact = store.package(&cfg, b"native").unwrap();
        let worker =
            ProcessDefinition::new("worker", artifact, &profile(), cfg.functions.clone()).unwrap();
        let mut topology = ProcessTopologyDefinition::new(None, vec![worker]).unwrap();
        topology.validate_programs(&store, &cfg.target).unwrap();
        topology.workers[0].functions[0].idempotency = IdempotencyDefinition::Idempotent;
        assert!(topology.validate_programs(&store, &cfg.target).is_err());
        topology.workers[0].functions[0].idempotency = IdempotencyDefinition::NonIdempotent;
        topology.workers[0].functions[0].parameters.clear();
        assert!(topology.validate_programs(&store, &cfg.target).is_err());
    }

    #[test]
    fn rejects_unknown_config_fields_versions_and_implicit_requirements() {
        let mut cfg = config();
        cfg.schema_version = 2;
        assert!(cfg.validate().is_err());
        cfg.schema_version = 1;
        cfg.target.os_dependencies.insert("".into(), "".into());
        assert!(cfg.validate().is_err());
        let mut json = serde_json::to_value(config()).unwrap();
        json["launch_path"] = "mutable.exe".into();
        assert!(serde_json::from_value::<ProgramConfig>(json).is_err());
    }
}
