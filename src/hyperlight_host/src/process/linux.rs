// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::ProcessControl;
use super::launch::{ControlOutcome, ControlResult, PreparedProcess, ProcessGuard};
use super::linux_domain::Domain;
use super::linux_output::Output;
use super::program::{ProcessDefinition, ProgramRole, ValidatedProgram};
use crate::{Result, new_error};

const MAX_HELPER_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;

/// Host-local resources for Linux process confinement.
///
/// The caller supplies a delegated cgroup2 directory and an explicitly trusted
/// Minijail build. These resources are not part of a portable guest snapshot.
#[derive(Clone, Debug)]
pub struct LinuxProcessResources {
    delegated_root: PathBuf,
    helper: HelperSource,
    helper_sha256: [u8; 32],
    hypervisor_device: Option<PathBuf>,
    vm_authority_devices: std::collections::BTreeMap<super::VmBackend, PathBuf>,
}

#[derive(Clone, Debug)]
enum HelperSource {
    Captured(Arc<[u8]>),
    Installed(PathBuf),
}

impl LinuxProcessResources {
    /// Captures helper bytes after verifying their SHA-256 digest.
    ///
    /// The helper must enforce required Landlock and seccomp without soft-failure
    /// or sanitizer bypasses. No helper is downloaded or resolved through PATH.
    pub fn new(
        delegated_root: impl Into<PathBuf>,
        helper: impl AsRef<Path>,
        expected_sha256: [u8; 32],
    ) -> Result<Self> {
        let mut bytes = Vec::new();
        File::open(helper)?
            .take(MAX_HELPER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_HELPER_BYTES {
            return Err(new_error!("Confinement helper has an invalid size"));
        }
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != expected_sha256 {
            return Err(new_error!("Confinement helper SHA-256 does not match"));
        }
        let delegated_root = delegated_root.into();
        if !delegated_root.is_absolute() {
            return Err(new_error!("Delegated cgroup directory must be absolute"));
        }
        Ok(Self {
            delegated_root,
            helper: HelperSource::Captured(bytes.into()),
            helper_sha256: expected_sha256,
            hypervisor_device: None,
            vm_authority_devices: Default::default(),
        })
    }

    fn installed_helper(mut self, helper: impl AsRef<Path>) -> Result<Self> {
        let helper = fs::canonicalize(helper)?;
        verify_installed_helper(&helper, self.helper_sha256)?;
        self.helper = HelperSource::Installed(helper);
        Ok(self)
    }

    /// Grants the sandbox-host role access to one hypervisor device.
    ///
    /// Function workers receive no hypervisor device. Only `/dev/kvm` and
    /// `/dev/mshv` are accepted.
    pub fn hypervisor_device(mut self, device: impl Into<PathBuf>) -> Result<Self> {
        let device = device.into();
        self.add_vm_authority_device(&device)?;
        self.hypervisor_device = Some(device);
        Ok(self)
    }

    fn add_vm_authority_device(&mut self, device: &Path) -> Result<()> {
        if device != Path::new("/dev/kvm") && device != Path::new("/dev/mshv") {
            return Err(new_error!("Unsupported hypervisor device: {device:?}"));
        }
        if !fs::symlink_metadata(&device)?.file_type().is_char_device() {
            return Err(new_error!("Hypervisor device must be a character device"));
        }
        let backend = if device == Path::new("/dev/kvm") {
            super::VmBackend::Kvm
        } else {
            super::VmBackend::Mshv
        };
        self.vm_authority_devices
            .insert(backend, device.to_path_buf());
        Ok(())
    }

    pub(super) fn vm_authority_device(&self, backend: super::VmBackend) -> Option<&Path> {
        self.vm_authority_devices
            .get(&backend)
            .map(PathBuf::as_path)
    }
}

pub(super) fn discover_provider() -> Result<LinuxProcessResources> {
    let delegated_root =
        std::env::var_os("HYPERLIGHT_MESH_PROCESS_CGROUP_ROOT").ok_or_else(|| {
            new_error!(
                "Mesh process placement needs operator-delegated Linux authority. \
             The configured supervisor did not supply it"
            )
        })?;
    let helper = PathBuf::from(
        std::env::var_os("HYPERLIGHT_MESH_PROCESS_MINIJAIL").ok_or_else(|| {
            new_error!("Mesh process placement needs the supervisor's verified confinement helper")
        })?,
    );
    if !helper.is_absolute() {
        return Err(new_error!(
            "The Mesh process confinement helper path must be absolute"
        ));
    }
    let digest: [u8; 32] = hex::decode(
        std::env::var("HYPERLIGHT_MESH_PROCESS_MINIJAIL_SHA256").map_err(|_| {
            new_error!("Mesh process placement needs the supervisor's helper digest")
        })?,
    )
    .map_err(|error| new_error!("Invalid Mesh process helper digest: {error}"))?
    .try_into()
    .map_err(|_| new_error!("Mesh process helper SHA-256 must be 32 bytes"))?;
    let mut resources =
        LinuxProcessResources::new(delegated_root, &helper, digest)?.installed_helper(helper)?;
    for device in [Path::new("/dev/kvm"), Path::new("/dev/mshv")] {
        if device.exists() {
            if resources.hypervisor_device.is_none() {
                resources = resources.hypervisor_device(device)?;
            } else if let Err(error) = resources.add_vm_authority_device(device) {
                tracing::warn!(?device, %error, "Ignoring unusable secondary hypervisor device");
            }
        }
    }
    Ok(resources)
}

pub(super) fn capture_origin_dependencies(
    executable: &[u8],
    source_directory: Option<&Path>,
    capture_origin: &Path,
    capture_boundary: &Path,
) -> Result<()> {
    let source_directory = source_directory
        .ok_or_else(|| new_error!("Native program path has no parent directory"))?;
    let mut pending = std::collections::VecDeque::from([(
        executable.to_vec(),
        source_directory.to_owned(),
        capture_origin.to_owned(),
        Vec::<OriginSearchPath>::new(),
    )]);
    let mut captured = std::collections::BTreeSet::new();
    let mut total = executable.len() as u64;
    while let Some((image, source_origin, capture_origin, inherited_rpaths)) = pending.pop_front() {
        let elf = goblin::elf::Elf::parse(&image)
            .map_err(|error| new_error!("Invalid native Linux ELF program: {error}"))?;
        let own_rpaths = origin_search_paths(
            &elf.rpaths,
            &source_origin,
            &capture_origin,
            capture_boundary,
        );
        let own_runpaths = origin_search_paths(
            &elf.runpaths,
            &source_origin,
            &capture_origin,
            capture_boundary,
        );
        let search_paths = if own_runpaths.is_empty() {
            own_rpaths
                .iter()
                .chain(&inherited_rpaths)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            inherited_rpaths
                .iter()
                .chain(&own_runpaths)
                .cloned()
                .collect::<Vec<_>>()
        };
        let child_rpaths = if own_runpaths.is_empty() {
            own_rpaths
                .into_iter()
                .chain(inherited_rpaths)
                .collect::<Vec<_>>()
        } else {
            inherited_rpaths
        };
        for library in elf.libraries {
            if Path::new(library).file_name() != Some(std::ffi::OsStr::new(library)) {
                continue;
            }
            let Some((source, destination)) = search_paths.iter().find_map(|path| {
                let source = path.source.join(library);
                source
                    .is_file()
                    .then(|| (source, path.capture.join(library)))
            }) else {
                continue;
            };
            let relative = destination
                .strip_prefix(capture_boundary)
                .map_err(|_| new_error!("Captured Linux dependency escaped its program root"))?
                .to_owned();
            if !captured.insert(relative) {
                continue;
            }
            if captured.len() > 128 {
                return Err(new_error!(
                    "Mesh provider runtime dependency closure exceeds 128 files"
                ));
            }
            let file = super::provider::capture_file(&source)?;
            total = total
                .checked_add(file.bytes.len() as u64)
                .filter(|total| *total <= super::provider::MAX_PROGRAM_BYTES)
                .ok_or_else(|| {
                    new_error!("Mesh provider runtime dependency closure exceeds 256 MiB")
                })?;
            let parent = destination
                .parent()
                .ok_or_else(|| new_error!("Captured Linux dependency has no parent directory"))?;
            fs::create_dir_all(parent)?;
            fs::write(&destination, &file.bytes)?;
            fs::set_permissions(&destination, file.permissions)?;
            pending.push_back((
                file.bytes,
                source
                    .parent()
                    .ok_or_else(|| new_error!("Linux dependency has no parent directory"))?
                    .to_owned(),
                parent.to_owned(),
                child_rpaths.clone(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct OriginSearchPath {
    source: PathBuf,
    capture: PathBuf,
}

fn origin_search_paths(
    paths: &[&str],
    source_origin: &Path,
    capture_origin: &Path,
    capture_boundary: &Path,
) -> Vec<OriginSearchPath> {
    paths
        .iter()
        .flat_map(|paths| paths.split(':'))
        .filter_map(|path| {
            let relative = origin_relative(path)?;
            let source = normalize_bounded(source_origin, &relative, Path::new("/"))?;
            let capture = normalize_bounded(capture_origin, &relative, capture_boundary)?;
            Some(OriginSearchPath { source, capture })
        })
        .collect()
}

fn origin_relative(path: &str) -> Option<PathBuf> {
    let suffix = path
        .strip_prefix("$ORIGIN")
        .or_else(|| path.strip_prefix("${ORIGIN}"))?;
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);
    let relative = PathBuf::from(suffix);
    relative
        .components()
        .all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::ParentDir
            )
        })
        .then_some(relative)
}

fn normalize_bounded(base: &Path, relative: &Path, boundary: &Path) -> Option<PathBuf> {
    let mut normalized = base.to_owned();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::ParentDir => {
                if normalized == boundary || !normalized.pop() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    normalized.starts_with(boundary).then_some(normalized)
}

#[cfg(test)]
pub(super) fn runtime_closure(executable: &Path) -> Result<Vec<super::program::ProgramFile>> {
    let root = executable
        .parent()
        .map(fs::canonicalize)
        .transpose()?
        .ok_or_else(|| new_error!("Native program path has no parent directory"))?;
    runtime_closure_in(executable, &root)
}

pub(super) fn runtime_closure_in(
    executable: &Path,
    capture_root: &Path,
) -> Result<Vec<super::program::ProgramFile>> {
    let capture_root = fs::canonicalize(capture_root)?;
    let executable = fs::canonicalize(executable)?;
    let captured_program = executable
        .strip_prefix(&capture_root)
        .ok()
        .map(|path| Path::new("/").join(path));
    let ldd = Path::new("/usr/bin/ldd");
    let output = Command::new(ldd)
        .arg(&executable)
        .output()
        .map_err(|error| {
            new_error!(
                "Mesh provider could not inspect runtime dependencies with {}: {error}",
                ldd.display()
            )
        })?;
    if !output.status.success() {
        if is_static_elf(&executable)? {
            return Ok(Vec::new());
        }
        return Err(new_error!(
            "Mesh provider runtime dependency inspection failed for {}: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| new_error!("Mesh provider runtime dependency output is not UTF-8"))?;
    let mut files = std::collections::BTreeMap::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.contains("not found") {
            return Err(new_error!(
                "Mesh provider found an unresolved runtime dependency: {line}"
            ));
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let image_path = match fields.as_slice() {
            [first, "=>", path, ..] if !first.starts_with("linux-vdso") => *path,
            [path, ..] if path.starts_with('/') => *path,
            _ => continue,
        };
        let source = std::fs::canonicalize(image_path)?;
        let image_path = source
            .strip_prefix(&capture_root)
            .ok()
            .and_then(|path| {
                let source_path = Path::new("/").join(path);
                let program_directory = captured_program.as_ref()?.parent()?;
                let relative = relative_path(program_directory, &source_path);
                Some(image_path_from_origin(&relative))
            })
            .unwrap_or_else(|| image_path.to_owned());
        files.insert(image_path, source);
        if files.len() > 128 {
            return Err(new_error!(
                "Mesh provider runtime dependency closure exceeds 128 files"
            ));
        }

        fn relative_path(from: &Path, to: &Path) -> PathBuf {
            let from = from.components().collect::<Vec<_>>();
            let to = to.components().collect::<Vec<_>>();
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

        fn image_path_from_origin(relative: &Path) -> String {
            let mut image = PathBuf::from("/");
            for component in relative.components() {
                match component {
                    std::path::Component::Normal(component) => image.push(component),
                    std::path::Component::ParentDir => {
                        image.pop();
                    }
                    _ => {}
                }
            }
            image.to_string_lossy().into_owned()
        }
    }
    let mut total = std::fs::metadata(executable)?.len();
    files
        .into_iter()
        .map(|(image_path, source)| {
            let file = super::provider::capture_file(&source)?;
            total = total
                .checked_add(file.bytes.len() as u64)
                .filter(|total| *total <= 256 * 1024 * 1024)
                .ok_or_else(|| {
                    new_error!("Mesh provider runtime dependency closure exceeds 256 MiB")
                })?;
            super::program::ProgramFile::new(image_path, file.bytes)
        })
        .collect()
}

fn is_static_elf(executable: &Path) -> Result<bool> {
    let bytes = std::fs::read(executable)?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|error| new_error!("Invalid native Linux ELF program: {error}"))?;
    let executable_type = matches!(
        elf.header.e_type,
        goblin::elf::header::ET_EXEC | goblin::elf::header::ET_DYN
    );
    let loadable = elf
        .program_headers
        .iter()
        .any(|header| header.p_type == goblin::elf::program_header::PT_LOAD);
    Ok(executable_type && loadable && elf.interpreter.is_none() && elf.libraries.is_empty())
}

struct Image {
    directory: tempfile::TempDir,
    helper: PathBuf,
    process_filter: PathBuf,
    root: PathBuf,
    readable: Vec<String>,
}

impl Image {
    fn stage(
        resources: &LinuxProcessResources,
        program: &ValidatedProgram,
        deny_child_processes: bool,
    ) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("hyperlight-process-")
            .tempdir()?;
        let helper = match &resources.helper {
            HelperSource::Installed(helper) => {
                verify_installed_helper(helper, resources.helper_sha256)?;
                helper.clone()
            }
            HelperSource::Captured(bytes) => {
                let helper = directory.path().join("supervisor");
                write_image_file(&helper, bytes, 0o500)?;
                helper
            }
        };
        let process_filter = directory.path().join("process-filter");
        write_image_file(
            &process_filter,
            &syscall_filter(deny_child_processes),
            0o400,
        )?;
        let root = directory.path().join("root");
        fs::create_dir(&root)?;
        write_image_file(&root.join("program"), program.executable(), 0o500)?;
        let mut readable = vec!["/program".to_owned()];
        for file in program.runtime_files() {
            let destination = root.join(file.image_path().trim_start_matches('/'));
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            write_image_file(&destination, file.bytes(), 0o500)?;
            readable.push(file.image_path().to_owned());
        }
        for name in ["proc", "tmp", "dev"] {
            fs::create_dir_all(root.join(name))?;
        }
        Ok(Self {
            directory,
            helper,
            process_filter,
            root,
            readable,
        })
    }

    fn arguments(
        &self,
        role: ProgramRole,
        resources: &LinuxProcessResources,
        deny_network: bool,
    ) -> Result<Vec<String>> {
        let root = self
            .root
            .to_str()
            .ok_or_else(|| new_error!("Confinement image path is not UTF-8"))?;
        if root.contains(',') {
            return Err(new_error!(
                "Confinement image path contains a bind separator"
            ));
        }
        let mut arguments = [
            "-U",
            "-m",
            "-M",
            "-I",
            "-l",
            "-w",
            "-n",
            "-c",
            "0",
            "--ambient",
            "-P",
            root,
            "-b",
            &format!("{root},/,1"),
            "-k",
            "proc,/proc,proc,15",
            "--landlock-abi",
            "5",
            "--require-landlock",
            "--preserve-fd",
            "3",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        arguments.extend([
            "--seccomp-bpf-binary".to_owned(),
            self.process_filter
                .to_str()
                .ok_or_else(|| new_error!("Process filter path is not UTF-8"))?
                .to_owned(),
        ]);
        if deny_network {
            arguments.push("-e".to_owned());
        }
        for path in &self.readable {
            arguments.extend(["--fs-path-rx".to_owned(), path.clone()]);
        }
        arguments.extend(["--fs-path-ro".to_owned(), "/proc".to_owned()]);
        if role == ProgramRole::SandboxHost {
            arguments.extend([
                "-k".to_owned(),
                "tmpfs,/tmp,tmpfs,14,mode=700".to_owned(),
                "--fs-path-rw".to_owned(),
                "/tmp".to_owned(),
            ]);
            let device = resources.hypervisor_device.as_ref().ok_or_else(|| {
                new_error!("A sandbox process requires an explicit hypervisor device")
            })?;
            if !fs::symlink_metadata(device)?.file_type().is_char_device() {
                return Err(new_error!("Hypervisor device is not a character device"));
            }
            let path = device
                .to_str()
                .ok_or_else(|| new_error!("Hypervisor device path is not UTF-8"))?;
            arguments.extend([
                "-b".to_owned(),
                format!("{path},{path},1"),
                // ABI 5 requires IOCTL_DEV on this validated character device.
                "--fs-path-advanced-rw".to_owned(),
                path.to_owned(),
            ]);
        }
        arguments
            .extend(["-T", "static", "--logging", "stderr", "--", "/program"].map(str::to_owned));
        Ok(arguments)
    }
}

fn verify_installed_helper(helper: &Path, expected_sha256: [u8; 32]) -> Result<()> {
    for path in helper.ancestors() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(new_error!(
                "Installed confinement helper path is not root-owned and immutable: {path:?}"
            ));
        }
    }
    let mut bytes = Vec::new();
    File::open(helper)?
        .take(MAX_HELPER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_HELPER_BYTES {
        return Err(new_error!("Confinement helper has an invalid size"));
    }
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != expected_sha256 {
        return Err(new_error!("Confinement helper SHA-256 does not match"));
    }
    Ok(())
}

fn syscall_filter(deny_child_processes: bool) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const EQUAL: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const SET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    const RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    const DENIED: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const UNAVAILABLE: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

    // seccomp_data contains nr at 0, arch at 4 and args[0] at 16.
    let mut filter = vec![
        (LOAD, 0, 0, 4),
        (EQUAL, 1, 0, ARCH),
        (RETURN, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        (LOAD, 0, 0, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    filter.extend([
        (SET, 0, 1, 0x4000_0000), // x32 shares the x86-64 audit architecture.
        (RETURN, 0, 0, DENIED),
    ]);
    for syscall in [libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key] {
        filter.extend([(EQUAL, 0, 1, syscall as u32), (RETURN, 0, 0, DENIED)]);
    }
    if deny_child_processes {
        #[cfg(target_arch = "x86_64")]
        filter.extend([
            (EQUAL, 0, 1, libc::SYS_fork as u32),
            (RETURN, 0, 0, DENIED),
            (EQUAL, 0, 1, libc::SYS_vfork as u32),
            (RETURN, 0, 0, DENIED),
        ]);
        filter.extend([
            // BPF cannot inspect clone3's pointed-to flags. glibc retries clone on ENOSYS.
            (EQUAL, 0, 1, libc::SYS_clone3 as u32),
            (RETURN, 0, 0, UNAVAILABLE),
            (EQUAL, 1, 0, libc::SYS_clone as u32),
            (RETURN, 0, 0, libc::SECCOMP_RET_ALLOW),
            (LOAD, 0, 0, 16),
            (SET, 1, 0, libc::CLONE_THREAD as u32),
            (RETURN, 0, 0, DENIED),
        ]);
    }
    filter.push((RETURN, 0, 0, libc::SECCOMP_RET_ALLOW));
    filter
        .into_iter()
        .flat_map(|(code, jt, jf, value)| {
            let code = code.to_ne_bytes();
            let value = value.to_ne_bytes();
            [
                code[0], code[1], jt, jf, value[0], value[1], value[2], value[3],
            ]
        })
        .collect()
}

fn write_image_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

struct Profile {
    enrollment: Arc<OwnedFd>,
}

impl mesh_process::SandboxProfile for Profile {
    fn apply(&mut self, builder: &mut pal::unix::process::Builder<'_>) {
        builder
            .stdin(pal::unix::process::Stdio::Null)
            .inherit_env(false)
            .set_close_fds(true)
            .set_cgroup_procs(self.enrollment.clone());
    }
}

struct Guard {
    domain: Domain,
    image: Mutex<Option<Image>>,
    output: Output,
    retain: AtomicBool,
}

impl ProcessGuard for Guard {
    fn start_launch(&self) {
        self.retain.store(true, Ordering::Release);
        self.domain.retain();
    }

    fn terminate_domain(&self) -> Result<()> {
        self.domain.terminate_domain()
    }

    fn wait_empty(&self, deadline: Instant) -> Result<()> {
        self.domain.wait_empty(deadline)
    }

    fn release_resources(&self, deadline: Instant) -> Result<()> {
        self.domain.remove(deadline)?;
        self.output.finish()?;
        let mut image = self
            .image
            .lock()
            .map_err(|_| new_error!("Process image ownership is poisoned"))?;
        if let Some(staged) = &*image {
            fs::remove_dir_all(staged.directory.path())?;
        }
        image.take();
        self.retain.store(false, Ordering::Release);
        Ok(())
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let termination = self.terminate_domain();
        let cleanup = if self.retain.load(Ordering::Acquire) {
            Err(new_error!(
                "Root cleanup has not authorized resource release"
            ))
        } else {
            self.release_resources(Instant::now() + Duration::from_secs(30))
        };
        if termination.is_err() || cleanup.is_err() {
            self.domain.retain();
            tracing::error!(
                ?termination,
                ?cleanup,
                "Linux confinement cleanup incomplete"
            );
            if let Some(image) = self
                .image
                .get_mut()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                let path = image.directory.keep();
                tracing::error!(?path, "Retaining process image after incomplete cleanup");
            }
        }
    }
}

pub(super) fn prepare(
    role: ProgramRole,
    definition: &ProcessDefinition,
    program: &ValidatedProgram,
    resources: Option<&LinuxProcessResources>,
    discovery_error: Option<&str>,
) -> Result<PreparedProcess> {
    let profile = definition.profile();
    profile.validate()?;
    if profile.is_unrestricted() {
        let directory = tempfile::Builder::new()
            .prefix("hyperlight-unrestricted-")
            .tempdir()?;
        let executable = directory.path().join("program");
        write_image_file(&executable, program.executable(), 0o500)?;
        if !program.runtime_files().is_empty() {
            return Err(new_error!(
                "Linux unrestricted process preparation requires a self-contained executable"
            ));
        }
        struct UnrestrictedGuard(Mutex<Option<tempfile::TempDir>>);
        impl ProcessGuard for UnrestrictedGuard {
            fn start_launch(&self) {}
            fn terminate_domain(&self) -> Result<()> {
                Ok(())
            }
            fn wait_empty(&self, _deadline: Instant) -> Result<()> {
                Ok(())
            }
            fn release_resources(&self, _deadline: Instant) -> Result<()> {
                self.0
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                Ok(())
            }
        }
        let guard = Arc::new(UnrestrictedGuard(Mutex::new(Some(directory))));
        return Ok(PreparedProcess {
            config: mesh_process::ProcessConfig::new(definition.name())
                .process_name(executable)
                .skip_worker_arg(true),
            guard,
            controls: Vec::new(),
            windows_policy: None,
            resources: Vec::new(),
            export_authority: None,
            resource_generation: None,
        });
    }
    let resources = resources.ok_or_else(|| {
        new_error!(
            "Restricted Linux process profiles require operator-delegated launch authority: {}",
            discovery_error.unwrap_or("Linux process resources were not configured")
        )
    })?;
    if profile.windows_cpu_rate_percent().is_some() {
        return Err(new_error!(
            "Required Windows CPU rate control for '{}' is unavailable on Linux",
            definition.name()
        ));
    }
    let domain = Domain::create(&resources.delegated_root)?;
    let mut controls = Vec::new();
    for request in &profile.controls {
        let unsupported = match request.control {
            ProcessControl::MemoryLimit(_)
                if !resources.delegated_root.join("memory.max").exists() =>
            {
                Some("The memory controller is unavailable")
            }
            ProcessControl::CpuBudget { quota, period }
                if quota.as_nanos() % 1000 != 0
                    || period.as_nanos() % 1000 != 0
                    || quota.as_micros() < 1000
                    || !(1000..=1_000_000).contains(&period.as_micros()) =>
            {
                Some(
                    "CPU periods require 1-1000 ms and quotas at least 1 ms, in exact microseconds",
                )
            }
            ProcessControl::CpuBudget { .. }
                if !resources.delegated_root.join("cpu.max").exists() =>
            {
                Some("The CPU controller is unavailable")
            }
            _ => None,
        };
        if let Some(reason) = unsupported {
            if request.required {
                return Err(new_error!(
                    "Required control for '{}' is unavailable: {reason}",
                    definition.name()
                ));
            }
            controls.push(ControlOutcome {
                requested: request.clone(),
                result: ControlResult::NotApplied {
                    reason: reason.to_owned(),
                },
            });
            continue;
        }
        match request.control {
            ProcessControl::MemoryLimit(_) | ProcessControl::CpuBudget { .. } => {
                controls.push(domain.configure(request)?);
            }
            ProcessControl::DenyNetwork => controls.push(ControlOutcome {
                requested: request.clone(),
                result: ControlResult::Applied {
                    effective: ProcessControl::DenyNetwork,
                    mechanism: "Private network namespace with no configured interfaces".to_owned(),
                },
            }),
            ProcessControl::DenyChildProcesses => controls.push(ControlOutcome {
                requested: request.clone(),
                result: ControlResult::Applied {
                    effective: ProcessControl::DenyChildProcesses,
                    mechanism: "Native-ABI seccomp before exec, inherited by threads: \
                        fork/vfork and clone without CLONE_THREAD return EPERM; \
                        clone3 returns ENOSYS for libc clone fallback"
                        .to_owned(),
                },
            }),
        }
    }
    let deny_child_processes = profile
        .controls
        .iter()
        .any(|request| request.control == ProcessControl::DenyChildProcesses);
    let image = Image::stage(resources, program, deny_child_processes)?;
    let arguments = image.arguments(role, resources, true)?;
    let (output, writer) = Output::new(definition.name())?;
    let config = mesh_process::ProcessConfig::new_with_sandbox(
        definition.name(),
        Box::new(Profile {
            enrollment: domain.procs_fd(),
        }),
    )
    .process_name(&image.helper)
    .args(arguments)
    .skip_worker_arg(true)
    .stdout(Some(writer.try_clone()?))
    .stderr(Some(writer));
    Ok(PreparedProcess {
        config,
        guard: Arc::new(Guard {
            domain,
            image: Mutex::new(Some(image)),
            output,
            retain: AtomicBool::new(false),
        }),
        controls,
        windows_policy: None,
        resources: Vec::new(),
        export_authority: None,
        resource_generation: None,
    })
}
