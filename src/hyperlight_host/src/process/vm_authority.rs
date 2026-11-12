// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::sync::{Arc, Mutex};

use super::{
    FIRST_TYPED_RESOURCE_KIND, LaunchResourceFactory, NativeResourcePayload,
    NativeResourceValidator, ProcessResourceManifest, ProcessResources,
};
use crate::{Result, new_error};

pub(crate) const VM_AUTHORITY_RESOURCE_KIND: u32 = FIRST_TYPED_RESOURCE_KIND + 1;

/// Hypervisor backend authorized for one function-worker generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmBackend {
    /// Linux KVM.
    Kvm,
    /// Linux Microsoft Hypervisor.
    Mshv,
    /// Windows Hypervisor Platform.
    Whp,
}

impl VmBackend {
    fn metadata(self) -> Vec<u8> {
        vec![match self {
            Self::Kvm => 1,
            Self::Mshv => 2,
            Self::Whp => 3,
        }]
    }

    fn from_metadata(metadata: &[u8]) -> Result<Self> {
        match metadata {
            [1] => Ok(Self::Kvm),
            [2] => Ok(Self::Mshv),
            [3] => Ok(Self::Whp),
            _ => Err(new_error!("VM authority metadata is invalid")),
        }
    }

    pub(crate) fn environment_value(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Mshv => "mshv",
            Self::Whp => "whp",
        }
    }

    pub(crate) fn from_environment_value(value: &str) -> Result<Self> {
        match value {
            "kvm" => Ok(Self::Kvm),
            "mshv" => Ok(Self::Mshv),
            "whp" => Ok(Self::Whp),
            _ => Err(new_error!("VM authority backend is invalid")),
        }
    }
}

/// Consume-once VM authority for one function-worker generation.
pub struct VmAuthority {
    generation: u64,
    backend: VmBackend,
    payload: NativeResourcePayload,
}

/// Runtime-only WHP authorization for one function-worker generation.
#[cfg(target_os = "windows")]
pub type VmHostAuthorization = VmAuthority;

impl VmAuthority {
    /// Installs this authority for the next VM created in this worker.
    pub fn install_for_current_generation(self) -> Result<()> {
        let expected = match captured_process_context()? {
            Some(generation) => generation,
            _ => {
                return Err(new_error!(
                    "VM authority installation requires a claimed worker authority"
                ));
            }
        };
        self.install_for("worker", expected)
    }

    fn install_for(self, role: &str, expected: u64) -> Result<()> {
        if role != "worker" {
            return Err(new_error!(
                "VM authority can only be installed by a function worker"
            ));
        }
        if expected == 0 || expected != self.generation {
            return Err(new_error!("VM authority generation mismatch"));
        }
        let mut installed = INSTALLED
            .lock()
            .map_err(|error| new_error!("VM authority installation lock failed: {error}"))?;
        if installed.is_some() {
            return Err(new_error!(
                "VM authority is already installed for this worker generation"
            ));
        }
        *installed = Some(InstalledVmAuthority {
            generation: self.generation,
            backend: self.backend,
            payload: self.payload,
        });
        *ACTIVE_BACKEND
            .lock()
            .map_err(|error| new_error!("VM authority backend lock failed: {error}"))? =
            Some(self.backend);
        Ok(())
    }
}

pub(crate) struct InstalledVmAuthority {
    generation: u64,
    pub(crate) backend: VmBackend,
    pub(crate) payload: NativeResourcePayload,
}

static INSTALLED: Mutex<Option<InstalledVmAuthority>> = Mutex::new(None);
static ACTIVE_BACKEND: Mutex<Option<VmBackend>> = Mutex::new(None);
static PROCESS_CONTEXT: Mutex<Option<u64>> = Mutex::new(None);

fn capture_process_context(generation: u64) -> Result<()> {
    if generation == 0 {
        return Err(new_error!("VM authority generation is invalid"));
    }
    let mut captured = PROCESS_CONTEXT
        .lock()
        .map_err(|error| new_error!("Process VM context lock failed: {error}"))?;
    if captured.is_some() {
        return Err(new_error!("Process VM context was already captured"));
    }
    *captured = Some(generation);
    Ok(())
}

pub(super) fn capture_declared_process_context(
    generation: u64,
    declarations: &[super::resource::WireResourceDeclaration],
) -> Result<()> {
    if declarations
        .iter()
        .any(|declaration| declaration.kind == VM_AUTHORITY_RESOURCE_KIND)
    {
        capture_process_context(generation)?;
    }
    Ok(())
}

fn captured_process_context() -> Result<Option<u64>> {
    PROCESS_CONTEXT
        .lock()
        .map(|context| *context)
        .map_err(|error| new_error!("Process VM context lock failed: {error}"))
}

pub(crate) fn take_installed_for_vm() -> Result<Option<InstalledVmAuthority>> {
    match captured_process_context()? {
        Some(generation) => take_installed_for("worker", generation),
        None => Ok(None),
    }
}

fn take_installed_for(role: &str, expected: u64) -> Result<Option<InstalledVmAuthority>> {
    if role != "worker" {
        return Ok(None);
    }
    let authority = INSTALLED
        .lock()
        .map_err(|error| new_error!("VM authority installation lock failed: {error}"))?
        .take();
    let Some(authority) = authority else {
        let active = ACTIVE_BACKEND
            .lock()
            .map_err(|error| new_error!("VM authority backend lock failed: {error}"))?
            .is_some();
        return Err(if active {
            new_error!("Function worker VM authority was already consumed by this generation")
        } else {
            new_error!("Function worker VM authority was not installed before VM creation")
        });
    };
    if expected == 0 || authority.generation != expected {
        return Err(new_error!("Installed VM authority is stale"));
    }
    Ok(Some(authority))
}

pub(crate) fn current_vm_backend() -> Option<VmBackend> {
    ACTIVE_BACKEND.lock().ok().and_then(|backend| *backend)
}

impl ProcessResourceManifest {
    /// Requires one backend-tagged VM authority capability.
    pub fn with_vm_authority(self, backend: VmBackend) -> Result<Self> {
        validate_platform_backend(backend)?;
        self.with_typed(
            VM_AUTHORITY_RESOURCE_KIND,
            backend.metadata(),
            Arc::new(VmAuthorityValidator { backend }),
        )
    }
}

impl ProcessResources {
    /// Claims the unique VM authority for this worker generation.
    pub fn take_vm_authority(&mut self, expected: VmBackend) -> Result<VmAuthority> {
        validate_platform_backend(expected)?;
        let generation = self
            .generation()
            .ok_or_else(|| new_error!("VM authority generation is missing"))?;
        let id = self.unique_typed_id(VM_AUTHORITY_RESOURCE_KIND)?;
        let claimed = self.take_typed(id, VM_AUTHORITY_RESOURCE_KIND)?;
        let backend = VmBackend::from_metadata(&claimed.metadata)?;
        if backend != expected {
            return Err(new_error!("VM authority backend mismatch"));
        }
        VmAuthorityValidator { backend }.validate(&claimed.metadata, &claimed.payload)?;
        Ok(VmAuthority {
            generation,
            backend,
            payload: claimed.payload,
        })
    }
}

struct VmAuthorityValidator {
    backend: VmBackend,
}

impl NativeResourceValidator for VmAuthorityValidator {
    fn validate(&self, metadata: &[u8], payload: &NativeResourcePayload) -> Result<()> {
        if VmBackend::from_metadata(metadata)? != self.backend {
            return Err(new_error!("VM authority declaration backend mismatch"));
        }
        match (self.backend, payload) {
            #[cfg(unix)]
            (VmBackend::Kvm, NativeResourcePayload::Descriptor(fd)) => validate_kvm(fd),
            #[cfg(unix)]
            (VmBackend::Mshv, NativeResourcePayload::Descriptor(fd)) => validate_mshv(fd),
            #[cfg(windows)]
            (VmBackend::Whp, NativeResourcePayload::AuthorizationMarker) => Ok(()),
            _ => Err(new_error!("VM authority native payload mismatch")),
        }
    }
}

#[cfg(target_os = "linux")]
struct LinuxVmAuthorityFactory {
    backend: VmBackend,
    device: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LaunchResourceFactory for LinuxVmAuthorityFactory {
    fn create(&self, _generation: u64) -> Result<NativeResourcePayload> {
        use std::os::fd::OwnedFd;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.device)?;
        let fd: OwnedFd = file.into();
        match self.backend {
            VmBackend::Kvm => validate_kvm(&fd)?,
            VmBackend::Mshv => validate_mshv(&fd)?,
            VmBackend::Whp => {
                return Err(new_error!("WHP VM authority is unavailable on Linux"));
            }
        }
        Ok(NativeResourcePayload::Descriptor(fd))
    }
}

#[cfg(windows)]
struct WhpVmAuthorityFactory;

#[cfg(windows)]
impl LaunchResourceFactory for WhpVmAuthorityFactory {
    fn create(&self, _generation: u64) -> Result<NativeResourcePayload> {
        Ok(NativeResourcePayload::AuthorizationMarker)
    }
}

pub(crate) fn registration(
    backend: VmBackend,
    #[cfg(target_os = "linux")] device: std::path::PathBuf,
) -> Result<(Vec<u8>, Arc<dyn LaunchResourceFactory>)> {
    validate_platform_backend(backend)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;

        let expected = match backend {
            VmBackend::Kvm => std::path::Path::new("/dev/kvm"),
            VmBackend::Mshv => std::path::Path::new("/dev/mshv"),
            VmBackend::Whp => unreachable!(),
        };
        if device != expected
            || !std::fs::symlink_metadata(&device)?
                .file_type()
                .is_char_device()
        {
            return Err(new_error!(
                "VM authority device does not match the selected backend"
            ));
        }
        let factory = LinuxVmAuthorityFactory { backend, device };
        let probe = factory.create(1)?;
        VmAuthorityValidator { backend }.validate(&backend.metadata(), &probe)?;
        Ok((backend.metadata(), Arc::new(factory)))
    }
    #[cfg(windows)]
    {
        Ok((backend.metadata(), Arc::new(WhpVmAuthorityFactory)))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = backend;
        Err(new_error!("VM authority is unavailable on this platform"))
    }
}

pub(crate) fn registered_backend(kind: u32, metadata: &[u8]) -> Result<Option<VmBackend>> {
    if kind != VM_AUTHORITY_RESOURCE_KIND {
        return Ok(None);
    }
    Ok(Some(VmBackend::from_metadata(metadata)?))
}

fn validate_platform_backend(backend: VmBackend) -> Result<()> {
    #[cfg(target_os = "linux")]
    if !matches!(backend, VmBackend::Kvm | VmBackend::Mshv) {
        return Err(new_error!("WHP VM authority is unavailable on Linux"));
    }
    #[cfg(windows)]
    if backend != VmBackend::Whp {
        return Err(new_error!("Linux VM authority is unavailable on Windows"));
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = backend;
        Err(new_error!("VM authority is unavailable on this platform"))
    }
    #[cfg(any(target_os = "linux", windows))]
    Ok(())
}

#[cfg(all(unix, any(kvm, mshv3)))]
fn duplicate_fd(fd: &std::os::fd::OwnedFd) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};

    // SAFETY: fd is live and F_DUPFD_CLOEXEC returns a fresh owned descriptor.
    let duplicated = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(all(unix, kvm))]
fn validate_kvm(fd: &std::os::fd::OwnedFd) -> Result<()> {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let duplicate = duplicate_fd(fd)?;
    // SAFETY: the duplicate is valid, uniquely owned, and transferred to Kvm.
    let kvm = unsafe { kvm_ioctls::Kvm::from_raw_fd(duplicate.into_raw_fd()) };
    if kvm.get_api_version() != 12 {
        return Err(new_error!("KVM API version 12 is required"));
    }
    if !kvm.check_extension(kvm_ioctls::Cap::UserMemory) {
        return Err(new_error!("KVM user-memory capability is required"));
    }
    #[cfg(target_arch = "x86_64")]
    if !kvm.check_extension(kvm_ioctls::Cap::X86MsrFilter) {
        return Err(new_error!("KVM MSR-filter capability is required"));
    }
    Ok(())
}

#[cfg(all(unix, not(kvm)))]
fn validate_kvm(_fd: &std::os::fd::OwnedFd) -> Result<()> {
    Err(new_error!("KVM support is not compiled"))
}

#[cfg(all(unix, mshv3, target_arch = "x86_64"))]
fn validate_mshv(fd: &std::os::fd::OwnedFd) -> Result<()> {
    use std::os::fd::IntoRawFd;

    let duplicate = duplicate_fd(fd)?;
    // SAFETY: the duplicate is valid, uniquely owned, and transferred to Mshv.
    let mshv = unsafe { mshv_ioctls::Mshv::new_with_fd_number(duplicate.into_raw_fd()) };
    mshv.get_host_partition_property(
        mshv_bindings::hv_partition_property_code_HV_PARTITION_PROPERTY_PROCESSOR_FEATURES0,
    )
    .map_err(|error| new_error!("MSHV host-property validation failed: {error}"))?;
    Ok(())
}

#[cfg(all(unix, any(not(mshv3), not(target_arch = "x86_64"))))]
fn validate_mshv(_fd: &std::os::fd::OwnedFd) -> Result<()> {
    Err(new_error!("MSHV support is not compiled for this target"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_metadata_is_exact() {
        for backend in [VmBackend::Kvm, VmBackend::Mshv, VmBackend::Whp] {
            assert_eq!(
                VmBackend::from_metadata(&backend.metadata()).unwrap(),
                backend
            );
        }
        assert!(VmBackend::from_metadata(&[]).is_err());
        assert!(VmBackend::from_metadata(&[1, 0]).is_err());
        assert!(VmBackend::from_metadata(&[4]).is_err());
    }

    #[test]
    fn marker_cannot_authorize_a_linux_backend() {
        for backend in [VmBackend::Kvm, VmBackend::Mshv] {
            assert!(
                VmAuthorityValidator { backend }
                    .validate(
                        &backend.metadata(),
                        &NativeResourcePayload::AuthorizationMarker
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn stale_generation_cannot_install() {
        let authority = VmAuthority {
            generation: 7,
            backend: VmBackend::Whp,
            payload: NativeResourcePayload::AuthorizationMarker,
        };
        assert!(authority.install_for("worker", 8).is_err());
    }

    #[test]
    fn non_worker_cannot_install() {
        let authority = VmAuthority {
            generation: 7,
            backend: VmBackend::Whp,
            payload: NativeResourcePayload::AuthorizationMarker,
        };
        assert!(authority.install_for("sandbox", 7).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn installed_authority_is_consumed_once() {
        *INSTALLED.lock().unwrap() = None;
        *ACTIVE_BACKEND.lock().unwrap() = None;
        VmAuthority {
            generation: 7,
            backend: VmBackend::Whp,
            payload: NativeResourcePayload::AuthorizationMarker,
        }
        .install_for("worker", 7)
        .unwrap();
        let authority = take_installed_for("worker", 7).unwrap().unwrap();
        assert_eq!(authority.backend, VmBackend::Whp);
        assert_eq!(current_vm_backend(), Some(VmBackend::Whp));
        assert!(take_installed_for("worker", 7).is_err());
        *ACTIVE_BACKEND.lock().unwrap() = None;
    }

    #[test]
    #[serial_test::serial]
    fn stale_installed_authority_is_rejected_at_vm_creation() {
        *INSTALLED.lock().unwrap() = None;
        *ACTIVE_BACKEND.lock().unwrap() = None;
        VmAuthority {
            generation: 7,
            backend: VmBackend::Whp,
            payload: NativeResourcePayload::AuthorizationMarker,
        }
        .install_for("worker", 7)
        .unwrap();
        assert!(take_installed_for("worker", 8).is_err());
        *INSTALLED.lock().unwrap() = None;
        *ACTIVE_BACKEND.lock().unwrap() = None;
    }

    #[test]
    #[serial_test::serial]
    fn declared_worker_context_enforces_authority_before_claim() {
        *PROCESS_CONTEXT.lock().unwrap() = None;
        *INSTALLED.lock().unwrap() = None;
        *ACTIVE_BACKEND.lock().unwrap() = None;
        capture_declared_process_context(
            7,
            &[super::super::resource::WireResourceDeclaration {
                session_high: 1,
                session_low: 2,
                slot: 3,
                generation: 7,
                kind: VM_AUTHORITY_RESOURCE_KIND,
                metadata: VmBackend::Whp.metadata(),
            }],
        )
        .unwrap();
        assert!(take_installed_for_vm().is_err());
        VmAuthority {
            generation: 7,
            backend: VmBackend::Whp,
            payload: NativeResourcePayload::AuthorizationMarker,
        }
        .install_for("worker", 7)
        .unwrap();
        assert_eq!(
            take_installed_for_vm().unwrap().unwrap().backend,
            VmBackend::Whp
        );
        assert!(take_installed_for_vm().is_err());
        *PROCESS_CONTEXT.lock().unwrap() = None;
        *ACTIVE_BACKEND.lock().unwrap() = None;
    }

    #[cfg(windows)]
    #[test]
    fn whp_accepts_only_the_authorization_marker() {
        VmAuthorityValidator {
            backend: VmBackend::Whp,
        }
        .validate(
            &VmBackend::Whp.metadata(),
            &NativeResourcePayload::AuthorizationMarker,
        )
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn whp_rejects_an_unexpected_handle() {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};

        use windows::Win32::System::Threading::CreateEventW;

        let handle = unsafe { CreateEventW(None, false, false, None) }.unwrap();
        // SAFETY: CreateEventW returned a fresh owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let payload = NativeResourcePayload::Handle(handle);
        assert!(
            VmAuthorityValidator {
                backend: VmBackend::Whp
            }
            .validate(&VmBackend::Whp.metadata(), &payload)
            .is_err()
        );
        drop(payload);
    }

    #[cfg(unix)]
    #[test]
    fn non_hypervisor_descriptor_is_rejected() {
        use std::os::fd::OwnedFd;

        let file = std::fs::File::open("/dev/null").unwrap();
        let fd: OwnedFd = file.into();
        assert!(validate_kvm(&fd).is_err());
        assert!(validate_mshv(&fd).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launch_factory_opens_fresh_owned_descriptors() {
        use std::os::fd::AsRawFd;

        let device = std::path::PathBuf::from("/dev/kvm");
        if !device.exists() {
            return;
        }
        let (_, factory) = registration(VmBackend::Kvm, device).unwrap();
        let NativeResourcePayload::Descriptor(first) = factory.create(11).unwrap() else {
            panic!("KVM factory returned the wrong payload");
        };
        let NativeResourcePayload::Descriptor(second) = factory.create(12).unwrap() else {
            panic!("KVM factory returned the wrong payload");
        };
        let first_fd = first.as_raw_fd();
        let second_fd = second.as_raw_fd();
        assert_ne!(first_fd, second_fd);
        drop(first);
        assert!(!std::path::Path::new(&format!("/proc/self/fd/{first_fd}")).exists());
        assert!(std::path::Path::new(&format!("/proc/self/fd/{second_fd}")).exists());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", kvm))]
    #[test]
    fn supplied_kvm_descriptor_creates_a_vm_without_reopening_the_device() {
        let device = std::path::PathBuf::from("/dev/kvm");
        if !device.exists() {
            return;
        }
        let (_, factory) = registration(VmBackend::Kvm, device).unwrap();
        let NativeResourcePayload::Descriptor(fd) = factory.create(21).unwrap() else {
            panic!("KVM factory returned the wrong payload");
        };
        // SAFETY: registration validates the KVM descriptor before returning it.
        unsafe { crate::hypervisor::virtual_machine::kvm::KvmVm::new_with_fd(fd) }.unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    #[ignore = "requires built fixture, guest, platform process authority, and a usable hypervisor"]
    fn end_to_end_worker_authority_qualification() {
        let fixture =
            std::env::var_os("HYPERLIGHT_TEST_VM_AUTHORITY_FIXTURE").expect("built fixture path");
        let guest =
            std::env::var_os("HYPERLIGHT_TEST_VM_AUTHORITY_GUEST").expect("guest binary path");
        let output = std::process::Command::new(fixture)
            .arg(guest)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fixture failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    #[ignore = "requires built nested fixture, guest, platform process authority, and a usable hypervisor"]
    fn end_to_end_nested_sandbox_qualification() {
        let fixture = std::env::var_os("HYPERLIGHT_TEST_NESTED_SANDBOX_FIXTURE")
            .expect("built nested fixture path");
        let guest =
            std::env::var_os("HYPERLIGHT_TEST_NESTED_SANDBOX_GUEST").expect("guest binary path");
        let output_directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(fixture)
            .arg(guest)
            .arg(output_directory.path().join("run"))
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "nested fixture failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
