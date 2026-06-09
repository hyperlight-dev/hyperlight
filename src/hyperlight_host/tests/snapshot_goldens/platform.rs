/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Local platform detection and tag naming for snapshot goldens.
//!
//! A snapshot is not portable across `(hypervisor, cpu vendor,
//! build profile)`. Each such triple gets its own set of tags,
//! named `{GOLDENS_VERSION}-{hv}-{cpu}-{profile}-{kind}`.

/// Goldens version. Follows a `vMAJOR.MINOR` scheme. Bump MAJOR when
/// the snapshot ABI changes (anything that invalidates older
/// snapshots: ABI bump, media type bump, layout arithmetic changes,
/// captured-register changes). Bump MINOR when the set of `CHECKS`
/// changes but the ABI does not. See `docs/snapshot-versioning.md`.
///
/// The runtime tripwire test
/// `hyperlight_host::sandbox::snapshot::tripwires::media_types_match_expected_for_goldens`
/// and the compile-time `SNAPSHOT_ABI_VERSION` assertion pin the
/// known ABI surface against this version's goldens.
pub const GOLDENS_VERSION: &str = "v1.0";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Init,
    Call,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Call => "call",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Hypervisor {
    Kvm,
    Mshv,
    Whp,
}

impl Hypervisor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Mshv => "mshv",
            Self::Whp => "whp",
        }
    }

    /// Detect the locally available hypervisor. Order matches the
    /// host crate's preference: `/dev/mshv` over `/dev/kvm` on
    /// Linux, WHP on Windows. `HYPERLIGHT_GOLDENS_HV` overrides on
    /// hosts that have more than one available.
    fn detect() -> Option<Self> {
        if let Some(v) = std::env::var_os("HYPERLIGHT_GOLDENS_HV") {
            return match v.to_string_lossy().as_ref() {
                "kvm" => Some(Self::Kvm),
                "mshv" => Some(Self::Mshv),
                "whp" => Some(Self::Whp),
                _ => None,
            };
        }
        #[cfg(target_os = "linux")]
        {
            if std::path::Path::new("/dev/mshv").exists() {
                return Some(Self::Mshv);
            }
            if std::path::Path::new("/dev/kvm").exists() {
                return Some(Self::Kvm);
            }
            None
        }
        #[cfg(target_os = "windows")]
        {
            Some(Self::Whp)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            None
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CpuVendor {
    Intel,
    Amd,
}

impl CpuVendor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Amd => "amd",
        }
    }

    /// Detect the local CPU vendor via the `0` leaf of `cpuid`.
    /// Returns `None` on non-`x86_64` targets or unknown vendor
    /// strings.
    fn detect() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: cpuid leaf 0 is always available on x86_64.
            let r = unsafe { core::arch::x86_64::__cpuid(0) };
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&r.ebx.to_le_bytes());
            bytes[4..8].copy_from_slice(&r.edx.to_le_bytes());
            bytes[8..12].copy_from_slice(&r.ecx.to_le_bytes());
            match &bytes {
                b"GenuineIntel" => Some(Self::Intel),
                b"AuthenticAMD" => Some(Self::Amd),
                _ => None,
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            None
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Profile {
    Debug,
    Release,
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    fn detect() -> Self {
        if cfg!(debug_assertions) {
            Self::Debug
        } else {
            Self::Release
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    hv: Hypervisor,
    cpu: CpuVendor,
    profile: Profile,
}

impl Platform {
    pub fn detect() -> Option<Self> {
        Some(Self {
            hv: Hypervisor::detect()?,
            cpu: CpuVendor::detect()?,
            profile: Profile::detect(),
        })
    }

    pub fn suffix(&self) -> String {
        format!(
            "{}-{}-{}",
            self.hv.as_str(),
            self.cpu.as_str(),
            self.profile.as_str(),
        )
    }

    pub fn tag(&self, kind: Kind) -> String {
        format!("{}-{}-{}", GOLDENS_VERSION, self.suffix(), kind.as_str())
    }
}
