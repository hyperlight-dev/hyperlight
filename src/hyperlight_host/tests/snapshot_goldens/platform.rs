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
//! A snapshot is bound to its CPU architecture, hypervisor, CPU
//! vendor, and build profile. None of these transfer, so each
//! `(arch, hypervisor, cpu vendor, build profile)` tuple gets its own
//! tag, named `{GOLDENS_VERSION}-{arch}-{hv}-{cpu}-{profile}`. Each
//! host verifies only its own tag.

use crate::goldens_version::GOLDENS_VERSION;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Hypervisor {
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    Kvm,
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    Mshv,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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
    /// Linux, WHP on Windows.
    fn detect() -> Option<Self> {
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
enum Arch {
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
    X86_64,
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    Aarch64,
}

impl Arch {
    fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn detect() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Self::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(Self::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
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
pub(crate) struct Platform {
    arch: Arch,
    hv: Hypervisor,
    cpu: &'static str,
    profile: Profile,
}

impl Platform {
    pub(crate) fn detect() -> Option<Self> {
        Some(Self {
            arch: Arch::detect()?,
            hv: Hypervisor::detect()?,
            cpu: hyperlight_host::sandbox::snapshot::host_cpu_vendor_golden_tag()?,
            profile: Profile::detect(),
        })
    }

    fn suffix(&self) -> String {
        // The `snapshot-goldens-pull` recipe in the Justfile rebuilds this
        // same `{arch}-{hv}-{cpu}-{profile}` string in bash. Keep both in sync.
        format!(
            "{}-{}-{}-{}",
            self.arch.as_str(),
            self.hv.as_str(),
            self.cpu,
            self.profile.as_str(),
        )
    }

    pub(crate) fn tag(&self) -> String {
        self.tag_for(GOLDENS_VERSION)
    }

    /// The golden tag for this platform at `version`.
    pub(crate) fn tag_for(&self, version: &str) -> String {
        format!("{}-{}", version, self.suffix())
    }

    pub(crate) fn cpu_str(&self) -> &'static str {
        self.cpu
    }
}
