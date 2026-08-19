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

use std::path::Path;
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Duration;

use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use tracing_core::LevelFilter;

use crate::func::HostFunction;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
use crate::sandbox::SandboxConfiguration;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
#[cfg(target_arch = "x86_64")]
use crate::sandbox::config::GuestMsrError;
use crate::sandbox::host_funcs::FunctionEntry;
use crate::sandbox::snapshot::Snapshot;
use crate::sandbox::uninitialized::{GuestBlob, GuestEnvironment};
use crate::{
    GuestBinary, HostFunctions, MultiUseSandbox as Sandbox, Result, UninitializedSandbox, new_error,
};

/// Builds a [`Sandbox`].
///
/// Start from [`SandboxBuilder::new`], chain the settings you need, then call
/// one of the `build_from_*` methods to create the sandbox from a guest binary
/// on disk, a guest binary in memory, or a [`Snapshot`]. Every setting has a
/// default, so a builder with no adjustments is valid.
///
/// # Examples
///
/// From a guest binary on disk:
///
/// ```no_run
/// # use hyperlight_host::{Result, SandboxBuilder};
/// # fn example() -> Result<()> {
/// let mut sandbox = SandboxBuilder::new()
///     .heap_size(1024 * 1024)
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build_from_file("guest.bin")?;
///
/// let result: String = sandbox.call("Echo", "hello".to_string())?;
/// # Ok(())
/// # }
/// ```
///
/// From a snapshot. The snapshot carries the guest binary and the state it was
/// taken in, so no guest binary is given here. The builder must still register
/// every host function the snapshot was taken with:
///
/// ```no_run
/// # use hyperlight_host::{Result, SandboxBuilder};
/// # fn example() -> Result<()> {
/// let mut sandbox = SandboxBuilder::new()
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build_from_file("guest.bin")?;
/// let snapshot = sandbox.snapshot()?;
///
/// let mut restored = SandboxBuilder::new()
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build_from_snapshot(snapshot)?;
///
/// let result: String = restored.call("Echo", "hello".to_string())?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct SandboxBuilder {
    cfg: SandboxConfiguration,
    host_funcs: HostFunctions,
    init_data: Option<(Vec<u8>, MemoryRegionFlags)>,
    mapped_file_cow: Vec<(std::path::PathBuf, u64)>,
    mapped_memory_regions: Vec<MemoryRegion>,
    guest_log_level: Option<LevelFilter>,
}

impl SandboxBuilder {
    /// Create a builder with the default configuration and the default host
    /// functions.
    ///
    /// By default only the `HostPrint` host function is registered, which
    /// writes guest output to the host's stdout. Replace it with
    /// [`Self::host_print`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a sandbox running the guest binary at `path`.
    pub fn build_from_file(self, path: impl AsRef<Path>) -> Result<Sandbox> {
        let path = path.as_ref().to_path_buf();
        self.build_from_guest_binary(GuestBinary::FilePath(path))
    }

    /// Build a sandbox running the guest binary held in `buffer`.
    pub fn build_from_bytes(self, buffer: impl AsRef<[u8]>) -> Result<Sandbox> {
        let buffer = buffer.as_ref();
        self.build_from_guest_binary(GuestBinary::Buffer(buffer))
    }

    fn build_from_guest_binary(self, guest_binary: GuestBinary) -> Result<Sandbox> {
        let init_data = self.init_data.as_ref().map(|(data, flags)| GuestBlob {
            data,
            permissions: *flags,
        });

        let env = GuestEnvironment {
            init_data,
            guest_binary,
        };

        let mut uninitialized_sandbox = UninitializedSandbox::new(env, Some(self.cfg))?;

        uninitialized_sandbox.host_funcs = Arc::new(Mutex::new(self.host_funcs.into_inner()));

        for (path, guest_base) in self.mapped_file_cow {
            uninitialized_sandbox.map_file_cow(&path, guest_base)?;
        }

        if let Some(log_level) = self.guest_log_level {
            uninitialized_sandbox.set_max_guest_log_level(log_level);
        }

        let mut sandbox = uninitialized_sandbox.evolve()?;

        for region in self.mapped_memory_regions {
            // SAFETY: the caller of `mapped_memory_region` guaranteed each region
            // stays valid and unmodified for the lifetime of this sandbox.
            unsafe { sandbox.map_region(&region)? };
        }

        Ok(sandbox)
    }

    /// Build a sandbox restored from `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Self::init_data`] or [`Self::guest_log_level`]
    /// are set. The snapshot already carries both, so they have no effect here.
    pub fn build_from_snapshot(self, snapshot: Arc<Snapshot>) -> Result<Sandbox> {
        if self.init_data.is_some() {
            return Err(new_error!(
                "init_data has no effect when building from a snapshot, as the snapshot already contains it"
            ));
        }

        if self.guest_log_level.is_some() {
            return Err(new_error!(
                "guest_log_level has no effect when building from a snapshot, as the snapshot already contains it"
            ));
        }

        let mut sandbox = Sandbox::from_snapshot(snapshot, self.host_funcs, Some(self.cfg))?;

        for (path, guest_base) in self.mapped_file_cow {
            sandbox.map_file_cow(&path, guest_base)?;
        }

        for region in self.mapped_memory_regions {
            // SAFETY: the caller of `mapped_memory_region` guaranteed each region
            // stays valid and unmodified for the lifetime of this sandbox.
            unsafe { sandbox.map_region(&region)? };
        }

        Ok(sandbox)
    }
}

impl SandboxBuilder {
    /// Sets the sandbox `init_data` into the sandbox's memory when it is built, with `flags` as
    /// the guest's permissions on that region.
    ///
    /// Note: [`Self::build_from_snapshot`] errors if this setting is set, as the snapshot already
    /// contains the init data.
    pub fn init_data(mut self, data: impl Into<Vec<u8>>, flags: MemoryRegionFlags) -> Self {
        self.init_data = Some((data.into(), flags));
        self
    }

    /// Map the contents of the file at `path` into the guest at `guest_base`,
    /// copy-on-write.
    ///
    /// `guest_base` must be page-aligned and lie outside the sandbox's primary
    /// shared memory region. Violations surface as an error from the
    /// `build_from_*` call, not here. Call this once per file to map several.
    pub fn mapped_file_cow(mut self, path: impl AsRef<Path>, guest_base: u64) -> Self {
        self.mapped_file_cow
            .push((path.as_ref().to_path_buf(), guest_base));
        self
    }

    /// Maps a region of host memory into the sandbox address space.
    ///
    /// The base address and length must meet platform alignment requirements
    /// (typically page-aligned). The `region_type` field is ignored as guest
    /// page table entries are not created.
    ///
    /// # Safety
    ///
    /// The caller must ensure the host memory region remains valid and
    /// unmodified for the lifetime of the sandbox this builder produces.
    pub unsafe fn mapped_memory_region(mut self, region: MemoryRegion) -> Self {
        self.mapped_memory_regions.push(region);
        self
    }

    /// Sets the maximum log level for guest code execution.
    ///
    /// If not set, the log level is determined by the `RUST_LOG` environment variable,
    /// defaulting to [`LevelFilter::ERROR`] if unset.
    ///
    /// Note: [`Self::build_from_snapshot`] errors if this setting is set, as the log level is
    /// already captured in the snapshot.
    pub fn guest_log_level(mut self, level: LevelFilter) -> Self {
        self.guest_log_level = Some(level);
        self
    }

    /// The maximum log level for guest code execution, or `None` if not set.
    pub fn get_guest_log_level(&self) -> Option<LevelFilter> {
        self.guest_log_level
    }
}

impl SandboxBuilder {
    /// Registers a host function that the guest can call.
    ///
    /// Note: registering under the name `HostPrint` overrides guest printing.
    /// Prefer [`Self::host_print`], which checks the signature at compile time.
    pub fn host_function<Args: ParameterTuple, Output: SupportedReturnType>(
        mut self,
        name: impl AsRef<str>,
        host_func: impl Into<HostFunction<Output, Args>>,
    ) -> Self {
        let func = host_func.into().into();
        let name = name.as_ref().to_string();

        let entry = FunctionEntry {
            function: func,
            parameter_types: Args::TYPE,
            return_type: Output::TYPE,
        };

        self.host_funcs
            .inner_mut()
            .register_host_function(name, entry);
        self
    }

    /// Registers the special "HostPrint" function for guest printing.
    ///
    /// This overrides the default behavior of writing to stdout.
    /// The function expects the signature `FnMut(String) -> i32`
    /// and will be called when the guest wants to print output.
    pub fn host_print(self, print_func: impl Into<HostFunction<i32, (String,)>>) -> Self {
        self.host_function("HostPrint", print_func)
    }

    /// Registers every host function in `host_funcs`.
    ///
    /// Entries whose names are already registered are overwritten.
    ///
    /// Note: an entry named `HostPrint` overrides guest printing. Prefer
    /// [`Self::host_print`], which checks the signature at compile time.
    pub fn host_functions(mut self, host_funcs: HostFunctions) -> Self {
        for (func_name, func_entry) in host_funcs.into_iter() {
            self.host_funcs
                .inner_mut()
                .register_host_function(func_name, func_entry);
        }
        self
    }
}

impl SandboxBuilder {
    /// Set the size of the memory buffer made available for input to the guest.
    /// Values below [`SandboxConfiguration::MIN_INPUT_SIZE`] are clamped up.
    pub fn input_data_size(mut self, size: usize) -> Self {
        self.cfg.set_input_data_size(size);
        self
    }

    /// The size of the memory buffer made available for input to the guest.
    pub fn get_input_data_size(&self) -> usize {
        self.cfg.get_input_data_size()
    }

    /// Set the size of the memory buffer made available for output from the guest.
    /// Values below [`SandboxConfiguration::MIN_OUTPUT_SIZE`] are clamped up.
    pub fn output_data_size(mut self, size: usize) -> Self {
        self.cfg.set_output_data_size(size);
        self
    }

    /// The size of the memory buffer made available for output from the guest.
    pub fn get_output_data_size(&self) -> usize {
        self.cfg.get_output_data_size()
    }

    /// Set the guest heap size. A size of 0 selects
    /// [`SandboxConfiguration::DEFAULT_HEAP_SIZE`].
    pub fn heap_size(mut self, size: u64) -> Self {
        self.cfg.set_heap_size(size);
        self
    }

    /// The guest heap size, defaulting to
    /// [`SandboxConfiguration::DEFAULT_HEAP_SIZE`] when no override is set.
    pub fn get_heap_size(&self) -> u64 {
        self.cfg.get_heap_size()
    }

    /// Set how much writable memory to offer the guest.
    pub fn scratch_size(mut self, size: usize) -> Self {
        self.cfg.set_scratch_size(size);
        self
    }

    /// How much writable memory is offered to the guest.
    pub fn get_scratch_size(&self) -> usize {
        self.cfg.get_scratch_size()
    }

    /// Declare MSRs the guest owns, saved and restored with the rest of the
    /// sandbox state. Adds to the declared set, so repeated calls accumulate.
    ///
    /// See [`SandboxConfiguration::guest_msrs`] for the platform-specific
    /// behavior and the capacity limit.
    ///
    /// # Errors
    ///
    /// Returns [`GuestMsrError::CapacityExceeded`] if the distinct entries
    /// would exceed [`SandboxConfiguration::MAX_GUEST_MSRS`]. The declared set
    /// is unchanged on error.
    #[cfg(target_arch = "x86_64")]
    pub fn guest_msrs(mut self, indices: &[u32]) -> std::result::Result<Self, GuestMsrError> {
        self.cfg.guest_msrs(indices)?;
        Ok(self)
    }

    /// Set how long to wait between attempts to signal the VCPU thread.
    #[cfg(target_os = "linux")]
    pub fn interrupt_retry_delay(mut self, delay: Duration) -> Self {
        self.cfg.set_interrupt_retry_delay(delay);
        self
    }

    /// How long to wait between attempts to signal the VCPU thread.
    #[cfg(target_os = "linux")]
    pub fn get_interrupt_retry_delay(&self) -> Duration {
        self.cfg.get_interrupt_retry_delay()
    }

    /// Set the offset from `SIGRTMIN` for the signal used to interrupt the VCPU
    /// thread.
    ///
    /// # Errors
    ///
    /// Returns an error if `SIGRTMIN + offset` exceeds `SIGRTMAX`.
    #[cfg(target_os = "linux")]
    pub fn interrupt_vcpu_sigrtmin_offset(mut self, offset: u8) -> Result<Self> {
        self.cfg.set_interrupt_vcpu_sigrtmin_offset(offset)?;
        Ok(self)
    }

    /// The offset from `SIGRTMIN` for the signal used to interrupt the VCPU thread.
    #[cfg(target_os = "linux")]
    pub fn get_interrupt_vcpu_sigrtmin_offset(&self) -> u8 {
        self.cfg.get_interrupt_vcpu_sigrtmin_offset()
    }

    /// Toggle guest core dump generation.
    #[cfg(crashdump)]
    pub fn guest_core_dump(mut self, enabled: bool) -> Self {
        self.cfg.set_guest_core_dump(enabled);
        self
    }

    /// Whether guest core dump generation is enabled.
    #[cfg(crashdump)]
    pub fn get_guest_core_dump(&self) -> bool {
        self.cfg.get_guest_core_dump()
    }

    /// Set the guest debug configuration.
    #[cfg(gdb)]
    pub fn guest_debug_info(mut self, debug_info: DebugInfo) -> Self {
        self.cfg.set_guest_debug_info(debug_info);
        self
    }

    /// The guest debug configuration, or `None` when debugging is not configured.
    #[cfg(gdb)]
    pub fn get_guest_debug_info(&self) -> Option<DebugInfo> {
        self.cfg.get_guest_debug_info()
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_testing::simple_guest_as_string;
    use tracing_core::LevelFilter;

    use super::SandboxBuilder;
    use crate::mem::memory_region::MemoryRegionFlags;

    #[test]
    fn build_from_file() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::new()
            .input_data_size(0x8000)
            .build_from_file(path)
            .unwrap();

        let result = sandbox.call::<String>("Echo", "hello".to_string()).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_bytes() {
        let bytes = std::fs::read(simple_guest_as_string().unwrap()).unwrap();
        let mut sandbox = SandboxBuilder::new().build_from_bytes(bytes).unwrap();

        let result = sandbox.call::<String>("Echo", "hello".to_string()).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_snapshot() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::new().build_from_file(path).unwrap();
        let snapshot = sandbox.snapshot().unwrap();

        let mut restored = SandboxBuilder::new().build_from_snapshot(snapshot).unwrap();

        let result = restored
            .call::<String>("Echo", "hello".to_string())
            .unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_snapshot_errors_on_ignored_settings() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::new().build_from_file(path).unwrap();
        let snapshot = sandbox.snapshot().unwrap();

        assert!(
            SandboxBuilder::new()
                .init_data([0u8; 8], MemoryRegionFlags::READ)
                .build_from_snapshot(snapshot.clone())
                .is_err()
        );

        assert!(
            SandboxBuilder::new()
                .guest_log_level(LevelFilter::INFO)
                .build_from_snapshot(snapshot)
                .is_err()
        );
    }
}
