// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyperlight_common::func::{ParameterTuple, SupportedReturnType};
use tracing_core::LevelFilter;

use crate::func::HostFunction;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags};
#[allow(deprecated)]
use crate::sandbox::SandboxConfiguration;
#[cfg(gdb)]
use crate::sandbox::config::DebugInfo;
#[cfg(target_arch = "x86_64")]
use crate::sandbox::config::GuestMsrError;
use crate::sandbox::config::defaults;
use crate::sandbox::host_funcs::FunctionEntry;
use crate::sandbox::snapshot::Snapshot;
use crate::sandbox::uninitialized::{GuestBlob, GuestEnvironment};
#[allow(deprecated)]
use crate::{GuestBinary, HostFunctions, Result, Sandbox, UninitializedSandbox, new_error};

/// What a [`SandboxBuilder`] builds the sandbox from.
enum Source {
    GuestBinary(GuestBinary),
    Snapshot(Arc<Snapshot>),
}

impl Source {
    fn file(path: impl AsRef<Path>) -> Self {
        Self::GuestBinary(GuestBinary::FilePath(path.as_ref().to_path_buf()))
    }

    fn bytes(buffer: impl Into<Vec<u8>>) -> Self {
        Self::GuestBinary(GuestBinary::Buffer(buffer.into()))
    }
}

/// Builds a [`Sandbox`].
///
/// Start from [`SandboxBuilder::from_file`],
/// [`SandboxBuilder::from_bytes`] or [`SandboxBuilder::from_snapshot`],
/// chain the settings you need, then call [`SandboxBuilder::build`]. Every
/// setting has a default, so a builder with no adjustments is valid.
///
/// By default only the `HostPrint` host function is registered, which writes
/// guest output to the host's stdout. Replace it with [`Self::host_print`].
///
/// # Examples
///
/// From a guest binary on disk:
///
/// ```no_run
/// # use hyperlight_host::{Result, SandboxBuilder};
/// # fn example() -> Result<()> {
/// let mut sandbox = SandboxBuilder::from_file("guest.bin")
///     .heap_size(1024 * 1024)
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build()?;
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
/// let mut sandbox = SandboxBuilder::from_file("guest.bin")
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build()?;
/// let snapshot = sandbox.snapshot()?;
///
/// let mut restored = SandboxBuilder::from_snapshot(snapshot)
///     .host_function("Add", |a: i32, b: i32| a + b)
///     .build()?;
///
/// let result: String = restored.call("Echo", "hello".to_string())?;
/// # Ok(())
/// # }
/// ```
#[allow(deprecated)]
pub struct SandboxBuilder {
    source: Source,
    cfg: SandboxConfiguration,
    host_funcs: HostFunctions,
    init_data: Option<(Vec<u8>, MemoryRegionFlags)>,
    mapped_file_cow: Vec<(std::path::PathBuf, u64)>,
    mapped_memory_regions: Vec<MemoryRegion>,
    guest_log_level: Option<LevelFilter>,
}

impl SandboxBuilder {
    /// The default interrupt retry delay.
    pub const DEFAULT_INTERRUPT_RETRY_DELAY: Duration = defaults::INTERRUPT_RETRY_DELAY;
    /// The default signal offset from `SIGRTMIN` used to interrupt the VCPU thread.
    pub const INTERRUPT_VCPU_SIGRTMIN_OFFSET: u8 = defaults::INTERRUPT_VCPU_SIGRTMIN_OFFSET;
    /// The default guest heap size.
    pub const DEFAULT_HEAP_SIZE: u64 = defaults::HEAP_SIZE;
    /// The default writable memory offered to the guest.
    pub const DEFAULT_SCRATCH_SIZE: usize = defaults::SCRATCH_SIZE;
    /// The default G2H virtqueue descriptor count.
    pub const DEFAULT_G2H_QUEUE_SIZE: usize = defaults::G2H_QUEUE_SIZE;
    /// The default H2G virtqueue descriptor count.
    pub const DEFAULT_H2G_QUEUE_SIZE: usize = defaults::H2G_QUEUE_SIZE;
    /// The default G2H upper-tier buffer size.
    pub const DEFAULT_G2H_BUFFER_SIZE: usize = defaults::G2H_BUFFER_SIZE;
    /// The default H2G buffer size.
    pub const DEFAULT_H2G_BUFFER_SIZE: usize = defaults::H2G_BUFFER_SIZE;
    /// The default total number of G2H pool pages.
    pub const DEFAULT_G2H_POOL_PAGES: usize = defaults::G2H_POOL_PAGES;
    /// The default total number of H2G pool pages.
    pub const DEFAULT_H2G_POOL_PAGES: usize = defaults::H2G_POOL_PAGES;
    /// The maximum number of distinct guest MSRs that can be declared.
    #[cfg(target_arch = "x86_64")]
    pub const MAX_GUEST_MSRS: usize = defaults::MAX_GUEST_MSRS;

    #[allow(deprecated)]
    fn with_source(source: Source) -> Self {
        Self {
            source,
            cfg: SandboxConfiguration::default(),
            host_funcs: HostFunctions::default(),
            init_data: None,
            mapped_file_cow: Vec::new(),
            mapped_memory_regions: Vec::new(),
            guest_log_level: None,
        }
    }

    /// Build a sandbox running the guest binary at `path`, an ELF file.
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self::with_source(Source::file(path))
    }

    /// Build a sandbox running the guest binary held in `buffer`, the contents
    /// of an ELF file.
    pub fn from_bytes(buffer: impl Into<Vec<u8>>) -> Self {
        Self::with_source(Source::bytes(buffer))
    }

    /// Build a sandbox restoring the guest from `snapshot`.
    ///
    /// The snapshot's layout overrides heap, scratch, and transport settings.
    pub fn from_snapshot(snapshot: Arc<Snapshot>) -> Self {
        Self::with_source(Source::Snapshot(snapshot))
    }

    /// Create the sandbox.
    ///
    /// # Errors
    ///
    /// When building from a snapshot, returns an error if [`Self::init_data`]
    /// is set because the snapshot already contains it.
    #[allow(deprecated)]
    pub fn build(self) -> Result<Sandbox> {
        let Self {
            source,
            mut cfg,
            host_funcs,
            init_data,
            mapped_file_cow,
            mapped_memory_regions,
            guest_log_level,
        } = self;

        let mut sandbox = match source {
            Source::GuestBinary(guest_binary) => {
                let env = GuestEnvironment {
                    init_data: init_data.as_ref().map(|(data, flags)| GuestBlob {
                        data,
                        permissions: *flags,
                    }),
                    guest_binary,
                };

                let mut uninitialized_sandbox = UninitializedSandbox::new(env, Some(cfg))?;

                uninitialized_sandbox.host_funcs = Arc::new(Mutex::new(host_funcs.into_inner()));

                for (path, guest_base) in mapped_file_cow {
                    uninitialized_sandbox.map_file_cow(&path, guest_base)?;
                }

                if let Some(log_level) = guest_log_level {
                    uninitialized_sandbox.set_max_guest_log_level(log_level);
                }

                uninitialized_sandbox.evolve()?
            }
            Source::Snapshot(snapshot) => {
                if init_data.is_some() {
                    return Err(new_error!(
                        "init_data has no effect when building from a snapshot, as the snapshot already contains it"
                    ));
                }

                if let Some(log_level) = guest_log_level {
                    cfg.set_max_guest_log_level(log_level);
                }

                let mut sandbox = Sandbox::from_snapshot(snapshot, host_funcs, Some(cfg))?;

                for (path, guest_base) in mapped_file_cow {
                    sandbox.map_file_cow(&path, guest_base)?;
                }

                sandbox
            }
        };

        for region in mapped_memory_regions {
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
    /// Note: [`Self::build`] errors if this setting is set and the builder's
    /// source is a snapshot, as the snapshot already contains the init data.
    pub fn init_data(mut self, data: impl Into<Vec<u8>>, flags: MemoryRegionFlags) -> Self {
        self.init_data = Some((data.into(), flags));
        self
    }

    /// Map the contents of the file at `path` into the guest at `guest_base`,
    /// copy-on-write.
    ///
    /// `guest_base` must be page-aligned and lie outside the sandbox's primary
    /// shared memory region. Violations surface as an error from
    /// [`Self::build`], not here. Call this once per file to map several.
    ///
    /// [`Self::shared_mem_size`] reports the size of that region.
    pub fn mapped_file_cow(mut self, path: impl AsRef<Path>, guest_base: u64) -> Self {
        self.mapped_file_cow
            .push((path.as_ref().to_path_buf(), guest_base));
        self
    }

    /// The size in bytes of the sandbox's primary shared memory region.
    ///
    /// The region starts at `0x4000`. Guest addresses passed to
    /// [`Self::mapped_file_cow`] must lie outside it.
    ///
    /// The size depends on the guest binary and on the memory settings, so
    /// this loads the guest binary and lays out guest memory to compute it.
    /// Call it once, after the memory settings are final.
    pub fn shared_mem_size(&self) -> Result<usize> {
        use crate::mem::shared_mem::SharedMemory;

        match &self.source {
            Source::Snapshot(snapshot) => Ok(snapshot.memory().mem_size()),
            Source::GuestBinary(guest_binary) => {
                let guest_binary = match guest_binary {
                    GuestBinary::FilePath(path) => GuestBinary::FilePath(path.clone()),
                    GuestBinary::Buffer(buffer) => GuestBinary::Buffer(buffer.clone()),
                };
                let env = GuestEnvironment {
                    guest_binary,
                    init_data: self.init_data.as_ref().map(|(data, flags)| GuestBlob {
                        data,
                        permissions: *flags,
                    }),
                };
                Snapshot::mem_size_for_env(env, self.cfg)
            }
        }
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
    /// When building from a snapshot, this overrides the level captured in the
    /// snapshot for subsequent guest calls.
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
    /// Set the guest heap size. A size of 0 selects [`Self::DEFAULT_HEAP_SIZE`].
    pub fn heap_size(mut self, size: u64) -> Self {
        self.cfg.set_heap_size(size);
        self
    }

    /// The guest heap size, defaulting to [`Self::DEFAULT_HEAP_SIZE`] when no
    /// override is set.
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

    /// Set the G2H virtqueue descriptor count.
    ///
    /// Values are rounded up to a power of two in `2..=32768`.
    pub fn g2h_queue_size(mut self, size: usize) -> Self {
        self.cfg.set_g2h_queue_size(size);
        self
    }

    /// Set the H2G virtqueue descriptor count.
    ///
    /// Values are rounded up to a power of two in `2..=32768`.
    pub fn h2g_queue_size(mut self, size: usize) -> Self {
        self.cfg.set_h2g_queue_size(size);
        self
    }

    /// Set the G2H upper-tier buffer capacity in bytes.
    ///
    /// Values are clamped to `256..=u32::MAX`. The pool grows if needed.
    pub fn g2h_buffer_size(mut self, size: usize) -> Self {
        self.cfg.set_g2h_buffer_size(size);
        self
    }

    /// Set the H2G buffer capacity in bytes.
    ///
    /// Values are clamped to `256..=u32::MAX`. The pool grows if needed.
    pub fn h2g_buffer_size(mut self, size: usize) -> Self {
        self.cfg.set_h2g_buffer_size(size);
        self
    }

    /// Set the G2H pool size in guest pages.
    ///
    /// The configured value is raised to the minimum transport capacity.
    pub fn g2h_pool_pages(mut self, pages: usize) -> Self {
        self.cfg.set_g2h_pool_pages(pages);
        self
    }

    /// Set the H2G pool size in guest pages.
    ///
    /// The configured value is raised to the minimum transport capacity.
    pub fn h2g_pool_pages(mut self, pages: usize) -> Self {
        self.cfg.set_h2g_pool_pages(pages);
        self
    }

    /// Declare MSRs the guest owns, saved and restored with the rest of the
    /// sandbox state. Adds to the declared set, so repeated calls accumulate.
    ///
    /// On KVM, the guest can access only declared MSRs. On MSHV and WHP,
    /// declarations control saved state but do not restrict guest access.
    ///
    /// # Errors
    ///
    /// Returns [`GuestMsrError::CapacityExceeded`] if the distinct entries
    /// would exceed [`Self::MAX_GUEST_MSRS`]. The declared set is unchanged on
    /// error.
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
    use std::time::Duration;

    use hyperlight_common::vmem::PAGE_SIZE;
    use hyperlight_testing::simple_guest_as_string;
    use tracing_core::LevelFilter;

    use super::SandboxBuilder;
    use crate::mem::memory_region::MemoryRegionFlags;

    #[test]
    fn configuration_defaults_are_exposed() {
        assert_eq!(
            SandboxBuilder::DEFAULT_INTERRUPT_RETRY_DELAY,
            Duration::from_micros(500)
        );
        assert_eq!(SandboxBuilder::INTERRUPT_VCPU_SIGRTMIN_OFFSET, 0);
        assert_eq!(SandboxBuilder::DEFAULT_HEAP_SIZE, 131_072);
        assert_eq!(SandboxBuilder::DEFAULT_SCRATCH_SIZE, 0x58000);
        assert_eq!(SandboxBuilder::DEFAULT_G2H_QUEUE_SIZE, 64);
        assert_eq!(SandboxBuilder::DEFAULT_H2G_QUEUE_SIZE, 32);
        assert_eq!(SandboxBuilder::DEFAULT_G2H_BUFFER_SIZE, PAGE_SIZE);
        assert_eq!(SandboxBuilder::DEFAULT_H2G_BUFFER_SIZE, PAGE_SIZE);
        assert_eq!(SandboxBuilder::DEFAULT_G2H_POOL_PAGES, 12);
        assert_eq!(SandboxBuilder::DEFAULT_H2G_POOL_PAGES, 8);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(SandboxBuilder::MAX_GUEST_MSRS, 16);
    }

    #[test]
    #[allow(deprecated)]
    fn shared_mem_size_matches_the_built_sandbox() {
        let path = simple_guest_as_string().unwrap();

        let builder = SandboxBuilder::from_file(&path).heap_size(256 * 1024);
        let reported = builder.shared_mem_size().unwrap();

        let mut cfg = crate::sandbox::SandboxConfiguration::default();
        cfg.set_heap_size(256 * 1024);
        let uninit =
            crate::UninitializedSandbox::new(crate::GuestBinary::FilePath(path.into()), Some(cfg))
                .unwrap();

        assert_eq!(reported, uninit.shared_mem_size());
    }

    #[test]
    fn shared_mem_size_handles_multi_gigabyte_layouts() {
        let path = simple_guest_as_string().unwrap();
        let heap = 4 * 1024 * 1024 * 1024u64;

        let size = SandboxBuilder::from_file(&path)
            .heap_size(heap)
            .scratch_size(16 * 1024 * 1024)
            .shared_mem_size()
            .unwrap();

        assert!(size as u64 > heap);
    }

    #[test]
    fn shared_mem_size_tracks_memory_settings() {
        let path = simple_guest_as_string().unwrap();

        let small = SandboxBuilder::from_file(&path).shared_mem_size().unwrap();
        let large = SandboxBuilder::from_file(&path)
            .heap_size(8 * 1024 * 1024)
            .shared_mem_size()
            .unwrap();

        assert!(large > small);
    }

    #[test]
    fn shared_mem_size_bounds_the_file_mapping_region() {
        use std::io::Write;

        use crate::mem::layout::SandboxMemoryLayout;

        let path = simple_guest_as_string().unwrap();
        let size = SandboxBuilder::from_file(&path).shared_mem_size().unwrap();

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![0u8; PAGE_SIZE]).unwrap();

        let just_outside = SandboxMemoryLayout::BASE_ADDRESS as u64 + size as u64;
        assert!(
            SandboxBuilder::from_file(&path)
                .mapped_file_cow(file.path(), just_outside)
                .build()
                .is_ok()
        );

        let just_inside = just_outside - PAGE_SIZE as u64;
        assert!(
            SandboxBuilder::from_file(&path)
                .mapped_file_cow(file.path(), just_inside)
                .build()
                .is_err()
        );
    }

    #[test]
    fn shared_mem_size_from_snapshot_reports_the_snapshot_region() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::from_file(&path).build().unwrap();
        let snapshot = sandbox.snapshot().unwrap();

        let size = SandboxBuilder::from_snapshot(snapshot.clone())
            .shared_mem_size()
            .unwrap();

        assert!(size > 0);
        assert!(size.is_multiple_of(PAGE_SIZE));
        assert_eq!(
            SandboxBuilder::from_snapshot(snapshot)
                .shared_mem_size()
                .unwrap(),
            size
        );
    }

    #[test]
    fn transport_settings_are_normalized() {
        let builder = SandboxBuilder::from_bytes([])
            .g2h_queue_size(3)
            .h2g_queue_size(usize::MAX)
            .g2h_buffer_size(0)
            .h2g_buffer_size(2 * PAGE_SIZE + 1)
            .g2h_pool_pages(0)
            .h2g_pool_pages(0);

        assert_eq!(builder.cfg.get_g2h_queue_size(), 4);
        assert_eq!(builder.cfg.get_h2g_queue_size(), 32_768);
        assert_eq!(builder.cfg.get_g2h_buffer_size(), 256);
        assert_eq!(builder.cfg.get_h2g_buffer_size(), 2 * PAGE_SIZE + 1);
        assert_eq!(builder.cfg.get_g2h_pool_pages(), 2);
        assert_eq!(builder.cfg.get_h2g_pool_pages(), 3);
    }

    #[test]
    fn transport_buffer_growth_raises_pool_minima() {
        let builder = SandboxBuilder::from_bytes([])
            .g2h_pool_pages(0)
            .h2g_pool_pages(0)
            .g2h_buffer_size(PAGE_SIZE + 1)
            .h2g_buffer_size(3 * PAGE_SIZE + 1);

        assert_eq!(builder.cfg.get_g2h_buffer_size(), PAGE_SIZE + 1);
        assert_eq!(builder.cfg.get_h2g_buffer_size(), 3 * PAGE_SIZE + 1);
        assert_eq!(builder.cfg.get_g2h_pool_pages(), 3);
        assert_eq!(builder.cfg.get_h2g_pool_pages(), 4);
    }

    #[test]
    fn build_from_file() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::from_file(path).build().unwrap();

        let result = sandbox.call::<String>("Echo", "hello".to_string()).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_bytes() {
        let bytes = std::fs::read(simple_guest_as_string().unwrap()).unwrap();
        let mut sandbox = SandboxBuilder::from_bytes(bytes).build().unwrap();

        let result = sandbox.call::<String>("Echo", "hello".to_string()).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_snapshot() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::from_file(path).build().unwrap();
        let snapshot = sandbox.snapshot().unwrap();

        let mut restored = SandboxBuilder::from_snapshot(snapshot).build().unwrap();

        let result = restored
            .call::<String>("Echo", "hello".to_string())
            .unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn build_from_snapshot_rejects_init_data_and_accepts_guest_log_level() {
        let path = simple_guest_as_string().unwrap();
        let mut sandbox = SandboxBuilder::from_file(path).build().unwrap();
        let snapshot = sandbox.snapshot().unwrap();

        assert!(
            SandboxBuilder::from_snapshot(snapshot.clone())
                .init_data([0u8; 8], MemoryRegionFlags::READ)
                .build()
                .is_err()
        );

        assert!(
            SandboxBuilder::from_snapshot(snapshot)
                .guest_log_level(LevelFilter::INFO)
                .build()
                .is_ok()
        );
    }
}
