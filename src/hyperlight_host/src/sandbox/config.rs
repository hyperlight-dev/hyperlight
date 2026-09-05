// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use std::cmp::max;
use std::time::Duration;

use hyperlight_common::virtq::G2H_LOWER_SLOT_SIZE;
use hyperlight_common::vmem::PAGE_SIZE;
#[cfg(target_os = "linux")]
use libc::c_int;
use tracing::{Span, instrument};

/// Used for passing debug configuration to a sandbox
#[cfg(gdb)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DebugInfo {
    /// Guest debug port
    pub port: u16,
}

/// Errors returned when declaring guest MSRs.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestMsrError {
    /// The declared MSR set exceeds its fixed capacity.
    #[error("declared guest MSRs exceed the maximum of {maximum} distinct entries")]
    CapacityExceeded {
        /// Maximum number of distinct declared MSRs.
        maximum: usize,
    },
}

/// The complete set of configuration needed to create a Sandbox
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct SandboxConfiguration {
    /// Guest core dump output directory
    /// This field is by default set to true which means the value core dumps will be placed in:
    /// - HYPERLIGHT_CORE_DUMP_DIR environment variable if it is set
    /// - default value of the temporary directory
    ///
    /// The core dump files generation can be disabled by setting this field to false.
    #[cfg(crashdump)]
    guest_core_dump: bool,
    /// Guest gdb debug port
    #[cfg(gdb)]
    guest_debug_info: Option<DebugInfo>,
    /// The heap size to use in the guest sandbox. If set to 0, the heap
    /// size will be determined from the PE file header
    ///
    /// Note: this is a C-compatible struct, so even though this optional
    /// field should be represented as an `Option`, that type is not
    /// FFI-safe, so it cannot be.
    heap_size_override: u64,
    /// Delay between interrupt retries. This duration specifies how long to wait
    /// between attempts to send signals to the thread running the sandbox's VCPU.
    /// Multiple retries may be necessary because signals only interrupt the VCPU
    /// thread when the vcpu thread is in kernel space. There's a narrow window during which a
    /// signal can be delivered to the thread, but the thread may not yet
    /// have entered kernel space.
    interrupt_retry_delay: Duration,
    /// Offset from `SIGRTMIN` used to determine the signal number for interrupting
    /// the VCPU thread. The actual signal sent is `SIGRTMIN + interrupt_vcpu_sigrtmin_offset`.
    ///
    /// This signal must fall within the valid real-time signal range supported by the host.
    ///
    /// Note: Since real-time signals can vary across platforms, ensure that the offset
    /// results in a signal number that is not already in use by other components of the system.
    interrupt_vcpu_sigrtmin_offset: u8,
    /// How much writable memory to offer the guest
    scratch_size: usize,
    /// Number of descriptors in the G2H virtqueue.
    g2h_queue_size: usize,
    /// Number of descriptors in the H2G virtqueue.
    h2g_queue_size: usize,
    /// Capacity of each G2H upper-tier buffer.
    g2h_buffer_size: usize,
    /// Capacity of each H2G buffer.
    h2g_buffer_size: usize,
    /// Number of pages in the G2H buffer pool.
    g2h_pool_pages: usize,
    /// Number of pages in the H2G buffer pool.
    h2g_pool_pages: usize,
    /// Declared guest MSRs, stored inline to keep this type `Copy`.
    #[cfg(target_arch = "x86_64")]
    guest_msrs: [u32; Self::MAX_GUEST_MSRS],
    /// Number of valid entries in `guest_msrs`.
    #[cfg(target_arch = "x86_64")]
    guest_msrs_count: usize,
}

impl SandboxConfiguration {
    /// The default interrupt retry delay
    pub const DEFAULT_INTERRUPT_RETRY_DELAY: Duration = Duration::from_micros(500);
    /// The default signal offset from `SIGRTMIN` used to determine the signal number for interrupting
    pub const INTERRUPT_VCPU_SIGRTMIN_OFFSET: u8 = 0;
    /// The default heap size of a hyperlight sandbox
    pub const DEFAULT_HEAP_SIZE: u64 = 131072;
    /// The default scratch size keeps enough dynamic space to back the default
    /// heap after reserving the transport arena and page tables.
    pub const DEFAULT_SCRATCH_SIZE: usize = 0x56000;
    /// The default G2H virtqueue descriptor count.
    pub const DEFAULT_G2H_QUEUE_SIZE: usize = 64;
    /// The default H2G virtqueue descriptor count.
    pub const DEFAULT_H2G_QUEUE_SIZE: usize = 32;
    /// The default G2H upper-tier buffer size.
    pub const DEFAULT_G2H_BUFFER_SIZE: usize = PAGE_SIZE;
    /// The default H2G buffer size.
    pub const DEFAULT_H2G_BUFFER_SIZE: usize = PAGE_SIZE;
    /// The default total number of G2H pool pages.
    pub const DEFAULT_G2H_POOL_PAGES: usize = 12;
    /// The default total number of H2G pool pages.
    pub const DEFAULT_H2G_POOL_PAGES: usize = 8;
    /// The minimum G2H virtqueue descriptor count.
    const MIN_QUEUE_SIZE: usize = 2;
    /// The maximum G2H virtqueue descriptor count.
    const MAX_QUEUE_SIZE: usize = 32_768;
    /// The minimum configured transport buffer size.
    const MIN_BUFFER_SIZE: usize = G2H_LOWER_SLOT_SIZE;
    /// The maximum configured transport buffer size.
    const MAX_BUFFER_SIZE: usize = u32::MAX as usize;
    /// Maximum number of distinct guest MSRs that can be declared.
    /// KVM supports at most 16 MSR filter ranges. Each index may require its
    /// own range, so 16 is the portable limit across backends.
    #[cfg(target_arch = "x86_64")]
    pub const MAX_GUEST_MSRS: usize = 16;

    /// Create a new configuration for a sandbox with the given sizes.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn new(
        heap_size_override: Option<u64>,
        scratch_size: usize,
        interrupt_retry_delay: Duration,
        interrupt_vcpu_sigrtmin_offset: u8,
        #[cfg(gdb)] guest_debug_info: Option<DebugInfo>,
        #[cfg(crashdump)] guest_core_dump: bool,
    ) -> Self {
        Self {
            heap_size_override: heap_size_override.unwrap_or(0),
            scratch_size,
            g2h_queue_size: Self::DEFAULT_G2H_QUEUE_SIZE,
            h2g_queue_size: Self::DEFAULT_H2G_QUEUE_SIZE,
            g2h_buffer_size: Self::DEFAULT_G2H_BUFFER_SIZE,
            h2g_buffer_size: Self::DEFAULT_H2G_BUFFER_SIZE,
            g2h_pool_pages: Self::DEFAULT_G2H_POOL_PAGES,
            h2g_pool_pages: Self::DEFAULT_H2G_POOL_PAGES,
            interrupt_retry_delay,
            interrupt_vcpu_sigrtmin_offset,
            #[cfg(gdb)]
            guest_debug_info,
            #[cfg(crashdump)]
            guest_core_dump,
            #[cfg(target_arch = "x86_64")]
            guest_msrs: [0; Self::MAX_GUEST_MSRS],
            #[cfg(target_arch = "x86_64")]
            guest_msrs_count: 0,
        }
    }

    /// Set the heap size to use in the guest sandbox. If set to 0, the heap size will be determined from the PE file header
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_heap_size(&mut self, heap_size: u64) {
        self.heap_size_override = heap_size;
    }

    /// Sets the interrupt retry delay
    #[cfg(any(kvm, mshv3, hvf))]
    pub fn set_interrupt_retry_delay(&mut self, delay: Duration) {
        self.interrupt_retry_delay = delay;
    }

    /// Get the delay between retries for interrupts
    #[cfg(any(kvm, mshv3, hvf))]
    pub fn get_interrupt_retry_delay(&self) -> Duration {
        self.interrupt_retry_delay
    }

    /// Get the signal offset from `SIGRTMIN` used to determine the signal number for interrupting the VCPU thread
    #[cfg(target_os = "linux")]
    pub fn get_interrupt_vcpu_sigrtmin_offset(&self) -> u8 {
        self.interrupt_vcpu_sigrtmin_offset
    }

    /// Declares the MSRs the guest depends on.
    ///
    /// A declared MSR's value is part of the sandbox's saved state: captured by
    /// [`MultiUseSandbox::snapshot`](crate::MultiUseSandbox::snapshot) and written
    /// back on [`MultiUseSandbox::restore`](crate::MultiUseSandbox::restore). Every
    /// MSR you do not declare is reset to a clean default on each restore.
    ///
    /// If this method is not called, only a small core of essential CPU state
    /// (kernel GS base, TSC) is saved and restored.
    ///
    /// # Platform-specific behavior
    ///
    /// * On KVM, declaring an MSR is also what lets the guest access it. The
    ///   guest faults on any `RDMSR`/`WRMSR` of an undeclared MSR.
    /// * On MSHV and WHP there is no such enforcement, so declaration only
    ///   controls what is saved and restored, not what the guest may touch.
    ///
    /// Duplicate indices, within the slice or against the existing set, are
    /// ignored and do not count toward capacity.
    ///
    /// # Errors
    ///
    /// Returns [`GuestMsrError::CapacityExceeded`] if the distinct entries
    /// would exceed [`Self::MAX_GUEST_MSRS`]. The declared set is unchanged on
    /// error.
    #[cfg(target_arch = "x86_64")]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn guest_msrs(&mut self, indices: &[u32]) -> Result<&mut Self, GuestMsrError> {
        let additional = indices
            .iter()
            .enumerate()
            .filter(|(position, index)| {
                !self.guest_msrs[..self.guest_msrs_count].contains(index)
                    && !indices[..*position].contains(index)
            })
            .count();
        if additional > Self::MAX_GUEST_MSRS - self.guest_msrs_count {
            return Err(GuestMsrError::CapacityExceeded {
                maximum: Self::MAX_GUEST_MSRS,
            });
        }
        for &index in indices {
            if !self.guest_msrs[..self.guest_msrs_count].contains(&index) {
                self.guest_msrs[self.guest_msrs_count] = index;
                self.guest_msrs_count += 1;
            }
        }
        Ok(self)
    }

    /// Returns the declared guest MSRs.
    #[cfg(target_arch = "x86_64")]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_msrs(&self) -> &[u32] {
        &self.guest_msrs[..self.guest_msrs_count]
    }

    /// Sets the offset from `SIGRTMIN` to determine the real-time signal used for
    /// interrupting the VCPU thread.
    ///
    /// The final signal number is computed as `SIGRTMIN + offset`, and it must fall within
    /// the valid range of real-time signals supported by the host system.
    ///
    /// Returns Ok(()) if the offset is valid, or an error if it exceeds the maximum real-time signal number.
    #[cfg(target_os = "linux")]
    pub fn set_interrupt_vcpu_sigrtmin_offset(&mut self, offset: u8) -> crate::Result<()> {
        if libc::SIGRTMIN() + offset as c_int > libc::SIGRTMAX() {
            return Err(crate::new_error!(
                "Invalid SIGRTMIN offset: {}. It exceeds the maximum real-time signal number.",
                offset
            ));
        }
        self.interrupt_vcpu_sigrtmin_offset = offset;
        Ok(())
    }

    /// Toggles the guest core dump generation for a sandbox
    /// Setting this to false disables the core dump generation
    /// This is only used when the `crashdump` feature is enabled
    #[cfg(crashdump)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_guest_core_dump(&mut self, enable: bool) {
        self.guest_core_dump = enable;
    }

    /// Sets the configuration for the guest debug
    #[cfg(gdb)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_guest_debug_info(&mut self, debug_info: DebugInfo) {
        self.guest_debug_info = Some(debug_info);
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_scratch_size(&self) -> usize {
        self.scratch_size
    }

    /// Set the size of the scratch regiong
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_scratch_size(&mut self, scratch_size: usize) {
        self.scratch_size = scratch_size;
    }

    /// Get the G2H virtqueue descriptor count.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_g2h_queue_size(&self) -> usize {
        self.g2h_queue_size
    }

    /// Set the G2H virtqueue descriptor count.
    ///
    /// Values are rounded up to a power of two in `2..=32768`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_g2h_queue_size(&mut self, size: usize) {
        self.g2h_queue_size = Self::normalize_queue_size(size);
    }

    /// Get the H2G virtqueue descriptor count.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_h2g_queue_size(&self) -> usize {
        self.h2g_queue_size
    }

    /// Set the H2G virtqueue descriptor count.
    ///
    /// Values are rounded up to a power of two in `2..=32768`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_h2g_queue_size(&mut self, size: usize) {
        self.h2g_queue_size = Self::normalize_queue_size(size);
    }

    /// Get the capacity of each G2H upper-tier buffer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_g2h_buffer_size(&self) -> usize {
        self.g2h_buffer_size
    }

    /// Set the capacity of each G2H upper-tier buffer.
    ///
    /// Values are clamped to `256..=u32::MAX`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_g2h_buffer_size(&mut self, size: usize) {
        self.g2h_buffer_size = size.clamp(Self::MIN_BUFFER_SIZE, Self::MAX_BUFFER_SIZE);
        self.g2h_pool_pages = max(
            self.g2h_pool_pages,
            Self::min_g2h_pool_pages(self.g2h_buffer_size),
        );
    }

    /// Get the capacity of each H2G buffer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_h2g_buffer_size(&self) -> usize {
        self.h2g_buffer_size
    }

    /// Set the capacity of each H2G buffer.
    ///
    /// Values are clamped to `256..=u32::MAX`.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_h2g_buffer_size(&mut self, size: usize) {
        self.h2g_buffer_size = size.clamp(Self::MIN_BUFFER_SIZE, Self::MAX_BUFFER_SIZE);
        self.h2g_pool_pages = max(
            self.h2g_pool_pages,
            Self::min_h2g_pool_pages(self.h2g_buffer_size),
        );
    }

    /// Get the total number of G2H pool pages.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_g2h_pool_pages(&self) -> usize {
        self.g2h_pool_pages
    }

    /// Set the total number of G2H pool pages.
    ///
    /// The pool contains one lower-tier page and at least one upper buffer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_g2h_pool_pages(&mut self, pages: usize) {
        self.g2h_pool_pages = max(pages, Self::min_g2h_pool_pages(self.g2h_buffer_size));
    }

    /// Get the total number of H2G pool pages.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_h2g_pool_pages(&self) -> usize {
        self.h2g_pool_pages
    }

    /// Set the total number of H2G pool pages.
    ///
    /// The pool contains at least one H2G buffer.
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set_h2g_pool_pages(&mut self, pages: usize) {
        self.h2g_pool_pages = max(pages, Self::min_h2g_pool_pages(self.h2g_buffer_size));
    }

    #[cfg(crashdump)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_core_dump(&self) -> bool {
        self.guest_core_dump
    }

    #[cfg(gdb)]
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_guest_debug_info(&self) -> Option<DebugInfo> {
        self.guest_debug_info
    }

    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn heap_size_override_opt(&self) -> Option<u64> {
        (self.heap_size_override > 0).then_some(self.heap_size_override)
    }

    /// If self.heap_size_override is non-zero, return it. Otherwise,
    /// return exe_info.heap_reserve()
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub(crate) fn get_heap_size(&self) -> u64 {
        self.heap_size_override_opt()
            .unwrap_or(Self::DEFAULT_HEAP_SIZE)
    }

    fn normalize_queue_size(size: usize) -> usize {
        size.clamp(Self::MIN_QUEUE_SIZE, Self::MAX_QUEUE_SIZE)
            .next_power_of_two()
    }

    fn min_g2h_pool_pages(buffer_size: usize) -> usize {
        1 + Self::min_h2g_pool_pages(buffer_size)
    }

    fn min_h2g_pool_pages(buffer_size: usize) -> usize {
        buffer_size.div_ceil(PAGE_SIZE)
    }
}

impl Default for SandboxConfiguration {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn default() -> Self {
        Self::new(
            None,
            Self::DEFAULT_SCRATCH_SIZE,
            Self::DEFAULT_INTERRUPT_RETRY_DELAY,
            Self::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::vmem::PAGE_SIZE;

    #[cfg(target_arch = "x86_64")]
    use super::GuestMsrError;
    use super::SandboxConfiguration;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn guest_msrs_reports_overflow() {
        let mut cfg = SandboxConfiguration::default();
        for index in 0..SandboxConfiguration::MAX_GUEST_MSRS as u32 {
            cfg.guest_msrs(&[index]).unwrap();
        }

        cfg.guest_msrs(&[0]).unwrap();
        assert_eq!(
            cfg.guest_msrs(&[SandboxConfiguration::MAX_GUEST_MSRS as u32]),
            Err(GuestMsrError::CapacityExceeded {
                maximum: SandboxConfiguration::MAX_GUEST_MSRS,
            })
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn bulk_guest_msrs_overflow_is_atomic() {
        let mut cfg = SandboxConfiguration::default();
        cfg.guest_msrs(&[1, 2]).unwrap();
        let oversized: Vec<u32> = (3..=SandboxConfiguration::MAX_GUEST_MSRS as u32 + 1).collect();

        assert!(matches!(
            cfg.guest_msrs(&oversized),
            Err(GuestMsrError::CapacityExceeded { .. })
        ));
        assert_eq!(cfg.get_guest_msrs(), &[1, 2]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn guest_msrs_dedups_and_preserves_order() {
        let mut cfg = SandboxConfiguration::default();
        cfg.guest_msrs(&[0x10]).unwrap();
        cfg.guest_msrs(&[0x20, 0x20, 0x10, 0x30, 0x20]).unwrap();
        // 0x10 already present, 0x20 and 0x30 added once each in first-seen order.
        assert_eq!(cfg.get_guest_msrs(), &[0x10, 0x20, 0x30]);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn guest_msrs_duplicates_do_not_count_toward_capacity() {
        let mut cfg = SandboxConfiguration::default();
        let fill: Vec<u32> = (0..SandboxConfiguration::MAX_GUEST_MSRS as u32 - 1).collect();
        cfg.guest_msrs(&fill).unwrap();
        // One slot remains. Three copies of one new index count as a single
        // distinct entry and fit.
        cfg.guest_msrs(&[u32::MAX, u32::MAX, u32::MAX]).unwrap();
        assert_eq!(
            cfg.get_guest_msrs().len(),
            SandboxConfiguration::MAX_GUEST_MSRS
        );
    }

    #[test]
    fn overrides() {
        const HEAP_SIZE_OVERRIDE: u64 = 0x50000;
        const SCRATCH_SIZE_OVERRIDE: usize = 0x60000;
        let mut cfg = SandboxConfiguration::new(
            Some(HEAP_SIZE_OVERRIDE),
            SCRATCH_SIZE_OVERRIDE,
            SandboxConfiguration::DEFAULT_INTERRUPT_RETRY_DELAY,
            SandboxConfiguration::INTERRUPT_VCPU_SIGRTMIN_OFFSET,
            #[cfg(gdb)]
            None,
            #[cfg(crashdump)]
            true,
        );

        let heap_size = cfg.get_heap_size();
        let scratch_size = cfg.get_scratch_size();
        assert_eq!(HEAP_SIZE_OVERRIDE, heap_size);
        assert_eq!(SCRATCH_SIZE_OVERRIDE, scratch_size);

        cfg.heap_size_override = 2048;
        cfg.scratch_size = 0x40000;
        assert_eq!(2048, cfg.heap_size_override);
        assert_eq!(0x40000, cfg.scratch_size);
        assert_eq!(
            SandboxConfiguration::DEFAULT_G2H_QUEUE_SIZE,
            cfg.get_g2h_queue_size()
        );
        assert_eq!(
            SandboxConfiguration::DEFAULT_H2G_QUEUE_SIZE,
            cfg.get_h2g_queue_size()
        );
        assert_eq!(
            SandboxConfiguration::DEFAULT_G2H_BUFFER_SIZE,
            cfg.get_g2h_buffer_size()
        );
        assert_eq!(
            SandboxConfiguration::DEFAULT_H2G_BUFFER_SIZE,
            cfg.get_h2g_buffer_size()
        );
        assert_eq!(
            SandboxConfiguration::DEFAULT_G2H_POOL_PAGES,
            cfg.get_g2h_pool_pages()
        );
        assert_eq!(
            SandboxConfiguration::DEFAULT_H2G_POOL_PAGES,
            cfg.get_h2g_pool_pages()
        );
    }

    #[test]
    fn queue_sizes_are_normalized() {
        let mut cfg = SandboxConfiguration::default();
        for (size, expected) in [
            (0, 2),
            (1, 2),
            (2, 2),
            (3, 4),
            (32_767, 32_768),
            (32_768, 32_768),
            (32_769, 32_768),
            (usize::MAX, 32_768),
        ] {
            cfg.set_g2h_queue_size(size);
            cfg.set_h2g_queue_size(size);
            assert_eq!(expected, cfg.get_g2h_queue_size());
            assert_eq!(expected, cfg.get_h2g_queue_size());
        }
    }

    #[test]
    fn buffer_sizes_are_normalized_without_page_rounding() {
        let mut cfg = SandboxConfiguration::default();

        cfg.set_g2h_buffer_size(0);
        cfg.set_h2g_buffer_size(0);
        assert_eq!(256, cfg.get_g2h_buffer_size());
        assert_eq!(256, cfg.get_h2g_buffer_size());

        cfg.set_g2h_buffer_size(3000);
        cfg.set_h2g_buffer_size(3001);
        assert_eq!(3000, cfg.get_g2h_buffer_size());
        assert_eq!(3001, cfg.get_h2g_buffer_size());

        cfg.set_g2h_buffer_size(usize::MAX);
        cfg.set_h2g_buffer_size(usize::MAX);
        assert_eq!(u32::MAX as usize, cfg.get_g2h_buffer_size());
        assert_eq!(u32::MAX as usize, cfg.get_h2g_buffer_size());
    }

    #[test]
    fn pool_page_counts_are_normalized() {
        let mut cfg = SandboxConfiguration::default();

        cfg.set_g2h_pool_pages(0);
        cfg.set_h2g_pool_pages(0);
        assert_eq!(2, cfg.get_g2h_pool_pages());
        assert_eq!(1, cfg.get_h2g_pool_pages());

        cfg.set_g2h_buffer_size(PAGE_SIZE + 1);
        cfg.set_h2g_buffer_size(PAGE_SIZE + 1);
        assert_eq!(3, cfg.get_g2h_pool_pages());
        assert_eq!(2, cfg.get_h2g_pool_pages());

        cfg.set_g2h_pool_pages(2);
        cfg.set_h2g_pool_pages(1);
        assert_eq!(3, cfg.get_g2h_pool_pages());
        assert_eq!(2, cfg.get_h2g_pool_pages());

        cfg.set_g2h_pool_pages(4);
        cfg.set_h2g_pool_pages(3);
        assert_eq!(4, cfg.get_g2h_pool_pages());
        assert_eq!(3, cfg.get_h2g_pool_pages());
    }

    mod proptests {
        use proptest::prelude::*;

        use super::SandboxConfiguration;
        #[cfg(gdb)]
        use crate::sandbox::config::DebugInfo;

        proptest! {
            #[test]
            fn heap_size_override(size in 0x1000..=0x10000u64) {
                let mut cfg = SandboxConfiguration::default();
                cfg.set_heap_size(size);
                prop_assert_eq!(size, cfg.heap_size_override);
            }

            #[test]
            #[cfg(gdb)]
            fn guest_debug_info(port in 9000..=u16::MAX) {
                let mut cfg = SandboxConfiguration::default();
                let debug_info = DebugInfo { port };
                cfg.set_guest_debug_info(debug_info);
                prop_assert_eq!(debug_info, *cfg.get_guest_debug_info().as_ref().unwrap());
            }
        }
    }
}
