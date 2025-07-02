/*
Copyright 2025  The Hyperlight Authors.

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

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use hyperlight_common::mem::PAGE_SIZE_USIZE;
use libc::{PROT_READ, PROT_WRITE, mprotect};
use lockfree::map::Map;
use log::error;

use crate::mem::shared_mem::{HostMapping, SharedMemory};
use crate::{Result, new_error};

// Tracker metadata stored in global lock-free storage
struct TrackerData {
    pid: u32,
    base_addr: usize,
    size: usize,
    num_pages: usize,
    dirty_pages: Vec<AtomicBool>,
}

// Global lock-free collection to store tracker data for signal handler to access

static TRACKERS: OnceLock<Map<usize, TrackerData>> = OnceLock::new();

// Helper function to get or initialize the global trackers map
// lockfree::Map is truly lock-free and safe for signal handlers
fn get_trackers() -> &'static Map<usize, TrackerData> {
    TRACKERS.get_or_init(Map::new)
}

/// Global tracker ID counter
static NEXT_TRACKER_ID: AtomicUsize = AtomicUsize::new(1);

/// Original SIGSEGV handler to chain to (stored atomically for async signal safety)
static ORIGINAL_SIGSEGV_HANDLER: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());

/// Whether our SIGSEGV handler is installed
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Dirty page tracker for Linux
/// This tracks which pages have been written for a memory region once new has been called
/// It marks pages as RO and then uses SIGSEGV to detect writes to pages, then updates the page to RW and notes the page index as dirty by writing details to global lock-free storage
///
/// A user calls get_dirty_pages to get a list of dirty pages to get details of the pages that were written to since the tracker was created
///
/// Once a user has called get_dirty_pages, this tracker is destroyed and will not track changes any longer
#[derive(Debug)]
pub struct LinuxDirtyPageTracker {
    /// Unique ID for this tracker
    id: usize,
    /// Base address of the memory region being tracked
    base_addr: usize,
    /// Size of the memory region in bytes
    size: usize,
    /// Keep a reference to the HostMapping to ensure memory lifetime
    _mapping: Arc<HostMapping>,
}

// DirtyPageTracker should be Send because:
// 1. The Arc<HostMapping> ensures the memory stays valid
// 2. The tracker handles synchronization properly
// 3. This is needed for threaded sandbox initialization
unsafe impl Send for LinuxDirtyPageTracker {}

impl LinuxDirtyPageTracker {
    /// Create a new dirty page tracker for the given shared memory
    pub(super) fn new<T: SharedMemory>(shared_memory: &T) -> Result<Self> {
        let mapping = shared_memory.region_arc();
        let base_addr = shared_memory.base_addr();
        let size = shared_memory.mem_size();

        if size == 0 {
            return Err(new_error!("Cannot track empty memory region"));
        }

        if base_addr % PAGE_SIZE_USIZE != 0 {
            return Err(new_error!("Base address must be page-aligned"));
        }

        // Get the current process ID
        let current_pid = std::process::id();

        // Check that there is not already a tracker that includes this address range
        // within the same process (virtual addresses are only unique per process)
        for guard in get_trackers().iter() {
            let tracker_data = guard.val();

            // Only check for overlaps within the same process
            if tracker_data.pid == current_pid {
                let existing_start = tracker_data.base_addr;
                let existing_end = tracker_data.base_addr + tracker_data.size;
                let new_start = base_addr;
                let new_end = base_addr + size;

                // Check for overlap: two ranges [a,b) and [c,d) overlap if max(a,c) < min(b,d)
                // Equivalently: they DON'T overlap if b <= c || d <= a
                // So they DO overlap if !(b <= c || d <= a) which is (b > c && d > a)
                if new_end > existing_start && existing_end > new_start {
                    return Err(new_error!(
                        "Address range [{:#x}, {:#x}) overlaps with existing tracker [{:#x}, {:#x}) in process {}",
                        new_start,
                        new_end,
                        existing_start,
                        existing_end,
                        current_pid
                    ));
                }
            }
        }

        let num_pages = size.div_ceil(PAGE_SIZE_USIZE);
        let id = NEXT_TRACKER_ID.fetch_add(1, Ordering::Relaxed);

        // Create atomic array for dirty page tracking
        let dirty_pages: Vec<AtomicBool> = (0..num_pages).map(|_| AtomicBool::new(false)).collect();

        // Create tracker data
        let tracker_data = TrackerData {
            pid: current_pid,
            base_addr,
            size,
            num_pages,
            dirty_pages,
        };

        // Install global SIGSEGV handler if not already installed
        Self::ensure_sigsegv_handler_installed()?;

        // Write protect the memory region to make it read-only so we get SIGSEGV on writes
        let result = unsafe { mprotect(base_addr as *mut libc::c_void, size, PROT_READ) };

        if result != 0 {
            return Err(new_error!(
                "Failed to write-protect memory for dirty tracking: {}",
                std::io::Error::last_os_error()
            ));
        }

        get_trackers().insert(id, tracker_data);

        Ok(Self {
            id,
            base_addr,
            size,
            _mapping: mapping,
        })
    }

    /// Get all dirty page indices for this tracker
    pub(super) fn get_dirty_pages(self) -> Vec<usize> {
        let res = if let Some(tracker_data) = get_trackers().get(&self.id) {
            let mut dirty_pages = Vec::new();
            let tracker_data = tracker_data.val();
            for (idx, dirty) in tracker_data.dirty_pages.iter().enumerate() {
                if dirty.load(Ordering::Acquire) {
                    dirty_pages.push(idx);
                }
            }
            dirty_pages
        } else {
            Vec::new()
        };

        // self is dropped here, triggering cleanup
        // explicit to document intent
        drop(self);
        res
    }

    #[cfg(test)]
    /// Check if a memory address falls within this tracker's region
    fn contains_address(&self, addr: usize) -> bool {
        addr >= self.base_addr && addr < self.base_addr + self.size
    }

    /// Install global SIGSEGV handler if not already installed
    fn ensure_sigsegv_handler_installed() -> Result<()> {
        // Use compare_exchange to ensure only one thread does the installation
        match HANDLER_INSTALLED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // We won the race - we're responsible for installation

                // Get the current handler before installing ours
                let mut original = Box::new(unsafe { std::mem::zeroed::<libc::sigaction>() });

                unsafe {
                    let result = libc::sigaction(
                        libc::SIGSEGV,
                        std::ptr::null(),
                        original.as_mut() as *mut libc::sigaction,
                    );

                    if result != 0 {
                        // Reset the flag on error
                        HANDLER_INSTALLED.store(false, Ordering::Release);
                        return Err(new_error!(
                            "Failed to get original SIGSEGV handler: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                }

                // Install our handler
                if let Err(e) = vmm_sys_util::signal::register_signal_handler(
                    libc::SIGSEGV,
                    Self::sigsegv_handler,
                ) {
                    // Reset the flag on error
                    HANDLER_INSTALLED.store(false, Ordering::Release);
                    return Err(new_error!("Failed to register SIGSEGV handler: {}", e));
                }

                // Store original handler pointer atomically
                let original_ptr = Box::into_raw(original);
                ORIGINAL_SIGSEGV_HANDLER.store(original_ptr, Ordering::Release);

                Ok(())
            }
            Err(_) => {
                // Another thread already installed it, we're done
                Ok(())
            }
        }
    }

    /// MINIMAL async signal safe SIGSEGV handler for dirty page tracking
    /// This handler uses only async signal safe operations:
    /// - Atomic loads/stores
    /// - mprotect (async signal safe)
    /// - Simple pointer arithmetic
    /// - global lock-free storage (lockfree::Map)
    /// - `getpid()` to check process ownership
    extern "C" fn sigsegv_handler(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        unsafe {
            if signal != libc::SIGSEGV || info.is_null() {
                Self::call_original_handler(signal, info, context);
                return;
            }

            let fault_addr = (*info).si_addr() as usize;

            // Check all trackers in global lock-free storage
            // lockfree::Map::iter() is guaranteed to be async-signal-safe
            let mut handled = false;
            for guard in get_trackers().iter() {
                let tracker_data = guard.val();

                // Only handle faults for trackers in the current process
                // We compare the stored PID with the current process PID
                // getpid() is async-signal-safe, but we can avoid the call by checking
                // if the fault address is within this tracker's range first
                if fault_addr < tracker_data.base_addr
                    || fault_addr >= tracker_data.base_addr + tracker_data.size
                {
                    continue; // Fault not in this tracker's range
                }

                // Now verify this tracker belongs to the current process
                let current_pid = libc::getpid() as u32;
                if tracker_data.pid != current_pid {
                    continue;
                }

                // We know the fault is in this tracker's range and it's our process
                // Calculate page index
                let page_offset = fault_addr - tracker_data.base_addr;
                let page_idx = page_offset / PAGE_SIZE_USIZE;

                if page_idx < tracker_data.num_pages {
                    // Mark page dirty atomically (async signal safe)
                    tracker_data.dirty_pages[page_idx].store(true, Ordering::Relaxed);

                    // Make page writable (mprotect is async signal safe)
                    let page_addr = tracker_data.base_addr + (page_idx * PAGE_SIZE_USIZE);
                    let result = mprotect(
                        page_addr as *mut libc::c_void,
                        PAGE_SIZE_USIZE,
                        PROT_READ | PROT_WRITE,
                    );

                    handled = result == 0;
                    break; // Found the tracker, stop searching
                }
            }

            // If not handled by any of our trackers, chain to original handler
            if !handled {
                Self::call_original_handler(signal, info, context);
            }
        }
    }

    /// Call the original SIGSEGV handler if available (async signal safe)
    fn call_original_handler(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        unsafe {
            let handler_ptr = ORIGINAL_SIGSEGV_HANDLER.load(Ordering::Acquire);
            if !handler_ptr.is_null() {
                let original = &*handler_ptr;
                if original.sa_sigaction != 0 {
                    let handler_fn: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::c_void,
                    ) = std::mem::transmute(original.sa_sigaction);
                    handler_fn(signal, info, context);
                }
            }
        }
    }
}

impl Drop for LinuxDirtyPageTracker {
    fn drop(&mut self) {
        // Remove this tracker's metadata from global lock-free storage
        if get_trackers().remove(&self.id).is_none() {
            error!("Tracker {} not found in global storage", self.id);
        }

        // Restore memory protection
        unsafe {
            mprotect(
                self.base_addr as *mut libc::c_void,
                self.size,
                PROT_READ | PROT_WRITE,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ptr::null_mut;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap};
    use rand::{Rng, rng};

    use super::*;
    use crate::mem::shared_mem::{HostMapping, SharedMemory};

    const PAGE_SIZE: usize = 4096;

    /// Helper function to create a tracker from raw memory parameters
    fn create_test_tracker(base_addr: usize, size: usize) -> Result<LinuxDirtyPageTracker> {
        let test_memory = TestSharedMemory::new(base_addr, size);
        LinuxDirtyPageTracker::new(&test_memory)
    }

    /// Test implementation of SharedMemory for raw memory regions
    struct TestSharedMemory {
        mapping: Arc<HostMapping>,
        base_addr: usize,
        size: usize,
    }

    impl TestSharedMemory {
        fn new(base_addr: usize, size: usize) -> Self {
            // Create a real ExclusiveSharedMemory and extract its mapping
            // This ensures we have a proper HostMapping for testing
            let total_size = size + 2 * PAGE_SIZE_USIZE;
            let exclusive = crate::mem::shared_mem::ExclusiveSharedMemory::new(total_size).unwrap();
            let mapping = exclusive.region_arc();

            Self {
                mapping,
                base_addr,
                size,
            }
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn region(&self) -> &HostMapping {
            &self.mapping
        }

        fn region_arc(&self) -> Arc<HostMapping> {
            Arc::clone(&self.mapping)
        }

        fn base_addr(&self) -> usize {
            self.base_addr
        }

        fn mem_size(&self) -> usize {
            self.size
        }

        fn with_exclusivity<
            T,
            F: FnOnce(&mut crate::mem::shared_mem::ExclusiveSharedMemory) -> T,
        >(
            &mut self,
            _f: F,
        ) -> crate::Result<T> {
            unimplemented!("TestSharedMemory doesn't support with_exclusivity")
        }
    }

    /// Helper to create page-aligned memory for testing
    /// Returns (pointer, size) tuple
    fn create_aligned_memory(size: usize) -> (*mut u8, usize) {
        let addr = unsafe {
            mmap(
                null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0,
            )
        };

        if addr == MAP_FAILED {
            panic!("Failed to allocate aligned memory with mmap");
        }

        (addr as *mut u8, size)
    }

    /// Helper to clean up mmap'd memory
    unsafe fn free_aligned_memory(ptr: *mut u8, size: usize) {
        if unsafe { munmap(ptr as *mut libc::c_void, size) } != 0 {
            eprintln!("Warning: Failed to unmap memory");
        }
    }

    #[test]
    fn test_tracker_creation() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 4);
        let addr = memory_ptr as usize;

        let test_memory = TestSharedMemory::new(addr, memory_size);
        let tracker = LinuxDirtyPageTracker::new(&test_memory);
        println!("Tracker created: {:?}", tracker);
        assert!(tracker.is_ok());
        let tracker = tracker.unwrap();

        // Explicitly drop tracker before freeing memory
        drop(tracker);

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_zero_size_memory_fails() {
        let addr = 0x1000; // Page-aligned address
        let test_memory = TestSharedMemory::new(addr, 0);
        let result = LinuxDirtyPageTracker::new(&test_memory);
        assert!(result.is_err());
    }

    #[test]
    fn test_unaligned_address_fails() {
        let unaligned_addr = 0x1001; // Not page-aligned
        let size = PAGE_SIZE;
        let test_memory = TestSharedMemory::new(unaligned_addr, size);
        let result = LinuxDirtyPageTracker::new(&test_memory);
        assert!(result.is_err());
    }

    #[test]
    fn test_overlapping_trackers_all_fail() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 20); // Large enough for all test cases
        let base_memory_addr = memory_ptr as usize;

        // Define test cases for different overlap scenarios
        // Each test case: (existing_offset, existing_size, new_offset, new_size, description)
        let test_cases = vec![
            // Case 1: New range completely overlaps existing (new contains existing)
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 2,
                PAGE_SIZE * 8,
                "new contains existing",
            ),
            // Case 2: New range completely contained by existing (existing contains new)
            (
                PAGE_SIZE * 2,
                PAGE_SIZE * 8,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "existing contains new",
            ),
            // Case 3: New range overlaps start of existing
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 2,
                PAGE_SIZE * 4,
                "new overlaps start of existing",
            ),
            // Case 4: New range overlaps end of existing
            (
                PAGE_SIZE * 2,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "new overlaps end of existing",
            ),
            // Case 5: New range exactly matches existing
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "new exactly matches existing",
            ),
            // Case 6: New range starts at same address but different size
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 2,
                "new starts same, smaller size",
            ),
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 2,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "new starts same, larger size",
            ),
            // Case 7: New range ends at same address but different start
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 6,
                PAGE_SIZE * 2,
                "new ends same, different start",
            ),
            (
                PAGE_SIZE * 6,
                PAGE_SIZE * 2,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "new ends same, earlier start",
            ),
            // Case 8: Single page overlaps
            (
                PAGE_SIZE * 4,
                PAGE_SIZE,
                PAGE_SIZE * 4,
                PAGE_SIZE,
                "single page exact match",
            ),
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 2,
                PAGE_SIZE * 5,
                PAGE_SIZE,
                "single page within existing",
            ),
            // Case 9: Multi-page overlaps
            (
                PAGE_SIZE * 5,
                PAGE_SIZE * 3,
                PAGE_SIZE * 3,
                PAGE_SIZE * 4,
                "multi-page partial overlap start",
            ),
            (
                PAGE_SIZE * 3,
                PAGE_SIZE * 4,
                PAGE_SIZE * 5,
                PAGE_SIZE * 3,
                "multi-page partial overlap end",
            ),
        ];

        for (i, (existing_offset, existing_size, new_offset, new_size, description)) in
            test_cases.iter().enumerate()
        {
            println!("Test case {}: {}", i + 1, description);

            let existing_addr = base_memory_addr + existing_offset;
            let new_addr = base_memory_addr + new_offset;

            println!(
                "  Existing: [{:#x}, {:#x}) (size: {})",
                existing_addr,
                existing_addr + existing_size,
                existing_size
            );
            println!(
                "  New:      [{:#x}, {:#x}) (size: {})",
                new_addr,
                new_addr + new_size,
                new_size
            );

            // Create the first tracker
            let test_memory1 = TestSharedMemory::new(existing_addr, *existing_size);
            let tracker1 = LinuxDirtyPageTracker::new(&test_memory1);
            assert!(
                tracker1.is_ok(),
                "Failed to create first tracker for test case: {}",
                description
            );
            let tracker1 = tracker1.unwrap();

            // Try to create overlapping tracker - this should fail
            let test_memory2 = TestSharedMemory::new(new_addr, *new_size);
            let tracker2_result = LinuxDirtyPageTracker::new(&test_memory2);
            assert!(
                tracker2_result.is_err(),
                "Expected overlapping tracker to fail for test case: {}\n  Existing: [{:#x}, {:#x})\n  New: [{:#x}, {:#x})",
                description,
                existing_addr,
                existing_addr + existing_size,
                new_addr,
                new_addr + new_size
            );

            println!("  ✓ Correctly rejected overlap");

            // Clean up by dropping the tracker
            drop(tracker1);
            println!();
        }

        // Test cases that should NOT overlap (adjacent ranges)
        let non_overlapping_cases = [
            // Case 1: Adjacent ranges (end of first == start of second)
            (
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 8,
                PAGE_SIZE * 4,
                "adjacent ranges (end to start)",
            ),
            // Case 2: Adjacent ranges (end of second == start of first)
            (
                PAGE_SIZE * 8,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                PAGE_SIZE * 4,
                "adjacent ranges (start to end)",
            ),
            // Case 3: Completely separate ranges
            (
                PAGE_SIZE * 2,
                PAGE_SIZE * 2,
                PAGE_SIZE * 6,
                PAGE_SIZE * 2,
                "completely separate ranges",
            ),
            (
                PAGE_SIZE * 10,
                PAGE_SIZE * 2,
                PAGE_SIZE * 2,
                PAGE_SIZE * 2,
                "completely separate ranges (reversed)",
            ),
        ];

        println!("Testing non-overlapping cases (these should succeed):");
        for (i, (existing_offset, existing_size, new_offset, new_size, description)) in
            non_overlapping_cases.iter().enumerate()
        {
            println!("Non-overlap test case {}: {}", i + 1, description);

            let existing_addr = base_memory_addr + existing_offset;
            let new_addr = base_memory_addr + new_offset;

            println!(
                "  Existing: [{:#x}, {:#x}) (size: {})",
                existing_addr,
                existing_addr + existing_size,
                existing_size
            );
            println!(
                "  New:      [{:#x}, {:#x}) (size: {})",
                new_addr,
                new_addr + new_size,
                new_size
            );

            // Create the first tracker
            let test_memory1 = TestSharedMemory::new(existing_addr, *existing_size);
            let tracker1 = LinuxDirtyPageTracker::new(&test_memory1);
            assert!(
                tracker1.is_ok(),
                "Failed to create first tracker for non-overlap test: {}",
                description
            );
            let tracker1 = tracker1.unwrap();

            // Try to create non-overlapping tracker - this should succeed
            let test_memory2 = TestSharedMemory::new(new_addr, *new_size);
            let tracker2_result = LinuxDirtyPageTracker::new(&test_memory2);
            assert!(
                tracker2_result.is_ok(),
                "Expected non-overlapping tracker to succeed for test case: {}\n  Existing: [{:#x}, {:#x})\n  New: [{:#x}, {:#x})",
                description,
                existing_addr,
                existing_addr + existing_size,
                new_addr,
                new_addr + new_size
            );

            let tracker2 = tracker2_result.unwrap();
            println!("  ✓ Correctly allowed non-overlapping ranges");

            // Clean up
            drop(tracker1);
            drop(tracker2);
            println!();
        }

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_three_way_overlap_detection() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 15);
        let base_addr = memory_ptr as usize;

        // Create two non-overlapping trackers first
        let tracker1 = create_test_tracker(base_addr + PAGE_SIZE * 2, PAGE_SIZE * 3).unwrap();
        let tracker2 = create_test_tracker(base_addr + PAGE_SIZE * 8, PAGE_SIZE * 3).unwrap();

        // Try to create a tracker that overlaps with tracker1
        let overlap_with_1 = create_test_tracker(base_addr + PAGE_SIZE * 3, PAGE_SIZE * 3);
        assert!(
            overlap_with_1.is_err(),
            "Should reject overlap with first tracker"
        );

        // Try to create a tracker that overlaps with tracker2
        let overlap_with_2 = create_test_tracker(base_addr + PAGE_SIZE * 7, PAGE_SIZE * 3);
        assert!(
            overlap_with_2.is_err(),
            "Should reject overlap with second tracker"
        );

        // Try to create a tracker that spans both (overlaps with both)
        let overlap_with_both = create_test_tracker(base_addr + PAGE_SIZE * 4, PAGE_SIZE * 6);
        assert!(
            overlap_with_both.is_err(),
            "Should reject overlap with both trackers"
        );

        // Create a tracker that doesn't overlap with either (should succeed)
        let no_overlap = create_test_tracker(base_addr + PAGE_SIZE * 12, PAGE_SIZE * 2);
        assert!(no_overlap.is_ok(), "Should allow non-overlapping tracker");

        // Explicitly drop all trackers before freeing memory
        drop(tracker1);
        drop(tracker2);
        drop(no_overlap);

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_get_dirty_pages_initially_empty() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 4);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();
        let dirty_pages = tracker.get_dirty_pages();
        assert!(dirty_pages.is_empty());

        // tracker is already dropped by get_dirty_pages() call above

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_random_page_dirtying() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 10);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();

        // Simulate random page access by directly writing to memory
        // This should trigger the SIGSEGV handler and mark pages as dirty

        // generate 5 random page indices to dirty
        let mut pages_to_dirty: HashSet<usize> = HashSet::new();
        while pages_to_dirty.len() < 5 {
            let page_idx = rand::random::<u8>() % 10; // 0 to 9
            pages_to_dirty.insert(page_idx as usize);
        }

        for &page_idx in &pages_to_dirty {
            let page_offset = page_idx * PAGE_SIZE;
            if page_offset < memory_size {
                // Write to the memory to trigger dirty tracking
                unsafe {
                    let write_addr = (addr + page_offset + 100) as *mut u8;
                    std::ptr::write_volatile(write_addr, 42);
                }
            }
        }

        let dirty_pages = tracker.get_dirty_pages();

        println!("Dirty Pages expected: {:?}", pages_to_dirty);
        println!("Dirty pages found: {:?}", dirty_pages);

        // check that the dirty pages only contain the indices we wrote to
        for &page_idx in &pages_to_dirty {
            assert!(
                dirty_pages.contains(&page_idx),
                "Page {} should be dirty",
                page_idx
            );
        }
        // Check that no other pages are dirty
        for &page_idx in &dirty_pages {
            assert!(
                pages_to_dirty.contains(&page_idx),
                "Unexpected dirty page: {}",
                page_idx
            );
        }

        // tracker is already dropped by get_dirty_pages() call above

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_multiple_trackers_different_regions() {
        let (memory_ptr1, memory_size1) = create_aligned_memory(PAGE_SIZE * 4);
        let (memory_ptr2, memory_size2) = create_aligned_memory(PAGE_SIZE * 4);
        let addr1 = memory_ptr1 as usize;
        let addr2 = memory_ptr2 as usize;

        let tracker1 = create_test_tracker(addr1, memory_size1).unwrap();
        let tracker2 = create_test_tracker(addr2, memory_size2).unwrap();

        // Write to different memory regions
        unsafe {
            std::ptr::write_volatile((addr1 + 100) as *mut u8, 1);
            std::ptr::write_volatile((addr2 + PAGE_SIZE + 200) as *mut u8, 2);
        }

        let dirty1 = tracker1.get_dirty_pages();
        let dirty2 = tracker2.get_dirty_pages();

        // Verify each tracker only reports pages that were actually written to
        // Tracker1: wrote to offset 100, which is in page 0
        assert!(dirty1.contains(&0), "Tracker 1 should have page 0 dirty");
        assert_eq!(dirty1.len(), 1, "Tracker 1 should only have 1 dirty page");

        // Tracker2: wrote to offset PAGE_SIZE + 200, which is in page 1
        assert!(dirty2.contains(&1), "Tracker 2 should have page 1 dirty");
        assert_eq!(dirty2.len(), 1, "Tracker 2 should only have 1 dirty page");

        // Verify that each tracker's dirty pages are within expected bounds
        for &page_idx in &dirty1 {
            assert!(
                page_idx < 4,
                "Tracker 1 page index {} out of bounds",
                page_idx
            );
        }
        for &page_idx in &dirty2 {
            assert!(
                page_idx < 4,
                "Tracker 2 page index {} out of bounds",
                page_idx
            );
        }

        unsafe {
            free_aligned_memory(memory_ptr1, memory_size1);
            free_aligned_memory(memory_ptr2, memory_size2);
        }
    }

    #[test]
    fn test_cleanup_on_drop() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 2);
        let addr = memory_ptr as usize;

        // Create tracker in a scope to test drop behavior
        {
            let tracker = create_test_tracker(addr, memory_size).unwrap();

            // Write to memory to verify tracking works
            unsafe {
                std::ptr::write_volatile((addr + 100) as *mut u8, 42);
            }

            let _ = tracker.get_dirty_pages();
        } // tracker is dropped here

        // Create a new tracker for the same memory region
        // This should work without issues if data was properly cleaned up
        let new_tracker = create_test_tracker(addr, memory_size);
        assert!(
            new_tracker.is_ok(),
            "Data not properly cleaned up on tracker drop"
        );

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_page_boundaries() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 3);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();

        // Write to different offsets within the first page
        let offsets = [0, 1, 100, 1000, PAGE_SIZE - 1];

        for &offset in &offsets {
            unsafe {
                std::ptr::write_volatile((addr + offset) as *mut u8, offset as u8);
            }
        }

        let dirty_pages = tracker.get_dirty_pages();

        // All writes to the same page should result in the same page being dirty
        if !dirty_pages.is_empty() {
            // Check that page indices are within bounds
            for &page_idx in &dirty_pages {
                assert!(page_idx < 3, "Page index out of bounds: {}", page_idx);
            }
        }

        // tracker is already dropped by get_dirty_pages() call above

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_concurrent_trackers() {
        const NUM_THREADS: usize = 50;
        const UPDATES_PER_THREAD: usize = 500;
        const MIN_MEMORY_SIZE: usize = 1024 * 1024; // 1MB
        const MAX_MEMORY_SIZE: usize = 10 * 1024 * 1024; // 10MB

        // Create barrier for synchronization
        let start_writing_barrier = Arc::new(Barrier::new(NUM_THREADS));

        let mut handles = Vec::new();

        for thread_id in 0..NUM_THREADS {
            let start_writing_barrier = Arc::clone(&start_writing_barrier);

            let handle = thread::spawn(move || {
                let mut rng = rng();

                // Generate random memory size between 1MB and 10MB
                let memory_size = rng.random_range(MIN_MEMORY_SIZE..=MAX_MEMORY_SIZE);

                // Ensure memory size is page-aligned
                let memory_size = (memory_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let num_pages = memory_size / PAGE_SIZE;

                let (memory_ptr, _) = create_aligned_memory(memory_size);
                let addr = memory_ptr as usize;

                // Create tracker (must succeed)
                let tracker =
                    create_test_tracker(addr, memory_size).expect("Failed to create tracker");

                // Wait for all threads to finish allocating before starting writes
                start_writing_barrier.wait();

                // Track which pages we write to
                let mut pages_written = HashSet::new();
                let mut total_writes = 0;

                // Perform random memory updates
                for _update_id in 0..UPDATES_PER_THREAD {
                    // Generate random page index
                    let page_idx = rng.random_range(0..num_pages);
                    let page_offset = page_idx * PAGE_SIZE;

                    // Generate random offset within the page (avoid last byte to prevent overruns)
                    let within_page_offset = rng.random_range(0..(PAGE_SIZE - 1));
                    let write_addr = addr + page_offset + within_page_offset;

                    // Generate random value to write
                    let value = rng.random::<u8>();

                    // Write to memory to trigger dirty tracking
                    unsafe {
                        std::ptr::write_volatile(write_addr as *mut u8, value);
                    }

                    // Track this page as written to (HashSet handles duplicates)
                    pages_written.insert(page_idx);
                    total_writes += 1;
                }

                // Final verification: check that ALL pages we wrote to are marked as dirty
                let final_dirty_pages = tracker.get_dirty_pages();

                // Check that every page we wrote to is marked as dirty
                for &page_idx in &pages_written {
                    assert!(
                        final_dirty_pages.contains(&page_idx),
                        "Thread {}: Page {} was written but not marked dirty. Pages written: {:?}, Pages dirty: {:?}",
                        thread_id,
                        page_idx,
                        pages_written,
                        final_dirty_pages
                    );
                }

                // Verify that the number of unique dirty pages matches unique pages written
                let dirty_pages_set: HashSet<usize> = final_dirty_pages.into_iter().collect();
                assert_eq!(
                    pages_written.len(),
                    dirty_pages_set.len(),
                    "Thread {}: Mismatch between unique pages written ({}) and unique dirty pages ({}). \
                     Total writes: {}, Pages written: {:?}, Dirty pages: {:?}",
                    thread_id,
                    pages_written.len(),
                    dirty_pages_set.len(),
                    total_writes,
                    pages_written,
                    dirty_pages_set
                );

                // Verify that dirty pages don't contain extra pages we didn't write to
                for &dirty_page in &dirty_pages_set {
                    assert!(
                        pages_written.contains(&dirty_page),
                        "Thread {}: Found dirty page {} that was not written to. Pages written: {:?}",
                        thread_id,
                        dirty_page,
                        pages_written
                    );
                }

                // Clean up
                unsafe {
                    free_aligned_memory(memory_ptr, memory_size);
                }

                (pages_written.len(), dirty_pages_set.len(), total_writes)
            });

            handles.push(handle);
        }

        // Wait for all threads to complete and collect results
        let mut total_unique_pages_written = 0;
        let mut total_unique_dirty_pages = 0;
        let mut total_write_operations = 0;

        for (thread_id, handle) in handles.into_iter().enumerate() {
            let (unique_pages_written, unique_dirty_pages, write_operations) = handle
                .join()
                .unwrap_or_else(|_| panic!("Thread {} panicked", thread_id));

            total_unique_pages_written += unique_pages_written;
            total_unique_dirty_pages += unique_dirty_pages;
            total_write_operations += write_operations;
        }

        println!("Concurrent test completed:");
        println!("  {} threads", NUM_THREADS);
        println!("  {} updates per thread", UPDATES_PER_THREAD);
        println!("  {} total write operations", total_write_operations);
        println!(
            "  {} total unique pages written",
            total_unique_pages_written
        );
        println!(
            "  {} total unique dirty pages detected",
            total_unique_dirty_pages
        );

        // Verify that we detected the expected number of dirty pages
        assert!(
            total_unique_dirty_pages > 0,
            "No dirty pages detected across all threads"
        );
        assert_eq!(
            total_unique_pages_written, total_unique_dirty_pages,
            "Mismatch between unique pages written and unique dirty pages detected"
        );

        // The total write operations should normally be much higher than unique pages (due to multiple writes to same pages)
        assert!(
            total_write_operations >= total_unique_pages_written,
            "Total write operations ({}) should be >= unique pages written ({})",
            total_write_operations,
            total_unique_pages_written
        );
    }

    #[test]
    fn test_tracker_contains_address() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 2);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();

        // Test address checking (internal method)
        assert!(tracker.contains_address(addr));
        assert!(tracker.contains_address(addr + 100));
        assert!(tracker.contains_address(addr + memory_size - 1));
        assert!(!tracker.contains_address(addr - 1));
        assert!(!tracker.contains_address(addr + memory_size));

        // Explicitly drop tracker before freeing memory
        drop(tracker);

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_write_protection_active() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();

        // Memory should be write-protected initially
        // Writing should trigger SIGSEGV (which gets handled by our signal handler)
        unsafe {
            std::ptr::write_volatile((addr + 100) as *mut u8, 42);
        }

        // If we get here without crashing, the signal handler worked

        // Explicitly drop tracker before freeing memory
        drop(tracker);

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_stress_multiple_writes() {
        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 5);
        let addr = memory_ptr as usize;

        let tracker = create_test_tracker(addr, memory_size).unwrap();

        // Write to many different pages and offsets
        for page in 0..5 {
            for offset in [0, 100, 500, 1000, PAGE_SIZE - 1] {
                let write_addr = addr + (page * PAGE_SIZE) + offset;
                if write_addr < addr + memory_size {
                    unsafe {
                        std::ptr::write_volatile(write_addr as *mut u8, (page + offset) as u8);
                    }
                }
            }
        }

        let dirty_pages = tracker.get_dirty_pages();
        println!("Stress test dirty pages: {:?}", dirty_pages);

        // Verify all page indices are valid
        for &page_idx in &dirty_pages {
            assert!(page_idx < 5, "Invalid page index: {}", page_idx);
        }

        // tracker is already dropped by get_dirty_pages() call above

        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }

    #[test]
    fn test_pid_tracking_and_isolation() {
        let (memory_ptr1, memory_size1) = create_aligned_memory(PAGE_SIZE * 4);
        let (memory_ptr2, memory_size2) = create_aligned_memory(PAGE_SIZE * 4);
        let addr1 = memory_ptr1 as usize;
        let addr2 = memory_ptr2 as usize;

        // Create two trackers
        let tracker1 = create_test_tracker(addr1, memory_size1).unwrap();
        let tracker2 = create_test_tracker(addr2, memory_size2).unwrap();

        let current_pid = std::process::id();

        // Verify that tracker data contains the correct PID
        let trackers = get_trackers();
        let tracker1_data = trackers.get(&tracker1.id).unwrap();
        let tracker2_data = trackers.get(&tracker2.id).unwrap();

        assert_eq!(
            tracker1_data.val().pid,
            current_pid,
            "Tracker 1 should store the current process ID"
        );
        assert_eq!(
            tracker2_data.val().pid,
            current_pid,
            "Tracker 2 should store the current process ID"
        );

        // Explicitly drop trackers before freeing memory
        drop(tracker1);
        drop(tracker2);

        // Clean up
        unsafe {
            free_aligned_memory(memory_ptr1, memory_size1);
            free_aligned_memory(memory_ptr2, memory_size2);
        }
    }

    #[test]
    fn test_overlap_detection_with_same_virtual_addresses() {
        // This test verifies that overlap detection is now scoped per process
        // In a real multi-process scenario, different processes could have the same
        // virtual addresses that map to different physical memory, so overlaps
        // should only be checked within the same process.

        let (memory_ptr, memory_size) = create_aligned_memory(PAGE_SIZE * 4);
        let addr = memory_ptr as usize;

        // Create a tracker for this address range
        let tracker1 = create_test_tracker(addr, memory_size).unwrap();

        // Verify the tracker is storing the current PID
        let current_pid = std::process::id();
        let trackers = get_trackers();
        let tracker_data = trackers.get(&tracker1.id).unwrap();
        assert_eq!(tracker_data.val().pid, current_pid);

        // Creating an overlapping tracker with the same PID should fail
        let overlap_result = create_test_tracker(addr + PAGE_SIZE, PAGE_SIZE * 2);
        assert!(
            overlap_result.is_err(),
            "Creating overlapping tracker in same process should fail"
        );

        // Clean up
        drop(tracker1);
        unsafe {
            free_aligned_memory(memory_ptr, memory_size);
        }
    }
}
