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

use crate::mem::shared_mem::HostMapping;
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
    pub(super) fn new(mapping: Arc<HostMapping>) -> Result<Self> {
        if mapping.size == 0 {
            return Err(new_error!("Cannot track empty memory region"));
        }

        if mapping.ptr as usize % PAGE_SIZE_USIZE != 0 {
            return Err(new_error!("Base address must be page-aligned"));
        }
        let base_addr = mapping.ptr as usize + PAGE_SIZE_USIZE; // Start after the first page to avoid tracking guard page
        let size = mapping.size - 2 * PAGE_SIZE_USIZE; // Exclude guard pages at start and end

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
                let new_end = base_addr.wrapping_add(size);

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

    /// Get all dirty page indices for this tracker.
    /// NOTE: This is not a bitmap, but a vector of indices where each index corresponds to a page that has been written to.
    #[cfg(test)]
    pub(super) fn get_dirty_pages(&self) -> Result<Vec<usize>> {
        let res: Vec<usize> = if let Some(tracker_data) = get_trackers().get(&self.id) {
            let mut dirty_pages = Vec::new();
            let tracker_data = tracker_data.val();
            for (idx, dirty) in tracker_data.dirty_pages.iter().enumerate() {
                if dirty.load(Ordering::Acquire) {
                    dirty_pages.push(idx);
                }
            }
            dirty_pages
        } else {
            return Err(new_error!(
                "Tried to get dirty pages from tracker, but no tracker data found"
            ));
        };

        Ok(res)
    }

    /// Get all dirty page indices for this tracker.
    /// NOTE: This is not a bitmap, but a vector of indices where each index corresponds to a page that has been written to.
    pub(super) fn stop_tracking_and_get_dirty_pages(self) -> Result<Vec<usize>> {
        let res: Vec<usize> = if let Some(tracker_data) = get_trackers().get(&self.id) {
            let mut dirty_pages = Vec::new();
            let tracker_data = tracker_data.val();
            for (idx, dirty) in tracker_data.dirty_pages.iter().enumerate() {
                if dirty.load(Ordering::Acquire) {
                    dirty_pages.push(idx);
                }
            }
            dirty_pages
        } else {
            return Err(new_error!(
                "Tried to get dirty pages from tracker, but no tracker data found"
            ));
        };

        // explicit to document intent
        drop(self);

        Ok(res)
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

    #[cfg(test)]
    /// Check if a memory address falls within this tracker's region
    fn contains_address(&self, addr: usize) -> bool {
        addr >= self.base_addr && addr < self.base_addr + self.size
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

    use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap};
    use rand::{Rng, rng};

    use super::*;
    use crate::mem::shared_mem::{ExclusiveSharedMemory, HostMapping, SharedMemory};

    const PAGE_SIZE: usize = 4096;

    /// Helper to create page-aligned memory for testing
    /// Returns (pointer, size) tuple
    fn create_aligned_memory(size: usize) -> Arc<HostMapping> {
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

        // HostMapping is only non-Send/Sync because raw pointers
        // are not ("as a lint", as the Rust docs say). We don't
        // want to mark HostMapping Send/Sync immediately, because
        // that could socially imply that it's "safe" to use
        // unsafe accesses from multiple threads at once. Instead, we
        // directly impl Send and Sync on this type. Since this
        // type does have Send and Sync manually impl'd, the Arc
        // is not pointless as the lint suggests.
        #[allow(clippy::arc_with_non_send_sync)]
        Arc::new(HostMapping {
            ptr: addr as *mut u8,
            size,
        })
    }

    #[test]
    fn test_tracker_creation() {
        let mut memory = ExclusiveSharedMemory::new(5 * 4096).unwrap();
        memory.stop_tracking_dirty_pages().unwrap();
    }

    #[test]
    fn test_get_dirty_pages_initially_empty() {
        let mut memory = ExclusiveSharedMemory::new(5 * 4096).unwrap();

        let bitmap = memory
            .stop_tracking_dirty_pages()
            .expect("Failed to stop tracking dirty pages");

        assert!(bitmap.is_empty(), "Dirty pages should be empty initially");
    }

    #[test]
    fn test_random_page_dirtying() {
        const MEMORY_SIZE: usize = 4096;
        let mut memory = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();

        let bitmap = memory.get_dirty_pages().expect("Failed to get dirty pages");

        assert!(bitmap.is_empty(), "Dirty pages should be empty initially");

        let mem = memory.as_mut_slice();
        let five_random_idx = rand::rng()
            .sample_iter(rand::distr::Uniform::new(0, MEMORY_SIZE).unwrap())
            .take(5)
            .collect::<Vec<usize>>();

        println!("Random indices: {:?}", &five_random_idx);

        for idx in &five_random_idx {
            mem[*idx] = 1; // Write to random indices
        }
        let dirty_pages = memory
            .stop_tracking_dirty_pages()
            .expect("Failed to stop tracking dirty pages");
        assert!(
            !dirty_pages.is_empty(),
            "Dirty pages should not be empty after writes"
        );
        for idx in five_random_idx {
            let page_idx = idx / PAGE_SIZE;
            assert!(
                dirty_pages.contains(&page_idx),
                "Page {} should be dirty after writing to index {}",
                page_idx,
                idx
            );
        }
    }

    #[test]
    fn test_multiple_trackers_different_regions() {
        const MEMORY_SIZE: usize = PAGE_SIZE * 4;

        let mut memory1 = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();
        let mut memory2 = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();

        // Verify initial state is clean
        let bitmap1 = memory1
            .get_dirty_pages()
            .expect("Failed to get dirty pages");
        let bitmap2 = memory2
            .get_dirty_pages()
            .expect("Failed to get dirty pages");
        assert!(bitmap1.is_empty(), "Dirty pages should be empty initially");
        assert!(bitmap2.is_empty(), "Dirty pages should be empty initially");

        // Write to different memory regions
        let mem1 = memory1.as_mut_slice();
        let mem2 = memory2.as_mut_slice();

        mem1[100] = 1; // Write to offset 100 in first memory region (page 0)
        mem2[PAGE_SIZE + 200] = 2; // Write to offset 200 in second memory region (page 1)

        let dirty1 = memory1.stop_tracking_dirty_pages().unwrap();
        let dirty2 = memory2.stop_tracking_dirty_pages().unwrap();

        // Verify each tracker only reports pages that were actually written to
        // Memory1: wrote to offset 100, which is in page 0
        assert!(dirty1.contains(&0), "Memory 1 should have page 0 dirty");
        assert_eq!(dirty1.len(), 1, "Memory 1 should only have 1 dirty page");

        // Memory2: wrote to offset 200, which is in page 1
        assert!(dirty2.contains(&1), "Memory 2 should have page 1 dirty");
        assert_eq!(dirty2.len(), 1, "Memory 2 should only have 1 dirty page");
    }

    #[test]
    fn test_cleanup_on_drop() {
        const MEMORY_SIZE: usize = PAGE_SIZE * 2;
        let mut memory = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();

        // Verify initial state is clean
        let bitmap = memory.get_dirty_pages().expect("Failed to get dirty pages");
        assert!(bitmap.is_empty(), "Dirty pages should be empty initially");

        // Get memory slice - this should work initially
        let mem = memory.as_mut_slice();

        // Memory should be read-only during tracking (writes will trigger SIGSEGV but get handled)
        // Write to memory to verify tracking works - this should succeed due to signal handler
        mem[100] = 42;

        let raw_addr = memory.raw_ptr();
        let raw_size = memory.raw_mem_size();
        // Verify the write was tracked
        let dirty_pages_before_stop = memory.get_dirty_pages().expect("Failed to get dirty pages");
        assert!(
            !dirty_pages_before_stop.is_empty(),
            "Should have dirty pages after write"
        );
        assert!(
            dirty_pages_before_stop.contains(&0),
            "Page 0 should be dirty"
        );

        drop(memory); // Explicitly drop the memory

        // now try mmap the memory again, it should work
        let res = unsafe {
            libc::mmap(
                raw_addr as *mut libc::c_void,
                raw_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        assert!(
            res != MAP_FAILED,
            "Failed to remap memory after tracker drop: {}",
            std::io::Error::last_os_error()
        );
    }

    #[test]
    fn test_page_boundaries() {
        const MEMORY_SIZE: usize = PAGE_SIZE * 3;
        let mut memory = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();

        // Verify initial state is clean
        let bitmap = memory.get_dirty_pages().expect("Failed to get dirty pages");
        assert!(bitmap.is_empty(), "Dirty pages should be empty initially");

        let mem = memory.as_mut_slice();

        // Write to different offsets within the first tracked page
        // Remember: tracker excludes the first page (guard page), so we need to offset by PAGE_SIZE
        let offsets = [0, 1, 100, 1000, PAGE_SIZE - 1];

        for &offset in &offsets {
            // Write to the first tracked page (which is the second page in the memory region)
            mem[offset] = offset as u8;
        }

        let dirty_pages = memory.stop_tracking_dirty_pages().unwrap();

        // All writes to the same page should result in the same page being dirty
        assert!(
            !dirty_pages.is_empty(),
            "Should have dirty pages after writes"
        );
        assert!(
            dirty_pages.contains(&0),
            "Page 0 should be dirty after writes to first tracked page"
        );

        // Since all writes were to the same page, we should only have one dirty page
        assert_eq!(
            dirty_pages.len(),
            1,
            "Should only have one dirty page since all writes were to the same page"
        );

        // Now test writing to different pages
        let mut memory2 = ExclusiveSharedMemory::new(MEMORY_SIZE).unwrap();
        let mem2 = memory2.as_mut_slice();

        // Write to first tracked page (page 0 in tracker terms)
        mem2[100] = 1;
        // Write to second tracked page (page 1 in tracker terms) - this is the third page in memory
        mem2[PAGE_SIZE] = 2;

        let dirty_pages2 = memory2.stop_tracking_dirty_pages().unwrap();

        assert_eq!(dirty_pages2.len(), 2, "Should have two dirty pages");
        assert!(dirty_pages2.contains(&0), "Page 0 should be dirty");
        assert!(dirty_pages2.contains(&1), "Page 1 should be dirty");
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

                let memory_size = rng.random_range(MIN_MEMORY_SIZE..=MAX_MEMORY_SIZE);

                // Ensure memory size is page-aligned
                let memory_size = (memory_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

                let mut memory = ExclusiveSharedMemory::new(memory_size)
                    .expect("Failed to create shared memory");

                // Wait for all threads to finish allocating before starting writes
                start_writing_barrier.wait();

                // Track which pages we write to (in tracker page indices)
                let mut pages_written = HashSet::new();
                let mut total_writes = 0;

                // Perform random memory updates in a scope to ensure slice is dropped
                {
                    let mem = memory.as_mut_slice();

                    for _ in 0..UPDATES_PER_THREAD {
                        // Generate random offset within the entire slice
                        let write_offset = rng.random_range(0..mem.len());

                        // Calculate which tracker page this corresponds to
                        let tracker_page_idx = write_offset / PAGE_SIZE;

                        // Generate random value to write
                        let value = rng.random::<u8>();

                        // Write to memory to trigger dirty tracking
                        mem[write_offset] = value;

                        // Track this page as written to (HashSet handles duplicates)
                        pages_written.insert(tracker_page_idx);
                        total_writes += 1;
                    }
                } // mem goes out of scope here

                // Final verification: check that ALL pages we wrote to are marked as dirty
                let final_dirty_pages = memory.stop_tracking_dirty_pages().unwrap();

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

                // Verify that dirty pages don't contain extra pages we didn't write to
                for &dirty_page in &final_dirty_pages {
                    assert!(
                        pages_written.contains(&dirty_page),
                        "Thread {}: Found dirty page {} that was not written to. Pages written: {:?}",
                        thread_id,
                        dirty_page,
                        pages_written
                    );
                }

                // Additional check: verify that pages we didn't write to are not dirty
                for page_idx in 0..(memory_size / PAGE_SIZE) {
                    if !pages_written.contains(&page_idx) {
                        assert!(
                            !final_dirty_pages.contains(&page_idx),
                            "Thread {}: Page {} was not written but is marked dirty. Pages written: {:?}, Pages dirty: {:?}",
                            thread_id,
                            page_idx,
                            pages_written,
                            final_dirty_pages
                        );
                    }
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
        const MEMORY_SIZE: usize = PAGE_SIZE * 10;
        let mapping = create_aligned_memory(MEMORY_SIZE);
        let tracker = LinuxDirtyPageTracker::new(mapping.clone()).unwrap();

        let base = mapping.ptr as usize;

        // Test all addresses in the memory region
        for offset in 0..MEMORY_SIZE {
            let address = base + offset;

            // First page (guard page) and last page (guard page) should not be contained
            let is_first_page = offset < PAGE_SIZE;
            let is_last_page = offset >= MEMORY_SIZE - PAGE_SIZE;

            if is_first_page || is_last_page {
                assert!(
                    !tracker.contains_address(address),
                    "Address at offset {} (page {}) should not be contained (guard page)",
                    offset,
                    offset / PAGE_SIZE
                );
            } else {
                assert!(
                    tracker.contains_address(address),
                    "Address at offset {} (page {}) should be contained",
                    offset,
                    offset / PAGE_SIZE
                );
            }
        }

        // try some random addresses far from the base address
        assert!(
            !tracker.contains_address(base - 213217),
            "Address far from base should not be contained"
        );
        assert!(
            !tracker.contains_address(base + MEMORY_SIZE + 12345),
            "Address far from end should not be contained"
        );
    }
}
