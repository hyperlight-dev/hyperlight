/*
Copyright 2026  The Hyperlight Authors.

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

use super::*;

fn make_run_pool<const L: usize, const U: usize>(size: usize) -> RunPool<L, U> {
    let base = align_up(0x10000, L.max(U)).unwrap() as u64;
    RunPool::<L, U>::new(base, size).unwrap()
}

fn make_slot_pool(slot_count: usize, slot_size: usize) -> SlotPool {
    let layout = SlotLayout::new(0x80000, slot_size, slot_count);
    SlotPool::new(layout).unwrap()
}

fn make_tiered_slot_pool(lower_count: usize, upper_count: usize) -> SlotPool {
    let lower = SlotLayout::new(0x80000, 256, lower_count);
    let upper = SlotLayout::new(0x90000, 4096, upper_count);
    SlotPool::new_tiered(lower, upper).unwrap()
}

fn alloc_exact_regions(
    pool: &impl BufferProvider,
    lengths: impl IntoIterator<Item = usize>,
) -> Result<Regions, AllocError> {
    pool.alloc_regions(lengths)
}

#[test]
fn test_run_pool_new_success() {
    let pool = RunPool::<256, 4096>::new(0x10000, 1024 * 1024).unwrap();
    assert!(pool.inner.borrow().lower.capacity() > 0);
    assert!(pool.inner.borrow().upper.capacity() > 0);
}

#[test]
fn test_run_pool_alloc_small_to_lower() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let alloc = pool.alloc(128).unwrap();

    // Should come from the lower tier.
    assert!(pool.inner.borrow().lower.contains(alloc.addr));
    assert_eq!(alloc.len, 256);
}

#[test]
fn test_run_pool_alloc_large_to_upper() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let alloc = pool.alloc(1500).unwrap();

    // Should come from the upper tier.
    assert!(pool.inner.borrow().upper.contains(alloc.addr));
    assert_eq!(alloc.len, 4096);
}

#[test]
fn test_run_pool_alloc_fallback_to_upper() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);

    // Fill the lower tier completely.
    let mut allocations = Vec::new();
    while pool.inner.borrow().lower.free_bytes() > 0 {
        allocations.push(pool.inner.borrow_mut().lower.alloc(256).unwrap());
    }

    // Small allocation should fall back to the upper tier.
    let alloc = pool.alloc(128).unwrap();
    assert!(pool.inner.borrow().upper.contains(alloc.addr));
}

#[test]
fn test_run_pool_free_from_lower() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let alloc = pool.alloc(128).unwrap();

    let free_before = pool.inner.borrow().lower.free_bytes();
    pool.dealloc(alloc.addr).unwrap();
    assert_eq!(
        pool.inner.borrow().lower.free_bytes(),
        free_before + alloc.len as usize
    );
}

#[test]
fn test_run_pool_free_from_upper() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let alloc = pool.alloc(1500).unwrap();

    let free_before = pool.inner.borrow().upper.free_bytes();
    pool.dealloc(alloc.addr).unwrap();
    assert_eq!(
        pool.inner.borrow().upper.free_bytes(),
        free_before + alloc.len as usize
    );
}

#[test]
fn test_run_pool_stress_many_allocations() {
    let pool = make_run_pool::<256, 4096>(4 * 1024 * 1024);
    let mut allocations = Vec::new();

    // Allocate many buffers
    for i in 0..100 {
        let size = if i % 2 == 0 { 128 } else { 1500 };
        allocations.push(pool.alloc(size).unwrap());
    }

    // Free half of them
    for i in (0..100).step_by(2) {
        pool.dealloc(allocations[i].addr).unwrap();
    }

    // Should be able to allocate again
    for i in 0..50 {
        let size = if i % 2 == 0 { 128 } else { 1500 };
        let _alloc = pool.alloc(size).unwrap();
    }
}

#[test]
fn test_run_pool_mixed_workload() {
    let pool = make_run_pool::<256, 4096>(2 * 1024 * 1024);

    // Simulate virtio-net workload
    let desc_buf = pool.alloc(64).unwrap(); // Control message
    let rx_buf1 = pool.alloc(1500).unwrap(); // MTU packet
    let rx_buf2 = pool.alloc(1500).unwrap(); // MTU packet
    let tx_buf = pool.alloc(4096).unwrap(); // Large buffer

    // Free and reallocate
    pool.dealloc(rx_buf1.addr).unwrap();
    let rx_buf3 = pool.alloc(1500).unwrap();

    // Should reuse freed buffer (LIFO)
    assert_eq!(rx_buf3.addr, rx_buf1.addr);

    pool.dealloc(desc_buf.addr).unwrap();
    pool.dealloc(rx_buf2.addr).unwrap();
    pool.dealloc(rx_buf3.addr).unwrap();
    pool.dealloc(tx_buf.addr).unwrap();
}

#[test]
fn test_run_pool_zero_allocation_error() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let result = pool.alloc(0);
    assert!(matches!(result, Err(AllocError::InvalidArg)));
}

#[test]
fn test_run_pool_too_large_allocation() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);
    let result = pool.alloc(2 * 1024 * 1024); // Larger than pool
    assert!(matches!(result, Err(AllocError::OutOfMemory)));
}

#[test]
fn test_align_up_helper() {
    assert_eq!(align_up(0, 256).unwrap(), 0);
    assert_eq!(align_up(1, 256).unwrap(), 256);
    assert_eq!(align_up(256, 256).unwrap(), 256);
    assert_eq!(align_up(257, 256).unwrap(), 512);
    assert_eq!(align_up(511, 256).unwrap(), 512);
    assert_eq!(align_up(512, 256).unwrap(), 512);
    assert!(matches!(align_up(1, 0), Err(AllocError::InvalidArg)));
    assert!(matches!(
        align_up(usize::MAX, 256),
        Err(AllocError::Overflow)
    ));
}

#[test]
fn test_slot_pool_preserves_exact_base() {
    let layout = SlotLayout::new(0x80001, 4096, 2);
    let pool = SlotPool::new(layout).unwrap();

    assert_eq!(pool.base_addr(), 0x80001);
    assert_eq!(pool.count(), 2);
    assert_eq!(pool.slot_addr(0), Some(0x80001));
    assert_eq!(pool.slot_addr(1), Some(0x81001));
}

#[test]
fn test_tiered_slot_pool_reports_layouts() {
    let lower = SlotLayout::new(0x80001, 0x100, 2);
    let upper = SlotLayout::new(0x90001, 0x1000, 2);
    let pool = SlotPool::new_tiered(lower, upper).unwrap();

    let (lower, upper) = pool.layouts();
    assert_eq!(lower, Some(SlotLayout::new(0x80001, 0x100, 2)));
    assert_eq!(upper, SlotLayout::new(0x90001, 0x1000, 2));
    assert_eq!(pool.base_addr(), 0x80001);
    assert_eq!(pool.slot_size(), 0x1000);
    assert_eq!(pool.count(), 4);
    assert_eq!(pool.slot_addr(0), Some(0x80001));
    assert_eq!(pool.slot_addr(1), Some(0x80101));
    assert_eq!(pool.slot_addr(2), Some(0x90001));
    assert_eq!(pool.slot_addr(3), Some(0x91001));
    assert_eq!(pool.slot_addr(4), None);
}

#[test]
fn test_tiered_slot_pool_combines_contiguous_equal_sized_layouts() {
    let lower = SlotLayout::new(0x80000, 0x100, 2);
    let upper = SlotLayout::new(0x80200, 0x100, 3);
    let pool = SlotPool::new_tiered(lower, upper).unwrap();

    assert_eq!(pool.layouts(), (None, SlotLayout::new(0x80000, 0x100, 5)));
    assert_eq!(pool.base_addr(), 0x80000);
    assert_eq!(pool.slot_size(), 0x100);
    assert_eq!(pool.count(), 5);
    assert_eq!(pool.num_free_lower(), 0);
    assert_eq!(pool.num_free_upper(), 5);
    assert_eq!(pool.slot_addr(4), Some(0x80400));
}

#[test]
fn test_tiered_slot_pool_rejects_invalid_layout() {
    let lower = SlotLayout::new(0x80000, 0x100, 32);
    let overlapping_upper = SlotLayout::new(0x81000, 0x1000, 2);
    let overlapping = SlotPool::new_tiered(lower, overlapping_upper);
    assert!(matches!(overlapping, Err(AllocError::InvalidArg)));

    let lower = SlotLayout::new(0x80000, 0x100, 2);
    let separated_upper = SlotLayout::new(0x80300, 0x100, 2);
    let separated = SlotPool::new_tiered(lower, separated_upper);
    assert!(matches!(separated, Err(AllocError::InvalidArg)));

    let lower = SlotLayout::new(0x80000, 0x1000, 2);
    let smaller_upper = SlotLayout::new(0x90000, 0x100, 32);
    let reversed_sizes = SlotPool::new_tiered(lower, smaller_upper);
    assert!(matches!(reversed_sizes, Err(AllocError::InvalidArg)));
}

#[cfg(target_pointer_width = "64")]
#[test]
fn test_slot_pool_rejects_unrepresentable_slot_size() {
    let layout = SlotLayout::new(0x80000, u32::MAX as usize + 1, 1);
    assert!(matches!(SlotPool::new(layout), Err(AllocError::InvalidArg)));
}

#[test]
fn test_tiered_slot_pool_routes_by_size() {
    let pool = make_tiered_slot_pool(2, 2);
    let lower = pool.alloc(128).unwrap();
    let upper = pool.alloc(257).unwrap();

    assert_eq!(lower.len, 256);
    assert!((0x80000..0x80200).contains(&lower.addr));
    assert_eq!(upper.len, 4096);
    assert!((0x90000..0x92000).contains(&upper.addr));
    assert_eq!(pool.allocation_len(lower.addr).unwrap(), 256);
    assert_eq!(pool.allocation_len(upper.addr).unwrap(), 4096);
}

#[test]
fn test_tiered_slot_pool_lower_falls_back_when_full() {
    let pool = make_tiered_slot_pool(1, 2);

    let lower = pool.alloc(128).unwrap();
    let fallback = pool.alloc(128).unwrap();

    assert_eq!(lower.len, 256);
    assert_eq!(fallback.len, 4096);
    assert!((0x90000..0x92000).contains(&fallback.addr));
}

#[test]
fn test_tiered_slot_pool_does_not_mask_lower_errors() {
    let pool = make_tiered_slot_pool(1, 1);

    assert!(matches!(pool.alloc(0), Err(AllocError::InvalidArg)));
    assert!(matches!(pool.alloc(4097), Err(AllocError::OutOfMemory)));
    assert_eq!(pool.num_free(), 2);
}

#[test]
fn test_tiered_slot_pool_reports_free_tier_counts() {
    let pool = make_tiered_slot_pool(2, 3);

    assert_eq!(pool.num_free_lower(), 2);
    assert_eq!(pool.num_free_upper(), 3);

    let lower = pool.alloc(128).unwrap();
    let upper = pool.alloc(4096).unwrap();
    assert_eq!(pool.num_free_lower(), 1);
    assert_eq!(pool.num_free_upper(), 2);

    pool.dealloc(lower.addr).unwrap();
    pool.dealloc(upper.addr).unwrap();
    assert_eq!(pool.num_free_lower(), 2);
    assert_eq!(pool.num_free_upper(), 3);
}

#[test]
fn test_tiered_slot_pool_region_uses_both_tiers() {
    let pool = make_tiered_slot_pool(1, 2);
    let regions = alloc_exact_regions(&pool, [4096 + 128]).unwrap();
    let allocations = &regions[0];

    assert_eq!(regions.len(), 1);
    assert_eq!(allocations.len(), 2);
    assert_eq!(allocations[0].len, 4096);
    assert_eq!(allocations[1].len, 256);
    assert!((0x90000..0x92000).contains(&allocations[0].addr));
    assert!((0x80000..0x80100).contains(&allocations[1].addr));

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
    assert_eq!(pool.num_free(), 3);
}

#[test]
fn test_tiered_slot_pool_allocates_regions_in_order() {
    let pool = make_tiered_slot_pool(1, 2);
    let regions = alloc_exact_regions(&pool, [128, 128]).unwrap();

    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].len(), 1);
    assert_eq!(regions[1].len(), 1);
    assert!((0x80000..0x80100).contains(&regions[0][0].addr));
    assert!((0x90000..0x92000).contains(&regions[1][0].addr));

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
}

#[test]
fn test_slot_pool_max_alloc_reserves_regions_and_honors_limit() {
    let pool = make_tiered_slot_pool(2, 3);

    let max = pool.max_alloc([128], 3).unwrap();
    assert_eq!(max, 2 * 4096);
    assert_eq!(pool.num_free(), 5);

    let regions = pool.alloc_regions([128, max]).unwrap();
    assert_eq!(regions.iter().map(Allocations::len).sum::<usize>(), 3);

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
}

#[test]
fn test_slot_pool_max_alloc_requires_one_remaining_allocation() {
    let pool = make_tiered_slot_pool(1, 1);

    assert!(matches!(pool.max_alloc([128], 1), Err(AllocError::NoSpace)));
    assert_eq!(pool.num_free(), 2);
}

#[test]
fn test_slot_pool_max_alloc_ignores_remaining_lower_slot() {
    let pool = make_tiered_slot_pool(1, 1);

    assert!(matches!(
        pool.max_alloc([4096], 2),
        Err(AllocError::NoSpace)
    ));
    assert_eq!(pool.num_free(), 2);
}

#[test]
fn test_slot_pool_rejects_invalid_or_unavailable_regions() {
    let pool = make_tiered_slot_pool(1, 1);

    assert!(matches!(
        pool.alloc_regions([0]),
        Err(AllocError::InvalidArg)
    ));
    assert!(matches!(
        pool.alloc_regions([]),
        Err(AllocError::InvalidArg)
    ));
    assert!(matches!(
        pool.alloc_regions([128, 0]),
        Err(AllocError::InvalidArg)
    ));
    assert!(matches!(
        pool.alloc_regions([4096 + 257]),
        Err(AllocError::NoSpace)
    ));
    assert!(matches!(
        pool.alloc_regions([128, 4096, 1]),
        Err(AllocError::NoSpace)
    ));
    assert_eq!(pool.num_free(), 2);
}

#[test]
fn test_tiered_slot_pool_dealloc_routes_by_region() {
    let pool = make_tiered_slot_pool(1, 1);
    let lower = pool.alloc(128).unwrap();
    let upper = pool.alloc(1024).unwrap();

    pool.dealloc(lower.addr).unwrap();
    pool.dealloc(upper.addr).unwrap();
    assert_eq!(pool.num_free(), 2);
    assert!(matches!(
        pool.dealloc(lower.addr),
        Err(AllocError::InvalidFree(_, _))
    ));
    assert!(matches!(
        pool.dealloc(0x88000),
        Err(AllocError::InvalidFree(_, _))
    ));
}

// Edge case: allocation exactly at boundary
#[test]
fn test_run_pool_boundary_allocation() {
    let pool = make_run_pool::<256, 4096>(1024 * 1024);

    // Allocate exactly at boundary
    let alloc = pool.alloc(256).unwrap();
    assert!(pool.inner.borrow().lower.contains(alloc.addr));

    // Allocate just over boundary
    let alloc2 = pool.alloc(257).unwrap();
    assert!(pool.inner.borrow().upper.contains(alloc2.addr));
}

#[test]
fn test_run_pool_dealloc_addr_routes_to_correct_tier() {
    let pool = make_run_pool::<256, 4096>(0x20000);
    let lower = pool.alloc(128).unwrap();
    let upper = pool.alloc(1024).unwrap();

    assert_eq!(pool.allocation_len(lower.addr).unwrap(), 256);
    assert_eq!(pool.allocation_len(upper.addr).unwrap(), 4096);

    pool.dealloc_addr(lower.addr).unwrap();
    pool.dealloc_addr(upper.addr).unwrap();
}

#[test]
fn test_run_pool_region_uses_one_contiguous_run() {
    let pool = make_run_pool::<256, 4096>(0x20000);
    let regions = alloc_exact_regions(&pool, [4096 * 2 + 1]).unwrap();

    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].len(), 1);
    assert_eq!(regions[0][0].len, 4096 * 3);

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
}

#[test]
fn test_run_pool_allocates_each_region_as_one_run() {
    let pool = make_run_pool::<256, 4096>(0x20000);
    let regions = alloc_exact_regions(&pool, [8192, 128]).unwrap();

    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].len(), 1);
    assert_eq!(regions[1].len(), 1);
    assert_eq!(regions[0][0].len, 8192);
    assert_eq!(regions[1][0].len, 256);

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
}

#[test]
fn test_slot_pool_region_splits() {
    let pool = make_slot_pool(8, 4096);
    let regions = alloc_exact_regions(&pool, [4096 * 2 + 1]).unwrap();
    let allocations = &regions[0];

    assert_eq!(regions.len(), 1);
    assert_eq!(allocations.len(), 3);
    assert_eq!(allocations[0].len, 4096);
    assert_eq!(allocations[1].len, 4096);
    assert_eq!(allocations[2].len, 4096);

    for allocation in regions.into_iter().flatten() {
        pool.dealloc(allocation.addr).unwrap();
    }
}

#[test]
fn test_tiered_slot_pool_live_addrs_are_deterministic() {
    let pool = make_tiered_slot_pool(2, 2);
    assert_eq!(pool.num_live(), 0);

    let lower_high = pool.alloc(128).unwrap();
    let upper_high = pool.alloc(1024).unwrap();
    let lower_low = pool.alloc(128).unwrap();

    assert_eq!(pool.num_live(), 3);
    assert_eq!(
        pool.live_addrs(),
        vec![lower_low.addr, lower_high.addr, upper_high.addr]
    );
}

#[test]
fn test_slot_pool_dealloc_out_of_range() {
    let pool = make_slot_pool(4, 4096);
    let _ = pool.alloc(4096).unwrap();

    assert!(matches!(
        pool.dealloc(0xDEAD),
        Err(AllocError::InvalidFree(0xDEAD, 0))
    ));
}

#[test]
fn test_slot_pool_dealloc_misaligned() {
    let pool = make_slot_pool(4, 4096);
    let _ = pool.alloc(4096).unwrap();

    assert!(matches!(
        pool.dealloc(0x80001),
        Err(AllocError::InvalidFree(0x80001, 0))
    ));
}

#[test]
fn test_slot_pool_dealloc_double_free() {
    let pool = make_slot_pool(4, 4096);
    let a = pool.alloc(4096).unwrap();
    pool.dealloc(a.addr).unwrap();

    // Second dealloc should fail - address is already in the free list
    assert!(matches!(
        pool.dealloc(a.addr),
        Err(AllocError::InvalidFree(_, _))
    ));
}

#[test]
fn test_slot_pool_alloc_regions_preflights_sequence() {
    let pool = make_slot_pool(2, 4096);

    assert!(matches!(
        pool.alloc_regions([]),
        Err(AllocError::InvalidArg)
    ));
    assert!(matches!(
        pool.alloc_regions([4096, 0]),
        Err(AllocError::InvalidArg)
    ));
    assert!(matches!(
        pool.alloc_regions([4096, 4096, 1]),
        Err(AllocError::NoSpace)
    ));
    assert_eq!(pool.num_free(), 2);

    let alloc = pool.alloc(4096).unwrap();
    assert_eq!(pool.num_free(), 1);
    pool.dealloc(alloc.addr).unwrap();
}

#[test]
fn test_slot_pool_dealloc_addr_and_allocation_len() {
    let pool = make_slot_pool(4, 4096);
    let alloc = pool.alloc(4096).unwrap();

    assert_eq!(pool.allocation_len(alloc.addr).unwrap(), 4096);
    pool.dealloc_addr(alloc.addr).unwrap();
    assert!(matches!(
        pool.allocation_len(alloc.addr),
        Err(AllocError::InvalidFree(_, 0))
    ));
}

#[test]
fn test_slot_pool_random_order_dealloc() {
    let pool = make_slot_pool(8, 4096);

    let mut allocs: Vec<Allocation> = (0..8).map(|_| pool.alloc(4096).unwrap()).collect();
    assert_eq!(pool.num_free(), 0);

    // Dealloc in reverse order
    allocs.reverse();
    for a in &allocs {
        pool.dealloc(a.addr).unwrap();
    }
    assert_eq!(pool.num_free(), 8);

    // All slots should be re-allocatable
    let reallocs: Vec<Allocation> = (0..8).map(|_| pool.alloc(4096).unwrap()).collect();
    assert_eq!(pool.num_free(), 0);

    // Verify all addresses are distinct
    let mut addrs: Vec<u64> = reallocs.iter().map(|a| a.addr).collect();
    addrs.sort();
    addrs.dedup();
    assert_eq!(addrs.len(), 8);
}

#[test]
fn test_slot_pool_interleaved_alloc_dealloc_order() {
    let pool = make_slot_pool(4, 4096);

    let a0 = pool.alloc(4096).unwrap();
    let a1 = pool.alloc(4096).unwrap();
    let a2 = pool.alloc(4096).unwrap();
    let a3 = pool.alloc(4096).unwrap();
    assert_eq!(pool.num_free(), 0);

    // Free middle slots first (out of allocation order)
    pool.dealloc(a2.addr).unwrap();
    pool.dealloc(a0.addr).unwrap();
    assert_eq!(pool.num_free(), 2);

    // Re-alloc gets the out-of-order slots back (LIFO)
    let b0 = pool.alloc(4096).unwrap();
    assert_eq!(b0.addr, a0.addr);
    let b1 = pool.alloc(4096).unwrap();
    assert_eq!(b1.addr, a2.addr);

    // Free everything in yet another order
    pool.dealloc(a1.addr).unwrap();
    pool.dealloc(b0.addr).unwrap();
    pool.dealloc(b1.addr).unwrap();
    pool.dealloc(a3.addr).unwrap();
    assert_eq!(pool.num_free(), 4);

    // All 4 original addresses should be available
    let mut final_addrs: Vec<u64> = (0..4).map(|_| pool.alloc(4096).unwrap().addr).collect();
    final_addrs.sort();
    let expected: Vec<u64> = (0..4).map(|i| 0x80000 + i * 4096).collect();
    assert_eq!(final_addrs, expected);
}

#[test]
fn test_slot_pool_dealloc_order_independent_of_alloc_order() {
    let pool = make_slot_pool(6, 256);

    // Allocate all
    let allocs: Vec<Allocation> = (0..6).map(|_| pool.alloc(256).unwrap()).collect();

    // Dealloc in scattered order: 4, 1, 5, 0, 3, 2
    let order = [4, 1, 5, 0, 3, 2];
    for &i in &order {
        pool.dealloc(allocs[i].addr).unwrap();
    }
    assert_eq!(pool.num_free(), 6);

    // Re-allocate all and verify we get back the full set
    let mut realloc_addrs: Vec<u64> = (0..6).map(|_| pool.alloc(256).unwrap().addr).collect();
    realloc_addrs.sort();

    let mut orig_addrs: Vec<u64> = allocs.iter().map(|a| a.addr).collect();
    orig_addrs.sort();

    assert_eq!(realloc_addrs, orig_addrs);
}
