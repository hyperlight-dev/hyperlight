// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::{BTreeMap, HashSet};

use quickcheck::{Arbitrary, Gen, QuickCheck};

use super::*;

const MAX_OPS: usize = 10;
const MAX_ALLOC_SIZE: usize = 8192;
const MAX_TIER_SLOTS: usize = 16;
const LOWER_BASE: u64 = 0x80000;
const UPPER_BASE: u64 = 0x90000;
const LOWER_SLOT_SIZE: usize = 256;
const UPPER_SLOT_SIZE: usize = 4096;

#[derive(Clone, Debug)]
enum Op {
    Alloc(usize),
    Dealloc(usize),
}

impl Arbitrary for Op {
    fn arbitrary(g: &mut Gen) -> Self {
        match u8::arbitrary(g) % 2 {
            0 => Op::Alloc(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
            1 => Op::Dealloc(usize::arbitrary(g)),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
struct SlotScenario {
    tiered: bool,
    lower_count: usize,
    upper_count: usize,
    ops: Vec<Op>,
}

impl Arbitrary for SlotScenario {
    fn arbitrary(g: &mut Gen) -> Self {
        let tiered = bool::arbitrary(g);
        let lower_count = usize::arbitrary(g) % MAX_TIER_SLOTS + 1;
        let upper_count = usize::arbitrary(g) % MAX_TIER_SLOTS + 1;
        let num_ops = usize::arbitrary(g) % MAX_OPS + 1;
        let ops = (0..num_ops).map(|_| Op::arbitrary(g)).collect();

        Self {
            tiered,
            lower_count,
            upper_count,
            ops,
        }
    }
}

fn make_slot_pool(scenario: &SlotScenario) -> SlotPool {
    if scenario.tiered {
        let lower = SlotLayout::new(LOWER_BASE, LOWER_SLOT_SIZE, scenario.lower_count);
        let upper = SlotLayout::new(UPPER_BASE, UPPER_SLOT_SIZE, scenario.upper_count);
        SlotPool::new_tiered(lower, upper).unwrap()
    } else {
        let layout = SlotLayout::new(UPPER_BASE, UPPER_SLOT_SIZE, scenario.upper_count);
        SlotPool::new(layout).unwrap()
    }
}

fn run_slot_pool_scenario(scenario: SlotScenario) -> bool {
    let pool = make_slot_pool(&scenario);
    let mut allocations: Vec<Allocation> = Vec::new();

    for op in &scenario.ops {
        match op {
            Op::Alloc(size) => match pool.alloc(*size) {
                Ok(allocation) => {
                    if (allocation.len as usize) < *size
                        || allocations
                            .iter()
                            .any(|existing| existing.addr == allocation.addr)
                    {
                        return false;
                    }
                    allocations.push(allocation);
                }
                Err(AllocError::NoSpace | AllocError::OutOfMemory) => {}
                Err(_) => return false,
            },
            Op::Dealloc(index) => {
                if !allocations.is_empty() {
                    let index = index % allocations.len();
                    if pool.dealloc(allocations[index].addr).is_err() {
                        return false;
                    }
                    allocations.swap_remove(index);
                }
            }
        }

        if check_slot_pool_invariants(&pool, &allocations).is_err() {
            return false;
        }
    }

    while let Some(alloc) = allocations.pop() {
        if pool.dealloc(alloc.addr).is_err() {
            return false;
        }
    }

    check_slot_pool_invariants(&pool, &allocations).is_ok()
}

fn layout_contains(layout: SlotLayout, addr: u64) -> bool {
    let Ok(end) = layout.end_addr() else {
        return false;
    };
    (layout.base_addr..end).contains(&addr)
}

fn slot_capacity(pool: &SlotPool, addr: u64) -> Option<usize> {
    let (lower, upper) = pool.layouts();
    if let Some(lower) = lower
        && layout_contains(lower, addr)
    {
        return Some(lower.slot_size);
    }
    layout_contains(upper, addr).then_some(upper.slot_size)
}

fn check_slot_pool_invariants(
    pool: &SlotPool,
    allocations: &[Allocation],
) -> Result<(), &'static str> {
    let mut expected_live = BTreeMap::new();
    for alloc in allocations {
        if expected_live.insert(alloc.addr, alloc.len).is_some() {
            return Err("duplicate allocation address in tracking");
        }
    }

    // Live addresses must match the order. Free plus live must cover every slot.
    let live = pool.live_addrs();
    let expected_addrs: Vec<u64> = expected_live.keys().copied().collect();
    if live != expected_addrs || live.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("live addresses are not unique and deterministic");
    }
    if pool.num_free() + live.len() != pool.count() {
        return Err("free + live != total slots");
    }

    // Free-slot enumeration must match the reported count and be strictly ordered.
    let mut free = Vec::new();
    pool.for_each_free(|allocation| free.push(allocation));

    if free.len() != pool.num_free() {
        return Err("free-slot visitation is inconsistent");
    }

    if free.windows(2).any(|pair| pair[0].addr >= pair[1].addr) {
        return Err("free-slot visitation is inconsistent");
    }

    // Free slots cannot also be live and must report their tier's full capacity.
    if free.iter().any(|allocation| {
        expected_live.contains_key(&allocation.addr)
            || slot_capacity(pool, allocation.addr) != Some(allocation.len as usize)
    }) {
        return Err("free-slot visitation is inconsistent");
    }

    // Reported geometry must agree with the stored tier layouts.
    let (lower, upper) = pool.layouts();
    let expected_base = lower.map_or(upper.base_addr, |layout| layout.base_addr);
    if pool.base_addr() != expected_base || pool.slot_size() != upper.slot_size {
        return Err("reported pool layout is inconsistent");
    }

    // Distinct tiers need increasing slot sizes and ordered, non-overlapping ranges.
    let mut expected_count = upper.slot_count;
    if let Some(lower) = lower {
        if lower.slot_size >= upper.slot_size
            || lower.end_addr().map_err(|_| "lower layout overflow")? > upper.base_addr
        {
            return Err("tier layout is invalid");
        }
        expected_count += lower.slot_count;
    }
    if pool.count() != expected_count || pool.slot_addr(pool.count()).is_some() {
        return Err("reported slot count is inconsistent");
    }

    // Indexed slots must be unique and inside a tier. Only live slots may report allocation lengths.
    let mut seen = HashSet::new();
    for index in 0..pool.count() {
        let Some(addr) = pool.slot_addr(index) else {
            return Err("missing slot address");
        };
        if !seen.insert(addr) {
            return Err("duplicate slot address");
        }
        let Some(capacity) = slot_capacity(pool, addr) else {
            return Err("slot address outside layout");
        };

        match expected_live.get(&addr) {
            Some(expected_capacity) => {
                if *expected_capacity as usize != capacity
                    || pool.allocation_len(addr).ok() != Some(capacity)
                {
                    return Err("live slot capacity is inconsistent");
                }
            }
            None if pool.allocation_len(addr).is_ok() => {
                return Err("free slot reported as live");
            }
            None => {}
        }
    }

    Ok(())
}

#[test]
fn prop_slot_pool_invariants() {
    #[cfg(miri)]
    let tests = 10;
    #[cfg(not(miri))]
    let tests = 1000;

    QuickCheck::new()
        .tests(tests)
        .quickcheck(run_slot_pool_scenario as fn(SlotScenario) -> bool);
}
