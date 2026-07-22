// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use std::collections::{BTreeMap, HashSet};

use quickcheck::{Arbitrary, Gen, QuickCheck};

use super::run::Tier as RunTier;
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
    AllocSg(usize),
    Dealloc(usize),
}

impl Arbitrary for Op {
    fn arbitrary(g: &mut Gen) -> Self {
        match u8::arbitrary(g) % 3 {
            0 => Op::Alloc(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
            1 => Op::AllocSg(usize::arbitrary(g) % MAX_ALLOC_SIZE + 1),
            2 => Op::Dealloc(usize::arbitrary(g)),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
struct RunScenario {
    pool_size: usize,
    ops: Vec<Op>,
}

impl Arbitrary for RunScenario {
    fn arbitrary(g: &mut Gen) -> Self {
        let pool_size = (usize::arbitrary(g) % (4 * 1024 * 1024)) + (1024 * 1024);
        let num_ops = usize::arbitrary(g) % MAX_OPS + 1;
        let ops = (0..num_ops).map(|_| Op::arbitrary(g)).collect();

        RunScenario { pool_size, ops }
    }
}

fn run_provider_ops<P, F>(pool: &P, ops: &[Op], check: F) -> bool
where
    P: BufferProvider,
    F: Fn(&P, &[Allocation]) -> Result<(), &'static str>,
{
    let mut allocations: Vec<Allocation> = Vec::new();

    for op in ops {
        match op {
            Op::Alloc(size) => match pool.alloc(*size) {
                Ok(alloc) => {
                    if alloc.len < *size
                        || allocations
                            .iter()
                            .any(|existing| existing.addr == alloc.addr)
                    {
                        return false;
                    }
                    allocations.push(alloc);
                }
                Err(AllocError::NoSpace | AllocError::OutOfMemory) => {}
                Err(_) => return false,
            },
            Op::AllocSg(size) => match pool.alloc_sg(*size) {
                Ok(sgs) => {
                    let mut total = 0usize;
                    for sg in sgs {
                        let Some(next_total) = total.checked_add(sg.len) else {
                            return false;
                        };
                        if allocations.iter().any(|existing| existing.addr == sg.addr) {
                            return false;
                        }
                        total = next_total;
                        allocations.push(sg);
                    }
                    if total < *size {
                        return false;
                    }
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

        if check(pool, &allocations).is_err() {
            return false;
        }
    }

    while let Some(alloc) = allocations.pop() {
        if pool.dealloc(alloc.addr).is_err() {
            return false;
        }
    }

    check(pool, &allocations).is_ok()
}

fn run_pool_scenario(scenario: RunScenario) -> bool {
    let base = align_up(0x10000, 4096).unwrap() as u64;
    let pool = match RunPool::<256, 4096>::new(base, scenario.pool_size) {
        Ok(pool) => pool,
        Err(_) => return true,
    };

    run_provider_ops(&pool, &scenario.ops, check_run_pool_invariants)
}

fn check_run_tier_invariants<const N: usize>(
    tier: &RunTier<N>,
    allocations: &[Allocation],
) -> Result<(), &'static str> {
    let mut expected_used = HashSet::new();
    let mut expected_starts = HashSet::new();

    for alloc in allocations.iter().filter(|alloc| tier.contains(alloc.addr)) {
        let offset = usize::try_from(alloc.addr - tier.base_addr)
            .map_err(|_| "allocation offset overflows usize")?;
        if alloc.len == 0 || !offset.is_multiple_of(N) || !alloc.len.is_multiple_of(N) {
            return Err("allocation is not tier-aligned");
        }

        let start = offset / N;
        let slots = alloc.len / N;
        let end = start
            .checked_add(slots)
            .ok_or("allocation slot range overflow")?;
        if end > tier.used_slots.len() || !expected_starts.insert(start) {
            return Err("allocation run is invalid");
        }
        for slot in start..end {
            if !expected_used.insert(slot) {
                return Err("allocation runs overlap");
            }
        }
    }

    for slot in 0..tier.used_slots.len() {
        if tier.used_slots.contains(slot) != expected_used.contains(&slot) {
            return Err("used bitmap does not match live allocations");
        }
        if tier.run_starts.contains(slot) != expected_starts.contains(&slot) {
            return Err("run-start bitmap does not match live allocations");
        }
    }

    if tier.free_bytes() != (tier.used_slots.len() - expected_used.len()) * N {
        return Err("free_bytes does not match live allocations");
    }

    if let Some(free_run) = tier.last_free_run {
        if !tier.contains(free_run.addr) {
            return Err("cached free-run address outside tier");
        }
        let offset = usize::try_from(free_run.addr - tier.base_addr)
            .map_err(|_| "cached free-run offset overflows usize")?;
        if free_run.len == 0 || !offset.is_multiple_of(N) || !free_run.len.is_multiple_of(N) {
            return Err("cached free run is not tier-aligned");
        }

        let start = offset / N;
        let end = start
            .checked_add(free_run.len / N)
            .ok_or("cached free-run range overflow")?;
        if end > tier.used_slots.len() || (start..end).any(|slot| tier.used_slots.contains(slot)) {
            return Err("cached free run overlaps live allocations");
        }
    }

    Ok(())
}

fn check_run_pool_invariants<const L: usize, const U: usize>(
    pool: &RunPool<L, U>,
    allocations: &[Allocation],
) -> Result<(), &'static str> {
    let inner = pool.inner.borrow();
    if inner.lower.range().end > inner.upper.range().start {
        return Err("lower and upper ranges overlap");
    }

    let mut seen = HashSet::new();
    for alloc in allocations {
        let in_lower = inner.lower.contains(alloc.addr);
        let in_upper = inner.upper.contains(alloc.addr);
        if in_lower == in_upper {
            return Err("allocation does not belong to exactly one tier");
        }
        if !seen.insert(alloc.addr) {
            return Err("duplicate allocation address in tracking");
        }
    }

    check_run_tier_invariants(&inner.lower, allocations)?;
    check_run_tier_invariants(&inner.upper, allocations)
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
    run_provider_ops(&pool, &scenario.ops, check_slot_pool_invariants)
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

    let live = pool.live_addrs();
    let expected_addrs: Vec<u64> = expected_live.keys().copied().collect();
    if live != expected_addrs || live.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("live addresses are not unique and deterministic");
    }
    if pool.num_free() + live.len() != pool.count() {
        return Err("free + live != total slots");
    }

    let (lower, upper) = pool.layouts();
    let expected_base = lower.map_or(upper.base_addr, |layout| layout.base_addr);
    if pool.base_addr() != expected_base || pool.slot_size() != upper.slot_size {
        return Err("reported pool layout is inconsistent");
    }

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
                if *expected_capacity != capacity
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
fn prop_run_pool_invariants() {
    #[cfg(miri)]
    let tests = 10;
    #[cfg(not(miri))]
    let tests = 1000;

    QuickCheck::new()
        .tests(tests)
        .quickcheck(run_pool_scenario as fn(RunScenario) -> bool);
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
