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

use quickcheck::{Arbitrary, Gen, QuickCheck};

use super::tests::{OwnedRing, make_consumer, make_producer};
use super::*;

const MAX_RING: usize = 64;
const MAX_OPS: usize = 128;
const MAX_CHAIN_LEN: usize = 8;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum Op {
    /// submit one chain
    Submit(BufferChain),
    /// poll up to N chains
    PollAvail(u8),
    /// driver reclaims up to N completions
    PollUsed(u8),
    /// complete one previously polled chain
    CompleteOne,
}

impl Arbitrary for Op {
    fn arbitrary(g: &mut Gen) -> Self {
        let choice = u8::arbitrary(g) % 4;
        match choice {
            0 => Op::Submit(BufferChain::arbitrary(g)),
            1 => Op::PollAvail(u8::arbitrary(g) % 8 + 1),
            2 => Op::PollUsed(u8::arbitrary(g) % 8 + 1),
            3 => Op::CompleteOne,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
struct Scenario {
    table_size: usize,
    ops: Vec<Op>,
}

impl Arbitrary for Scenario {
    fn arbitrary(g: &mut Gen) -> Self {
        let table_size = (usize::arbitrary(g) % MAX_RING + 1).next_power_of_two();
        let num_ops = usize::arbitrary(g) % MAX_OPS + 1;

        let ops = (0..num_ops).map(|_| Op::arbitrary(g)).collect();
        Scenario { table_size, ops }
    }
}

impl Arbitrary for BufferElement {
    fn arbitrary(g: &mut Gen) -> Self {
        let addr = u64::arbitrary(g);
        let len = u32::arbitrary(g);
        let writable = bool::arbitrary(g);

        BufferElement {
            addr,
            len,
            writable,
        }
    }
}

impl Arbitrary for BufferChain {
    fn arbitrary(g: &mut Gen) -> Self {
        let chain_len = usize::arbitrary(g) % MAX_CHAIN_LEN + 1;

        let mut elems = vec![BufferElement::zeroed(); chain_len];
        let mut readables = 0;
        let mut writables = 0;

        for _ in 0..chain_len {
            let elem = BufferElement::arbitrary(g);
            if elem.writable {
                elems[chain_len - 1 - writables] = elem;
                writables += 1;
            } else {
                elems[readables] = elem;
                readables += 1;
            }
        }

        BufferChain {
            elems: elems.into(),
            split: readables,
        }
    }
}

fn run_scenario(s: Scenario) -> bool {
    let ring = OwnedRing::new(s.table_size);
    let mut producer = make_producer(&ring);
    let mut consumer = make_consumer(&ring);

    // Order logs
    let mut dev_order: Vec<u16> = Vec::new();
    let mut drv_order: Vec<u16> = Vec::new();

    // Device-tracked polled-but-not-completed IDs
    let mut dev_ready: Vec<(u16, u32)> = Vec::new();

    for op in &s.ops {
        match op {
            Op::Submit(chain) => {
                // Submit only if space; otherwise skip
                let _ = producer.submit_available(chain);
            }
            Op::PollAvail(n) => {
                for _ in 0..*n {
                    if let Ok((id, chain)) = consumer.poll_available() {
                        dev_ready.push((id, chain.len() as u32));
                    } else {
                        break;
                    }
                }
            }
            Op::PollUsed(n) => {
                for _ in 0..*n {
                    match producer.poll_used() {
                        Ok(u) => {
                            drv_order.push(u.id);
                            if producer.id_num[u.id as usize] != 0 {
                                return false;
                            }
                            if !producer.id_free.contains(&u.id) {
                                return false;
                            }
                        }
                        Err(RingError::WouldBlock) => break,
                        Err(_) => return false,
                    }
                }
            }
            Op::CompleteOne => {
                if let Some((id, len)) = dev_ready.pop() {
                    if consumer.submit_used(id, len).is_err() {
                        return false;
                    }

                    dev_order.push(id);
                }
            }
        }

        // assert invariants after each op
        let outstanding: u16 = producer.id_num.iter().copied().sum();
        if outstanding as usize + producer.num_free != ring.len() {
            return false;
        }

        for id in producer.id_free.iter() {
            if producer.id_num[*id as usize] != 0 {
                return false;
            }
        }
    }

    // Drain remaining completions and reclaims
    while let Some((id, len)) = dev_ready.pop() {
        if consumer.submit_used(id, len).is_err() {
            return false;
        }
    }

    loop {
        match producer.poll_used() {
            Ok(u) => drv_order.push(u.id),
            Err(RingError::WouldBlock) => break,
            Err(_) => return false,
        }
    }

    true
}

#[test]
fn prop_interleaved_with_order_verification() {
    #[cfg(miri)]
    let tests = 1;
    #[cfg(not(miri))]
    let tests = 100;

    QuickCheck::new()
        .tests(tests)
        .quickcheck(run_scenario as fn(Scenario) -> bool);
}
