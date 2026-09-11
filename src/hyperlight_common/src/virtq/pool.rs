// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.
//! Fixed-slot allocation for virtqueue payloads.

use thiserror::Error;

mod slot;

pub use slot::{SlotLayout, SlotPool};

/// Buffer allocation failure.
#[derive(Debug, Error, Copy, Clone)]
pub enum AllocError {
    /// An address does not identify a live allocation.
    #[error("Invalid free addr {0} and size {1}")]
    InvalidFree(u64, usize),
    /// An argument is zero or otherwise invalid.
    #[error("Invalid argument")]
    InvalidArg,
    /// A region cannot hold any allocation.
    #[error("Empty region")]
    EmptyRegion,
    /// No currently free allocation can satisfy the request.
    #[error("No space available")]
    NoSpace,
    /// The request exceeds the pool's allocation capacity.
    #[error("Requested size exceeds pool capacity")]
    OutOfMemory,
    /// Allocation bookkeeping could not be reserved.
    #[error("Failed to allocate buffer bookkeeping")]
    Bookkeeping,
    /// Address or size arithmetic overflowed.
    #[error("Overflow")]
    Overflow,
}

/// One pool allocation.
#[derive(Debug, Clone, Copy)]
pub struct Allocation {
    /// Starting address of the allocation.
    pub addr: u64,
    /// Nonzero descriptor-safe capacity in bytes.
    pub len: u32,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fuzz;
