// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Byte streams shared by the host and the guest.
//!
//! `new` creates a reader and writer sharing a bounded pipe. The `streams` feature lets the
//! reader cross the sandbox boundary.

#![cfg_attr(not(feature = "streams"), expect(dead_code, reason = "stream gating"))]

mod endpoint;
mod error;
mod id;
mod pipe;
mod producer;
mod record;
mod sync;

#[cfg_attr(not(feature = "streams"), path = "noop.rs")]
mod mux;

use core::num::NonZeroU32;

pub use endpoint::{StreamReader, StreamWriter, new};
pub use error::{ProtocolError, StreamError};
pub use id::StreamId;
pub use mux::Mux;
pub use producer::producer;
pub use record::{BatchEncoder, Record, StatusFlags};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

// Each session sets its window size. The other limits are fixed.

/// Streams per side with a reader on the peer.
pub const MAX_STREAMS: usize = 16;
/// Readers per function call or result.
pub const MAX_TRANSFERS: usize = 16;
/// Default window size, the most unconsumed bytes per stream.
pub const DEFAULT_WINDOW: NonZeroU32 = NonZeroU32::new(16384).unwrap();
/// Bytes copied by one copy write.
pub const MAX_COPY_WRITE: usize = 65536;
/// Largest DATA record the guest copies out of an H2G slot.
pub const GOOD_COPY_LEN: usize = 128;

/// Transfer metadata prepared for one message.
pub(crate) type Transfers = SmallVec<[Transfer; 4]>;

/// A reader's wire identity and consumed position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Transfer {
    /// The sid of the trip.
    pub(crate) sid: StreamId,
    /// Bytes the reader consumed on the trip it ends. A reader leaving its origin carries 0.
    pub(crate) position: u64,
}

/// One side of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The host process.
    Host,
    /// The guest running in the VM.
    Guest,
}

impl Side {
    /// The other side.
    pub const fn peer(self) -> Self {
        match self {
            Self::Host => Self::Guest,
            Self::Guest => Self::Host,
        }
    }
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for u8 {}
}

/// Item types that streams carry. Only `u8` implements it.
pub trait StreamItem: sealed::Sealed + Send + Sync + 'static {}

impl StreamItem for u8 {}
