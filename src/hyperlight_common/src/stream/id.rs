// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Stream identifiers.

use core::fmt;

use serde::de::{Error as _, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Side;

/// A stream identifier within one session.
///
/// Bit 0 holds the initiator, the side that allocated the ID,
/// The upper 63 bits hold a nonzero index.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// Create an ID from its initiator and a nonzero index below `2^63`.
    pub const fn new(initiator: Side, index: u64) -> Option<Self> {
        if index > u64::MAX >> 1 {
            return None;
        }

        let bit = match initiator {
            Side::Host => 0,
            Side::Guest => 1,
        };

        Self::from_raw(index << 1 | bit)
    }

    /// Decode a wire value. Returns `None` when its index is zero.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw >> 1 == 0 {
            return None;
        }

        Some(Self(raw))
    }

    /// The wire representation.
    pub const fn as_raw(self) -> u64 {
        self.0
    }

    /// The side that allocated the ID.
    pub const fn initiator(self) -> Side {
        if self.0 & 1 == 0 {
            Side::Host
        } else {
            Side::Guest
        }
    }

    /// The index among the initiator's IDs.
    pub const fn index(self) -> u64 {
        self.0 >> 1
    }
}

impl fmt::LowerHex for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Serialize for StreamId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for StreamId {
    /// Rejects a zero index.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u64::deserialize(deserializer)?;

        Self::from_raw(raw).ok_or_else(|| {
            D::Error::invalid_value(Unexpected::Unsigned(raw), &"a nonzero stream index")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_is_bit_zero() {
        assert_eq!(StreamId::new(Side::Host, 1).map(StreamId::as_raw), Some(2));
        assert_eq!(StreamId::new(Side::Guest, 1).map(StreamId::as_raw), Some(3));

        for (side, index) in [(Side::Host, 5), (Side::Guest, u64::MAX >> 1)] {
            let id = StreamId::new(side, index).unwrap();

            assert_eq!(id.initiator(), side);
            assert_eq!(id.index(), index);
            assert_eq!(StreamId::from_raw(id.as_raw()), Some(id));
        }
    }

    #[test]
    fn rejects_zero_and_oversized_indexes() {
        for side in [Side::Host, Side::Guest] {
            assert_eq!(StreamId::new(side, 0), None);
            assert_eq!(StreamId::new(side, 1 << 63), None);
        }

        assert_eq!(StreamId::from_raw(0), None);
        assert_eq!(StreamId::from_raw(1), None);
    }
}
