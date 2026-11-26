// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Stream records and their encoding.
//!
//! The control data of a Stream message is a sequence of postcard records. The
//! message header's `control_len` gives its length. DATA payloads follow the
//! control data as external values, in record order.

use alloc::vec::Vec;
use core::mem;

use bitflags::bitflags;
use postcard as wire;
use serde::de::{Error as _, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::error::ProtocolError;
use super::{Side, StreamId};

bitflags! {
    /// Guest activity reported by STATUS.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct StatusFlags: u8 {
        /// The guest has work for a progress turn.
        const READY = 1 << 0;
        /// The guest holds stream state, tasks, or callbacks.
        const ACTIVE = 1 << 1;
    }
}

/// A stream record.
///
/// Variant order sets the wire tags. Snapshotted guest code uses them.
/// DATA payloads are external values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Record {
    /// The reader of `sid` consumed `bytes` more bytes. Sent to the origin.
    Credit { sid: StreamId, bytes: u32 },
    /// The reader of `sid` closed. Sent to the origin.
    CloseReader { sid: StreamId },
    /// The next `len` payload bytes of `sid`. Sent to the reader's side.
    Data { sid: StreamId, len: u32 },
    /// The writer of `sid` closed, or aborted when `aborted` is set. No DATA
    /// follows. Sent to the reader's side.
    End { sid: StreamId, aborted: bool },
    /// Guest activity in `flags`. Sent to the host.
    Status { flags: StatusFlags },
}

impl Record {
    /// The encoded size in bytes.
    // Measuring a record does not fail.
    #[allow(clippy::expect_used)]
    pub(crate) fn encoded_len(&self) -> usize {
        wire::serialize_with_flavor(self, wire::ser_flavors::Size::default())
            .expect("stream record sizing failed")
    }

    /// Check the fields that decoding accepts unchecked.
    ///
    /// CREDIT and DATA carry 1 to `window` bytes. Only the host receives
    /// STATUS. Checks that need stream state run when the record is applied.
    fn is_valid(&self, recv: Side, window: usize) -> bool {
        match *self {
            Self::Credit { bytes, .. } => (1..=window).contains(&(bytes as usize)),
            Self::Data { len, .. } => (1..=window).contains(&(len as usize)),
            Self::Status { .. } => recv == Side::Host,
            Self::CloseReader { .. } | Self::End { .. } => true,
        }
    }
}

/// Encodes the control data of one Stream message into a caller's buffer.
#[derive(Debug)]
pub struct BatchEncoder<'a> {
    cntl: &'a mut Vec<u8>,
}

impl<'a> BatchEncoder<'a> {
    /// Create an encoder with no records. It clears `cntl` and keeps its capacity.
    pub(crate) fn new(cntl: &'a mut Vec<u8>) -> Self {
        cntl.clear();
        Self { cntl }
    }

    /// Append a record.
    pub(crate) fn push(&mut self, rec: Record) {
        let cntl = mem::take(self.cntl);

        // Encoding into a growable vector does not fail.
        #[allow(clippy::expect_used)]
        let cntl = wire::to_extend(&rec, cntl).expect("stream record encoding failed");
        *self.cntl = cntl;
    }

    /// Return the control data, or `None` when the batch has no records.
    pub(crate) fn finish(self) -> Option<&'a [u8]> {
        let cntl: &'a [u8] = self.cntl;
        (!cntl.is_empty()).then_some(cntl)
    }
}

/// Decodes the control data of one Stream message.
///
/// The control data comes from the peer, so decoding treats it as untrusted:
///
/// - Decoding always ends. Each record takes at least two bytes, so `n` bytes
///   hold at most `n / 2` records. Postcard reads at most 5 bytes for a `u32`
///   varint and 10 for a `u64`. Iteration stops after the first error.
/// - Records are flat `Copy` values, so decoding allocates nothing and its
///   stack depth is fixed.
/// - Decoding rejects truncated records, unknown tags, sids with a zero index,
///   CREDIT and DATA lengths outside 1 to `window`, END flags that are not
///   booleans, unknown STATUS bits, and STATUS sent to the guest.
pub(crate) struct BatchDecoder<'a> {
    rest: &'a [u8],
    recv: Side,
    window: usize,
}

impl<'a> BatchDecoder<'a> {
    /// Decode `cntl` for the `recv` side, whose streams have a `window` byte
    /// window.
    pub(crate) fn new(cntl: &'a [u8], recv: Side, window: usize) -> Result<Self, ProtocolError> {
        if cntl.is_empty() {
            return Err(ProtocolError::EmptyBatch);
        }

        Ok(Self {
            rest: cntl,
            recv,
            window,
        })
    }

    /// Decode the next record and check its fields.
    ///
    /// Undecodable input is a serde error. Fields that fail the checks are
    /// malformed.
    fn decode(&mut self) -> Result<Record, ProtocolError> {
        // Errors leave no input, which ends the batch.
        let bytes = mem::take(&mut self.rest);
        let (rec, rest): (Record, _) = wire::take_from_bytes(bytes)?;

        if !rec.is_valid(self.recv, self.window) {
            let b = bytes.first().copied().unwrap_or_default();
            return Err(ProtocolError::Malformed(b));
        }

        self.rest = rest;
        Ok(rec)
    }
}

impl Iterator for BatchDecoder<'_> {
    type Item = Result<Record, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        (!self.rest.is_empty()).then(|| self.decode())
    }
}

impl Serialize for StatusFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.bits())
    }
}

impl<'de> Deserialize<'de> for StatusFlags {
    /// Rejects unknown bits.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u8::deserialize(deserializer)?;

        Self::from_bits(bits).ok_or_else(|| {
            D::Error::invalid_value(Unexpected::Unsigned(bits.into()), &"known STATUS flags")
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::assert_matches;

    use super::*;
    use crate::stream::DEFAULT_WINDOW;

    const WINDOW: usize = DEFAULT_WINDOW.get() as usize;
    const SID: StreamId = StreamId::new(Side::Guest, 1).unwrap();
    const TRUNCATED: ProtocolError =
        ProtocolError::SerdeError(wire::Error::DeserializeUnexpectedEnd);
    const END: Record = Record::End {
        sid: SID,
        aborted: false,
    };

    fn encode(record: Record) -> Vec<u8> {
        let mut cntl = Vec::new();
        BatchEncoder::new(&mut cntl).push(record);
        cntl
    }

    /// Decode the first record of `cntl`.
    fn decode(cntl: &[u8], recv: Side) -> Result<Record, ProtocolError> {
        BatchDecoder::new(cntl, recv, WINDOW)?.decode()
    }

    #[test]
    fn records_round_trip() {
        let records: [Record; 6] = [
            Record::CloseReader { sid: SID },
            Record::Data { sid: SID, len: 300 },
            END,
            Record::End {
                sid: SID,
                aborted: true,
            },
            Record::Status {
                flags: StatusFlags::READY | StatusFlags::ACTIVE,
            },
            Record::Credit {
                sid: SID,
                bytes: 300,
            },
        ];

        // Changing these bytes changes the wire format and needs a snapshot ABI bump.
        let wire_reps: [&[u8]; 6] = [
            &[1, 3],
            &[2, 3, 0xac, 2],
            &[3, 3, 0],
            &[3, 3, 1],
            &[4, 3],
            &[0, 3, 0xac, 2],
        ];

        let mut buf = Vec::new();
        let mut batch = BatchEncoder::new(&mut buf);
        let mut wire = Vec::new();

        for (record, bytes) in records.into_iter().zip(wire_reps) {
            assert_eq!(encode(record), bytes, "{record:?}");
            assert_eq!(record.encoded_len(), bytes.len(), "{record:?}");

            batch.push(record);
            wire.extend_from_slice(bytes);
        }

        let control = batch.finish().unwrap();
        assert_eq!(control, wire);

        let decoded: Vec<_> = BatchDecoder::new(control, Side::Host, WINDOW)
            .unwrap()
            .collect();

        assert_eq!(decoded, records.map(Ok));
    }

    #[test]
    fn rejects_bad_framing() {
        let mut cntl = encode(END);
        cntl.push(0);

        let records: Vec<_> = BatchDecoder::new(&cntl, Side::Guest, WINDOW)
            .unwrap()
            .collect();

        assert_eq!(records, [Ok(END), Err(TRUNCATED)]);
        assert_eq!(
            BatchDecoder::new(&[], Side::Guest, WINDOW).err(),
            Some(ProtocolError::EmptyBatch)
        );
        // A new encoder starts empty in a reused buffer.
        assert_matches!(BatchEncoder::new(&mut cntl).finish(), None);
    }

    #[test]
    fn records_stop_after_an_error() {
        let mut buf = Vec::new();
        let mut batch = BatchEncoder::new(&mut buf);

        batch.push(END);
        batch.push(Record::Status {
            flags: StatusFlags::READY,
        });
        batch.push(END);

        let cntl = batch.finish().unwrap();
        let mut records = BatchDecoder::new(cntl, Side::Guest, WINDOW).unwrap();

        assert_eq!(records.next(), Some(Ok(END)));
        assert_eq!(records.next(), Some(Err(ProtocolError::Malformed(4))));
        assert_eq!(records.next(), None);
    }

    #[test]
    fn rejects_truncated_records() {
        let record = encode(Record::Data { sid: SID, len: 300 });

        for len in 1..record.len() {
            assert_eq!(decode(&record[..len], Side::Host), Err(TRUNCATED));
        }
    }

    #[test]
    fn rejects_invalid_fields() {
        use ProtocolError::{Malformed, SerdeError};
        use wire::Error::{DeserializeBadBool, DeserializeBadVarint, SerdeDeCustom};

        let cases: [&[u8]; 12] = [
            // Unknown tag.
            &[5],
            // Stream IDs with a zero index.
            &[0, 0, 1],
            &[0, 1, 1],
            &[1, 1],
            &[3, 0],
            // Zero lengths.
            &[0, 3, 0],
            &[2, 3, 0],
            // Lengths one above the window.
            &[0, 3, 0x81, 0x80, 1],
            &[2, 3, 0x81, 0x80, 1],
            // A length above u32::MAX.
            &[0, 3, 0xff, 0xff, 0xff, 0xff, 0x7f],
            // An END flag that is not a bool.
            &[3, 3, 2],
            // An unknown STATUS bit.
            &[4, 4],
        ];

        let errors = [
            SerdeError(SerdeDeCustom),
            SerdeError(SerdeDeCustom),
            SerdeError(SerdeDeCustom),
            SerdeError(SerdeDeCustom),
            SerdeError(SerdeDeCustom),
            Malformed(0),
            Malformed(2),
            Malformed(0),
            Malformed(2),
            SerdeError(DeserializeBadVarint),
            SerdeError(DeserializeBadBool),
            SerdeError(SerdeDeCustom),
        ];

        for (record, error) in cases.into_iter().zip(errors) {
            assert_eq!(decode(record, Side::Host), Err(error), "{record:?}");
        }
    }

    #[test]
    fn host_only_records_reject_guest_receivers() {
        let status = encode(Record::Status {
            flags: StatusFlags::READY,
        });

        assert!(decode(&status, Side::Host).is_ok());
        assert_eq!(
            decode(&status, Side::Guest),
            Err(ProtocolError::Malformed(4))
        );
    }
}
