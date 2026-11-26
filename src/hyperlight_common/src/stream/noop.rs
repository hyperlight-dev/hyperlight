// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use core::num::NonZeroU32;
use core::task::{Context, Poll};

pub use NoopMux as Mux;
use bytes::Bytes;
use smallvec::SmallVec;

use super::{ProtocolError, Record, Side, StatusFlags, StreamReader, Transfer, Transfers};
use crate::flatbuffer_wrappers::ExternalValueSource;

/// A call-only mux. It has no stream state and rejects transfers in either direction.
pub struct NoopMux;

impl NoopMux {
    /// Both sides use the same stateless mux.
    pub fn new(_: Side, _: NonZeroU32) -> Self {
        Self
    }

    /// A call-only peer never holds a stream open across a snapshot.
    pub fn has_live_streams(&self) -> bool {
        false
    }

    /// A call-only peer has no activity to report.
    pub fn status(&self) -> StatusFlags {
        StatusFlags::empty()
    }

    /// A call-only peer has no streams to end.
    pub fn fail(&mut self) {}

    /// A call-only peer never has pending stream records.
    pub fn poll_pending(&self, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }

    /// Reject the message without reading its external data.
    pub fn recv_records(
        &mut self,
        _: &[u8],
        _: &mut impl ExternalValueSource,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::Disabled)
    }

    pub(crate) fn recv_transfer(&mut self, _: Transfer) -> Result<StreamReader<u8>, ProtocolError> {
        Err(ProtocolError::Disabled)
    }

    /// Ordinary messages have no readers to transfer.
    pub(crate) fn prepare_transfers<'r>(
        &mut self,
        readers: impl IntoIterator<Item = &'r StreamReader<u8>>,
    ) -> Result<Transfers, ProtocolError> {
        if readers.into_iter().next().is_some() {
            return Err(ProtocolError::Disabled);
        }

        Ok(Transfers::new())
    }

    pub(crate) fn commit_transfers(
        &mut self,
        _: impl IntoIterator<Item = (StreamReader<u8>, Transfer)>,
    ) {
    }

    pub(crate) fn prepare_records(
        &self,
        _: usize,
        _: &mut SmallVec<[Record; 8]>,
        _: &mut SmallVec<[Bytes; 4]>,
    ) {
    }

    pub(crate) fn pending_status(&self, _: StatusFlags) -> Option<Record> {
        None
    }

    pub(crate) fn commit_records(&mut self, _: SmallVec<[Record; 8]>) {}
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::flatbuffer_wrappers::function_call::{FunctionCall, FunctionCallType};
    use crate::flatbuffer_wrappers::function_types::{FunctionCallResult, ReturnValue};
    use crate::func::{ParameterTuple, ReturnType};
    use crate::future;
    use crate::stream::{self, DEFAULT_WINDOW};
    use crate::transport::PendingMessage;
    use crate::virtq::Segments;

    #[test]
    fn rejects_a_reader_result() {
        let mut mux = NoopMux::new(Side::Host, DEFAULT_WINDOW);
        // Ok(StreamReader), host stream 1 at position 0.
        let err = FunctionCallResult::decode(&[0, 10, 2, 0], &mut Segments::default(), &mut mux)
            .err()
            .unwrap();
        assert_eq!(err.downcast_ref(), Some(&ProtocolError::Disabled));
    }

    #[test]
    fn rejects_sending_a_local_reader() {
        let mut mux = Mux::new(Side::Guest, DEFAULT_WINDOW);
        let (reader, _writer) = stream::new();
        let result = FunctionCallResult::new(Ok(ReturnValue::StreamReader(reader)));
        let err = PendingMessage::new_result(result, 1, &mut mux)
            .err()
            .unwrap();
        assert_eq!(err.downcast_ref(), Some(&ProtocolError::Disabled));
    }

    #[test]
    fn rejects_a_future_argument() {
        let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);
        let (reader, _writer) = future::new::<()>();
        let call = FunctionCall::new(
            "read".into(),
            Some(reader.into_value()),
            FunctionCallType::Guest,
            ReturnType::Void,
        );

        let err = PendingMessage::new_call(call, 1, &mut mux).err().unwrap();
        assert_eq!(err.downcast_ref(), Some(&ProtocolError::Disabled));
    }

    #[test]
    fn rejects_peer_status() {
        let mut mux = NoopMux::new(Side::Host, DEFAULT_WINDOW);
        // STATUS(ACTIVE) is valid for a host that supports streams.
        assert_eq!(
            mux.recv_records(&[4, 2], &mut Segments::default()),
            Err(ProtocolError::Disabled)
        );
    }

    #[test]
    fn does_not_publish_guest_activity() {
        let mut mux = NoopMux::new(Side::Guest, DEFAULT_WINDOW);
        assert!(PendingMessage::new_status(&mut mux, StatusFlags::ACTIVE).is_none());
        assert!(PendingMessage::next_stream(&mut mux, 4096).is_none());
    }
}
