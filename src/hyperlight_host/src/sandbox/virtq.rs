use std::sync::{Arc, Mutex};
use std::collections::BTreeMap;

use hyperlight_common::{flatbuffer_wrappers::{function_call::FunctionCallType, function_types::FunctionCallResult, guest_error::{ErrorCode, GuestError}}, transport::MsgKind, virtq::{MemOps, PolledChain, ReplyChain, VirtqConsumer}};

use crate::{mem::{mgr::{ExecutionMode, SandboxMemoryManager}, shared_mem::HostSharedMemory, virtq::{self, G2hConsumer, RecvMessage, mem::HostMemOps}}, sandbox::host_funcs::FunctionRegistry};
use super::initialized::PendingGuestCall;
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;

/// Errors that can occur when handling a requested operation from the guest.
#[derive(Debug, thiserror::Error)]
pub enum GuestRequestError {
    #[error("Failed to read host function call: {0}")]
    ReadHostFunctionCall(String),
    #[error("Guest called a host function during a snapshot checkpoint")]
    HostCallDuringCheckpoint,
    #[error("Failed to acquire lock at {0}:{1} - {2}")]
    LockFailed(&'static str, u32, String),
    #[error("Failed to write host function response: {0}")]
    WriteHostFunctionResponse(String),
    #[error("Could not send completion to queue: {0}")]
    Complete(String),
    #[error("Failed to read guest function call result: {0}")]
    ReadGuestFunctionCallResult(String),
}

pub(crate) fn dispatch_guest_requests(
    mem_mgr: &mut SandboxMemoryManager<HostSharedMemory>,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
    pending_guest_calls: &mut BTreeMap<u32, PendingGuestCall>,
    waiting_for_sync_cid: Option<u32>,
) -> Result<(bool, Option<FunctionCallResult>), GuestRequestError> {
    let max_recv_len = mem_mgr.layout.get_g2h_queue_dims().pool_len();

    let Some(consumer) = mem_mgr.g2h_consumer.as_mut() else {
        return Err(GuestRequestError::ReadHostFunctionCall(
            "G2H consumer is not attached".into(),
        ));
    };

    let mut has_done_work = false;

    loop {
        let maybe_next = consumer.poll(max_recv_len).map_err(|error| {
            GuestRequestError::ReadHostFunctionCall(format!("G2H poll failed: {error}"))
        })?;

        match maybe_next {
            Some(chains) => match dispatch_guest_request(mem_mgr.execution_mode, host_funcs, consumer, pending_guest_calls, waiting_for_sync_cid, chains)? {
                // Return early if we got a sync call result
                fcr@Some(_) => return Ok((true, fcr)),
                _ => {},
            },
            None => return Ok((has_done_work, None))
        };

        has_done_work = true;
    };
}

fn dispatch_guest_request(
    mode: ExecutionMode,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
    consumer: &mut G2hConsumer,
    pending_guest_calls: &mut BTreeMap<u32, PendingGuestCall>,
    waiting_for_sync_cid: Option<u32>,
    (request, reply): PolledChain<HostMemOps>,
) -> Result<Option<FunctionCallResult>, GuestRequestError> {
    let mut message = RecvMessage::new(request)
        .map_err(|error| GuestRequestError::ReadHostFunctionCall(error.to_string()))?;

    let mut sync_result = None;

    let resp = match message.kind() {
        MsgKind::Request => handle_request(mode, host_funcs, &mut message, reply)?,
        MsgKind::Log => handle_guest_log(&mut message, reply)?,
        MsgKind::Response if let Some(cid) = waiting_for_sync_cid && message.cid() == cid => {
            let result = message
                .decode_result()
                .map_err(|error| GuestRequestError::ReadGuestFunctionCallResult(error.to_string()))?;
            sync_result = Some(result);
            reply
        },
        MsgKind::Response => {
            let result = message
                .decode_result()
                .map_err(|error| GuestRequestError::ReadGuestFunctionCallResult(error.to_string()))?;
            let pending_entry = pending_guest_calls.get_mut(&message.cid())
                .ok_or_else(|| GuestRequestError::ReadHostFunctionCall("cid entry missing".to_string()))?;
            match core::mem::replace(pending_entry, PendingGuestCall::Completed(Ok(result))) {
                PendingGuestCall::Unpolled => {},
                PendingGuestCall::Polled(waker) => waker.wake(),
                PendingGuestCall::Completed(_) => return Err(GuestRequestError::ReadGuestFunctionCallResult("Guest returned two results for the same function call".to_string())),
            };
            reply
        }

        kind => {
            return Err(GuestRequestError::ReadHostFunctionCall(format!(
                "Expected G2H request, got {kind:?}"
            )));
        }
    };

    consumer
        .complete(message.into_chain(), resp)
        .map_err(|err| GuestRequestError::Complete(err.to_string()))?;

    Ok(sync_result)
}

fn handle_request(
    mode: ExecutionMode,
    host_funcs: &Arc<Mutex<FunctionRegistry>>,
    message: &mut RecvMessage,
    reply: ReplyChain<HostMemOps>
) -> Result<ReplyChain<HostMemOps>, GuestRequestError> {
    if mode == ExecutionMode::Restricted{
        return Err(GuestRequestError::HostCallDuringCheckpoint);
    }

    if message.cid() == 0 {
        return Err(GuestRequestError::ReadHostFunctionCall(
            "G2H function call has a zero correlation ID".into(),
        ));
    }

    let mut resp = reply.into_writable().map_err(|_| {
        GuestRequestError::WriteHostFunctionResponse(
            "G2H request has no writable response buffers".into(),
        )
    })?;

    let cid = message.cid();
    let call = message
        .decode_call()
        .map_err(|error| GuestRequestError::ReadHostFunctionCall(error.to_string()))?;

    if call.function_call_type() != FunctionCallType::Host {
        return Err(GuestRequestError::ReadHostFunctionCall(
            "G2H request does not target a host function".into(),
        ));
    }

    let name = call.function_name;
    let args = call.parameters.unwrap_or_default();

    let result = host_funcs
        .try_lock()
        .map_err(|err| GuestRequestError::LockFailed(file!(), line!(), err.to_string()))?
        .call_host_function(&name, args)
        .map_err(|err| GuestError::new(ErrorCode::HostFunctionError, err.to_string()));

    let result = FunctionCallResult::new(result);
    let resp_capacity = resp.capacity();

    // Capacity is checked before writing, so an oversized result leaves the
    // chain untouched and can be replaced with a bounded transport error.
    if !virtq::try_write_response(&mut resp, cid, &result)
        .map_err(|err| GuestRequestError::WriteHostFunctionResponse(err.to_string()))?
    {
        let fallback = FunctionCallResult::new(Err(GuestError::new(
            ErrorCode::HostFunctionError,
            "Host response exceeds virtqueue capacity".into(),
        )));

        // The guest must receive a response for this correlation id. Failure
        // to fit even this small error makes the transport unusable.
        if !virtq::try_write_response(&mut resp, cid, &fallback)
            .map_err(|err| GuestRequestError::WriteHostFunctionResponse(err.to_string()))?
        {
            return Err(GuestRequestError::WriteHostFunctionResponse(format!(
                "Writable response capacity {resp_capacity} cannot hold a transport error"
            )));
        }
    }

    Ok(resp.into())
}

fn handle_guest_log(
    message: &mut RecvMessage,
    reply: ReplyChain<HostMemOps>
) -> Result<ReplyChain<HostMemOps>, GuestRequestError> {
    if message.cid() != 0 {
        return Err(GuestRequestError::ReadHostFunctionCall(
            "G2H log has a nonzero correlation ID".into(),
        ));
    }

    if !matches!(reply, ReplyChain::Ack(_)) {
        return Err(GuestRequestError::ReadHostFunctionCall(
            "G2H log has writable response buffers".into(),
        ));
    }

    let log = message
        .decode_log()
        .map_err(|error| GuestRequestError::ReadHostFunctionCall(error.to_string()))?;

    emit_guest_log(&log);

    Ok(reply)
}

pub(crate) fn emit_guest_log(log_data: &GuestLogData) {
    // Emit guest log data as a tracing event with structured fields.
    //
    // We match on the level at runtime because tracing macros determine their
    // level at compile time. Guest file/line/module are passed as structured
    // fields (rather than tracing metadata) because they originate from the
    // guest, not from this call site.
    //
    // Consumers using a `log` logger (without a tracing subscriber) still
    // receive these events thanks to the `tracing` crate's `log` feature,
    // which forwards tracing events to the `log` facade when no subscriber
    // is set.
    let source_file = log_data.source_file.as_str();
    let line = log_data.line;
    let source = log_data.source.as_str();
    let message = log_data.message.as_str();

    match &log_data.level {
        LogLevel::Error | LogLevel::Critical => {
            tracing::error!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Warning => {
            tracing::warn!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Information => {
            tracing::info!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Debug => {
            tracing::debug!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
        LogLevel::Trace | LogLevel::None => {
            tracing::trace!(
                target: "hyperlight_guest",
                guest_file = source_file,
                guest_line = line,
                guest_module = source,
                "{}",
                message
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::guest_log_level::LogLevel;
    use hyperlight_testing::logger::{LOGGER, Logger};
    use tracing_core::callsite::rebuild_interest_cache;
    use super::{GuestLogData, emit_guest_log};
    use crate::testing::log_values::test_value_as_str;

    fn new_guest_log_data(level: LogLevel) -> GuestLogData {
        GuestLogData::new(
            "test log".to_string(),
            "test source".to_string(),
            level,
            "test caller".to_string(),
            "test source file".to_string(),
            123,
        )
    }

    // Verifies that guest log events are forwarded to a `log` logger when no
    // tracing subscriber is set.
    #[test]
    #[ignore]
    fn test_log_emit_guest_log() {
        Logger::initialize_test_logger();
        LOGGER.set_max_level(log::LevelFilter::Off);

        emit_guest_log(&new_guest_log_data(LogLevel::Information));
        assert_eq!(0, LOGGER.num_log_calls());
        LOGGER.clear_log_calls();

        LOGGER.set_max_level(log::LevelFilter::Trace);
        let levels = vec![
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Information,
            LogLevel::Warning,
            LogLevel::Error,
            LogLevel::Critical,
            LogLevel::None,
        ];

        for level in levels {
            LOGGER.clear_log_calls();
            emit_guest_log(&new_guest_log_data(level));

            LOGGER.test_log_records(|log_calls| {
                let expected_level: tracing::Level = match level {
                    LogLevel::Trace => tracing::Level::TRACE,
                    LogLevel::Debug => tracing::Level::DEBUG,
                    LogLevel::Information => tracing::Level::INFO,
                    LogLevel::Warning => tracing::Level::WARN,
                    LogLevel::Error | LogLevel::Critical => tracing::Level::ERROR,
                    LogLevel::None => tracing::Level::TRACE,
                };

                assert_eq!(
                    log_calls
                        .iter()
                        .filter(|log_call| {
                            log_call.level.as_str() == expected_level.as_str()
                                && log_call.args.contains("test log")
                        })
                        .count(),
                    1,
                    "log call did not occur for level {level:?}"
                );
            });
        }
    }

    // Tests that guest logs emit traces when a trace subscriber is set
    // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
    // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
    // from their workstation to be successful without needed to know about test interdependencies
    // this test will be run explicitly as a part of the CI pipeline
    #[ignore]
    #[test]
    fn test_trace_emit_guest_log() {
        Logger::initialize_log_tracer();
        rebuild_interest_cache();
        let subscriber =
            hyperlight_testing::tracing_subscriber::TracingSubscriber::new(tracing::Level::TRACE);
        tracing::subscriber::with_default(subscriber.clone(), || {
            let levels = vec![
                LogLevel::Trace,
                LogLevel::Debug,
                LogLevel::Information,
                LogLevel::Warning,
                LogLevel::Error,
                LogLevel::Critical,
                LogLevel::None,
            ];
            for level in levels {
                let log_data: GuestLogData = new_guest_log_data(level);
                subscriber.clear();
                emit_guest_log(&log_data);

                subscriber.test_trace_records(|_, events| {
                    let expected_level = match level {
                        LogLevel::Trace => "TRACE",
                        LogLevel::Debug => "DEBUG",
                        LogLevel::Information => "INFO",
                        LogLevel::Warning => "WARN",
                        LogLevel::Error => "ERROR",
                        LogLevel::Critical => "ERROR",
                        LogLevel::None => "TRACE",
                    };

                    let mut count_matching_events = 0;

                    for json_value in events {
                        let event_values = json_value.as_object().unwrap().get("event").unwrap();
                        let metadata_values_map =
                            event_values.get("metadata").unwrap().as_object().unwrap();
                        let event_values_map = event_values.as_object().unwrap();
                        test_value_as_str(metadata_values_map, "level", expected_level);
                        test_value_as_str(event_values_map, "guest_file", "test source file");
                        test_value_as_str(event_values_map, "guest_module", "test source");
                        test_value_as_str(metadata_values_map, "target", "hyperlight_guest");
                        count_matching_events += 1;
                    }
                    assert!(
                        count_matching_events == 1,
                        "trace log call did not occur for level {:?}",
                        level.clone()
                    );
                });
            }
        });
    }
}
