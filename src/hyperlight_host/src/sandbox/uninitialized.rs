/*
Copyright 2024 The Hyperlight Authors.

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

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use log::LevelFilter;
use tracing::{instrument, Span};

#[cfg(gdb)]
use super::config::DebugInfo;
use super::uninitialized_evolve::evolve_impl_multi_use;
use crate::mem::mgr::SandboxMemoryManager;
use crate::mem::shared_mem::ExclusiveSharedMemory;
use crate::sandbox::config::SandboxConfiguration;
use crate::sandbox::host_funcs::HostFuncsWrapper;
use crate::sandbox_state::sandbox::{EvolvableSandbox, Sandbox};
use crate::sandbox_state::transition::Noop;
use crate::{MultiUseSandbox, Result};

/// A preliminary `Sandbox`, not yet ready to execute guest code.
///
/// Prior to initializing a full-fledged sandbox, you must create a
/// `UninitializedSandbox` with the `new` function, register all the
/// host-implemented functions you need to be available to the guest, then
/// call  `evolve` to transform your `UninitializedSandbox` into an initialized
/// sandbox.
pub struct UninitializedSandbox {
    pub(crate) host_funcs: Arc<Mutex<HostFuncsWrapper>>,
    pub(crate) mem_mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
    pub(crate) config: SandboxConfiguration,
    pub(crate) max_guest_log_level: Option<LevelFilter>,
    #[cfg(gdb)]
    pub(crate) debug_info: Option<DebugInfo>,
}

impl Debug for UninitializedSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UninitializedSandbox")
            .field("Memory Layout", &self.mem_mgr.memory_sections)
            .finish()
    }
}

impl Sandbox for UninitializedSandbox {}

impl
    EvolvableSandbox<
        UninitializedSandbox,
        MultiUseSandbox,
        Noop<UninitializedSandbox, MultiUseSandbox>,
    > for UninitializedSandbox
{
    /// Evolve `self` to a `MultiUseSandbox` without any additional metadata.
    #[instrument(err(Debug), skip_all, parent = Span::current(), level = "Trace")]
    fn evolve(self, _: Noop<UninitializedSandbox, MultiUseSandbox>) -> Result<MultiUseSandbox> {
        evolve_impl_multi_use(self)
    }
}

impl UninitializedSandbox {
    /// Create a new uninitialized sandbox.
    pub(crate) fn new(
        mem_mgr: SandboxMemoryManager<ExclusiveSharedMemory>,
        config: SandboxConfiguration,
        #[cfg(gdb)] debug_info: Option<DebugInfo>,
    ) -> Self {
        Self {
            host_funcs: Arc::new(Mutex::new(HostFuncsWrapper::default())),
            mem_mgr,
            config,
            max_guest_log_level: None,
            #[cfg(gdb)]
            debug_info,
        }
    }

    /// Set the max log level to be used by the guest.
    /// If this is not set then the log level will be determined by parsing the RUST_LOG environment variable.
    /// If the RUST_LOG environment variable is not set then the max log level will be set to `LevelFilter::Error`.
    pub fn set_max_guest_log_level(&mut self, log_level: LevelFilter) {
        self.max_guest_log_level = Some(log_level);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use hyperlight_testing::logger::{Logger as TestLogger, LOGGER as TEST_LOGGER};
    use hyperlight_testing::simple_guest_as_string;
    use hyperlight_testing::tracing_subscriber::TracingSubscriber as TestSubscriber;
    use log::Level;
    use serde_json::{Map, Value};
    use tracing::Level as tracing_level;
    use tracing_core::callsite::rebuild_interest_cache;
    use tracing_core::Subscriber;
    use uuid::Uuid;

    use crate::sandbox::sandbox_builder::SandboxBuilder;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::testing::log_values::{test_value_as_str, try_to_strings};
    use crate::{GuestBinary, MultiUseSandbox, Result};

    #[test]
    // Tests that trace data are emitted when a trace subscriber is set
    // this test is ignored because it is incompatible with other tests , specifically those which require a logger for tracing
    // marking  this test as ignored means that running `cargo test` will not run this test but will allow a developer who runs that command
    // from their workstation to be successful without needed to know about test interdependencies
    // this test will be run explicitly as a part of the CI pipeline
    #[ignore]
    fn test_trace_trace() {
        TestLogger::initialize_log_tracer();
        rebuild_interest_cache();
        let subscriber = TestSubscriber::new(tracing_level::TRACE);
        tracing::subscriber::with_default(subscriber.clone(), || {
            let correlation_id = Uuid::new_v4().as_hyphenated().to_string();
            let span = tracing::error_span!("test_trace_logs", correlation_id).entered();

            // We should be in span 1

            let current_span = subscriber.current_span();
            assert!(current_span.is_known(), "Current span is unknown");
            let current_span_metadata = current_span.into_inner().unwrap();
            assert_eq!(
                current_span_metadata.0.into_u64(),
                1,
                "Current span is not span 1"
            );
            assert_eq!(current_span_metadata.1.name(), "test_trace_logs");

            // Get the span data and check the correlation id

            let span_data = subscriber.get_span(1);
            let span_attributes: &Map<String, Value> = span_data
                .get("span")
                .unwrap()
                .get("attributes")
                .unwrap()
                .as_object()
                .unwrap();

            test_value_as_str(span_attributes, "correlation_id", correlation_id.as_str());

            let mut binary_path = simple_guest_as_string().unwrap();
            binary_path.push_str("does_not_exist");

            let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath(binary_path));

            assert!(sandbox_builder.is_err());

            // Now we should still be in span 1 but span 2 should be created (we created entered and exited span 2 when we called UninitializedSandbox::new)

            let current_span = subscriber.current_span();
            assert!(current_span.is_known(), "Current span is unknown");
            let current_span_metadata = current_span.into_inner().unwrap();
            assert_eq!(
                current_span_metadata.0.into_u64(),
                1,
                "Current span is not span 1"
            );

            let span_metadata = subscriber.get_span_metadata(2);
            assert_eq!(span_metadata.name(), "new");

            // There should be one event for the error that the binary path does not exist

            let events = subscriber.get_events();
            assert_eq!(events.len(), 1);

            let mut count_matching_events = 0;

            for json_value in events {
                let event_values = json_value.as_object().unwrap().get("event").unwrap();
                let metadata_values_map =
                    event_values.get("metadata").unwrap().as_object().unwrap();
                let event_values_map = event_values.as_object().unwrap();

                let expected_error_start = "Error(\"Guest binary not found:";

                let err_vals_res = try_to_strings([
                    (metadata_values_map, "level"),
                    (event_values_map, "error"),
                    (metadata_values_map, "module_path"),
                    (metadata_values_map, "target"),
                ]);
                if let Ok(err_vals) = err_vals_res {
                    if err_vals[0] == "ERROR"
                        && err_vals[1].starts_with(expected_error_start)
                        && err_vals[2] == "hyperlight_host::sandbox::sandbox_builder"
                        && err_vals[3] == "hyperlight_host::sandbox::sandbox_builder"
                    {
                        count_matching_events += 1;
                    }
                }
            }
            assert_eq!(
                count_matching_events, 1,
                "Unexpected number of matching events {}",
                count_matching_events
            );
            span.exit();
            subscriber.clear();
        });
    }

    #[test]
    #[ignore]
    // Tests that traces are emitted as log records when there is no trace
    // subscriber configured.
    fn test_log_trace() {
        {
            TestLogger::initialize_test_logger();
            TEST_LOGGER.set_max_level(log::LevelFilter::Trace);

            // This makes sure that the metadata interest cache is rebuilt so that
            // the log records are emitted for the trace records

            rebuild_interest_cache();

            let mut invalid_binary_path = simple_guest_as_string().unwrap();
            invalid_binary_path.push_str("does_not_exist");

            let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath(invalid_binary_path));

            assert!(sandbox_builder.is_err());

            // When tracing is creating log records it will create a log
            // record for the creation of the span (from the instrument
            // attribute), and will then create a log record for the entry to
            // and exit from the span.
            //
            // It also creates a log record for the span being dropped.
            //
            // In addition there are 14 info log records created for build information
            //
            // So we expect 19 log records for this test, four for the span and
            // then one for the error as the file that we are attempting to
            // load into the sandbox does not exist, plus the 14 info log records

            let num_calls = TEST_LOGGER.num_log_calls();
            assert_eq!(5, num_calls);

            // Log record 1

            let logcall = TEST_LOGGER.get_log_call(0).unwrap();
            assert_eq!(Level::Info, logcall.level);

            assert!(logcall.args.starts_with("new;"));
            assert_eq!("tracing::span", logcall.target);

            // Log record 2

            let logcall = TEST_LOGGER.get_log_call(1).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "-> new;");
            assert_eq!("tracing::span::active", logcall.target);

            // Log record 17

            let logcall = TEST_LOGGER.get_log_call(2).unwrap();
            assert_eq!(Level::Error, logcall.level);
            assert!(logcall
                .args
                .starts_with("error=Error(\"Guest binary not found:"));
            assert_eq!("hyperlight_host::sandbox::sandbox_builder", logcall.target);

            // Log record 18

            let logcall = TEST_LOGGER.get_log_call(3).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "<- new;");
            assert_eq!("tracing::span::active", logcall.target);

            // Log record 19

            let logcall = TEST_LOGGER.get_log_call(4).unwrap();
            assert_eq!(Level::Trace, logcall.level);
            assert_eq!(logcall.args, "-- new;");
            assert_eq!("tracing::span", logcall.target);
        }
        {
            // test to ensure an invalid binary logs & traces properly
            TEST_LOGGER.clear_log_calls();
            TEST_LOGGER.set_max_level(log::LevelFilter::Info);

            let mut valid_binary_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            valid_binary_path.push("src");
            valid_binary_path.push("sandbox");
            valid_binary_path.push("initialized.rs");

            let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath(
                valid_binary_path.into_os_string().into_string().unwrap(),
            ));

            assert!(sandbox_builder.is_err());

            // There should be 2 calls this time when we change to the log
            // LevelFilter to Info.
            let num_calls = TEST_LOGGER.num_log_calls();
            assert_eq!(2, num_calls);

            // Log record 1

            let logcall = TEST_LOGGER.get_log_call(0).unwrap();
            assert_eq!(Level::Info, logcall.level);

            assert!(logcall.args.starts_with("new;"));
            assert_eq!("tracing::span", logcall.target);

            // Log record 2

            let logcall = TEST_LOGGER.get_log_call(1).unwrap();
            assert_eq!(Level::Error, logcall.level);
            assert!(logcall
                .args
                .starts_with("error=Error(\"Guest binary not found:"));
            assert_eq!("hyperlight_host::sandbox::sandbox_builder", logcall.target);
        }
        {
            TEST_LOGGER.clear_log_calls();
            TEST_LOGGER.set_max_level(log::LevelFilter::Error);

            let sbox = {
                let sandbox_builder =
                    SandboxBuilder::new(GuestBinary::FilePath(simple_guest_as_string().unwrap()))
                        .unwrap();

                sandbox_builder.build().unwrap()
            };
            let _: Result<MultiUseSandbox> = sbox.evolve(Noop::default());

            let num_calls = TEST_LOGGER.num_log_calls();

            assert_eq!(0, num_calls);
        }
    }

    #[test]
    fn test_invalid_path() {
        let invalid_path = "some/path/that/does/not/exist".to_string();
        let sandbox_builder = SandboxBuilder::new(GuestBinary::FilePath(invalid_path));

        #[cfg(target_os = "windows")]
        assert!(
            matches!(sandbox_builder, Err(e) if e.to_string().contains("Guest binary not found: 'some/path/that/does/not/exist': The system cannot find the path specified. (os error 3)"))
        );
        #[cfg(target_os = "linux")]
        assert!(
            matches!(sandbox_builder, Err(e) if e.to_string().contains("Guest binary not found: 'some/path/that/does/not/exist': No such file or directory (os error 2)"))
        );
    }
}
