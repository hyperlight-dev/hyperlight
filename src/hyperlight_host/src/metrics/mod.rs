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

// Counter metric that counter number of times a guest error occurred
pub(crate) static METRIC_GUEST_ERROR: &str = "guest_errors_total";
pub(crate) static METRIC_GUEST_ERROR_LABEL_CODE: &str = "code";

// Counter metric that counts the number of times a guest function was called due to timing out
pub(crate) static METRIC_GUEST_CANCELLATION: &str = "guest_cancellations_total";

// Histogram metric that measures the duration of guest function calls
#[cfg(feature = "function_call_metrics")]
pub(crate) static METRIC_GUEST_FUNC_DURATION: &str = "guest_call_duration_seconds";

// Histogram metric that measures the duration of host function calls
#[cfg(feature = "function_call_metrics")]
pub(crate) static METRIC_HOST_FUNC_DURATION: &str = "host_call_duration_seconds";

/// If the the `function_call_metrics` feature is enabled, this function measures
/// the time it takes to execute the given closure, and will then emit a guest call metric
/// with the given function name.
///
/// If the feature is not enabled, the given closure is executed without any additional metrics being emitted,
/// and the result of the closure is returned directly.
pub(crate) fn maybe_time_and_emit_guest_call<T, F: FnOnce() -> T>(
    #[allow(unused_variables)] name: &str,
    f: F,
) -> T {
    cfg_if::cfg_if! {
        if #[cfg(feature = "function_call_metrics")] {
            use std::time::Instant;

            let start = Instant::now();
            let result = f();
            let duration = start.elapsed();

            static LABEL_GUEST_FUNC_NAME: &str = "function_name";
            metrics::histogram!(METRIC_GUEST_FUNC_DURATION, LABEL_GUEST_FUNC_NAME => name.to_string()).record(duration);
            result
        } else {
            f()
        }
    }
}

/// If the the `function_call_metrics` feature is enabled, this function measures
/// the time it takes to execute the given closure, and will then emit a host call metric
/// with the given function name.
///
/// If the feature is not enabled, the given closure is executed without any additional metrics being emitted,
/// and the result of the closure is returned directly.
pub(crate) fn maybe_time_and_emit_host_call<T, F: FnOnce() -> T>(
    #[allow(unused_variables)] name: &str,
    f: F,
) -> T {
    cfg_if::cfg_if! {
        if #[cfg(feature = "function_call_metrics")] {
            use std::time::Instant;

            let start = Instant::now();
            let result = f();
            let duration = start.elapsed();

            static LABEL_HOST_FUNC_NAME: &str = "function_name";
            metrics::histogram!(METRIC_HOST_FUNC_DURATION, LABEL_HOST_FUNC_NAME => name.to_string()).record(duration);
            result
        } else {
            f()
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperlight_common::flatbuffer_wrappers::function_types::{ParameterValue, ReturnType};
    use hyperlight_testing::simple_guest_as_string;
    use metrics::Key;
    use metrics_util::CompositeKey;

    use super::*;
    use crate::sandbox_state::sandbox::EvolvableSandbox;
    use crate::sandbox_state::transition::Noop;
    use crate::{GuestBinary, UninitializedSandbox};

    #[test]
    #[ignore = "This test needs to be run separately to avoid having other tests interfere with it"]
    fn test_metrics_are_emitted() {
        // Set up the recorder and snapshotter
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // we cannot use with_local_recorder, since that won't capture the metrics
        // emitted by the hypervisor-thread (which is all of them)
        recorder.install().unwrap();

        let snapshot = {
            let uninit = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().unwrap()),
                None,
                None,
            )
            .unwrap();

            let mut multi = uninit.evolve(Noop::default()).unwrap();

            multi
                .call_guest_function_by_name(
                    "PrintOutput",
                    ReturnType::Int,
                    Some(vec![ParameterValue::String("Hello".to_string())]),
                )
                .unwrap();

            multi
                .call_guest_function_by_name("Spin", ReturnType::Int, None)
                .unwrap_err();

            snapshotter.snapshot()
        };

        // Convert snapshot into a hashmap for easier lookup
        #[expect(clippy::mutable_key_type)]
        let snapshot = snapshot.into_hashmap();

        cfg_if::cfg_if! {
            if #[cfg(feature = "function_call_metrics")] {
                use metrics::Label;
                // Verify that the histogram metrics are recorded correctly
                assert_eq!(snapshot.len(), 4, "Expected two metrics in the snapshot");

                // 1. Host print duration
                let histogram_key = CompositeKey::new(
                    metrics_util::MetricKind::Histogram,
                    Key::from_parts(
                        METRIC_HOST_FUNC_DURATION,
                        vec![Label::new("function_name", "HostPrint")],
                    ),
                );
                let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
                assert!(
                    matches!(
                        histogram_value,
                        metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1
                    ),
                    "Histogram metric does not match expected value"
                );

                // 2. Guest call duration
                let histogram_key = CompositeKey::new(
                    metrics_util::MetricKind::Histogram,
                    Key::from_parts(
                        METRIC_GUEST_FUNC_DURATION,
                        vec![Label::new("function_name", "PrintOutput")],
                    ),
                );
                let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
                assert!(
                    matches!(
                        histogram_value,
                        metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1
                    ),
                    "Histogram metric does not match expected value"
                );

                // 3. Guest cancellation
                let counter_key = CompositeKey::new(
                    metrics_util::MetricKind::Counter,
                    Key::from_name(METRIC_GUEST_CANCELLATION),
                );
                assert_eq!(
                    snapshot.get(&counter_key).unwrap().2,
                    metrics_util::debugging::DebugValue::Counter(1)
                );

                // 4. Guest call duration
                let histogram_key = CompositeKey::new(
                    metrics_util::MetricKind::Histogram,
                    Key::from_parts(
                        METRIC_GUEST_FUNC_DURATION,
                        vec![Label::new("function_name", "Spin")],
                    ),
                );
                let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
                assert!(
                    matches!(
                        histogram_value,
                        metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1
                    ),
                    "Histogram metric does not match expected value"
                );
            } else {
                // Verify that the counter metrics are recorded correctly
                assert_eq!(snapshot.len(), 1, "Expected two metrics in the snapshot");

                let counter_key = CompositeKey::new(
                    metrics_util::MetricKind::Counter,
                    Key::from_name(METRIC_GUEST_CANCELLATION),
                );
                assert_eq!(
                    snapshot.get(&counter_key).unwrap().2,
                    metrics_util::debugging::DebugValue::Counter(1)
                );
            }
        }
    }
}
