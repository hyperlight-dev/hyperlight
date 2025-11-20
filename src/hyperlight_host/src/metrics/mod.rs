/*
Copyright 2025  The Hyperlight Authors.

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

// Counter metric that counts the number of times a vcpu was kicked by a stale signal
pub(crate) static METRIC_ERRONEOUS_VCPU_KICK: &str = "erroneous_vcpu_kicks_total";

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
    use std::thread;
    use std::time::Duration;

    use hyperlight_testing::simple_guest_as_string;
    use metrics::{Key, with_local_recorder};
    use metrics_util::CompositeKey;

    use super::*;
    use crate::{GuestBinary, UninitializedSandbox};

    #[test]
    fn test_metrics_are_emitted() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let snapshot = with_local_recorder(&recorder, || {
            let uninit = UninitializedSandbox::new(
                GuestBinary::FilePath(simple_guest_as_string().unwrap()),
                None,
            )
            .unwrap();

            let mut multi = uninit.evolve().unwrap();
            let interrupt_handle = multi.interrupt_handle();

            // interrupt the guest function call to "Spin" after 1 second
            let thread = thread::spawn(move || {
                thread::sleep(Duration::from_secs(1));
                assert!(interrupt_handle.kill());
            });

            multi
                .call::<i32>("PrintOutput", "Hello".to_string())
                .unwrap();

            multi.call::<i32>("Spin", ()).unwrap_err();
            thread.join().unwrap();

            snapshotter.snapshot()
        });

        // Convert snapshot into a hashmap for easier lookup
        #[expect(clippy::mutable_key_type)]
        let snapshot = snapshot.into_hashmap();

        cfg_if::cfg_if! {
            if #[cfg(feature = "function_call_metrics")] {
                use metrics::Label;

                let expected_num_metrics = 4;

                // Verify that the histogram metrics are recorded correctly
                assert_eq!(snapshot.len(), expected_num_metrics);

                // 1. Guest call duration
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
                        metrics_util::debugging::DebugValue::Histogram(histogram) if histogram.len() == 1
                    ),
                    "Histogram metric does not match expected value"
                );

                // 2. Guest cancellation
                let counter_key = CompositeKey::new(
                    metrics_util::MetricKind::Counter,
                    Key::from_name(METRIC_GUEST_CANCELLATION),
                );
                assert_eq!(
                    snapshot.get(&counter_key).unwrap().2,
                    metrics_util::debugging::DebugValue::Counter(1)
                );

                // 3. Guest call duration
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
                        metrics_util::debugging::DebugValue::Histogram(histogram) if histogram.len() == 1
                    ),
                    "Histogram metric does not match expected value"
                );
            } else {
                // Verify that the counter metrics are recorded correctly
                assert_eq!(snapshot.len(), 1);

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

    #[test]
    fn test_erroneous_vcpu_kick_metric_exists() {
        // This test verifies that the metric can be incremented without errors.
        // The actual scenario where this metric is incremented (stale signal delivery)
        // is a race condition that's difficult to reliably reproduce in a test.
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let snapshot = with_local_recorder(&recorder, || {
            // Manually increment the metric to verify it works
            metrics::counter!(METRIC_ERRONEOUS_VCPU_KICK).increment(1);
            snapshotter.snapshot()
        });

        // Verify the metric was recorded
        #[expect(clippy::mutable_key_type)]
        let snapshot = snapshot.into_hashmap();

        let counter_key = CompositeKey::new(
            metrics_util::MetricKind::Counter,
            Key::from_name(METRIC_ERRONEOUS_VCPU_KICK),
        );
        assert_eq!(
            snapshot.get(&counter_key).unwrap().2,
            metrics_util::debugging::DebugValue::Counter(1),
            "Erroneous vCPU kick metric should be recorded"
        );
    }
}
