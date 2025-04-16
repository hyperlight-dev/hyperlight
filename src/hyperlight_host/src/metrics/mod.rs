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

use std::sync::Once;
use std::time::Duration;

use metrics_macro::NamedMetric;

#[macro_use]
mod metrics_macro;

// These defines all types of metrics in this crate
define_metrics! {
    CounterMetric {
        GuestErrors { code: u64 } => {
            name: "guest_errors_total",
            description: "Number of errors encountered by guests",
            unit: metrics::Unit::Count,
        },
        GuestCancellations => {
            name: "guest_cancellations_total",
            description: "Number of times guest execution was cancelled due to timeout",
            unit: metrics::Unit::Count,
        },
    }
    HistogramMetric {
        GuestCallDuration { name: String, duration: Duration } => {
            name: "guest_call_duration_seconds",
            description: "Duration of guest function calls",
            unit: metrics::Unit::Seconds,
        },
        HostCallDuration { name: String, duration: Duration} => {
            name: "host_call_duration_seconds",
            description: "Duration of host function calls",
            unit: metrics::Unit::Seconds,
        },
    }
}

impl CounterMetric {
    /// Create a new guest error metric, ready to be emitted
    #[must_use]
    pub(crate) fn guest_error(code: u64) -> Self {
        CounterMetric::GuestErrors { code }
    }
    /// Create a new guest cancellation metric, ready to be emitted
    #[must_use]
    pub(crate) fn guest_cancellation() -> Self {
        CounterMetric::GuestCancellations
    }
}

impl HistogramMetric {
    /// Measures the time to execute the given closure, and then emits the duration
    /// as a guest call metric.
    ///
    /// Note: If the `function_call_metrics` feature is not enabled, this function
    /// will simply execute the closure without measuring time or emitting metrics.
    pub(crate) fn time_and_emit_guest_call<T, F: FnOnce() -> T>(
        #[allow(unused_variables)] name: &str,
        f: F,
    ) -> T {
        cfg_if::cfg_if! {
            if #[cfg(feature = "function_call_metrics")] {
                use std::time::Instant;

                let start = Instant::now();
                let result = f();
                let duration = start.elapsed();
                HistogramMetric::GuestCallDuration { name: name.to_string(), duration }.emit();
                result
            } else {
                f()
            }
        }
    }

    /// Measures the time to execute the given closure, and then emits the duration
    /// as a host call metric.
    ///
    /// Note: If the `function_call_metrics` feature is not enabled, this function
    /// will simply execute the closure without measuring time or emitting metrics.
    pub(crate) fn time_and_emit_host_call<T, F: FnOnce() -> T>(
        #[allow(unused_variables)] name: &str,
        f: F,
    ) -> T {
        cfg_if::cfg_if! {
            if #[cfg(feature = "function_call_metrics")] {
                use std::time::Instant;

                let start = Instant::now();
                let result = f();
                let duration = start.elapsed();
                HistogramMetric::HostCallDuration { name: name.to_string(), duration }.emit();
                result
            } else {
                f()
            }
        }
    }

    /// Create a new guest call metric, ready to be emitted
    #[cfg(test)]
    #[must_use]
    fn guest_call(name: String, duration: Duration) -> HistogramMetric {
        HistogramMetric::GuestCallDuration { name, duration }
    }
    /// Create a new host call metric, ready to be emitted
    #[cfg(test)]
    #[must_use]
    fn host_call(name: String, duration: Duration) -> HistogramMetric {
        HistogramMetric::HostCallDuration { name, duration }
    }
}

/// A metric which can be emitted to the underlying metrics system
pub(crate) trait EmittableMetric {
    /// Emits the metric to the underlying metrics system.
    /// The first time this is called for a given metric variant, it will
    /// also describe the metric to the underlying metrics system.
    fn emit(self);
}

impl EmittableMetric for CounterMetric {
    /// Increases the counter represented by `self` by 1
    fn emit(self) {
        let name = self.name();
        let unit = self.unit();
        let description = self.description();

        match self {
            CounterMetric::GuestErrors { code } => {
                // Describe each metric variant only once
                static DESCRIBE: Once = Once::new();
                DESCRIBE.call_once(|| {
                    metrics::describe_counter!(name, unit, description);
                });

                static LABEL_ERROR_CODE: &str = "code";
                metrics::counter!(name, LABEL_ERROR_CODE => code.to_string()).increment(1);
            }
            CounterMetric::GuestCancellations => {
                // Describe each metric variant only once
                static DESCRIBE: Once = Once::new();
                DESCRIBE.call_once(|| {
                    metrics::describe_counter!(name, unit, description);
                });

                metrics::counter!(name).increment(1);
            }
        }
    }
}

impl EmittableMetric for HistogramMetric {
    fn emit(self) {
        let metric_name = self.name();
        let unit = self.unit();
        let description = self.description();

        static LABEL_FUNCTION_NAME: &str = "function_name";

        match self {
            HistogramMetric::GuestCallDuration { name, duration } => {
                // Describe each metric variant only once
                static DESCRIBE: Once = Once::new();
                DESCRIBE.call_once(|| {
                    metrics::describe_histogram!(metric_name, unit, description);
                });

                metrics::histogram!(metric_name, LABEL_FUNCTION_NAME => name).record(duration);
            }
            HistogramMetric::HostCallDuration { name, duration } => {
                // Describe each metric variant only once
                static DESCRIBE: Once = Once::new();
                DESCRIBE.call_once(|| {
                    metrics::describe_histogram!(metric_name, unit, description);
                });

                metrics::histogram!(metric_name, LABEL_FUNCTION_NAME => name).record(duration);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use metrics::{Counter, Gauge, Histogram, Key, Label};
    use metrics_util::CompositeKey;

    use super::*;

    #[test]
    fn test_counter_and_histogram_metrics() {
        // Set up the recorder and snapshotter
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let metric_1 = CounterMetric::guest_error(404);
        let metric_2 = CounterMetric::guest_cancellation();
        let metric_3 =
            HistogramMetric::guest_call("GuestFunc1".to_string(), Duration::from_secs(1));
        let metric_4 = HistogramMetric::host_call("HostFunc1".to_string(), Duration::from_secs(3));

        // Perform actions that will update metrics
        let snapshot = metrics::with_local_recorder(&recorder, || {
            metric_1.clone().emit();
            metric_2.clone().emit();
            metric_3.clone().emit();
            metric_4.clone().emit();

            snapshotter.snapshot()
        });

        // Convert snapshot into a hashmap for easier lookup
        #[expect(clippy::mutable_key_type)]
        let snapshot = snapshot.into_hashmap();
        assert_eq!(snapshot.len(), 4, "Expected three metrics in the snapshot");

        // Verify that the counter metrics are recorded correctly

        // metric 1
        let counter_key = CompositeKey::new(
            metrics_util::MetricKind::Counter,
            Key::from_parts(metric_1.name(), vec![Label::new("code", "404")]),
        );
        assert_eq!(
            snapshot.get(&counter_key).unwrap().2,
            metrics_util::debugging::DebugValue::Counter(1)
        );

        // metric 2
        let counter_key =
            CompositeKey::new(metrics_util::MetricKind::Counter, metric_2.name().into());
        assert_eq!(
            snapshot.get(&counter_key).unwrap().2,
            metrics_util::debugging::DebugValue::Counter(1)
        );

        // Verify that the histograms metrics are recorded correctly

        // metric 3
        let histogram_key = CompositeKey::new(
            metrics_util::MetricKind::Histogram,
            Key::from_parts(
                metric_3.name(),
                vec![Label::new("function_name", "GuestFunc1")],
            ),
        );
        let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
        assert!(
            matches!(
                histogram_value,
                metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1 && histogram[0].0 == 1.0
            ),
            "Histogram metric does not match expected value"
        );

        // metric 4
        let histogram_key = CompositeKey::new(
            metrics_util::MetricKind::Histogram,
            Key::from_parts(
                metric_4.name(),
                vec![Label::new("function_name", "HostFunc1")],
            ),
        );
        let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
        assert!(
            matches!(
                histogram_value,
                metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1 && histogram[0].0 == 3.0
            ),
            "Histogram metric does not match expected value"
        );
    }

    /// Makes sure that the description function is called only once for each metric variant.
    /// This helps performance
    ///
    /// This test needs to ran in its own process
    #[test]
    #[ignore = "Other tests interfere by initializing the Once statics before our local recorder is installed"]
    fn test_description_called_once() {
        struct DescriptionCounterRecorder {
            num_descriptions: AtomicU64,
        }

        impl metrics::Recorder for DescriptionCounterRecorder {
            fn describe_counter(
                &self,
                _key: metrics::KeyName,
                _unit: Option<metrics::Unit>,
                _description: metrics::SharedString,
            ) {
                self.num_descriptions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            fn describe_gauge(
                &self,
                _key: metrics::KeyName,
                _unit: Option<metrics::Unit>,
                _description: metrics::SharedString,
            ) {
                self.num_descriptions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            fn describe_histogram(
                &self,
                _key: metrics::KeyName,
                _unit: Option<metrics::Unit>,
                _description: metrics::SharedString,
            ) {
                self.num_descriptions
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            fn register_counter(
                &self,
                _key: &Key,
                _metadata: &metrics::Metadata<'_>,
            ) -> metrics::Counter {
                Counter::noop()
            }

            fn register_gauge(
                &self,
                _key: &Key,
                _metadata: &metrics::Metadata<'_>,
            ) -> metrics::Gauge {
                Gauge::noop()
            }

            fn register_histogram(
                &self,
                _key: &Key,
                _metadata: &metrics::Metadata<'_>,
            ) -> metrics::Histogram {
                Histogram::noop()
            }
        }

        let recorder = DescriptionCounterRecorder {
            num_descriptions: AtomicU64::new(0),
        };

        metrics::with_local_recorder(&recorder, || {
            CounterMetric::guest_error(404).emit();
            CounterMetric::guest_error(500).emit();
            CounterMetric::GuestCancellations.emit();
            CounterMetric::GuestCancellations.emit();
            HistogramMetric::guest_call("GuestFunc1".to_string(), Duration::from_secs(1)).emit();
            HistogramMetric::guest_call("GuestFunc2".to_string(), Duration::from_secs(2)).emit();
            HistogramMetric::host_call("HostFunc1".to_string(), Duration::from_secs(3)).emit();
            HistogramMetric::host_call("HostFunc2".to_string(), Duration::from_secs(4)).emit();
        });

        // Despite 8 emitted metrics above, we expect only 4 descriptions to be recorded
        assert_eq!(
            recorder
                .num_descriptions
                .load(std::sync::atomic::Ordering::Relaxed),
            4,
            "Expected each metric variant to be described exactly once"
        );
    }
}
