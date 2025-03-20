use std::time::Duration;

use metrics_macro::NamedMetric;
#[macro_use]
mod metrics_macro;

// These defines all types of metrics in this crate
define_metrics! {
    CounterMetric {
        GuestErrors { code: u64, message: String } => "guest_errors_total",
        GuestCancellations => "guest_cancellations_total",
    }
    HistogramMetric {
        GuestCallDuration { duration: Duration } => "guest_call_duration_seconds",
        HostCallDuration { duration: Duration} => "host_call_duration_seconds",
    }
}

impl CounterMetric {
    /// Create a new guest error metric, ready to be emitted
    #[must_use]
    pub(crate) fn guest_error(code: u64, message: String) -> CounterMetric {
        CounterMetric::GuestErrors { code, message }
    }
    /// Create a new guest cancellation metric, ready to be emitted
    #[must_use]
    pub(crate) fn guest_cancellation() -> CounterMetric {
        CounterMetric::GuestCancellations
    }
}

impl HistogramMetric {
    /// Create a new guest call metric, ready to be emitted
    #[must_use]
    pub(crate) fn guest_call(duration: Duration) -> HistogramMetric {
        HistogramMetric::GuestCallDuration { duration }
    }
    /// Create a new host call metric, ready to be emitted
    #[must_use]
    pub(crate) fn host_call(duration: Duration) -> HistogramMetric {
        HistogramMetric::HostCallDuration { duration }
    }
}

/// A metric which can be emitted to the underlying metrics system
pub(crate) trait Metric {
    /// Emits the metric to the underlying metrics system
    fn emit(self);
}

impl Metric for CounterMetric {
    /// Increases the counter represented by `self` by 1
    fn emit(self) {
        match self {
            CounterMetric::GuestErrors { code, ref message } => {
                // label keys
                static ERROR_CODE_STR: &str = "code";
                static ERROR_MESSAGE_STR: &str = "message";

                metrics::counter!(self.name(), ERROR_CODE_STR => code.to_string(), ERROR_MESSAGE_STR => message.clone())
                    .increment(1);
            }
            CounterMetric::GuestCancellations => {
                metrics::counter!(self.name()).increment(1);
            }
        }
    }
}

impl Metric for HistogramMetric {
    fn emit(self) {
        match self {
            HistogramMetric::GuestCallDuration { duration }
            | HistogramMetric::HostCallDuration { duration } => {
                metrics::histogram!(self.name()).record(duration);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use metrics::{Key, Label};
    use metrics_util::CompositeKey;

    use super::*;

    #[test]
    fn test_counter_and_histogram_metrics() {
        // Set up the recorder and snapshotter
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        let metric_1 = CounterMetric::guest_error(404, "Not Found".to_string());
        let metric_2 = CounterMetric::guest_cancellation();
        let metric_3 = HistogramMetric::guest_call(Duration::from_secs(1));
        let metric_4 = HistogramMetric::host_call(Duration::from_secs(3));

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

        println!("Snapshot: {:#?}", snapshot);

        // Verify that the counter metrics are recorded correctly
        // metric 1
        let counter_key = CompositeKey::new(
            metrics_util::MetricKind::Counter,
            Key::from_parts(
                metric_1.name(),
                vec![
                    Label::new("code", "404"),
                    Label::new("message", "Not Found"),
                ],
            ),
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
        let histogram_key =
            CompositeKey::new(metrics_util::MetricKind::Histogram, metric_3.name().into());
        let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
        assert!(
            matches!(
                histogram_value,
                metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1 && histogram[0].0 == 1.0
            ),
            "Histogram metric does not match expected value"
        );

        // metric 4
        let histogram_key =
            CompositeKey::new(metrics_util::MetricKind::Histogram, metric_4.name().into());
        let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
        assert!(
            matches!(
                histogram_value,
                metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1 && histogram[0].0 == 3.0
            ),
            "Histogram metric does not match expected value"
        );
    }
}
