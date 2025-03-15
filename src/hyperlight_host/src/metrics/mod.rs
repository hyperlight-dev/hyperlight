use std::time::Duration;

/// Increases the given counter by 1
pub(crate) fn increase_counter(metric: CounterMetric) {
    metrics::counter!(metric.name()).increment(1);
}

/// Records the given duration in the histogram
pub(crate) fn record_histogram_duration(metric: HistogramMetric, duration: Duration) {
    metrics::histogram!(metric.name()).record(duration);
}

trait Metric {
    /// Returns the name of the metric as a static string
    fn name(&self) -> &'static str;
}

macro_rules! define_metrics {
    (
        $( $metric_type:ident {
            $(
                $( #[cfg($feature:meta)] )?
                $variant:ident = $name:expr
            ),* $(,)?
        } )*
    ) => {
        $(
            #[derive(Debug, Copy, Clone)]
            pub(crate) enum $metric_type {
                $( $( #[cfg($feature)] )? $variant ),*
            }

            impl Metric for $metric_type {
                fn name(&self) -> &'static str {
                    match self {
                        $( $( #[cfg($feature)] )? Self::$variant => $name ),*
                    }
                }
            }
        )*
    };
}

define_metrics! {
    // Counters which only can be increased, never decreased
    CounterMetric {
        NumGuestErrors = "NUM_GUEST_ERRORS",
        NumGuestCancellations = "NUM_GUEST_CANCELLATIONS"
    }
    // Histograms which can be recorded with a duration
    HistogramMetric {
        GuestCallDuration = "GUEST_CALL_DURATION",
        HostCallDuration = "HOST_CALL_DURATION"
    }
    // Add other types here once we need it
}

#[cfg(test)]
mod tests {
    use metrics_util::CompositeKey;

    use super::*;

    #[test]
    fn test_counter_and_histogram_metrics() {
        // Set up the recorder and snapshotter
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        // Perform actions that will update metrics
        let snapshot = metrics::with_local_recorder(&recorder, || {
            increase_counter(CounterMetric::NumGuestErrors);
            increase_counter(CounterMetric::NumGuestErrors);
            record_histogram_duration(HistogramMetric::GuestCallDuration, Duration::from_secs(1));
            record_histogram_duration(HistogramMetric::HostCallDuration, Duration::from_secs(3));

            snapshotter.snapshot()
        });

        // Convert snapshot into a hashmap for easier lookup
        #[allow(
            clippy::mutable_key_type,
            reason = "This is just a test so we don't care"
        )]
        let snapshot = snapshot.into_hashmap();
        assert_eq!(snapshot.len(), 3, "Expected three metrics in the snapshot");

        // Verify that the counter metric is recorded correctly
        let counter_key = CompositeKey::new(
            metrics_util::MetricKind::Counter,
            CounterMetric::NumGuestErrors.name().into(),
        );
        let counter_metric = snapshot.get(&counter_key);
        assert_eq!(
            counter_metric.unwrap().2,
            metrics_util::debugging::DebugValue::Counter(2),
            "Counter value for NumGuestErrors is incorrect"
        );

        // Verify that the histogram guestcall metric is recorded correctly
        let histogram_key = CompositeKey::new(
            metrics_util::MetricKind::Histogram,
            HistogramMetric::GuestCallDuration.name().into(),
        );
        let histogram_value = &snapshot.get(&histogram_key).unwrap().2;
        assert!(
            matches!(
                histogram_value,
                metrics_util::debugging::DebugValue::Histogram(ref histogram) if histogram.len() == 1 && histogram[0].0 == 1.0
            ),
            "Histogram metric does not match expected value"
        );

        // Verify that the histogram hostcall metric is recorded correctly
        let histogram_key = CompositeKey::new(
            metrics_util::MetricKind::Histogram,
            HistogramMetric::HostCallDuration.name().into(),
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
}
