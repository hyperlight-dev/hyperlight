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

/*!
This module contains the definitions and implementations of the metrics used by the sandbox module
*/
use std::collections::HashMap;
use std::sync::Once;

use once_cell::sync::OnceCell;
use strum::{EnumIter, EnumVariantNames, IntoStaticStr};
use tracing::{instrument, Span};

use crate::metrics::{
    HyperlightMetric, HyperlightMetricDefinition, HyperlightMetricEnum, HyperlightMetricType,
};

// This is required to ensure that the metrics are only initialized once
static INIT_METRICS: Once = Once::new();
// This contains a hashmap of all the metrics using metric names defined below as keys
static METRICS: OnceCell<HashMap<&'static str, HyperlightMetric>> = OnceCell::new();

// This is the definition of all the metrics used by the sandbox module
static SANDBOX_METRIC_DEFINITIONS: &[HyperlightMetricDefinition] = &[
    HyperlightMetricDefinition {
        name: "guest_error_count",
        help: "Number of guest errors encountered",
        metric_type: HyperlightMetricType::IntCounterVec,
        labels: &["error_code", "error_message"],
        buckets: &[],
    },
    #[cfg(feature = "function_call_metrics")]
    HyperlightMetricDefinition {
        name: "guest_function_call_duration_microseconds",
        help: "Duration of guest function calls in microseconds",
        metric_type: HyperlightMetricType::HistogramVec,
        labels: &["function_name"],
        buckets: &[
            50.00, 150.0, 250.0, 350.0, 450.0, 550.0, 650.0, 750.0, 850.0, 950.0, 1050.00, 1150.00,
            1250.00, 1350.00, 1450.00, 1550.00, 1650.00, 1750.00, 1850.00, 1950.00, 2050.00,
            2150.00, 2250.00, 2350.00, 2450.00, 2550.00, 2650.00, 2750.00, 2850.00, 2950.00,
            3050.00, 3150.00, 3250.00, 3350.00, 3450.00, 3550.00, 3650.00, 3750.00, 3850.00,
            3950.00, 4050.00, 4150.00, 4250.00, 4350.00, 4450.00, 4550.00, 4650.00, 4750.00,
            4850.00, 4950.00, 5050.00, 5150.00, 5250.00, 5350.00, 5450.00, 5550.00, 5650.00,
            5750.00, 5850.00, 5950.00, 6050.00,
        ],
    },
    #[cfg(feature = "function_call_metrics")]
    HyperlightMetricDefinition {
        name: "host_function_calls_duration_microseconds",
        help: "Duration of host function calls in Microseconds",
        metric_type: HyperlightMetricType::HistogramVec,
        labels: &["function_name"],
        buckets: &[
            50.00, 150.0, 250.0, 350.0, 450.0, 550.0, 650.0, 750.0, 850.0, 950.0, 1050.00, 1150.00,
            1250.00, 1350.00, 1450.00, 1550.00, 1650.00, 1750.00, 1850.00, 1950.00, 2050.00,
            2150.00, 2250.00, 2350.00, 2450.00, 2550.00, 2650.00, 2750.00, 2850.00, 2950.00,
            3050.00, 4050.00, 4150.00, 4250.00, 4350.00, 4450.00, 4550.00, 4650.00, 4750.00,
            4850.00, 4950.00, 5050.00, 5150.00, 5250.00, 5350.00, 5450.00, 5550.00, 5650.00,
            5750.00, 5850.00, 5950.00, 6050.00,
        ],
    },
];

/// There is an enum variant for each error metric in the module
/// the names of the variant take the form of CamelCase, but the metric names are snake_case
/// so for example, the enum variant CurrentNumberOfMultiUseSandboxes corresponds to the
/// metric name current_number_of_multi_use_sandboxes.
/// At runtime we location the correct metric by looking up the enum variant name in the hashmap
/// the conversion of the enum variant name to the metric name is done by the IntoStaticStr derive macro
/// along with the strum(serialize_all = "snake_case") attribute.
/// This enum contains all the metrics used by the sandbox module
///
/// The enum is required to derive from EnumIter, EnumVariantNames, IntoStaticStr
/// and strum(serialize_all = "snake_case") performs the name conversion from CamelCase to snake_case
/// when the enum variant is serialized to a string
#[derive(Debug, EnumIter, EnumVariantNames, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum SandboxMetric {
    GuestErrorCount,
    #[cfg(feature = "function_call_metrics")]
    GuestFunctionCallDurationMicroseconds,
    #[cfg(feature = "function_call_metrics")]
    HostFunctionCallsDurationMicroseconds,
}

// It is required for the enum to implement HyperlightMetricEnum
impl HyperlightMetricEnum<SandboxMetric> for SandboxMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_init_metrics() -> &'static Once {
        &INIT_METRICS
    }
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_metrics() -> &'static OnceCell<HashMap<&'static str, HyperlightMetric>> {
        &METRICS
    }
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn get_metric_definitions() -> &'static [HyperlightMetricDefinition] {
        SANDBOX_METRIC_DEFINITIONS
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use prometheus::Registry;
    use strum::{IntoEnumIterator, VariantNames};

    use super::*;
    use crate::metrics::get_metrics_registry;
    use crate::metrics::tests::HyperlightMetricEnumTest;
    use crate::{
        histogram_vec_observe, histogram_vec_sample_count, histogram_vec_sample_sum,
        int_counter_vec_get, int_counter_vec_inc, int_counter_vec_inc_by, int_counter_vec_reset,
        int_gauge_add, int_gauge_dec, int_gauge_get, int_gauge_inc, int_gauge_set, int_gauge_sub,
    };

    impl HyperlightMetricEnumTest<SandboxMetric> for SandboxMetric {
        fn get_enum_variant_names() -> &'static [&'static str] {
            SandboxMetric::VARIANTS
        }
    }

    #[test]
    fn test_enum_has_variant_for_all_metrics() {
        <super::SandboxMetric as HyperlightMetricEnumTest<SandboxMetric>>::enum_has_variant_for_all_metrics();
    }
    #[test]
    fn test_metric_definitions() {
        <super::SandboxMetric as HyperlightMetricEnumTest<SandboxMetric>>::check_metric_definitions(
        );
    }
    #[test]
    #[ignore]
    /// This test is ignored because as it uses real counters if it runs at the same time as other tests it may fail.
    ///
    /// Marking this test as ignored means that running `cargo test` will not
    /// run it. This feature will allow a developer who runs that command
    /// from their workstation to be successful without needing to know about
    /// test interdependencies. This test will, however, be run explicitly as a
    /// part of the CI pipeline.
    fn test_metrics() {
        let iter: SandboxMetricIter = SandboxMetric::iter();
        for sandbox_metric in iter {
            match sandbox_metric.get_hyperlight_metric() {
                Ok(hyperlight_metric) => match hyperlight_metric {
                    HyperlightMetric::IntGauge(int_gauge) => {
                        let gauge = <super::SandboxMetric as HyperlightMetricEnumTest<
                            SandboxMetric,
                        >>::get_intguage_metric(int_gauge.name);
                        assert!(gauge.is_ok());
                        let gauge = gauge.unwrap();
                        int_gauge_set!(&sandbox_metric, 0);
                        assert_eq!(gauge.get(), 0);
                        int_gauge_inc!(&sandbox_metric);
                        assert_eq!(gauge.get(), 1);
                        int_gauge_dec!(&sandbox_metric);
                        assert_eq!(gauge.get(), 0);
                        int_gauge_add!(&sandbox_metric, 5);
                        assert_eq!(gauge.get(), 5);
                        int_gauge_sub!(&sandbox_metric, 2);
                        assert_eq!(gauge.get(), 3);
                        int_gauge_set!(&sandbox_metric, 10);
                        assert_eq!(gauge.get(), 10);
                        let val = int_gauge_get!(&sandbox_metric);
                        assert_eq!(val, 10);
                    }
                    HyperlightMetric::IntCounterVec(int_counter_vec) => {
                        let counter = <super::SandboxMetric as HyperlightMetricEnumTest<
                            SandboxMetric,
                        >>::get_intcountervec_metric(
                            int_counter_vec.name
                        );
                        assert!(counter.is_ok());
                        let counter = counter.unwrap();
                        let label_vals = ["test", "test2"];
                        int_counter_vec_reset!(&sandbox_metric, &label_vals);
                        let value = counter.get(&label_vals);
                        assert!(value.is_ok());
                        let value = value.unwrap();
                        assert_eq!(value, 0);
                        int_counter_vec_inc!(&sandbox_metric, &label_vals);
                        let value = counter.get(&label_vals);
                        assert!(value.is_ok());
                        let value = value.unwrap();
                        assert_eq!(value, 1);
                        int_counter_vec_inc_by!(&sandbox_metric, &label_vals, 5);
                        let value = counter.get(&label_vals);
                        assert!(value.is_ok());
                        let value = value.unwrap();
                        assert_eq!(value, 6);
                        int_counter_vec_reset!(&sandbox_metric, &label_vals);
                        let value = int_counter_vec_get!(&sandbox_metric, &label_vals);
                        assert_eq!(value, 0);
                    }
                    HyperlightMetric::HistogramVec(histogram_vec) => {
                        let histogram = <super::SandboxMetric as HyperlightMetricEnumTest<
                            SandboxMetric,
                        >>::get_histogramvec_metric(
                            histogram_vec.name
                        );
                        assert!(histogram.is_ok());
                        let histogram = histogram.unwrap();
                        let label_vals = ["test"];
                        histogram_vec_observe!(&sandbox_metric, &label_vals, 1.0);
                        let result = histogram_vec_sample_sum!(&sandbox_metric, &label_vals);
                        assert_eq!(result, 1.0);
                        assert!(histogram.get_sample_count(&label_vals).is_ok());
                        assert_eq!(histogram.get_sample_count(&label_vals).unwrap(), 1);
                        let result = histogram_vec_sample_count!(&sandbox_metric, &label_vals);
                        assert_eq!(result, 1);
                        assert!(histogram.get_sample_sum(&label_vals).is_ok());
                        assert_eq!(histogram.get_sample_sum(&label_vals).unwrap(), 1.0);
                    }
                    _ => {
                        panic!("metric is not an IntGauge,IntCounterVec or HistogramVec");
                    }
                },
                Err(e) => {
                    panic!("error getting metric: {}", e);
                }
            }
        }
    }
    #[test]
    #[ignore]
    /// This test is ignored because it is requires that metrics and registry have not been set or initialised yet.
    ///
    /// Marking this test as ignored means that running `cargo test` will not
    /// run it. This feature will allow a developer who runs that command
    /// from their workstation to be successful without needing to know about
    /// test interdependencies. This test will, however, be run explicitly as a
    /// part of the CI pipeline.
    fn test_gather_metrics() {
        lazy_static! {
            static ref REGISTRY: Registry = Registry::default();
        }
        test_metrics();
        let registry = get_metrics_registry();
        let result = registry.gather();
        #[cfg(feature = "function_call_metrics")]
        assert_eq!(result.len(), 3);
        #[cfg(not(feature = "function_call_metrics"))]
        assert_eq!(result.len(), 1);
    }
}
