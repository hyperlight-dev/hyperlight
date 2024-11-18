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

use std::collections::HashMap;
use std::sync::Once;

use log::error;
use once_cell::sync::OnceCell;
use prometheus::{default_registry, histogram_opts, opts, HistogramOpts, Opts, Registry};
use strum::{IntoEnumIterator, VariantNames};

use crate::error::HyperlightError::{Error, MetricNotFound};
use crate::{log_then_return, new_error, Result};
mod int_gauge_vec;
/// An Integer Gauge Metric for Hyperlight
///
pub use int_gauge_vec::IntGaugeVec;
mod int_gauge;
/// An Integer Gauge Metric for Hyperlight
pub use int_gauge::IntGauge;
mod int_counter_vec;
/// An Integer Counter Vec for Hyperlight
pub use int_counter_vec::IntCounterVec;
mod int_counter;
/// An Integer Counter for Hyperlight
pub use int_counter::IntCounter;
mod histogram_vec;
/// A Histogram Vec for Hyperlight
pub use histogram_vec::HistogramVec;
mod histogram;
/// AHistogram for Hyperlight
pub use histogram::Histogram;
/// A trait that should be implemented by all enums that represent hyperlight metrics
pub trait HyperlightMetricEnum<T>:
    IntoEnumIterator + VariantNames + From<T> + Into<&'static str>
where
    &'static str: From<Self>,
    &'static str: for<'a> From<&'a Self>,
{
    /// A function that should return a static reference to a Once that is used to guard the initialization of the metrics hashmap.
    fn get_init_metrics() -> &'static Once;
    /// A function that should return a static reference to a OnceCell that is used to store the metrics hashmap.
    fn get_metrics() -> &'static OnceCell<HashMap<&'static str, HyperlightMetric>>;
    /// A function that should return a static reference to a slice of HyperlightMetricDefinitions that are used to initialize the metrics hashmap.
    fn get_metric_definitions() -> &'static [HyperlightMetricDefinition];

    /// Gets a HyperlightMetric from the hashmap using the enum variant name as the key
    #[inline]
    fn get_hyperlight_metric(&self) -> Result<&HyperlightMetric> {
        Self::get_init_metrics().call_once(|| {
            let result = init_metrics(Self::get_metric_definitions(), Self::get_metrics());
            if let Err(e) = result {
                error!("Error initializing metrics : {0:?}", e);
            }
        });
        let key: &'static str = <&Self as Into<&'static str>>::into(self);
        HyperlightMetric::get_metric_using_key(key, Self::get_hash_map()?)
    }
    /// Gets the hashmap using the containing the metrics
    #[inline]
    fn get_hash_map() -> Result<&'static HashMap<&'static str, HyperlightMetric>> {
        Self::get_metrics()
            .get()
            .ok_or_else(|| Error("metrics hashmap not initialized".to_string()))
    }
}
/// A trait that should be implemented by all enums that represent hyperlight metrics to
/// convert the enum into a HyperlightMetric
pub trait HyperlightMetricOps {
    /// Converts the enum into a HyperlightMetric
    fn get_metric(&self) -> Result<&HyperlightMetric>;
}

/// A trait that should be implemented by all hyperlight metric definitions to convert the metric into a HyperlightMetric
pub trait GetHyperlightMetric<T> {
    /// Converts the metric into a HyperlightMetric
    fn metric(&self) -> Result<&T>;
}

impl<T: HyperlightMetricEnum<T>> HyperlightMetricOps for T
where
    &'static str: From<T>,
    for<'a> &'static str: From<&'a T>,
{
    fn get_metric(&self) -> Result<&HyperlightMetric> {
        self.get_hyperlight_metric()
    }
}

/// Initializes the metrics hashmap using the metric definitions
#[inline]
fn init_metrics(
    metric_definitions: &[HyperlightMetricDefinition],
    metrics: &OnceCell<HashMap<&'static str, HyperlightMetric>>,
) -> Result<()> {
    let mut hash_map: HashMap<&'static str, HyperlightMetric> = HashMap::new();
    register_metrics(metric_definitions, &mut hash_map)?;
    // the only failure case is if the metrics hashmap is already set which should not be possible
    // but if it were to happen we dont care.
    if let Err(e) = metrics.set(hash_map) {
        error!("metrics hashmap already set : {0:?}", e);
    }
    Ok(())
}
//TODO: Remove this when we have uses of all metric types
#[allow(dead_code)]
#[derive(Debug)]
/// The types of Hyperlight metrics that can be created
pub enum HyperlightMetricType {
    /// A counter that can only be incremented
    IntCounter,
    /// A counter that can only be incremented and has labels
    IntCounterVec,
    /// A gauge that can be incremented, decremented, set, added to, and subtracted from
    IntGauge,
    /// A gauge that can be incremented, decremented, set, added to, and subtracted from and has labels
    IntGaugeVec,
    /// A histogram that can observe values for activities   
    Histogram,
    /// A histogram that can observe values for activities and has labels
    HistogramVec,
}

/// The definition of a Hyperlight metric
pub struct HyperlightMetricDefinition {
    /// The name of the metric
    pub name: &'static str,
    /// The help text for the metric
    pub help: &'static str,
    /// The type of the metric
    pub metric_type: HyperlightMetricType,
    /// The labels for the metric
    pub labels: &'static [&'static str],
    /// The buckets for the metric
    pub buckets: &'static [f64],
}

fn register_metrics(
    metric_definitions: &[HyperlightMetricDefinition],
    hash_map: &mut HashMap<&'static str, HyperlightMetric>,
) -> Result<()> {
    for metric_definition in metric_definitions {
        let metric: HyperlightMetric = match &metric_definition.metric_type {
            HyperlightMetricType::IntGauge => {
                IntGauge::new(metric_definition.name, metric_definition.help)?.into()
            }

            HyperlightMetricType::IntCounterVec => IntCounterVec::new(
                metric_definition.name,
                metric_definition.help,
                metric_definition.labels,
            )?
            .into(),

            HyperlightMetricType::IntCounter => {
                IntCounter::new(metric_definition.name, metric_definition.help)?.into()
            }
            HyperlightMetricType::HistogramVec => HistogramVec::new(
                metric_definition.name,
                metric_definition.help,
                metric_definition.labels,
                metric_definition.buckets.to_vec(),
            )?
            .into(),
            HyperlightMetricType::Histogram => Histogram::new(
                metric_definition.name,
                metric_definition.help,
                metric_definition.buckets.to_vec(),
            )?
            .into(),
            HyperlightMetricType::IntGaugeVec => IntGaugeVec::new(
                metric_definition.name,
                metric_definition.help,
                metric_definition.labels,
            )?
            .into(),
        };

        hash_map.insert(metric_definition.name, metric);
    }
    Ok(())
}

#[derive(Debug)]
/// An instance of a Hyperlight metric
pub enum HyperlightMetric {
    /// A counter that can only be incremented
    IntCounter(IntCounter),
    /// A counter that can only be incremented and has labels
    IntCounterVec(IntCounterVec),
    /// A gauge that can be incremented, decremented, set, added to, and subtracted from
    IntGauge(IntGauge),
    /// A gauge that can be incremented, decremented, set, added to, and subtracted from and has labels
    IntGaugeVec(IntGaugeVec),
    /// A histogram that can observe values for activities
    Histogram(Histogram),
    /// A histogram that can observe values for activities and has labels
    HistogramVec(HistogramVec),
}

impl HyperlightMetric {
    #[inline]
    fn get_metric_using_key<'a>(
        key: &'static str,
        hash_map: &'a HashMap<&'static str, HyperlightMetric>,
    ) -> Result<&'a HyperlightMetric> {
        hash_map.get(key).ok_or_else(|| MetricNotFound(key))
    }
}

// The registry used for all metrics, this can be set by the user of the library, if its not set then the default will be used.

static REGISTRY: OnceCell<&Registry> = OnceCell::new();

/// Get the registry to be used for all metrics, this can be set by the user of the library, if its not set then the default registry will be used.
#[inline]
pub fn get_metrics_registry() -> &'static Registry {
    REGISTRY.get_or_init(default_registry)
}
/// Set the registry to be used for all metrics, this can be set by the user of the library, if its not set then the default registry will be used.
/// This function should be called before any other function in this module is called.
///
/// The user of can then use the registry to gather metrics from the library.
pub fn set_metrics_registry(registry: &'static Registry) -> Result<()> {
    match REGISTRY.get() {
        Some(_) => {
            log_then_return!("Registry was already set");
        }
        None => {
            REGISTRY
                .set(registry)
                // This should be impossible
                .map_err(|e| new_error!("Registry already set : {0:?}", e))
        }
    }
}

fn get_metric_opts(name: &str, help: &str) -> Opts {
    let opts = opts!(name, help);
    opts.namespace("hyperlight")
}

fn get_histogram_opts(name: &str, help: &str, buckets: Vec<f64>) -> HistogramOpts {
    let mut opts = histogram_opts!(name, help);
    opts = opts.namespace("hyperlight");
    opts.buckets(buckets)
}

/// Provides functionality to help with testing Hyperlight Metrics
pub mod tests {
    use std::collections::HashSet;

    use super::*;

    /// A trait that provides test helper functions for Hyperlight Metrics
    pub trait HyperlightMetricEnumTest<T>:
        HyperlightMetricEnum<T> + From<T> + Into<&'static str>
    where
        &'static str: From<Self>,
        &'static str: for<'a> From<&'a Self>,
    {
        /// Defines a function that should return the names of all the metric enum variants
        fn get_enum_variant_names() -> &'static [&'static str];

        /// Provides a function to test that all hyperlight metric definitions in a module have a corresponding enum variant
        /// Should be called in tests in modules that define hyperlight metrics.
        #[track_caller]
        fn enum_has_variant_for_all_metrics() {
            let metric_definitions = Self::get_metric_definitions().iter();
            for metric_definition in metric_definitions {
                let metric_definition_name = metric_definition.name;
                assert!(
                    Self::get_enum_variant_names().contains(&metric_definition_name),
                    "Metric Definition Name {} not found",
                    metric_definition_name,
                );
            }
        }

        /// Provides a function to test that all hyperlight metric definitions have a unique help text
        /// and that there are the same number of enum variants as metric definitions
        /// Should be called in tests in modules that define hyperlight metrics.
        #[track_caller]
        fn check_metric_definitions() {
            let sandbox_metric_definitions = Self::get_metric_definitions();
            let metric_definitions = sandbox_metric_definitions.iter();
            let mut help_text = HashSet::new();
            for metric_definition in metric_definitions {
                assert!(
                    help_text.insert(metric_definition.help),
                    "duplicate metric help definition for {}",
                    metric_definition.name
                );
            }
            assert_eq!(
                Self::get_enum_variant_names().len(),
                sandbox_metric_definitions.len()
            );
        }

        /// Gets a named int gauge metric
        fn get_intguage_metric(name: &str) -> Result<&IntGauge> {
            Self::get_metrics()
                .get()
                .ok_or_else(|| new_error!("metrics hashmap not initialized"))?
                .get(name)
                .ok_or_else(|| new_error!("metric not found : {0:?}", name))?
                .try_into()
        }

        /// Gets a named int counter vec metric
        fn get_intcountervec_metric(name: &str) -> Result<&IntCounterVec> {
            Self::get_metrics()
                .get()
                .ok_or_else(|| new_error!("metrics hashmap not initialized"))?
                .get(name)
                .ok_or_else(|| new_error!("metric not found : {0:?}", name))?
                .try_into()
        }

        /// Gets a named int counter metric
        fn get_intcounter_metric(name: &str) -> Result<&IntCounter> {
            Self::get_metrics()
                .get()
                .ok_or_else(|| new_error!("metrics hashmap not initialized"))?
                .get(name)
                .ok_or_else(|| new_error!("metric not found : {0:?}", name))?
                .try_into()
        }

        /// Gets a named histogram vec metric
        fn get_histogramvec_metric(name: &str) -> Result<&HistogramVec> {
            Self::get_metrics()
                .get()
                .ok_or_else(|| new_error!("metrics hashmap not initialized"))?
                .get(name)
                .ok_or_else(|| new_error!("metric not found : {0:?}", name))?
                .try_into()
        }
    }
}
