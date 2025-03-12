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

use prometheus::core::{AtomicI64, GenericGaugeVec};
use prometheus::register_int_gauge_vec_with_registry;
use tracing::{Span, instrument};

use super::{
    GetHyperlightMetric, HyperlightMetric, HyperlightMetricOps, get_metric_opts,
    get_metrics_registry,
};
use crate::{HyperlightError, Result, new_error};

/// A list of gauges, each backed by an `AtomicI64`
#[derive(Debug)]
pub struct IntGaugeVec {
    gauge: GenericGaugeVec<AtomicI64>,
    /// The name of the gauge vec
    pub name: &'static str,
}

impl IntGaugeVec {
    /// Creates a new gauge vec and registers it with the metric registry
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(name: &'static str, help: &str, labels: &[&str]) -> Result<Self> {
        let registry = get_metrics_registry();
        let opts = get_metric_opts(name, help);
        let gauge = register_int_gauge_vec_with_registry!(opts, labels, registry)?;
        Ok(Self { gauge, name })
    }
    /// Increments a gauge by 1
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc(&self, label_vals: &[&str]) {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .inc();
    }
    /// Decrements a gauge by 1
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn dec(&self, label_vals: &[&str]) {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .dec();
    }
    /// Gets the value of a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get(&self, label_vals: &[&str]) -> i64 {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .get()
    }
    /// Resets a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set(&self, label_vals: &[&str], val: i64) {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .set(val);
    }
    /// Adds a value to a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn add(&self, label_vals: &[&str], val: i64) {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .add(val);
    }
    /// Subtracts a value from a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn sub(&self, label_vals: &[&str], val: i64) {
        self.gauge
            .get_metric_with_label_values(label_vals)
            .unwrap()
            .sub(val);
    }
}

impl<S: HyperlightMetricOps> GetHyperlightMetric<IntGaugeVec> for S {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn metric(&self) -> Result<&IntGaugeVec> {
        let metric = self.get_metric()?;
        <&HyperlightMetric as TryInto<&IntGaugeVec>>::try_into(metric)
    }
}

impl<'a> TryFrom<&'a HyperlightMetric> for &'a IntGaugeVec {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(metric: &'a HyperlightMetric) -> Result<Self> {
        match metric {
            HyperlightMetric::IntGaugeVec(gauge) => Ok(gauge),
            _ => Err(new_error!("metric is not a IntGaugeVec")),
        }
    }
}

impl From<IntGaugeVec> for HyperlightMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(gauge: IntGaugeVec) -> Self {
        HyperlightMetric::IntGaugeVec(gauge)
    }
}
