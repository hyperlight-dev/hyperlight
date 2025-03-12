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

use prometheus::core::{AtomicI64, GenericGauge};
use prometheus::register_int_gauge_with_registry;
use tracing::{Span, instrument};

use super::{
    GetHyperlightMetric, HyperlightMetric, HyperlightMetricOps, get_metric_opts,
    get_metrics_registry,
};
use crate::{HyperlightError, Result, new_error};

/// A gauge backed by an `AtomicI64`
#[derive(Debug)]
pub struct IntGauge {
    gauge: GenericGauge<AtomicI64>,
    /// The name of the gauge
    pub name: &'static str,
}

impl IntGauge {
    /// Creates a new gauge and registers it with the metric registry
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(name: &'static str, help: &str) -> Result<Self> {
        let registry = get_metrics_registry();
        let opts = get_metric_opts(name, help);
        let gauge = register_int_gauge_with_registry!(opts, registry)?;
        Ok(Self { gauge, name })
    }
    /// Increments a gauge by 1
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc(&self) {
        self.gauge.inc();
    }
    /// Decrements a gauge by 1
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn dec(&self) {
        self.gauge.dec();
    }
    /// Gets the value of a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn set(&self, val: i64) {
        self.gauge.set(val);
    }
    /// Resets a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get(&self) -> i64 {
        self.gauge.get()
    }
    /// Adds a value to a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn add(&self, val: i64) {
        self.gauge.add(val);
    }
    /// Subtracts a value from a gauge
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn sub(&self, val: i64) {
        self.gauge.sub(val)
    }
}

impl<S: HyperlightMetricOps> GetHyperlightMetric<IntGauge> for S {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn metric(&self) -> Result<&IntGauge> {
        let metric = self.get_metric()?;
        <&HyperlightMetric as TryInto<&IntGauge>>::try_into(metric)
    }
}

impl<'a> TryFrom<&'a HyperlightMetric> for &'a IntGauge {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(metric: &'a HyperlightMetric) -> Result<Self> {
        match metric {
            HyperlightMetric::IntGauge(gauge) => Ok(gauge),
            _ => Err(new_error!("metric is not a IntGauge")),
        }
    }
}

impl From<IntGauge> for HyperlightMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(gauge: IntGauge) -> Self {
        HyperlightMetric::IntGauge(gauge)
    }
}

/// Increments an IntGauge by 1 or logs an error if the metric is not found
#[macro_export]
macro_rules! int_gauge_inc {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.inc(),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Decrements an IntGauge by 1 or logs an error if the metric is not found
#[macro_export]
macro_rules! int_gauge_dec {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.dec(),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Sets an IntGauge to value or logs an error if the metric is not found
#[macro_export]
macro_rules! int_gauge_set {
    ($metric:expr_2021, $val:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.set($val),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Gets the value of an IntGauge logs an error
/// and returns 0 if the metric is not found
#[macro_export]
macro_rules! int_gauge_get {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.get(),
            Err(e) => {
                log::error!("error getting metric: {}", e);
                0
            }
        }
    }};
}

/// Adds a value to an IntGauge or logs an error if the metric is not found
#[macro_export]
macro_rules! int_gauge_add {
    ($metric:expr_2021, $val:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.add($val),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Subtracts a value from an IntGauge or logs an error if the metric is not found
#[macro_export]
macro_rules! int_gauge_sub {
    ($metric:expr_2021, $val:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntGauge>::metric($metric) {
            Ok(val) => val.sub($val),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}
