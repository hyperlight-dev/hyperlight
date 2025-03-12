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

use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::register_int_counter_with_registry;
use tracing::{Span, instrument};

use super::{
    GetHyperlightMetric, HyperlightMetric, HyperlightMetricOps, get_metric_opts,
    get_metrics_registry,
};
use crate::{HyperlightError, Result, new_error};

/// A named counter backed by an `AtomicU64`
#[derive(Debug)]
pub struct IntCounter {
    counter: GenericCounter<AtomicU64>,
    /// The name of the counter
    pub name: &'static str,
}

impl IntCounter {
    /// Creates a new counter and registers it with the metric registry
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(name: &'static str, help: &str) -> Result<Self> {
        let registry = get_metrics_registry();
        let opts = get_metric_opts(name, help);
        let counter = register_int_counter_with_registry!(opts, registry)?;
        Ok(Self { counter, name })
    }
    /// Increments a counter by 1
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc(&self) {
        self.counter.inc();
    }
    /// Increments a counter by a value
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc_by(&self, val: u64) {
        self.counter.inc_by(val);
    }
    /// Gets the value of a counter
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn get(&self) -> u64 {
        self.counter.get()
    }
    /// Resets a counter
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    pub fn reset(&self) {
        self.counter.reset();
    }
}

impl<S: HyperlightMetricOps> GetHyperlightMetric<IntCounter> for S {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn metric(&self) -> Result<&IntCounter> {
        let metric = self.get_metric()?;
        <&HyperlightMetric as TryInto<&IntCounter>>::try_into(metric)
    }
}

impl<'a> TryFrom<&'a HyperlightMetric> for &'a IntCounter {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(metric: &'a HyperlightMetric) -> Result<Self> {
        match metric {
            HyperlightMetric::IntCounter(counter) => Ok(counter),
            _ => Err(new_error!("metric is not a IntCounter")),
        }
    }
}

impl From<IntCounter> for HyperlightMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(counter: IntCounter) -> Self {
        HyperlightMetric::IntCounter(counter)
    }
}

/// Increments an IntCounter by 1 or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_inc {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounter>::metric($metric) {
            Ok(val) => val.inc(),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Increments an IntCounter by a given value or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_inc_by {
    ($metric:expr_2021, $val:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounter>::metric($metric) {
            Ok(val) => val.inc_by($val),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Gets the value of an IntCounter or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_get {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounter>::metric($metric) {
            Ok(val) => val.get(),
            Err(e) => {
                log::error!("error getting metric: {}", e);
                0
            }
        }
    }};
}

/// Resets an IntCounter or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_reset {
    ($metric:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounter>::metric($metric) {
            Ok(val) => val.reset(),
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}
