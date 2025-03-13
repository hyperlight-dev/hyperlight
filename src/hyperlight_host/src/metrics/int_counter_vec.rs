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

use prometheus::core::{AtomicU64, GenericCounterVec};
use prometheus::register_int_counter_vec_with_registry;
use tracing::{Span, instrument};

use super::{
    GetHyperlightMetric, HyperlightMetric, HyperlightMetricOps, get_metric_opts,
    get_metrics_registry,
};
use crate::{HyperlightError, Result, new_error};

/// A 64-bit counter
#[derive(Debug)]
pub struct IntCounterVec {
    counter: GenericCounterVec<AtomicU64>,
    /// The name of the counter
    pub name: &'static str,
}

impl IntCounterVec {
    /// Creates a new counter and registers it with the metric registry
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(name: &'static str, help: &str, labels: &[&str]) -> Result<Self> {
        let registry = get_metrics_registry();
        let opts = get_metric_opts(name, help);
        let counter = register_int_counter_vec_with_registry!(opts, labels, registry)?;
        Ok(Self { counter, name })
    }
    /// Increments a counter by 1
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc(&self, label_vals: &[&str]) -> Result<()> {
        self.counter.get_metric_with_label_values(label_vals)?.inc();
        Ok(())
    }
    /// Increments a counter by a value
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn inc_by(&self, label_vals: &[&str], val: u64) -> Result<()> {
        self.counter
            .get_metric_with_label_values(label_vals)?
            .inc_by(val);
        Ok(())
    }
    /// Gets the value of a counter
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn get(&self, label_vals: &[&str]) -> Result<u64> {
        Ok(self.counter.get_metric_with_label_values(label_vals)?.get())
    }
    /// Resets a counter
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn reset(&self, label_vals: &[&str]) -> Result<()> {
        self.counter
            .get_metric_with_label_values(label_vals)?
            .reset();
        Ok(())
    }
}

impl<S: HyperlightMetricOps> GetHyperlightMetric<IntCounterVec> for S {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn metric(&self) -> Result<&IntCounterVec> {
        let metric = self.get_metric()?;
        <&HyperlightMetric as TryInto<&IntCounterVec>>::try_into(metric)
    }
}

impl<'a> TryFrom<&'a HyperlightMetric> for &'a IntCounterVec {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(metric: &'a HyperlightMetric) -> Result<Self> {
        match metric {
            HyperlightMetric::IntCounterVec(counter) => Ok(counter),
            _ => Err(new_error!("metric is not a IntCounterVec")),
        }
    }
}

impl From<IntCounterVec> for HyperlightMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(counter: IntCounterVec) -> Self {
        HyperlightMetric::IntCounterVec(counter)
    }
}

/// Increments an IntCounterVec by 1 or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_vec_inc {
    ($metric:expr, $label_vals:expr) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounterVec>::metric(
            $metric,
        ) {
            Ok(val) => {
                if let Err(e) = val.inc($label_vals) {
                    log::error!(
                        "error incrementing metric with labels: {} {:?}",
                        e,
                        $label_vals
                    )
                }
            }
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Increments an IntCounterVec by a value or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_vec_inc_by {
    ($metric:expr, $label_vals:expr, $val:expr) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounterVec>::metric(
            $metric,
        ) {
            Ok(val) => {
                if let Err(e) = val.inc_by($label_vals, $val) {
                    log::error!(
                        "error incrementing metric by {} with labels: {} {:?}",
                        $val,
                        e,
                        $label_vals
                    )
                }
            }
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}

/// Gets the value of an IntCounterVec or logs an error if the metric is not found
/// Returns 0 if the metric is not found
#[macro_export]
macro_rules! int_counter_vec_get {
    ($metric:expr, $label_vals:expr) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounterVec>::metric(
            $metric,
        ) {
            Ok(val) => match val.get($label_vals) {
                Ok(val) => val,
                Err(e) => {
                    log::error!("error getting metric with labels: {} {:?}", e, $label_vals);
                    0
                }
            },

            Err(e) => {
                log::error!("error getting metric: {}", e);
                0
            }
        }
    }};
}

/// Resets an IntCounterVec or logs an error if the metric is not found
#[macro_export]
macro_rules! int_counter_vec_reset {
    ($metric:expr, $label_vals:expr) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::IntCounterVec>::metric(
            $metric,
        ) {
            Ok(val) => {
                if let Err(e) = val.reset($label_vals) {
                    log::error!(
                        "error resetting metric with labels: {} {:?}",
                        e,
                        $label_vals
                    )
                }
            }
            Err(e) => log::error!("error getting metric: {}", e),
        };
    }};
}
