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

use prometheus::{HistogramVec as PHistogramVec, register_histogram_vec_with_registry};
use tracing::{Span, instrument};

use super::{
    GetHyperlightMetric, HyperlightMetric, HyperlightMetricOps, get_histogram_opts,
    get_metrics_registry,
};
use crate::{HyperlightError, Result, new_error};

/// A named bundle of histograms
#[derive(Debug)]
pub struct HistogramVec {
    histogram: PHistogramVec,
    /// The name of the histogram vec
    pub name: &'static str,
}

impl HistogramVec {
    /// Creates a new histogram vec and registers it with the metric registry
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn new(name: &'static str, help: &str, labels: &[&str], buckets: Vec<f64>) -> Result<Self> {
        let registry = get_metrics_registry();
        let opts = get_histogram_opts(name, help, buckets);
        let histogram = register_histogram_vec_with_registry!(opts, labels, registry)?;
        Ok(Self { histogram, name })
    }

    /// Observes a value for a HistogramVec
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn observe(&self, label_vals: &[&str], val: f64) -> Result<()> {
        self.histogram
            .get_metric_with_label_values(label_vals)?
            .observe(val);
        Ok(())
    }

    /// Gets the sum of values of an HistogramVec
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_sample_sum(&self, label_vals: &[&str]) -> Result<f64> {
        Ok(self
            .histogram
            .get_metric_with_label_values(label_vals)?
            .get_sample_sum())
    }

    /// Gets the count of values of an HistogramVec
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    pub fn get_sample_count(&self, label_vals: &[&str]) -> Result<u64> {
        Ok(self
            .histogram
            .get_metric_with_label_values(label_vals)?
            .get_sample_count())
    }
}

impl<S: HyperlightMetricOps> GetHyperlightMetric<HistogramVec> for S {
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn metric(&self) -> Result<&HistogramVec> {
        let metric = self.get_metric()?;
        <&HyperlightMetric as TryInto<&HistogramVec>>::try_into(metric)
    }
}

impl<'a> TryFrom<&'a HyperlightMetric> for &'a HistogramVec {
    type Error = HyperlightError;
    #[instrument(err(Debug), skip_all, parent = Span::current(), level= "Trace")]
    fn try_from(metric: &'a HyperlightMetric) -> Result<Self> {
        match metric {
            HyperlightMetric::HistogramVec(histogram) => Ok(histogram),
            _ => Err(new_error!("metric is not a HistogramVec")),
        }
    }
}

impl From<HistogramVec> for HyperlightMetric {
    #[instrument(skip_all, parent = Span::current(), level= "Trace")]
    fn from(histogram_vec: HistogramVec) -> Self {
        HyperlightMetric::HistogramVec(histogram_vec)
    }
}

/// Observes a value for a HistogramVec
#[macro_export]
macro_rules! histogram_vec_observe {
    ($metric:expr_2021, $label_vals:expr_2021, $val:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::HistogramVec>::metric($metric)
        {
            Ok(val) => {
                if let Err(e) = val.observe($label_vals, $val) {
                    log::error!(
                        "error calling observe with {} on metric with labels: {} {:?}",
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

/// Gets the sum of values of an HistogramVec or logs an error if the metric is not found
/// Returns 0.0 if the metric is not found
#[macro_export]
macro_rules! histogram_vec_sample_sum {
    ($metric:expr_2021, $label_vals:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::HistogramVec>::metric($metric)
        {
            Ok(val) => match val.get_sample_sum($label_vals) {
                Ok(val) => val,
                Err(e) => {
                    log::error!(
                        "error getting samples sum of metric with labels: {} {:?}",
                        e,
                        $label_vals
                    );
                    0.0
                }
            },

            Err(e) => {
                log::error!("error getting metric: {}", e);
                0.0
            }
        }
    }};
}

/// Gets the count of values of an HistogramVec or logs an error if the metric is not found
/// Returns 0 if the metric is not found
#[macro_export]
macro_rules! histogram_vec_sample_count {
    ($metric:expr_2021, $label_vals:expr_2021) => {{
        match $crate::metrics::GetHyperlightMetric::<$crate::metrics::HistogramVec>::metric($metric)
        {
            Ok(val) => match val.get_sample_count($label_vals) {
                Ok(val) => val,
                Err(e) => {
                    log::error!(
                        "error getting samples count of metric with labels: {} {:?}",
                        e,
                        $label_vals
                    );
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

/// Observe the time it takes to execute an expression, record that time in microseconds in a
/// `HistogramVec`, and return the result of that expression
#[macro_export]
macro_rules! histogram_vec_time_micros {
    ($metric:expr_2021, $label_vals:expr_2021, $expr:expr_2021) => {{
        let start = std::time::Instant::now();
        let result = $expr;
        $crate::histogram_vec_observe!($metric, $label_vals, start.elapsed().as_micros() as f64);
        result
    }};
}
