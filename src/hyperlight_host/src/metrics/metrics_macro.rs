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

/// Crate-internal trait for defining metrics.
pub(crate) trait NamedMetric {
    /// The name of the metric.
    fn name(&self) -> &'static str;
    /// The description of the metric.
    fn description(&self) -> &'static str;
    /// The unit of the metric.
    fn unit(&self) -> metrics::Unit;
}

/// A macro to define metrics with variants and optional fields.
#[macro_export]
macro_rules! define_metrics {
    (
        $(
            $metric_type:ident $( < $( $gen:tt ),+ > )? {
                $(
                    $variant:ident $( { $($field_name:ident : $field_ty:ty),* $(,)? } )? => {
                        name: $name:expr,
                        description: $description:expr,
                        unit: $unit:expr $(,)?
                    }
                ),* $(,)?
            }
        )*
    ) => {
        $(
            #[derive(Debug, Clone)]
            #[allow(dead_code)]
            pub(crate) enum $metric_type $( < $( $gen ),+ > )? {
                $(
                    $variant $( { $($field_name : $field_ty),* } )?
                ),*
            }

            impl $( < $( $gen ),+ > )? $crate::metrics::metrics_macro::NamedMetric for $metric_type $( < $( $gen ),+ > )? {
                fn name(&self) -> &'static str {
                    match self {
                        $(
                            Self::$variant { .. } => $name,
                        )*
                    }
                }

                fn description(&self) -> &'static str {
                    match self {
                        $(
                            Self::$variant { .. } => $description,
                        )*
                    }
                }

                fn unit(&self) -> metrics::Unit {
                    match self {
                        $(
                            Self::$variant { .. } => $unit,
                        )*
                    }
                }
            }
        )*
    };
}
