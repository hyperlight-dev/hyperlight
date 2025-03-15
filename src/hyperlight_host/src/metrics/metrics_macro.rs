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
                    $( #[cfg($feature:meta)] )?
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
                    $( #[cfg($feature)] )?
                    $variant $( { $($field_name : $field_ty),* } )?
                ),*
            }

            impl $( < $( $gen ),+ > )? $crate::metrics::metrics_macro::NamedMetric for $metric_type $( < $( $gen ),+ > )? {
                fn name(&self) -> &'static str {
                    match self {
                        $(
                            $( #[cfg($feature)] )?
                            Self::$variant { .. } => $name,
                        )*
                    }
                }

                fn description(&self) -> &'static str {
                    match self {
                        $(
                            $( #[cfg($feature)] )?
                            Self::$variant { .. } => $description,
                        )*
                    }
                }

                fn unit(&self) -> metrics::Unit {
                    match self {
                        $(
                            $( #[cfg($feature)] )?
                            Self::$variant { .. } => $unit,
                        )*
                    }
                }
            }
        )*
    };
}
