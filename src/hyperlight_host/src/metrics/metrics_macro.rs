pub(crate) trait NamedMetric {
    /// Returns the name of the metric as a static string
    fn name(&self) -> &'static str;
}

/// A macro to define metrics with variants and optional fields.
#[macro_export]
macro_rules! define_metrics {
    (
        $( $metric_type:ident {
            $(
                $( #[cfg($feature:meta)] )?
                $variant:ident $( { $($field_name:ident : $field_ty:ty),* } )? => $name:expr
            ),* $(,)?
        } )*
    ) => {
        $(
            #[derive(Debug, Clone)]
            pub(crate) enum $metric_type {
                $(
                    $( #[cfg($feature)] )?
                    $variant $( { $($field_name : $field_ty),* } )?
                ),*
            }

            impl $crate::metrics::metrics_macro::NamedMetric for $metric_type {
                fn name(&self) -> &'static str {
                    match self {
                        $(
                            $( #[cfg($feature)] )?
                            Self::$variant{..} => $name,
                        )*
                    }
                }
            }
        )*
    };
}
