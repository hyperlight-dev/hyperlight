/*
Copyright 2025 The Hyperlight Authors.

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

/// An utility macro to execute a macro for each tuple of parameters
/// up to 32 parameters. This is useful to implement traits on functions
/// for may parameter tuples.
///
/// Usage:
/// ```rust
/// use hyperlight_host::func::for_each_tuple;
///
/// macro_rules! my_macro {
///     ([$count:expr] ($($name:ident: $type:ident),*)) => {
///         // $count is the arity of the tuple
///         // $name is the name of the parameter: p1, p2, ..., p$count
///         // $type is the type of the parameter: P1, P2, ..., P$count
///     };
/// }
///
/// for_each_tuple!(impl_host_function);
/// ```
macro_rules! for_each_tuple {
    (@
        $macro:ident
        [$count:expr]
        [
            $($param_id:ident: $param_ty:ident),*
        ]
        []
    ) => {
        $macro!([$count] ($($param_id: $param_ty),*));
    };
    (@
        $macro:ident
        [$count:expr]
        [
            $($param_id:ident: $param_ty:ident),*
        ]
        [
            $first_ident:ident: $first_type:ident
            $(, $rest_ident:ident: $rest_type:ident)*
            $(,)?
        ]
    ) => {
        $macro!([$count] ($($param_id: $param_ty),*));
        for_each_tuple!(@
            $macro
            [$count + 1]
            [
                $($param_id: $param_ty, )*
                $first_ident: $first_type
            ]
            [
                $($rest_ident: $rest_type),*
            ]
        );
    };
    ($macro:ident) => {
        for_each_tuple!(@ $macro [0] [] [
            p1:  P1,  p2:  P2,  p3:  P3,  p4:  P4,  p5:  P5,  p6:  P6,  p7:  P7,  p8:  P8,
            p9:  P9,  p10: P10, p11: P11, p12: P12, p13: P13, p14: P14, p15: P15, p16: P16,
            p17: P17, p18: P18, p19: P19, p20: P20, p21: P21, p22: P22, p23: P23, p24: P24,
            p25: P25, p26: P26, p27: P27, p28: P28, p29: P29, p30: P30, p31: P31, p32: P32,
        ]);
    };
}

pub(super) use for_each_tuple;
