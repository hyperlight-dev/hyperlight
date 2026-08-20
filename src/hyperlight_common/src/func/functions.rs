// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use super::utils::for_each_tuple;
use super::{Error, ParameterTuple, ResultType, SupportedReturnType};

pub trait Function<Output: SupportedReturnType, Args: ParameterTuple, E: From<Error>> {
    fn call(&self, args: Args) -> Result<Output, E>;
}

macro_rules! impl_function {
    ([$N:expr] ($($p:ident: $P:ident),*)) => {
        impl<F, R, E, $($P),*> Function<R::ReturnType, ($($P,)*), E> for F
        where
            F: Fn($($P),*) -> R,
            ($($P,)*): ParameterTuple,
            R: ResultType<E>,
            E: From<Error> + core::fmt::Debug,
        {
            fn call(&self, ($($p,)*): ($($P,)*)) -> Result<R::ReturnType, E> {
                (self)($($p),*).into_result()
            }
        }
    };
}

for_each_tuple!(impl_function);
