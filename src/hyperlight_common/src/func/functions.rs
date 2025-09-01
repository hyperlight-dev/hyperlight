/*
Copyright 2025  The Hyperlight Authors.

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
            E: From<Error>,
        {
            fn call(&self, ($($p,)*): ($($P,)*)) -> Result<R::ReturnType, E> {
                (self)($($p),*).into_result()
            }
        }
    };
}

for_each_tuple!(impl_function);
