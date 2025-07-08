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

use std::marker::PhantomData;

use super::sandbox::Sandbox;

/// Transition metadata that contains and does nothing. `Noop` is a
/// placeholder when you want to implement an `EvolvableSandbox`
/// that needs no additional metadata to succeed.
///
/// Construct one of these by using the `default()` method.
pub struct Noop<Cur: Sandbox, Next: Sandbox> {
    cur_ph: PhantomData<Cur>,
    next_ph: PhantomData<Next>,
}

impl<Cur: Sandbox, Next: Sandbox> Default for Noop<Cur, Next> {
    fn default() -> Self {
        Self {
            cur_ph: PhantomData,
            next_ph: PhantomData,
        }
    }
}
