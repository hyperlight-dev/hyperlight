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

use serde_json::{Map, Value};

use crate::{new_error, Result};

/// Call `check_value_as_str` and panic if it returned an `Err`. Otherwise,
/// do nothing.
#[track_caller]
pub(crate) fn test_value_as_str(values: &Map<String, Value>, key: &str, expected_value: &str) {
    if let Err(e) = check_value_as_str(values, key, expected_value) {
        panic!("{e:?}");
    }
}

/// Check to see if the value in `values` for key `key` matches
/// `expected_value`. If so, return `Ok(())`. Otherwise, return an `Err`
/// indicating the mismatch.
pub(crate) fn check_value_as_str(
    values: &Map<String, Value>,
    key: &str,
    expected_value: &str,
) -> Result<()> {
    let value = try_to_string(values, key)?;
    if expected_value != value {
        return Err(new_error!(
            "expected value {} != value {}",
            expected_value,
            value
        ));
    }
    Ok(())
}

/// Fetch the value in `values` with key `key` and, if it existed, convert
/// it to a string. If all those steps succeeded, return an `Ok` with the
/// string value inside. Otherwise, return an `Err`.
fn try_to_string<'a>(values: &'a Map<String, Value>, key: &'a str) -> Result<&'a str> {
    if let Some(value) = values.get(key) {
        if let Some(value_str) = value.as_str() {
            Ok(value_str)
        } else {
            Err(new_error!("value with key {} was not a string", key))
        }
    } else {
        Err(new_error!("value for key {} was not found", key))
    }
}

#[cfg(feature = "build-metadata")]
pub(crate) mod build_metadata_testing {
    use super::*;

    /// A single value in the parameter list for the `try_to_strings`
    /// function.
    pub(crate) type MapLookup<'a> = (&'a Map<String, Value>, &'a str);

    /// Given a constant-size slice of `MapLookup`s, attempt to look up the
    /// string value in each `MapLookup`'s map (the first tuple element) for
    /// that `MapLookup`'s key (the second tuple element). If the lookup
    /// succeeded, attempt to convert the resulting value to a string. Return
    /// `Ok` with all the successfully looked-up string values, or `Err`
    /// if any one or more lookups or string conversions failed.
    pub(crate) fn try_to_strings<'a, const NUM: usize>(
        lookups: [MapLookup<'a>; NUM],
    ) -> Result<[&'a str; NUM]> {
        // Note (from arschles) about this code:
        //
        // In theory, there's a way to write this function in the functional
        // programming (FP) style -- e.g. with a fold, map, flat_map, or
        // something similar -- and without any mutability.
        //
        // In practice, however, since we're taking in a statically-sized slice,
        // and we are expected to return a statically-sized slice of the same
        // size, we are more limited in what we can do. There is a way to design
        // a fold or flat_map to iterate over the lookups parameter and attempt to
        // transform each MapLookup into the string value at that key.
        //
        // I wrote that code, which I'll called the "FP code" hereafter, and
        // noticed two things:
        //
        // - It required several places where I had to explicitly deal with long
        // and complex (in my opinion) types
        // - It wasn't much more succinct or shorter than the code herein
        //
        // The FP code is functionally "pure" and maybe fun to write (if you like
        // Rust or you love FP), but not fun to read. In fact, because of all the
        // explicit type ceremony, I bet it'd make even the most hardcore Haskell
        // programmer blush.
        //
        // So, I've decided to use a little bit of mutability to implement this
        // function in a way I think most programmers would agree is easier to
        // reason about and understand quickly.
        //
        // Final performance note:
        //
        // It's likely, but not certain, that the FP code is probably not
        // significantly more memory efficient than this, since the compiler knows
        // the size of both the input and output slices. Plus, this is test code,
        // so even if this were 2x slower, I'd still argue the ease of
        // understanding is more valuable than the (relatively small) memory
        // savings.
        let mut ret_slc: [&'a str; NUM] = [""; NUM];
        for (idx, lookup) in lookups.iter().enumerate() {
            let map = lookup.0;
            let key = lookup.1;
            let val = try_to_string(map, key)?;
            ret_slc[idx] = val
        }
        Ok(ret_slc)
    }
}
