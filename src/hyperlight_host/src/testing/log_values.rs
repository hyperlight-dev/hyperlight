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

use serde_json::{Map, Value};

use crate::{Result, new_error};

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
