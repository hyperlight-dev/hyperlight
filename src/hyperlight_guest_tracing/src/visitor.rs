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
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

use hyperlight_common::flatbuffer_wrappers::guest_trace_data::EventKeyValue;
use tracing_core::field::{Field, Visit};

/// Visitor implementation to collect fields into a vector of key-value pairs
pub(crate) struct FieldsVisitor<'a> {
    pub out: &'a mut Vec<EventKeyValue>,
}

impl<'a> Visit for FieldsVisitor<'a> {
    /// Record a byte slice field
    /// # Arguments
    /// * `field` - The field metadata
    /// * `value` - The byte slice value
    fn record_bytes(&mut self, f: &Field, v: &[u8]) {
        let k = String::from(f.name());
        let val = alloc::format!("{v:?}");
        self.out.push(EventKeyValue { key: k, value: val });
    }

    /// Record a string field
    /// # Arguments
    /// * `f` - The field metadata
    /// * `v` - The string value
    fn record_str(&mut self, f: &Field, v: &str) {
        let k = String::from(f.name());
        let val = String::from(v);
        self.out.push(EventKeyValue { key: k, value: val });
    }

    /// Record a debug field
    /// # Arguments
    /// * `f` - The field metadata
    /// * `v` - The debug value
    fn record_debug(&mut self, f: &Field, v: &dyn Debug) {
        let k = String::from(f.name());
        let val = alloc::format!("{v:?}");
        self.out.push(EventKeyValue { key: k, value: val });
    }
}
