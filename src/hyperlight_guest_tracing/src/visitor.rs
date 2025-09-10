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

use core::fmt::Debug;

use heapless as hl;
use tracing_core::field::{Field, Visit};

/// Visitor implementation to collect fields into a vector of key-value pairs
pub(crate) struct FieldsVisitor<'a, const FK: usize, const FV: usize, const F: usize> {
    pub out: &'a mut hl::Vec<(hl::String<FK>, hl::String<FV>), F>,
}

impl<const FK: usize, const FV: usize, const F: usize> Visit for FieldsVisitor<'_, FK, FV, F> {
    /// Record a byte slice field
    /// # Arguments
    /// * `field` - The field metadata
    /// * `value` - The byte slice value
    ///   NOTE: This implementation truncates the key and value if they exceed the allocated capacity
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        let mut k = hl::String::<FK>::new();
        let mut val = hl::String::<FV>::new();
        // Shorten key and value if they are bigger than the space allocated
        let _ = k.push_str(&field.name()[..usize::min(field.name().len(), k.capacity())]);
        let _ =
            val.push_str(&alloc::format!("{value:?}")[..usize::min(value.len(), val.capacity())]);
        let _ = self.out.push((k, val));
    }

    /// Record a string field
    /// # Arguments
    /// * `f` - The field metadata
    /// * `v` - The string value
    ///   NOTE: This implementation truncates the key and value if they exceed the allocated capacity
    fn record_str(&mut self, f: &Field, v: &str) {
        let mut k = heapless::String::<FK>::new();
        let mut val = heapless::String::<FV>::new();
        // Shorten key and value if they are bigger than the space allocated
        let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
        let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
        let _ = self.out.push((k, val));
    }

    /// Record a debug field
    /// # Arguments
    /// * `f` - The field metadata
    /// * `v` - The debug value
    ///   NOTE: This implementation truncates the key and value if they exceed the allocated capacity
    fn record_debug(&mut self, f: &Field, v: &dyn Debug) {
        use heapless::String;
        let mut k = String::<FK>::new();
        let mut val = String::<FV>::new();
        // Shorten key and value if they are bigger than the space allocated
        let _ = k.push_str(&f.name()[..usize::min(f.name().len(), k.capacity())]);
        let v = alloc::format!("{v:?}");
        let _ = val.push_str(&v[..usize::min(v.len(), val.capacity())]);
        let _ = self.out.push((k, val));
    }
}
