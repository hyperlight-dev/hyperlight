// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

// This, unlike the rest of hyperlight, isn't really a library (since
// it's only used by our own build-time tools), so the reasons not to
// panic don't really apply.
#![allow(clippy::unwrap_used)]
// "Needless" lifetimes are useful for clarity
#![allow(clippy::needless_lifetimes)]

// Typechecking and elaboration
pub mod component;
pub mod elaborate;
pub mod etypes;
pub mod structure;
pub mod substitute;
pub mod subtype;
pub mod tv;
pub mod wf;

// Generally useful for code emit
pub mod emit;
pub mod hl;
pub mod resource;
pub mod rtypes;
pub mod util;

// Specific code emit
pub mod guest;
pub mod host;
