// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

//! Decodes arbitrary function calls, results and logs from untrusted control
//! data and external bytes. Calls and results accept their readers into one
//! host Mux.

#![no_main]

use hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use hyperlight_common::flatbuffer_wrappers::function_types::{Bytes, FunctionCallResult};
use hyperlight_common::flatbuffer_wrappers::guest_log_data::GuestLogData;
use hyperlight_common::stream::{DEFAULT_WINDOW, Mux, Side};
use hyperlight_common::virtq::Segments;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((split, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let split = usize::from(u16::from_le_bytes(*split)).min(rest.len());
    let (control, external) = rest.split_at(split);

    let mut mux = Mux::new(Side::Host, DEFAULT_WINDOW);

    let mut source = Segments::single(Bytes::copy_from_slice(external));
    let _ = FunctionCall::decode(control, &mut source, &mut mux);

    let mut source = Segments::single(Bytes::copy_from_slice(external));
    let _ = FunctionCallResult::decode(control, &mut source, &mut mux);

    let _ = GuestLogData::try_from(control);
});
