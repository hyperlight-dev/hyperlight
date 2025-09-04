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

#![no_std]
#![no_main]

extern crate alloc;
extern crate hyperlight_guest;

use alloc::string::String;

use spin::Mutex;

mod bindings;
use bindings::*;

struct Guest {
    host_resource: Option<<Host as Testresource>::T>,
}

impl test::wit::Roundtrip for Guest {
    fn roundtrip_bool(&mut self, x: bool) -> bool {
        (Host {}).roundtrip_bool(x)
    }
    fn roundtrip_s8(&mut self, x: i8) -> i8 {
        (Host {}).roundtrip_s8(x)
    }
    fn roundtrip_s16(&mut self, x: i16) -> i16 {
        (Host {}).roundtrip_s16(x)
    }
    fn roundtrip_s32(&mut self, x: i32) -> i32 {
        (Host {}).roundtrip_s32(x)
    }
    fn roundtrip_s64(&mut self, x: i64) -> i64 {
        (Host {}).roundtrip_s64(x)
    }
    fn roundtrip_u8(&mut self, x: u8) -> u8 {
        (Host {}).roundtrip_u8(x)
    }
    fn roundtrip_u16(&mut self, x: u16) -> u16 {
        (Host {}).roundtrip_u16(x)
    }
    fn roundtrip_u32(&mut self, x: u32) -> u32 {
        (Host {}).roundtrip_u32(x)
    }
    fn roundtrip_u64(&mut self, x: u64) -> u64 {
        (Host {}).roundtrip_u64(x)
    }
    fn roundtrip_f32(&mut self, x: f32) -> f32 {
        (Host {}).roundtrip_f32(x)
    }
    fn roundtrip_f64(&mut self, x: f64) -> f64 {
        (Host {}).roundtrip_f64(x)
    }
    fn roundtrip_char(&mut self, x: char) -> char {
        (Host {}).roundtrip_char(x)
    }
    fn roundtrip_string(&mut self, x: alloc::string::String) -> alloc::string::String {
        (Host {}).roundtrip_string(x)
    }
    fn roundtrip_list(&mut self, x: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
        (Host {}).roundtrip_list(x)
    }
    fn roundtrip_tuple(&mut self, x: (alloc::string::String, u8)) -> (alloc::string::String, u8) {
        (Host {}).roundtrip_tuple(x)
    }
    fn roundtrip_option(
        &mut self,
        x: ::core::option::Option<alloc::string::String>,
    ) -> ::core::option::Option<alloc::string::String> {
        (Host {}).roundtrip_option(x)
    }
    fn roundtrip_result(
        &mut self,
        x: ::core::result::Result<char, alloc::string::String>,
    ) -> ::core::result::Result<char, alloc::string::String> {
        (Host {}).roundtrip_result(x)
    }
    fn roundtrip_record(
        &mut self,
        x: test::wit::roundtrip::Testrecord,
    ) -> test::wit::roundtrip::Testrecord {
        (Host {}).roundtrip_record(x)
    }
    fn roundtrip_flags_small(
        &mut self,
        x: test::wit::roundtrip::Smallflags,
    ) -> test::wit::roundtrip::Smallflags {
        (Host {}).roundtrip_flags_small(x)
    }
    fn roundtrip_flags_large(
        &mut self,
        x: test::wit::roundtrip::Largeflags,
    ) -> test::wit::roundtrip::Largeflags {
        (Host {}).roundtrip_flags_large(x)
    }
    fn roundtrip_variant(
        &mut self,
        x: test::wit::roundtrip::Testvariant,
    ) -> test::wit::roundtrip::Testvariant {
        (Host {}).roundtrip_variant(x)
    }
    fn roundtrip_enum(
        &mut self,
        x: test::wit::roundtrip::Testenum,
    ) -> test::wit::roundtrip::Testenum {
        (Host {}).roundtrip_enum(x)
    }
    fn roundtrip_fix_list(&mut self, x: [u8; 4]) -> [u8; 4] {
        (Host {}).roundtrip_fix_list(x)
    }
    fn roundtrip_fix_list_u32(&mut self, x: [u32; 4]) -> [u32; 4] {
        (Host {}).roundtrip_fix_list_u32(x)
    }
    fn roundtrip_fix_list_u64(&mut self, x: [u64; 4]) -> [u64; 4] {
        (Host {}).roundtrip_fix_list_u64(x)
    }
    fn roundtrip_fix_list_i8(&mut self, x: [i8; 4]) -> [i8; 4] {
        (Host {}).roundtrip_fix_list_i8(x)
    }
    fn roundtrip_fix_list_i16(&mut self, x: [i16; 4]) -> [i16; 4] {
        (Host {}).roundtrip_fix_list_i16(x)
    }
    fn roundtrip_fix_list_i32(&mut self, x: [i32; 4]) -> [i32; 4] {
        (Host {}).roundtrip_fix_list_i32(x)
    }
    fn roundtrip_fix_list_i64(&mut self, x: [i64; 4]) -> [i64; 4] {
        (Host {}).roundtrip_fix_list_i64(x)
    }
    fn roundtrip_fix_list_f32(&mut self, x: [f32; 4]) -> [f32; 4] {
        (Host {}).roundtrip_fix_list_f32(x)
    }
    fn roundtrip_fix_list_f64(&mut self, x: [f64; 4]) -> [f64; 4] {
        (Host {}).roundtrip_fix_list_f64(x)
    }
    fn roundtrip_fix_list_u8_size8(&mut self, x: [u8; 8]) -> [u8; 8] {
        (Host {}).roundtrip_fix_list_u8_size8(x)
    }
    fn roundtrip_fix_list_u64_size2(&mut self, x: [u64; 2]) -> [u64; 2] {
        (Host {}).roundtrip_fix_list_u64_size2(x)
    }
    fn roundtrip_fix_list_string(&mut self, x: [String; 4]) -> [String; 4] {
        (Host {}).roundtrip_fix_list_string(x)
    }
    fn roundtrip_fix_array_of_lists(&mut self, x: [Vec<u8>; 3]) -> [Vec<u8>; 3] {
        x
    }
    fn roundtrip_fix_array_of_string_lists(&mut self, x: [Vec<String>; 2]) -> [Vec<String>; 2] {
        x
    }
    fn roundtrip_no_result(&mut self, x: u32) {
        (Host {}).roundtrip_no_result(x)
    }
}

use alloc::string::ToString;

use test::wit::host_resource::Testresource;
impl test::wit::TestHostResource<<Host as Testresource>::T> for Guest {
    fn test_uses_locally(&mut self) -> bool {
        let mut host = Host {};
        let r = <Host as Testresource>::new(&mut host, "str".to_string(), 'z');
        <Host as Testresource>::append_char(&mut host, &r, 'a');
        <Host as Testresource>::append_char(&mut host, &r, 'b');
        let r = <Host as test::wit::HostResource>::roundtrip_own(&mut host, r);
        let r = <Host as test::wit::HostResource>::roundtrip_own(&mut host, r);
        <Host as Testresource>::append_char(&mut host, &r, 'c');
        <Host as test::wit::HostResource>::return_own(&mut host, r);
        true
    }
    fn test_makes(&mut self) -> <Host as Testresource>::T {
        let mut host = Host {};
        <Host as Testresource>::new(&mut host, "str".to_string(), 'z')
    }
    fn test_accepts_borrow(&mut self, r: &<Host as Testresource>::T) {
        let mut host = Host {};
        <Host as Testresource>::append_char(&mut host, r, 'a');
    }
    fn test_accepts_own(&mut self, r: <Host as Testresource>::T) {
        let mut host = Host {};
        // TODO: add test about the old contents of this being
        // dropped, when #810 is fixed.
        <Host as Testresource>::append_char(&mut host, &r, 'b');
        self.host_resource = Some(r);
    }
    fn test_returns(&mut self) -> <Host as Testresource>::T {
        let mut host = Host {};
        let r = self.host_resource.take().unwrap();
        <Host as Testresource>::append_char(&mut host, &r, 'c');
        r
    }
}

#[allow(refining_impl_trait)]
impl test::wit::TestExports<Host> for Guest {
    type Roundtrip = Self;
    fn roundtrip(&mut self) -> &mut Self {
        self
    }
    type TestHostResource = Self;
    fn test_host_resource(&mut self) -> &mut Self {
        self
    }
}

static GUEST_STATE: Mutex<Guest> = Mutex::new(Guest {
    host_resource: None,
});

impl bindings::Guest for Guest {
    fn with_guest_state<R, F: FnOnce(&mut Self) -> R>(f: F) -> R {
        let mut g = GUEST_STATE.lock();
        f(&mut g)
    }
}

#[no_mangle]
pub extern "C" fn hyperlight_main() {
    bindings::hyperlight_guest_init::<Guest>();
}

use ::alloc::vec::Vec;
use ::hyperlight_common::flatbuffer_wrappers::function_call::FunctionCall;
use ::hyperlight_common::flatbuffer_wrappers::guest_error::ErrorCode;
use ::hyperlight_guest::error::{HyperlightGuestError, Result};
#[no_mangle]
pub fn guest_dispatch_function(function_call: FunctionCall) -> Result<Vec<u8>> {
    Err(HyperlightGuestError::new(
        ErrorCode::GuestFunctionNotFound,
        function_call.function_name.clone(),
    ))
}
