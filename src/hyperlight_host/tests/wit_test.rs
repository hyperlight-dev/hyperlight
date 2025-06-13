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
#![allow(clippy::disallowed_macros)]

use std::sync::{Arc, Mutex};

use hyperlight_common::resource::BorrowedResourceGuard;
use hyperlight_host::{GuestBinary, MultiUseGuestCallContext, UninitializedSandbox};
use hyperlight_testing::wit_guest_as_string;

extern crate alloc;
mod bindings {
    hyperlight_component_macro::host_bindgen!("../tests/rust_guests/witguest/interface.wasm");
}

use bindings::test::wit::roundtrip::{Testrecord, Testvariant};
use bindings::*;

impl PartialEq for Testrecord {
    fn eq(&self, other: &Self) -> bool {
        self.contents == other.contents && self.length == other.length
    }
}

impl PartialEq for Testvariant {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Testvariant::VariantA, Testvariant::VariantA) => true,
            (Testvariant::VariantB(s1), Testvariant::VariantB(s2)) => s1 == s2,
            (Testvariant::VariantC(c1), Testvariant::VariantC(c2)) => c1 == c2,
            _ => false,
        }
    }
}

impl Clone for Testrecord {
    fn clone(&self) -> Self {
        Self {
            contents: self.contents.clone(),
            length: self.length,
        }
    }
}

impl Clone for Testvariant {
    fn clone(&self) -> Self {
        match self {
            Self::VariantA => Self::VariantA,
            Self::VariantB(s) => Self::VariantB(s.clone()),
            Self::VariantC(c) => Self::VariantC(*c),
        }
    }
}

struct Host {}

impl test::wit::Roundtrip for Host {
    fn roundtrip_bool(&mut self, x: bool) -> bool {
        x
    }
    fn roundtrip_s8(&mut self, x: i8) -> i8 {
        x
    }
    fn roundtrip_s16(&mut self, x: i16) -> i16 {
        x
    }
    fn roundtrip_s32(&mut self, x: i32) -> i32 {
        x
    }
    fn roundtrip_s64(&mut self, x: i64) -> i64 {
        x
    }
    fn roundtrip_u8(&mut self, x: u8) -> u8 {
        x
    }
    fn roundtrip_u16(&mut self, x: u16) -> u16 {
        x
    }
    fn roundtrip_u32(&mut self, x: u32) -> u32 {
        x
    }
    fn roundtrip_u64(&mut self, x: u64) -> u64 {
        x
    }
    fn roundtrip_f32(&mut self, x: f32) -> f32 {
        x
    }
    fn roundtrip_f64(&mut self, x: f64) -> f64 {
        x
    }
    fn roundtrip_char(&mut self, x: char) -> char {
        x
    }
    fn roundtrip_string(&mut self, x: alloc::string::String) -> alloc::string::String {
        x
    }
    fn roundtrip_list(&mut self, x: alloc::vec::Vec<u8>) -> alloc::vec::Vec<u8> {
        x
    }
    fn roundtrip_tuple(&mut self, x: (alloc::string::String, u8)) -> (alloc::string::String, u8) {
        x
    }
    fn roundtrip_option(
        &mut self,
        x: ::core::option::Option<alloc::string::String>,
    ) -> ::core::option::Option<alloc::string::String> {
        x
    }
    fn roundtrip_result(
        &mut self,
        x: ::core::result::Result<char, alloc::string::String>,
    ) -> ::core::result::Result<char, alloc::string::String> {
        x
    }
    fn roundtrip_record(
        &mut self,
        x: test::wit::roundtrip::Testrecord,
    ) -> test::wit::roundtrip::Testrecord {
        x
    }
    fn roundtrip_flags_small(
        &mut self,
        x: test::wit::roundtrip::Smallflags,
    ) -> test::wit::roundtrip::Smallflags {
        x
    }
    fn roundtrip_flags_large(
        &mut self,
        x: test::wit::roundtrip::Largeflags,
    ) -> test::wit::roundtrip::Largeflags {
        x
    }
    fn roundtrip_variant(
        &mut self,
        x: test::wit::roundtrip::Testvariant,
    ) -> test::wit::roundtrip::Testvariant {
        x
    }
    fn roundtrip_enum(
        &mut self,
        x: test::wit::roundtrip::Testenum,
    ) -> test::wit::roundtrip::Testenum {
        x
    }
}

struct TestResource {
    n_calls: u32,
    x: String,
    last: char,
}

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
// We only have 1 test that uses this, and it isn't a proptest or
// anything, so it should only run once. If multiple tests using this
// could run in parallel, there would be problems.
static HAS_BEEN_DROPPED: AtomicBool = AtomicBool::new(false);

impl Drop for TestResource {
    fn drop(&mut self) {
        assert_eq!(self.x, "strabc");
        assert_eq!(self.last, 'c');
        assert!(!HAS_BEEN_DROPPED.swap(true, Relaxed));
    }
}

impl test::wit::host_resource::Testresource for Host {
    type T = Arc<Mutex<TestResource>>;
    fn new(&mut self, x: String, last: char) -> Self::T {
        Arc::new(Mutex::new(TestResource {
            n_calls: 0,
            x,
            last,
        }))
    }
    fn append_char(&mut self, self_: BorrowedResourceGuard<'_, Self::T>, c: char) {
        let mut self_ = self_.lock().unwrap();
        match self_.n_calls {
            // These line up to the initial values and calls made by
            // witguest.rs. Mostly, this just checks that (even after
            // round-tripping an owned reference through the host), we
            // do always seem to get the correct structure.
            0 => {
                assert_eq!(self_.x, "str");
                assert_eq!(self_.last, 'z');
            }
            1 => {
                assert_eq!(self_.x, "stra");
                assert_eq!(self_.last, 'a');
            }
            2 => {
                assert_eq!(self_.x, "strab");
                assert_eq!(self_.last, 'b');
            }
            _ => panic!(),
        };
        self_.n_calls += 1;
        self_.x.push(c);
        self_.last = c;
    }
}

impl test::wit::HostResource for Host {
    fn roundtrip_own(&mut self, owned: Arc<Mutex<TestResource>>) -> Arc<Mutex<TestResource>> {
        owned
    }

    fn return_own(&mut self, _: Arc<Mutex<TestResource>>) {
        // Not much to do here other than let it be dropped
    }
}

#[allow(refining_impl_trait)]
impl test::wit::TestImports for Host {
    type Roundtrip = Self;
    fn roundtrip(&mut self) -> &mut Self {
        self
    }
    type HostResource = Self;
    fn host_resource(&mut self) -> &mut Self {
        self
    }
}

fn sb() -> TestSandbox<Host, MultiUseGuestCallContext> {
    let path = wit_guest_as_string().unwrap();
    let guest_path = GuestBinary::FilePath(path);
    let uninit = UninitializedSandbox::new(guest_path, None).unwrap();
    test::wit::Test::instantiate(uninit, Host {})
}

mod wit_test {

    use proptest::prelude::*;

    use crate::bindings::test::wit::{Roundtrip, TestExports, TestHostResource, roundtrip};
    use crate::sb;

    prop_compose! {
        fn arb_testrecord()(contents in ".*", length in any::<u64>()) -> roundtrip::Testrecord {
            roundtrip::Testrecord { contents, length }
        }
    }

    prop_compose! {
        fn arb_smallflags()(flag_a: bool, flag_b: bool, flag_c: bool) -> roundtrip::Smallflags {
            roundtrip::Smallflags { flag_a, flag_b, flag_c }
        }
    }

    prop_compose! {
        fn arb_largeflags()(
            flag00: bool, flag01: bool, flag02: bool, flag03: bool, flag04: bool, flag05: bool, flag06: bool, flag07: bool,
            flag08: bool, flag09: bool, flag0a: bool, flag0b: bool, flag0c: bool, flag0d: bool, flag0e: bool, flag0f: bool,

            flag10: bool, flag11: bool, flag12: bool, flag13: bool, flag14: bool, flag15: bool, flag16: bool, flag17: bool,
            flag18: bool, flag19: bool, flag1a: bool, flag1b: bool, flag1c: bool, flag1d: bool, flag1e: bool, flag1f: bool,
       ) -> roundtrip::Largeflags {
            roundtrip::Largeflags {
                flag00, flag01, flag02, flag03, flag04, flag05, flag06, flag07,
                flag08, flag09, flag0a, flag0b, flag0c, flag0d, flag0e, flag0f,

                flag10, flag11, flag12, flag13, flag14, flag15, flag16, flag17,
                flag18, flag19, flag1a, flag1b, flag1c, flag1d, flag1e, flag1f,
            }
        }
    }

    fn arb_testvariant() -> impl Strategy<Value = roundtrip::Testvariant> {
        use roundtrip::Testvariant::*;
        prop_oneof![
            Just(VariantA),
            any::<String>().prop_map(VariantB),
            any::<char>().prop_map(VariantC),
        ]
    }

    fn arb_testenum() -> impl Strategy<Value = roundtrip::Testenum> {
        use roundtrip::Testenum::*;
        prop_oneof![Just(EnumA), Just(EnumB), Just(EnumC),]
    }

    macro_rules! make_test {
        ($fn:ident, $($ty:tt)*) => {
            proptest! {
                #[test]
                fn $fn(x $($ty)*) {
                    assert_eq!(x, sb().roundtrip().$fn(x.clone()))
                }
            }
        }
    }

    make_test! { roundtrip_bool,        : bool }
    make_test! { roundtrip_u8,          : u8 }
    make_test! { roundtrip_u16,         : u16 }
    make_test! { roundtrip_u32,         : u32 }
    make_test! { roundtrip_u64,         : u64 }
    make_test! { roundtrip_s8,          : i8 }
    make_test! { roundtrip_s16,         : i16 }
    make_test! { roundtrip_s32,         : i32 }
    make_test! { roundtrip_s64,         : i64 }
    make_test! { roundtrip_f32,         : f32 }
    make_test! { roundtrip_f64,         : f64 }
    make_test! { roundtrip_char,        : char }
    make_test! { roundtrip_string,      : String }

    make_test! { roundtrip_list,        : Vec<u8> }
    make_test! { roundtrip_tuple,       : (String, u8) }
    make_test! { roundtrip_option,      : Option<String> }
    make_test! { roundtrip_result,      : Result<char, String> }

    make_test! { roundtrip_record,      in arb_testrecord() }
    make_test! { roundtrip_flags_small, in arb_smallflags() }
    make_test! { roundtrip_flags_large, in arb_largeflags() }
    make_test! { roundtrip_variant,     in arb_testvariant() }
    make_test! { roundtrip_enum,        in arb_testenum() }

    #[test]
    fn test_host_resource() {
        {
            sb().test_host_resource().test();
        }
        use std::sync::atomic::Ordering::Relaxed;
        assert!(crate::HAS_BEEN_DROPPED.load(Relaxed));
    }
}
