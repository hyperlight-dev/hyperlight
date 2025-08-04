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

use hyperlight_host::GuestBinary;
use hyperlight_host::sandbox::UninitializedSandbox;
use hyperlight_testing::simple_guest_as_string;

fn main() {
    // create a new `Sandbox` configured to run the `simpleguest.exe`
    // test guest binary
    let path = simple_guest_as_string().unwrap();
    let mut sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None)
        .unwrap()
        .evolve()
        .unwrap();

    // Do several calls against a sandbox running the `simpleguest.exe` binary,
    // and print their results
    let res: String = sbox
        .call_guest_function_by_name("Echo", "hello".to_string())
        .unwrap();
    println!("got Echo res: {res}");

    let res: i32 = sbox
        .call_guest_function_by_name("CallMalloc", 200_i32)
        .unwrap();
    println!("got CallMalloc res: {res}");
}
