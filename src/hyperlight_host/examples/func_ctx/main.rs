// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 The Hyperlight Authors.

use hyperlight_host::SandboxBuilder;
use hyperlight_testing::simple_guest_as_pathbuf;

fn main() {
    // create a new `MultiUseSandbox` configured to run the `simpleguest.exe`
    // test guest binary
    let path = simple_guest_as_pathbuf();
    let mut sbox = SandboxBuilder::new().build_from_file(path).unwrap();

    // Do several calls against a sandbox running the `simpleguest.exe` binary,
    // and print their results
    let res: String = sbox.call("Echo", "hello".to_string()).unwrap();
    println!("got Echo res: {res}");

    let res: i32 = sbox.call("CallMalloc", 200_i32).unwrap();
    println!("got CallMalloc res: {res}");
}
