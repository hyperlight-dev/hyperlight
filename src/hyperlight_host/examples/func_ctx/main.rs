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

use hyperlight_host::func::call_ctx::MultiUseGuestCallContext;
use hyperlight_host::sandbox::{MultiUseSandbox, UninitializedSandbox};
use hyperlight_host::sandbox_state::sandbox::EvolvableSandbox;
use hyperlight_host::sandbox_state::transition::Noop;
use hyperlight_host::{GuestBinary, Result};
use hyperlight_testing::simple_guest_as_string;

fn main() {
    // create a new `MultiUseSandbox` configured to run the `simpleguest.exe`
    // test guest binary
    let sbox1: MultiUseSandbox = {
        let path = simple_guest_as_string().unwrap();
        let u_sbox = UninitializedSandbox::new(GuestBinary::FilePath(path), None).unwrap();
        u_sbox.evolve(Noop::default())
    }
    .unwrap();

    // create a new call context from the sandbox, then do some calls with it.
    let ctx1 = sbox1.new_call_context();
    let sbox2 = do_calls(ctx1).unwrap();
    // create a new call context from the returned sandbox, then do some calls
    // with that one
    let ctx2 = sbox2.new_call_context();
    do_calls(ctx2).unwrap();
}

/// Given a `MultiUseGuestCallContext` derived from an existing
/// `MultiUseSandbox` configured to run the `simpleguest.exe` test guest
/// binary, do several calls against that binary, print their results, then
/// call `ctx.finish()` and return the resulting `MultiUseSandbox`. Return an `Err`
/// if anything failed.
fn do_calls(mut ctx: MultiUseGuestCallContext) -> Result<MultiUseSandbox> {
    let res: String = ctx.call("Echo", "hello".to_string())?;
    println!("got Echo res: {res}");

    let res: i32 = ctx.call("CallMalloc", 200_i32)?;
    println!("got CallMalloc res: {res}");
    ctx.finish()
}
