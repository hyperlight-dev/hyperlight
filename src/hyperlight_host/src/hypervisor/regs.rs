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

mod debug_regs;
mod fpu;
mod special_regs;
mod standard_regs;

#[cfg(target_os = "windows")]
use std::collections::HashSet;

pub(crate) use debug_regs::*;
pub(crate) use fpu::*;
pub(crate) use special_regs::*;
pub(crate) use standard_regs::*;

#[cfg(target_os = "windows")]
#[derive(Debug, PartialEq)]
pub(crate) enum FromWhpRegisterError {
    MissingRegister(HashSet<i32>),
    InvalidLength(usize),
    InvalidEncoding,
    DuplicateRegister(i32),
    InvalidRegister(i32),
}
