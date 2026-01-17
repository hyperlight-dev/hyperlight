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

//! aarch64 FPU/SIMD register types.

/// AArch64 FPU/SIMD registers.
///
/// ARM64 has 32 128-bit SIMD/FP registers (v0-v31), plus control and status registers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CommonFpu {}

impl Default for CommonFpu {
    fn default() -> Self {
        todo!()
    }
}
