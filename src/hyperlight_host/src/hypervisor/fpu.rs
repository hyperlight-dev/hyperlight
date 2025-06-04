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

pub(crate) const FP_CONTROL_WORD_DEFAULT: u16 = 0x37f; // mask all fp-exception, set rounding to nearest, set precision to 64-bit
pub(crate) const FP_TAG_WORD_DEFAULT: u8 = 0xff; // each 8 of x87 fpu registers is empty
pub(crate) const MXCSR_DEFAULT: u32 = 0x1f80; // mask simd fp-exceptions, clear exception flags, set rounding to nearest, disable flush-to-zero mode, disable denormals-are-zero mode
