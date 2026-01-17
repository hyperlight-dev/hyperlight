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

/// AArch64 system registers.
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {}

impl CommonSpecialRegisters {
    /// todo
    #[cfg(feature = "init-paging")]
    pub(crate) fn standard_64bit_defaults(_page_table_addr: u64) -> Self {
        todo!()
    }

    /// todo
    #[cfg(not(feature = "init-paging"))]
    pub(crate) fn standard_real_mode_defaults() -> Self {
        todo!()
    }
}
