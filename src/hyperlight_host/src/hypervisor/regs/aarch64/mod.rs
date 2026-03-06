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

// TODO(aarch64): implement real register definitions

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonRegisters {
    _placeholder: u64,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonSpecialRegisters {
    _placeholder: u64,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonFpu {
    _placeholder: u64,
}

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonDebugRegs {
    _placeholder: u64,
}
