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

#[cfg(kvm)]
use kvm_bindings::kvm_debugregs;
#[cfg(mshv3)]
use mshv_bindings::DebugRegisters;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub(crate) struct CommonDebugRegs {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[cfg(kvm)]
impl From<kvm_debugregs> for CommonDebugRegs {
    fn from(kvm_regs: kvm_debugregs) -> Self {
        Self {
            dr0: kvm_regs.db[0],
            dr1: kvm_regs.db[1],
            dr2: kvm_regs.db[2],
            dr3: kvm_regs.db[3],
            dr6: kvm_regs.dr6,
            dr7: kvm_regs.dr7,
        }
    }
}
#[cfg(kvm)]
impl From<&CommonDebugRegs> for kvm_debugregs {
    fn from(common_regs: &CommonDebugRegs) -> Self {
        kvm_debugregs {
            db: [
                common_regs.dr0,
                common_regs.dr1,
                common_regs.dr2,
                common_regs.dr3,
            ],
            dr6: common_regs.dr6,
            dr7: common_regs.dr7,
            ..Default::default()
        }
    }
}
#[cfg(mshv3)]
impl From<DebugRegisters> for CommonDebugRegs {
    fn from(mshv_regs: DebugRegisters) -> Self {
        Self {
            dr0: mshv_regs.dr0,
            dr1: mshv_regs.dr1,
            dr2: mshv_regs.dr2,
            dr3: mshv_regs.dr3,
            dr6: mshv_regs.dr6,
            dr7: mshv_regs.dr7,
        }
    }
}
#[cfg(mshv3)]
impl From<&CommonDebugRegs> for DebugRegisters {
    fn from(common_regs: &CommonDebugRegs) -> Self {
        DebugRegisters {
            dr0: common_regs.dr0,
            dr1: common_regs.dr1,
            dr2: common_regs.dr2,
            dr3: common_regs.dr3,
            dr6: common_regs.dr6,
            dr7: common_regs.dr7,
        }
    }
}
