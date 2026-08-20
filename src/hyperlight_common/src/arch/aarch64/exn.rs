/*
Copyright 2026 The Hyperlight Authors.

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

use crate::vmem::bits;

const ESR_EC_DATA_ABORT_LOWER_EL: u64 = 0b100100;
const ESR_EC_DATA_ABORT_SAME_EL: u64 = 0b100101;

// some of the data in these is not used presently, but is logically
// part of the code being decoded & should be accounted for
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum DataFaultKind {
    TranslationFault(i64),
    PermissionFault(i64),
    Other(u64),
}
fn decode_data_fault_status_code(dfsc: u64) -> DataFaultKind {
    if bits::<5, 2>(dfsc) == 0b0011 {
        DataFaultKind::PermissionFault(bits::<1, 0>(dfsc) as i64)
    } else if bits::<5, 2>(dfsc) == 0b0001 {
        DataFaultKind::TranslationFault(bits::<1, 0>(dfsc) as i64)
    } else if bits::<5, 2>(dfsc) == 0b1010 {
        if bits::<1, 0>(dfsc) >= 2 {
            DataFaultKind::TranslationFault(bits::<1, 0>(dfsc) as i64 - 4)
        } else {
            DataFaultKind::Other(dfsc)
        }
    } else {
        DataFaultKind::Other(dfsc)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct DataFaultInstructionSyndrome {
    pub srt: u8,
    // ...
}
fn decode_data_fault_instruction_syndrome(iss: u64) -> Option<DataFaultInstructionSyndrome> {
    let isv = bits::<24, 24>(iss);
    if isv != 0b1 {
        return None;
    }
    Some(DataFaultInstructionSyndrome {
        srt: bits::<20, 16>(iss) as u8,
    })
}

#[derive(Debug, Copy, Clone)]
pub struct DataFault {
    pub from_lower_el: bool,
    pub is_s1ptw: bool,
    pub is_write: bool,
    pub kind: DataFaultKind,
    pub insn: Option<DataFaultInstructionSyndrome>,
}

fn decode_data_fault(from_lower_el: bool, iss: u64) -> DataFault {
    DataFault {
        from_lower_el,
        is_s1ptw: bits::<7, 7>(iss) == 0b1,
        is_write: bits::<6, 6>(iss) == 0b1,
        kind: decode_data_fault_status_code(bits::<5, 0>(iss)),
        insn: decode_data_fault_instruction_syndrome(iss),
    }
}

// some of the data in these is not used presently, but is logically
// part of the code being decoded & should be accounted for
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum Exception {
    /// lower el?, faulting address, status code
    DataFault(DataFault),
    Other(u64),
}
/// Decode the value of ESR_ELx into a nice enum. Also takes FAR_ELx,
/// which will be embedded in the structure if relevant.
pub fn decode_syndrome(esr: u64) -> Exception {
    let ec = bits::<31, 26>(esr);
    match ec {
        ESR_EC_DATA_ABORT_LOWER_EL | ESR_EC_DATA_ABORT_SAME_EL => Exception::DataFault(
            decode_data_fault(ec == ESR_EC_DATA_ABORT_LOWER_EL, bits::<24, 0>(esr)),
        ),
        _ => Exception::Other(esr),
    }
}
