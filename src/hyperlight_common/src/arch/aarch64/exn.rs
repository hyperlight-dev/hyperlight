// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

use crate::vmem::bits;

const ESR_EC_UNKNOWN: u64 = 0b000000; // udf generates this
const ESR_EC_DATA_ABORT_LOWER_EL: u64 = 0b100100;
const ESR_EC_DATA_ABORT_SAME_EL: u64 = 0b100101;
const ESR_EC_INSN_ABORT_LOWER_EL: u64 = 0b100000;
const ESR_EC_INSN_ABORT_SAME_EL: u64 = 0b100001;

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
pub enum InsnFaultKind {
    TranslationFault(i64),
    PermissionFault(i64),
    Other(u64),
}
fn decode_insn_fault_status_code(ifsc: u64) -> InsnFaultKind {
    if bits::<5, 2>(ifsc) == 0b0011 {
        InsnFaultKind::PermissionFault(bits::<1, 0>(ifsc) as i64)
    } else if bits::<5, 2>(ifsc) == 0b0001 {
        InsnFaultKind::TranslationFault(bits::<1, 0>(ifsc) as i64)
    } else if bits::<5, 2>(ifsc) == 0b1010 {
        if bits::<1, 0>(ifsc) >= 2 {
            InsnFaultKind::TranslationFault(bits::<1, 0>(ifsc) as i64 - 4)
        } else {
            InsnFaultKind::Other(ifsc)
        }
    } else {
        InsnFaultKind::Other(ifsc)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct InsnFault {
    pub from_lower_el: bool,
    pub is_s1ptw: bool,
    pub kind: InsnFaultKind,
}

fn decode_insn_fault(from_lower_el: bool, iss: u64) -> InsnFault {
    InsnFault {
        from_lower_el,
        is_s1ptw: bits::<7, 7>(iss) == 0b1,
        kind: decode_insn_fault_status_code(bits::<5, 0>(iss)),
    }
}

// some of the data in these is not used presently, but is logically
// part of the code being decoded & should be accounted for
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum Exception {
    Unknown,
    DataFault(DataFault),
    InsnFault(InsnFault),
    Other(u64),
}
/// Decode the value of ESR_ELx into a nice enum. Also takes FAR_ELx,
/// which will be embedded in the structure if relevant.
pub fn decode_syndrome(esr: u64) -> Exception {
    let ec = bits::<31, 26>(esr);
    match ec {
        ESR_EC_UNKNOWN => Exception::Unknown,
        ESR_EC_DATA_ABORT_LOWER_EL | ESR_EC_DATA_ABORT_SAME_EL => Exception::DataFault(
            decode_data_fault(ec == ESR_EC_DATA_ABORT_LOWER_EL, bits::<24, 0>(esr)),
        ),
        ESR_EC_INSN_ABORT_LOWER_EL | ESR_EC_INSN_ABORT_SAME_EL => Exception::InsnFault(
            decode_insn_fault(ec == ESR_EC_INSN_ABORT_LOWER_EL, bits::<24, 0>(esr)),
        ),
        _ => Exception::Other(esr),
    }
}
