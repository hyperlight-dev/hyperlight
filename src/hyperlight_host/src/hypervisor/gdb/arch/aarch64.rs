// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Hyperlight Authors.

pub(crate) const SW_BP_SIZE: usize = 4;
pub(crate) const SW_BP: [u8; SW_BP_SIZE] = 0xd420_0000u32.to_le_bytes();

pub(crate) fn valid_sw_breakpoint_address(addr: u64) -> bool {
    addr.is_multiple_of(SW_BP_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_breakpoint_is_brk() {
        assert_eq!(SW_BP, [0, 0, 0x20, 0xd4]);
    }

    #[test]
    fn software_breakpoints_require_instruction_alignment() {
        assert!(valid_sw_breakpoint_address(0x4000));
        assert!(!valid_sw_breakpoint_address(0x4001));
        assert!(!valid_sw_breakpoint_address(0x4002));
        assert!(!valid_sw_breakpoint_address(0x4003));
    }
}
