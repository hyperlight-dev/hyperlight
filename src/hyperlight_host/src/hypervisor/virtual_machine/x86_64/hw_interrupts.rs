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

//! Shared x86-64 helpers for the `hw-interrupts` feature, used by
//! MSHV and WHP backends.  KVM uses an in-kernel IRQ chip so it
//! handles most of this transparently.

/// Hardcoded timer interrupt vector.  The guest remaps IRQ0 to
/// vector 0x20 via PIC ICW2, so we use that same vector directly
/// — no PIC state machine needed.
pub(crate) const TIMER_VECTOR: u32 = 0x20;

/// Handle an IO IN request for hardware-interrupt related ports.
/// Returns `Some(value)` if the port was handled, `None` if the
/// port should be passed through to the guest handler.
///
/// No PIC state machine — PIC data ports return 0xFF (all masked),
/// PIC command ports return 0 (no pending IRQ), PIT returns 0.
pub(crate) fn handle_io_in(port: u16) -> Option<u64> {
    match port {
        // PIC master/slave data ports — return "all masked"
        0x21 | 0xA1 => Some(0xFF),
        // PIC master/slave command ports — return 0 (ISR/IRR read)
        0x20 | 0xA0 => Some(0),
        // PIT data port read — return 0
        0x40 => Some(0),
        _ => None,
    }
}

/// Handle IO OUT requests for common legacy hardware ports
/// (PIC, PIT, PC speaker, diagnostic port).
///
/// Returns `true` if the port was fully handled, `false` otherwise.
/// When the guest sends a non-specific EOI on the master PIC command
/// port (0x20, OCW2 byte with bits 7:5 = 001) and a timer is active,
/// `eoi_callback` is invoked to bridge the PIC EOI to the LAPIC.
pub(crate) fn handle_common_io_out(
    port: u16,
    data: &[u8],
    timer_active: bool,
    eoi_callback: impl FnOnce(),
) -> bool {
    // PIC ports (0x20, 0x21, 0xA0, 0xA1): accept as no-ops.
    // We only need LAPIC EOI bridging when the guest sends a
    // non-specific EOI on the master PIC command port.
    if port == 0x20 || port == 0x21 || port == 0xA0 || port == 0xA1 {
        if port == 0x20 && !data.is_empty() && (data[0] & 0xE0) == 0x20 && timer_active {
            eoi_callback();
        }
        return true;
    }
    // PIT ports
    if port == 0x43 || port == 0x40 {
        return true;
    }
    // PC speaker
    if port == 0x61 {
        return true;
    }
    // Diagnostic port
    if port == 0x80 {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// LAPIC register helpers
//
// LAPIC register offsets from Intel SDM Vol. 3A, Table 11-1.
// These operate on a raw byte slice representing the LAPIC register page.
// ---------------------------------------------------------------------------

/// Write a u32 to a LAPIC register page at the given APIC offset.
///
/// # Panics
/// Panics if `offset + 4 > state.len()`.
pub(crate) fn write_lapic_u32(state: &mut [u8], offset: usize, val: u32) {
    state[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Read a u32 from a LAPIC register page at the given APIC offset.
///
/// # Panics
/// Panics if `offset + 4 > state.len()`.
pub(crate) fn read_lapic_u32(state: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        state[offset],
        state[offset + 1],
        state[offset + 2],
        state[offset + 3],
    ])
}

/// Initialize LAPIC registers in a raw register page to sensible
/// defaults for timer interrupt delivery.
///
/// Register values from Intel SDM Vol. 3A, Table 11-1:
/// - SVR (0xF0): bit 8 = enable APIC, bits 0-7 = spurious vector 0xFF
/// - TPR (0x80): 0 = accept all interrupt priorities
/// - DFR (0xE0): 0xFFFF_FFFF = flat model
/// - LDR (0xD0): logical APIC ID for flat model
/// - LINT0 (0x350): masked — not wired to PIC
/// - LINT1 (0x360): NMI delivery, not masked
/// - LVT Timer (0x320): masked — host timer thread injects instead
/// - LVT Error (0x370): masked
pub(crate) fn init_lapic_registers(state: &mut [u8]) {
    write_lapic_u32(state, 0xF0, 0x1FF);
    write_lapic_u32(state, 0x80, 0);
    write_lapic_u32(state, 0xE0, 0xFFFF_FFFF);
    write_lapic_u32(state, 0xD0, 1 << 24);
    write_lapic_u32(state, 0x350, 0x0001_0000);
    write_lapic_u32(state, 0x360, 0x400);
    write_lapic_u32(state, 0x320, 0x0001_0000);
    write_lapic_u32(state, 0x370, 0x0001_0000);
}

/// Perform LAPIC EOI: clear the highest-priority in-service bit.
///
/// The ISR is at LAPIC offset 0x100, organized as 8 × 32-bit words
/// (one per 16 bytes).  Scans from highest priority (ISR\[7\]) to
/// lowest (ISR\[0\]).
pub(crate) fn lapic_eoi(state: &mut [u8]) {
    for i in (0u32..8).rev() {
        let offset = 0x100 + (i as usize) * 0x10;
        let isr_val = read_lapic_u32(state, offset);
        if isr_val != 0 {
            let bit = 31 - isr_val.leading_zeros();
            write_lapic_u32(state, offset, isr_val & !(1u32 << bit));
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read_lapic_roundtrip() {
        let mut state = vec![0u8; 1024];
        write_lapic_u32(&mut state, 0xF0, 0xDEAD_BEEF);
        assert_eq!(read_lapic_u32(&state, 0xF0), 0xDEAD_BEEF);
    }

    #[test]
    fn write_read_lapic_multiple_offsets() {
        let mut state = vec![0u8; 1024];
        write_lapic_u32(&mut state, 0x80, 0x1234_5678);
        write_lapic_u32(&mut state, 0xF0, 0xABCD_EF01);
        write_lapic_u32(&mut state, 0xE0, 0xFFFF_FFFF);
        assert_eq!(read_lapic_u32(&state, 0x80), 0x1234_5678);
        assert_eq!(read_lapic_u32(&state, 0xF0), 0xABCD_EF01);
        assert_eq!(read_lapic_u32(&state, 0xE0), 0xFFFF_FFFF);
    }

    #[test]
    fn write_read_lapic_zero() {
        let mut state = vec![0xFFu8; 1024];
        write_lapic_u32(&mut state, 0x80, 0);
        assert_eq!(read_lapic_u32(&state, 0x80), 0);
    }

    #[test]
    fn write_does_not_clobber_neighbors() {
        let mut state = vec![0u8; 1024];
        write_lapic_u32(&mut state, 0x80, 0xAAAA_BBBB);
        assert_eq!(state[0x7F], 0);
        assert_eq!(state[0x84], 0);
    }

    #[test]
    fn lapic_eoi_clears_highest_isr_bit() {
        let mut state = vec![0u8; 1024];
        // Set bit 5 in ISR[0] (offset 0x100)
        write_lapic_u32(&mut state, 0x100, 1 << 5);
        lapic_eoi(&mut state);
        assert_eq!(read_lapic_u32(&state, 0x100), 0);
    }

    #[test]
    fn lapic_eoi_clears_only_highest() {
        let mut state = vec![0u8; 1024];
        // Set bits in ISR[0] and ISR[1]
        write_lapic_u32(&mut state, 0x100, 0b11); // bits 0 and 1
        write_lapic_u32(&mut state, 0x110, 1 << 2); // bit 2 in ISR[1]
        lapic_eoi(&mut state);
        // ISR[1] should be cleared (higher priority), ISR[0] untouched
        assert_eq!(read_lapic_u32(&state, 0x110), 0);
        assert_eq!(read_lapic_u32(&state, 0x100), 0b11);
    }

    #[test]
    fn init_lapic_registers_sets_svr() {
        let mut state = vec![0u8; 1024];
        init_lapic_registers(&mut state);
        let svr = read_lapic_u32(&state, 0xF0);
        assert_ne!(svr & 0x100, 0, "APIC enable bit should be set");
        assert_eq!(svr & 0xFF, 0xFF, "spurious vector should be 0xFF");
    }

    #[test]
    fn handle_io_in_pic_ports() {
        assert_eq!(handle_io_in(0x21), Some(0xFF));
        assert_eq!(handle_io_in(0xA1), Some(0xFF));
        assert_eq!(handle_io_in(0x20), Some(0));
        assert_eq!(handle_io_in(0xA0), Some(0));
        assert_eq!(handle_io_in(0x40), Some(0));
        assert_eq!(handle_io_in(0x42), None);
    }

    #[test]
    fn handle_common_io_out_pic_eoi() {
        let mut eoi_called = false;
        // Non-specific EOI (0x20) on master PIC command port
        let handled = handle_common_io_out(0x20, &[0x20], true, || eoi_called = true);
        assert!(handled);
        assert!(eoi_called);
    }

    #[test]
    fn handle_common_io_out_no_eoi_when_timer_inactive() {
        let mut eoi_called = false;
        let handled = handle_common_io_out(0x20, &[0x20], false, || eoi_called = true);
        assert!(handled);
        assert!(!eoi_called);
    }

    #[test]
    fn handle_common_io_out_pit_ports() {
        assert!(handle_common_io_out(0x40, &[], false, || {}));
        assert!(handle_common_io_out(0x43, &[], false, || {}));
    }

    #[test]
    fn handle_common_io_out_speaker_and_diag() {
        assert!(handle_common_io_out(0x61, &[], false, || {}));
        assert!(handle_common_io_out(0x80, &[], false, || {}));
    }

    #[test]
    fn handle_common_io_out_unknown_port() {
        assert!(!handle_common_io_out(0x100, &[], false, || {}));
    }

    #[test]
    #[should_panic]
    fn write_lapic_u32_panics_on_short_buffer() {
        let mut state = vec![0u8; 4];
        write_lapic_u32(&mut state, 2, 0xDEAD); // offset 2 + 4 = 6 > 4
    }

    #[test]
    #[should_panic]
    fn read_lapic_u32_panics_on_short_buffer() {
        let state = vec![0u8; 4];
        read_lapic_u32(&state, 2); // offset 2 + 4 = 6 > 4
    }
}
