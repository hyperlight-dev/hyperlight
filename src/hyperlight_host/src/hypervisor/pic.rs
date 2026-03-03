/*
Copyright 2026  The Hyperlight Authors.

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

//! Minimal userspace PIC (8259A) emulation for MSHV/WHP.
//! KVM provides in-kernel PIC via `create_irq_chip()`.

// PIC I/O port constants
const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;

/// Tracks where we are in the ICW (Initialization Command Word) sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PicInitState {
    /// Not in an init sequence; normal operation.
    Ready,
    /// Expecting ICW2 (vector base).
    Icw2,
    /// Expecting ICW3 (cascade info).
    Icw3,
    /// Expecting ICW4 (mode).
    Icw4,
}

/// Minimal 8259A PIC state for one chip (master or slave).
#[derive(Debug)]
pub(crate) struct Pic {
    master_init_state: PicInitState,
    master_vector_base: u8,
    master_imr: u8,

    slave_init_state: PicInitState,
    slave_vector_base: u8,
    slave_imr: u8,
}

impl Pic {
    /// Create a new PIC pair with default state.
    pub(crate) fn new() -> Self {
        Self {
            master_init_state: PicInitState::Ready,
            master_vector_base: 0,
            master_imr: 0xFF, // all masked

            slave_init_state: PicInitState::Ready,
            slave_vector_base: 0,
            slave_imr: 0xFF, // all masked
        }
    }

    /// Handle an I/O OUT to a PIC port. Returns `true` if the port was handled.
    pub(crate) fn handle_io_out(&mut self, port: u16, data: u8) -> bool {
        match port {
            PIC_MASTER_CMD => {
                if data & 0x10 != 0 {
                    // ICW1 -- start init sequence
                    self.master_init_state = PicInitState::Icw2;
                }
                // else: OCW (e.g. EOI) -- we accept but ignore
                true
            }
            PIC_MASTER_DATA => {
                match self.master_init_state {
                    PicInitState::Icw2 => {
                        self.master_vector_base = data;
                        self.master_init_state = PicInitState::Icw3;
                    }
                    PicInitState::Icw3 => {
                        self.master_init_state = PicInitState::Icw4;
                    }
                    PicInitState::Icw4 => {
                        self.master_init_state = PicInitState::Ready;
                    }
                    PicInitState::Ready => {
                        // IMR write
                        self.master_imr = data;
                    }
                }
                true
            }
            PIC_SLAVE_CMD => {
                if data & 0x10 != 0 {
                    self.slave_init_state = PicInitState::Icw2;
                }
                true
            }
            PIC_SLAVE_DATA => {
                match self.slave_init_state {
                    PicInitState::Icw2 => {
                        self.slave_vector_base = data;
                        self.slave_init_state = PicInitState::Icw3;
                    }
                    PicInitState::Icw3 => {
                        self.slave_init_state = PicInitState::Icw4;
                    }
                    PicInitState::Icw4 => {
                        self.slave_init_state = PicInitState::Ready;
                    }
                    PicInitState::Ready => {
                        self.slave_imr = data;
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Handle an I/O IN from a PIC port. Returns `Some(value)` if handled.
    pub(crate) fn handle_io_in(&self, port: u16) -> Option<u8> {
        match port {
            PIC_MASTER_DATA => Some(self.master_imr),
            PIC_SLAVE_DATA => Some(self.slave_imr),
            PIC_MASTER_CMD | PIC_SLAVE_CMD => Some(0), // ISR reads return 0
            _ => None,
        }
    }

    /// Returns the master PIC vector base.
    pub(crate) fn master_vector_base(&self) -> u8 {
        self.master_vector_base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pic_initial_state() {
        let pic = Pic::new();
        assert_eq!(pic.master_vector_base, 0);
        assert_eq!(pic.slave_vector_base, 0);
        assert_eq!(pic.master_imr, 0xFF);
        assert_eq!(pic.slave_imr, 0xFF);
    }

    #[test]
    fn pic_master_icw_sequence() {
        let mut pic = Pic::new();
        // ICW1
        assert!(pic.handle_io_out(PIC_MASTER_CMD, 0x11));
        // ICW2: vector base 0x20
        assert!(pic.handle_io_out(PIC_MASTER_DATA, 0x20));
        assert_eq!(pic.master_vector_base(), 0x20);
        // ICW3
        assert!(pic.handle_io_out(PIC_MASTER_DATA, 0x04));
        // ICW4
        assert!(pic.handle_io_out(PIC_MASTER_DATA, 0x01));
        // Should be back to Ready -- IMR write
        assert!(pic.handle_io_out(PIC_MASTER_DATA, 0xFE)); // unmask IRQ0
        assert_eq!(pic.master_imr, 0xFE);
    }

    #[test]
    fn pic_slave_icw_sequence() {
        let mut pic = Pic::new();
        assert!(pic.handle_io_out(PIC_SLAVE_CMD, 0x11));
        assert!(pic.handle_io_out(PIC_SLAVE_DATA, 0x28));
        assert_eq!(pic.slave_vector_base, 0x28);
        assert!(pic.handle_io_out(PIC_SLAVE_DATA, 0x02));
        assert!(pic.handle_io_out(PIC_SLAVE_DATA, 0x01));
        assert!(pic.handle_io_out(PIC_SLAVE_DATA, 0xFF));
        assert_eq!(pic.slave_imr, 0xFF);
    }

    #[test]
    fn pic_eoi_accepted() {
        let mut pic = Pic::new();
        // EOI (OCW2, non-specific EOI = 0x20)
        assert!(pic.handle_io_out(PIC_MASTER_CMD, 0x20));
    }

    #[test]
    fn pic_unhandled_port() {
        let mut pic = Pic::new();
        assert!(!pic.handle_io_out(0x60, 0x00));
        assert_eq!(pic.handle_io_in(0x60), None);
    }

    #[test]
    fn pic_reinitialize_master() {
        let mut pic = Pic::new();
        // First init
        pic.handle_io_out(PIC_MASTER_CMD, 0x11);
        pic.handle_io_out(PIC_MASTER_DATA, 0x20);
        pic.handle_io_out(PIC_MASTER_DATA, 0x04);
        pic.handle_io_out(PIC_MASTER_DATA, 0x01);
        assert_eq!(pic.master_vector_base(), 0x20);
        // Reinit
        pic.handle_io_out(PIC_MASTER_CMD, 0x11);
        pic.handle_io_out(PIC_MASTER_DATA, 0x30);
        pic.handle_io_out(PIC_MASTER_DATA, 0x04);
        pic.handle_io_out(PIC_MASTER_DATA, 0x01);
        assert_eq!(pic.master_vector_base(), 0x30);
    }

    #[test]
    fn pic_imr_preserved_across_reinit() {
        let mut pic = Pic::new();
        // Set IMR before init
        pic.handle_io_out(PIC_MASTER_CMD, 0x11);
        pic.handle_io_out(PIC_MASTER_DATA, 0x20);
        pic.handle_io_out(PIC_MASTER_DATA, 0x04);
        pic.handle_io_out(PIC_MASTER_DATA, 0x01);
        pic.handle_io_out(PIC_MASTER_DATA, 0xFE);
        assert_eq!(pic.master_imr, 0xFE);
        // Reinit -- IMR is set during ICW sequence, not explicitly preserved
        pic.handle_io_out(PIC_MASTER_CMD, 0x11);
        // After ICW1, IMR should still read as whatever it was -- we only
        // change it on Ready state writes.
        assert_eq!(pic.handle_io_in(PIC_MASTER_DATA), Some(0xFE));
    }
}
