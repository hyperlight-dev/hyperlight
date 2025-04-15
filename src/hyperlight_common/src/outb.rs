use core::arch;

use anyhow::{bail, Result};

use crate::hyperlight_peb::RunMode;
use crate::RUNNING_MODE;

/// Supported actions when issuing an OUTB actions by Hyperlight.
/// - Log: for logging,
/// - CallFunction: makes a call to a host function,
/// - Abort: aborts the execution of the guest,
/// - DebugPrint: prints a message to the host console.
pub enum OutBAction {
    Log = 99,
    CallFunction = 101,
    Abort = 102,
    DebugPrint = 103,
}

impl TryFrom<u16> for OutBAction {
    type Error = anyhow::Error;
    fn try_from(val: u16) -> Result<Self> {
        match val {
            99 => Ok(OutBAction::Log),
            101 => Ok(OutBAction::CallFunction),
            102 => Ok(OutBAction::Abort),
            103 => Ok(OutBAction::DebugPrint),
            _ => bail!("Invalid OutB value: {}", val),
        }
    }
}

/// Issues an OUTB instruction to the specified port with the given value.
fn hloutb(port: u16, val: u8) {
    unsafe {
        arch::asm!("out dx, al", in("dx") port, in("al") val, options(preserves_flags, nomem, nostack));
    }
}

pub fn outb(port: u16, value: u8) {
    unsafe {
        match RUNNING_MODE {
            RunMode::Hypervisor => {
                hloutb(port, value);
            }
            RunMode::InProcessLinux | RunMode::InProcessWindows => {
                // TODO(danbugs:297): bring back
                // if let Some(outb_func) = OUTB_PTR_WITH_CONTEXT {
                //     if let Some(peb_ptr) = PEB {
                //         outb_func((*peb_ptr).pOutbContext, port, value);
                //     }
                // } else if let Some(outb_func) = OUTB_PTR {
                //     outb_func(port, value);
                // } else {
                //     panic!("Tried to call outb without hypervisor and without outb function ptrs");
                // }
            }
            _ => {
                panic!("Tried to call outb in invalid runmode");
            }
        }
    }
}
