use core::arch;

use anyhow::{bail, Result};

use crate::peb::RunMode;
use crate::{OUTB_HANDLER, OUTB_HANDLER_CTX, PEB, RUNNING_MODE};

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

pub fn outb(port: u16, value: u8) -> Result<()> {
    unsafe {
        match RUNNING_MODE {
            RunMode::Hypervisor => {
                hloutb(port, value);
            }
            RunMode::InProcessLinux | RunMode::InProcessWindows => {
                if let Some(outb_func) = OUTB_HANDLER_CTX {
                    outb_func(
                        (*PEB).get_outb_ptr_ctx() as *mut core::ffi::c_void,
                        port,
                        value,
                    );
                } else if let Some(outb_func) = OUTB_HANDLER {
                    outb_func(port, value);
                } else {
                    bail!("Tried to call outb without hypervisor and without outb function ptrs");
                }
            }
            _ => {
                bail!("Tried to call outb in invalid runmode");
            }
        }
    }

    Ok(())
}
