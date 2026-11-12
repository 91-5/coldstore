//! Cooperative Ctrl-C handling.
//!
//! The default Windows console behaviour for Ctrl-C is to terminate the
//! process on the spot. For a long NTFS compression batch that is the
//! worst possible outcome: the batch is killed between two files and the
//! user never learns how far it got.
//!
//! Instead we install a console handler that only flips a flag. The
//! compression worker checks that flag at every file boundary, stops
//! cleanly and reports exactly how much was done — and because already
//! compressed files are skipped on the next run, re-running the same
//! command simply resumes where the batch stopped.

use std::sync::atomic::{AtomicBool, Ordering};

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
mod imp {
    use std::sync::atomic::Ordering;

    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT,
    };

    extern "system" fn handler(ctrl_type: u32) -> BOOL {
        if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
            super::CANCEL_REQUESTED.store(true, Ordering::SeqCst);
            TRUE
        } else {
            FALSE
        }
    }

    pub fn install() {
        // SAFETY: `handler` is a plain `extern "system"` function with no
        // captured state; the handler stays valid for the process
        // lifetime, which is exactly the lifetime of the flag it sets.
        unsafe {
            SetConsoleCtrlHandler(Some(handler), TRUE);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn install() {}
}

/// Install the console handler (idempotent).
pub fn install() {
    imp::install();
}

/// Clear a previously recorded interrupt (used before a new batch).
pub fn reset() {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
}

/// Has the user asked to stop?
pub fn cancel_requested() -> bool {
    CANCEL_REQUESTED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_round_trips() {
        reset();
        assert!(!cancel_requested());
        CANCEL_REQUESTED.store(true, Ordering::SeqCst);
        assert!(cancel_requested());
        reset();
        assert!(!cancel_requested());
    }
}
