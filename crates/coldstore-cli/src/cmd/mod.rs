//! CLI subcommand modules. `main.rs` owns arg parsing and dispatch; each
//! module owns one command's behavior and its human printer.

pub mod archive;
pub mod compress;
pub mod dedupe;
pub mod extract;
pub mod list;
pub mod mark;
pub mod plan;
pub mod predict;
pub mod quarantine;
pub mod rule;
pub mod run;
pub mod scan;
pub mod undo;
pub mod verify;

use std::time::SystemTime;

/// Human-readable mtime (epoch seconds; "未知" when absent).
pub(crate) fn fmt_time(t: Option<SystemTime>) -> String {
    match t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
        Some(d) => format!("{} s", d.as_secs()),
        None => "未知".to_string(),
    }
}
