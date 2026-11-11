//! ColdStore core engine.
//!
//! Engine layer only: file scanning, compression gain prediction, duplicate
//! detection and a zstd frame archive format with single-file retrieval.
//!
//! This crate is deliberately read-only with respect to user files: the
//! archive/extract API is the only part that writes to disk (the container
//! and the requested destination). Deleting, moving or quarantining user
//! files belongs to a later execution layer and must not be implemented
//! here.
//!
//! Design invariants (card OC-20261110-001):
//! - no solid compression: one independent zstd frame per file, so any
//!   single file can be retrieved without decompressing the rest;
//! - the embedded (skippable-frame) index is the single source of truth;
//!   a sidecar `.idx` is a derived cache and any disagreement between the
//!   two is a hard error (fail-closed);
//! - every archive index entry stores the SHA-256 of the original file
//!   content, mandatory since format v0.1.

pub mod magic;
pub mod predict;
pub mod scan;

/// Crate version as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_0_1_0() {
        assert_eq!(VERSION, "0.1.0");
    }
}
