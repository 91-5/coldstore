//! P3 · NTFS transparent compression — real round-trip on a temporary copy.
//!
//! This test never touches a user tree: it builds its own fixture under
//! the system temp directory, compresses it, verifies the measured effect
//! and then decompresses it again, checking that the content survived
//! byte-for-byte (card D3 reversibility, acceptance B7/B8).
//!
//! On a non-NTFS volume (FAT32/exFAT/network share) the compression call
//! fails; the test then reports the environment limitation instead of
//! pretending the feature works.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use coldstore_core::ntfs::{
    compress_batch, file_compressed_size, file_is_compressed, CompressOptions, CompressionMode,
};
use coldstore_core::scan::FileEntry;
use sha2::{Digest, Sha256};

fn temp_fixture(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "coldstore-p3-test-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A compressible payload: repeated text compresses well, so the measured
/// ratio is meaningfully above 1.0.
fn payload(seed: &str, repeat: usize) -> Vec<u8> {
    let line = format!("{seed}: the quick brown fox jumps over the lazy dog\n");
    line.repeat(repeat).into_bytes()
}

fn sha256(path: &Path) -> String {
    let data = fs::read(path).unwrap();
    let mut h = Sha256::new();
    h.update(&data);
    format!("{:x}", h.finalize())
}

fn entry(path: &Path) -> FileEntry {
    let meta = fs::metadata(path).unwrap();
    FileEntry {
        path: path.to_path_buf(),
        size: meta.len(),
        ext: path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default(),
        modified: meta.modified().ok(),
        accessed: None,
        is_reparse: false,
        is_hidden: false,
        is_system: false,
        magic_hex: String::new(),
        magic_read_failed: false,
    }
}

#[test]
fn ntfs_compression_round_trip_is_lossless_and_reversible() {
    let dir = temp_fixture("roundtrip");

    let mut files: Vec<PathBuf> = Vec::new();
    for (i, name) in ["a.bin", "b.bin", "c.bin"].iter().enumerate() {
        let p = dir.join(name);
        fs::write(&p, payload(name, 40_000 + i * 5_000)).unwrap();
        files.push(p);
    }

    let before: Vec<String> = files.iter().map(|p| sha256(p)).collect();
    let entries: Vec<FileEntry> = files.iter().map(|p| entry(p)).collect();

    // ── compress ────────────────────────────────────────────────────────
    let opts = CompressOptions {
        mode: CompressionMode::Enable,
        ..Default::default()
    };
    let stats = compress_batch(&entries, &opts).expect("compress batch");

    if stats.files_failed == stats.files_total && stats.files_total > 0 {
        // The volume refused NTFS compression (FAT32/exFAT/network).
        let reason = stats
            .failures
            .first()
            .map(|f| f.error.clone())
            .unwrap_or_default();
        fs::remove_dir_all(&dir).ok();
        panic!("NTFS compression is unavailable on this volume: {reason}");
    }

    assert_eq!(
        stats.files_processed,
        files.len() as u64,
        "all files compressed"
    );
    assert_eq!(stats.files_failed, 0, "no compression failures");
    assert!(
        stats.ratio() > 1.5,
        "measured ratio should be clearly above 1.0, got {:.2}",
        stats.ratio()
    );

    for p in &files {
        assert!(
            file_is_compressed(p).unwrap(),
            "file must carry FILE_ATTRIBUTE_COMPRESSED: {}",
            p.display()
        );
        assert!(
            file_compressed_size(p).unwrap() < fs::metadata(p).unwrap().len(),
            "on-disk size must be smaller than the logical size"
        );
    }

    // Content is untouched by the compression itself.
    let during: Vec<String> = files.iter().map(|p| sha256(p)).collect();
    assert_eq!(during, before, "compression must not change the bytes");

    // ── decompress (the reversibility half) ─────────────────────────────
    let opts = CompressOptions {
        mode: CompressionMode::Disable,
        ..Default::default()
    };
    let stats = compress_batch(&entries, &opts).expect("decompress batch");
    assert_eq!(
        stats.files_processed,
        files.len() as u64,
        "all files decompressed"
    );
    assert_eq!(stats.files_failed, 0, "no decompression failures");

    for p in &files {
        assert!(
            !file_is_compressed(p).unwrap(),
            "compression must be gone: {}",
            p.display()
        );
        assert_eq!(
            file_compressed_size(p).unwrap(),
            fs::metadata(p).unwrap().len(),
            "on-disk size must be back to the logical size"
        );
    }

    let after: Vec<String> = files.iter().map(|p| sha256(p)).collect();
    assert_eq!(after, before, "round trip must be byte-identical");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn compression_skips_excluded_paths_and_already_compressed_formats() {
    let dir = temp_fixture("skips");

    // A file inside a hardcoded system directory — never compressed.
    let excluded_dir = dir.join("Program Files");
    fs::create_dir_all(&excluded_dir).unwrap();
    let excluded = excluded_dir.join("install.bin");
    fs::write(&excluded, payload("excluded", 40_000)).unwrap();

    // A pre-compressed format — refused by the executor.
    let png = dir.join("shot.png");
    fs::write(&png, payload("png", 40_000)).unwrap();

    // A normal candidate.
    let plain = dir.join("plain.bin");
    fs::write(&plain, payload("plain", 40_000)).unwrap();

    let entries = vec![entry(&excluded), entry(&png), entry(&plain)];
    let opts = CompressOptions::default();
    let stats = compress_batch(&entries, &opts).expect("compress batch");

    assert_eq!(stats.files_processed, 1, "only the plain file is touched");
    assert_eq!(
        stats.skipped_by_reason.get("excluded_path").copied(),
        Some(1),
        "system directory must be skipped"
    );
    assert_eq!(
        stats
            .skipped_by_reason
            .get("pre_compressed_format")
            .copied(),
        Some(1),
        "png must be skipped"
    );

    assert!(!file_is_compressed(&excluded).unwrap());
    assert!(!file_is_compressed(&png).unwrap());
    assert!(file_is_compressed(&plain).unwrap());

    // Clean up: the plain file is compressed, undo it before removing.
    let _ = compress_batch(
        &[entry(&plain)],
        &CompressOptions {
            mode: CompressionMode::Disable,
            ..Default::default()
        },
    );
    fs::remove_dir_all(&dir).ok();
}
