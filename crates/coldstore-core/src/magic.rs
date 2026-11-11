//! File-header (magic bytes) identification.
//!
//! The scanner captures the first up-to-16 bytes of every file. This module
//! maps them to a coarse [`MagicKind`] so the predictor can catch
//! "extension lies" (a `.png` that is really plain text, a `.log` that is
//! really a zip) before any compression work is scheduled — measured real
//! corpora show zstd on already-compressed formats yields ≈100% ratio
//! (i.e. zero gain), so trusting the extension alone is not an option.

/// Number of leading bytes the scanner captures per file.
pub const MAGIC_CAPTURE_LEN: usize = 16;

/// Coarse classification from the leading bytes of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MagicKind {
    /// File exists but has zero bytes.
    Empty,
    /// Looks like plain text: no control bytes in the captured head.
    Text,
    /// `!<arch>\n` ar archive — Rust `.rlib` and static libraries.
    ArArchive,
    /// Microsoft PDB (MSF) program database.
    Pdb,
    Zip,
    SevenZip,
    Rar,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
    Png,
    Jpeg,
    Gif,
    Webp,
    Bmp,
    Mp4,
    /// Matroska / WebM (`EBML` header).
    Mkv,
    Avi,
    Mp3,
    Flac,
    /// ADTS stream (`FF F1` / `FF F9`).
    Aac,
    Ogg,
    Pdf,
    /// OLE compound file (legacy Office, MSI).
    Ole,
    /// `MZ` — PE executable / DLL.
    Pe,
    Elf,
    Wasm,
    Vhdx,
    Sqlite,
    Woff,
    Woff2,
    /// No known signature.
    Unknown,
}

impl MagicKind {
    /// Human-readable name used in reason strings and reports.
    pub fn describe(self) -> &'static str {
        match self {
            MagicKind::Empty => "empty file",
            MagicKind::Text => "text",
            MagicKind::ArArchive => "ar archive (rlib/static lib)",
            MagicKind::Pdb => "pdb (MSF)",
            MagicKind::Zip => "zip",
            MagicKind::SevenZip => "7z",
            MagicKind::Rar => "rar",
            MagicKind::Gzip => "gzip",
            MagicKind::Bzip2 => "bzip2",
            MagicKind::Xz => "xz",
            MagicKind::Zstd => "zstd",
            MagicKind::Lz4 => "lz4",
            MagicKind::Png => "png",
            MagicKind::Jpeg => "jpeg",
            MagicKind::Gif => "gif",
            MagicKind::Webp => "webp",
            MagicKind::Bmp => "bmp",
            MagicKind::Mp4 => "mp4",
            MagicKind::Mkv => "matroska/webm",
            MagicKind::Avi => "avi",
            MagicKind::Mp3 => "mp3",
            MagicKind::Flac => "flac",
            MagicKind::Aac => "aac",
            MagicKind::Ogg => "ogg",
            MagicKind::Pdf => "pdf",
            MagicKind::Ole => "ole compound (msi/legacy office)",
            MagicKind::Pe => "pe executable (mz)",
            MagicKind::Elf => "elf",
            MagicKind::Wasm => "wasm",
            MagicKind::Vhdx => "vhdx",
            MagicKind::Sqlite => "sqlite",
            MagicKind::Woff => "woff",
            MagicKind::Woff2 => "woff2",
            MagicKind::Unknown => "unknown",
        }
    }

    /// Formats whose content is already compressed (or otherwise known to
    /// resist general-purpose compression): compression containers, media,
    /// images, PDF and web fonts. Measured real-corpus ratios for these are
    /// ≈ 0.9–1.0 (png 100.0%, mp3 92.9%), so they are skipped without
    /// sampling. Note: `Vhdx` is deliberately NOT here — virtual disk
    /// images must be sampled before any verdict (they are also
    /// rebuildable-hostile, so deleting is never suggested).
    pub fn is_incompressible(self) -> bool {
        matches!(
            self,
            MagicKind::Zip
                | MagicKind::SevenZip
                | MagicKind::Rar
                | MagicKind::Gzip
                | MagicKind::Bzip2
                | MagicKind::Xz
                | MagicKind::Zstd
                | MagicKind::Lz4
                | MagicKind::Png
                | MagicKind::Jpeg
                | MagicKind::Gif
                | MagicKind::Webp
                | MagicKind::Mp4
                | MagicKind::Mkv
                | MagicKind::Avi
                | MagicKind::Mp3
                | MagicKind::Flac
                | MagicKind::Aac
                | MagicKind::Ogg
                | MagicKind::Pdf
                | MagicKind::Woff
                | MagicKind::Woff2
        )
    }
}

/// Classify a file by its leading bytes.
pub fn identify(bytes: &[u8]) -> MagicKind {
    if bytes.is_empty() {
        return MagicKind::Empty;
    }
    let b = bytes;
    let starts = |sig: &[u8]| b.len() >= sig.len() && &b[..sig.len()] == sig;

    if starts(b"\x89PNG") {
        return MagicKind::Png;
    }
    if starts(b"\xFF\xD8\xFF") {
        return MagicKind::Jpeg;
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return MagicKind::Gif;
    }
    if b.len() >= 12 && &b[0..4] == b"RIFF" {
        if &b[8..12] == b"WEBP" {
            return MagicKind::Webp;
        }
        if &b[8..12] == b"AVI " {
            return MagicKind::Avi;
        }
    }
    if starts(b"BM") {
        return MagicKind::Bmp;
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return MagicKind::Zip;
    }
    if starts(b"7z\xBC\xAF\x27\x1C") {
        return MagicKind::SevenZip;
    }
    if starts(b"Rar!\x1A\x07") {
        return MagicKind::Rar;
    }
    if starts(b"\x1F\x8B") {
        return MagicKind::Gzip;
    }
    if starts(b"BZh") {
        return MagicKind::Bzip2;
    }
    if starts(b"\xFD7zXZ\x00") {
        return MagicKind::Xz;
    }
    if starts(b"\x28\xB5\x2F\xFD") {
        return MagicKind::Zstd;
    }
    if starts(b"\x04\x22\x4D\x18") {
        return MagicKind::Lz4;
    }
    if b.len() >= 8 && &b[4..8] == b"ftyp" {
        return MagicKind::Mp4;
    }
    if starts(b"\x1A\x45\xDF\xA3") {
        return MagicKind::Mkv;
    }
    if starts(b"\x00asm") {
        return MagicKind::Wasm;
    }
    if starts(b"fLaC") {
        return MagicKind::Flac;
    }
    if starts(b"OggS") {
        return MagicKind::Ogg;
    }
    if starts(b"%PDF") {
        return MagicKind::Pdf;
    }
    if starts(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        return MagicKind::Ole;
    }
    if starts(b"vhdxfile") {
        return MagicKind::Vhdx;
    }
    if starts(b"SQLite format 3") {
        return MagicKind::Sqlite;
    }
    if starts(b"wOFF") {
        return MagicKind::Woff;
    }
    if starts(b"wOF2") {
        return MagicKind::Woff2;
    }
    if starts(b"!<arch>\n") {
        return MagicKind::ArArchive;
    }
    if starts(b"Microsoft C/C+") {
        return MagicKind::Pdb;
    }
    if starts(b"\x7FELF") {
        return MagicKind::Elf;
    }
    if starts(b"MZ") {
        return MagicKind::Pe;
    }
    // MPEG audio: 11-bit frame sync `FF E?`/`FF F?`. ADTS AAC uses layer
    // bits `00` (reserved in MPEG-1/2 audio), MP3 is layer 3 (`01`).
    if b[0] == 0xFF && b.len() >= 2 && (b[1] & 0xE0) == 0xE0 {
        return if (b[1] >> 1) & 0x03 == 0x00 {
            MagicKind::Aac
        } else {
            MagicKind::Mp3
        };
    }
    if starts(b"ID3") {
        return MagicKind::Mp3;
    }
    if looks_like_text(b) {
        return MagicKind::Text;
    }
    MagicKind::Unknown
}

/// Heuristic text check: no C0 control bytes other than tab/LF/CR.
/// Bytes ≥ 0x80 are allowed (UTF-8, GBK, Latin-1 …).
fn looks_like_text(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| matches!(c, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) || c >= 0x80)
}

#[cfg(test)]
mod tests {
    use super::{identify, MagicKind};

    #[test]
    fn identifies_common_containers() {
        assert_eq!(identify(b"\x89PNG\r\n\x1a\n"), MagicKind::Png);
        assert_eq!(identify(b"\xFF\xD8\xFF\xE0"), MagicKind::Jpeg);
        assert_eq!(identify(b"GIF89a...."), MagicKind::Gif);
        assert_eq!(identify(b"PK\x03\x04...."), MagicKind::Zip);
        assert_eq!(identify(b"7z\xBC\xAF\x27\x1C"), MagicKind::SevenZip);
        assert_eq!(identify(b"\x1F\x8B\x08"), MagicKind::Gzip);
        assert_eq!(identify(b"\x28\xB5\x2F\xFD\x00"), MagicKind::Zstd);
        assert_eq!(identify(b"%PDF-1.7\n"), MagicKind::Pdf);
        assert_eq!(identify(b"MZ\x90\x00"), MagicKind::Pe);
        assert_eq!(identify(b"vhdxfile...."), MagicKind::Vhdx);
    }

    #[test]
    fn identifies_ar_archive_and_pdb() {
        assert_eq!(identify(b"!<arch>\ndate"), MagicKind::ArArchive);
        assert_eq!(identify(b"Microsoft C/C++ MSF 7.00"), MagicKind::Pdb);
    }

    #[test]
    fn identifies_empty_text_and_unknown() {
        assert_eq!(identify(b""), MagicKind::Empty);
        assert_eq!(identify(b"hello, world\n"), MagicKind::Text);
        assert_eq!(
            identify(b"\x01\x02\x03\x04\x05\x06\x07"),
            MagicKind::Unknown
        );
    }

    #[test]
    fn distinguishes_mp3_from_adts_aac() {
        // AAC ADTS: layer bits 00
        assert_eq!(identify(&[0xFF, 0xF1, 0x50, 0x80]), MagicKind::Aac);
        assert_eq!(identify(&[0xFF, 0xF9, 0x50, 0x80]), MagicKind::Aac);
        // MP3: layer bits 01
        assert_eq!(identify(&[0xFF, 0xFB, 0x90, 0x00]), MagicKind::Mp3);
        assert_eq!(identify(b"ID3\x04\x00"), MagicKind::Mp3);
    }

    #[test]
    fn incompressible_set_matches_card_a7_findings() {
        // Measured 2026-11-10: png → 100.0%, mp3 → 92.9% — must be skipped
        // without sampling; vhdx must NOT be (sample first, AV-N3).
        assert!(MagicKind::Png.is_incompressible());
        assert!(MagicKind::Mp3.is_incompressible());
        assert!(MagicKind::Zip.is_incompressible());
        assert!(!MagicKind::Vhdx.is_incompressible());
        assert!(!MagicKind::Text.is_incompressible());
        assert!(!MagicKind::ArArchive.is_incompressible());
    }
}
