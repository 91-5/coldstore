//! Archive index: entries, JSON serialization, skippable-frame embedding
//! and the fail-closed embedded-vs-sidecar rule (AV-3, review Q3).
//!
//! Adjudicated semantics (REVIEW-OC-20261110-001 §3 Q3):
//! - the **embedded skippable-frame index is the single source of truth**;
//!   it is written atomically with the container (header last, rename after
//!   full write) and travels with it;
//! - a sidecar `.idx` is a **derived cache**. When both exist and disagree
//!   on any key, every operation fails closed with
//!   `embedded index vs sidecar idx disagree on key N` — never a silent
//!   preference (the sidecar goes stale exactly when a container is
//!   appended or repaired, which is its typical failure mode);
//! - skippable-frame content is limited to **255 MiB** (32-bit length
//!   field). Beyond that, v0.1 falls back to a sidecar-authoritative
//!   container (no index chunking).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Skippable-frame magic used for ColdStore indexes. The zstd spec reserves
/// `0x184D2A50..=0x184D2A5F` for skippable frames; we pin one value.
pub const SKIPPABLE_MAGIC: u32 = 0x184D2A5F;
/// Skippable frames carry a 32-bit content length: hard cap 255 MiB.
pub const SKIPPABLE_MAX_CONTENT: u64 = 255 * 1024 * 1024;
/// Identity string of the JSON index payload.
pub const INDEX_FORMAT: &str = "coldstore-index/v0.1";
/// Container format version (header field).
pub const CONTAINER_VERSION: u16 = 1;
/// Fixed header size in bytes.
pub const HEADER_SIZE: u64 = 64;

/// Key used to address one entry of a container (card §7: NTFS is
/// case-insensitive → *path + ordinal* is the identity pair, not path alone).
#[derive(Debug, Clone)]
pub enum EntryKey {
    Ordinal(u64),
    Path(String),
}

/// One archived file. `sha256_hex` is mandatory for containers written by
/// this crate (AV-6); it is an `Option` only so *foreign*/legacy containers
/// can still be read — retrieval then degrades to size-only checking with
/// an explicit `UNVERIFIED` warning, never a silent pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexEntry {
    pub ordinal: u64,
    /// Original absolute path as archived ("原路径").
    pub path: String,
    /// Original file size in bytes.
    pub size: u64,
    /// Compressed frame size in bytes (frame header included).
    pub compressed_size: u64,
    /// Absolute byte offset of the frame inside the container.
    pub offset: u64,
    /// mtime split into (seconds, subsec-nanos) since UNIX epoch — u64
    /// bookkeeping throughout (AV-8: no 2 GiB overflow anywhere).
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    /// SHA-256 of the original content, lowercase hex (64 chars).
    pub sha256_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchiveIndex {
    pub format: String,
    pub container_version: u16,
    /// Why the index lives where it lives (embedded / sidecar fallback).
    pub index_mode: String,
    pub entries: Vec<IndexEntry>,
}

impl ArchiveIndex {
    pub fn new(index_mode: &str) -> Self {
        ArchiveIndex {
            format: INDEX_FORMAT.to_string(),
            container_version: CONTAINER_VERSION,
            index_mode: index_mode.to_string(),
            entries: Vec::new(),
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("索引 JSON 序列化失败")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let idx: ArchiveIndex =
            serde_json::from_slice(bytes).context("索引 JSON 解析失败（容器损坏或版本不符）")?;
        if idx.format != INDEX_FORMAT {
            bail!("索引格式不符: 期望 {INDEX_FORMAT}，实际 {}", idx.format);
        }
        if idx.container_version > CONTAINER_VERSION {
            bail!(
                "容器版本过新: 索引 {} > 本程序支持 {}",
                idx.container_version,
                CONTAINER_VERSION
            );
        }
        Ok(idx)
    }

    /// Address one entry. Path keys match case-insensitively (NTFS
    /// semantics); an ambiguous match is an error listing the candidates —
    /// the user is told to use the ordinal instead.
    pub fn lookup(&self, key: &EntryKey) -> Result<&IndexEntry> {
        match key {
            EntryKey::Ordinal(o) => {
                self.entries
                    .iter()
                    .find(|e| e.ordinal == *o)
                    .ok_or_else(|| {
                        anyhow!(
                            "序号 {o} 不在索引中（共 {} 个条目，范围 0..={}）",
                            self.entries.len(),
                            self.entries.len().saturating_sub(1)
                        )
                    })
            }
            EntryKey::Path(p) => {
                let lower = p.to_lowercase();
                let matches: Vec<&IndexEntry> = self
                    .entries
                    .iter()
                    .filter(|e| e.path.to_lowercase() == lower)
                    .collect();
                match matches.len() {
                    0 => bail!(
                        "路径 {p} 不在此容器中（共 {} 个条目；可用 `coldstore list` 查看）",
                        self.entries.len()
                    ),
                    1 => Ok(matches[0]),
                    _ => bail!(
                        "路径 {p} 命中多个条目（NTFS 大小写不敏感）——请用序号取回: {}",
                        matches
                            .iter()
                            .map(|e| format!("#{} {}", e.ordinal, e.path))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                }
            }
        }
    }
}

/// Wrap index JSON in a zstd skippable frame (magic + u32 LE length).
pub fn pack_skippable(content: &[u8]) -> Result<Vec<u8>> {
    let len = content.len() as u64;
    if len > SKIPPABLE_MAX_CONTENT {
        bail!(
            "索引内容 {} 超过 skippable 帧上限 255 MiB —— 需退回 sidecar .idx 模式（v0.1 不分块）",
            len
        );
    }
    let mut out = Vec::with_capacity(8 + content.len());
    out.extend_from_slice(&SKIPPABLE_MAGIC.to_le_bytes());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    Ok(out)
}

/// Inverse of [`pack_skippable`]; validates magic and declared length.
pub fn unpack_skippable(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < 8 {
        bail!("skippable 帧截断: {} 字节 < 8", buf.len());
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != SKIPPABLE_MAGIC {
        bail!("skippable 帧魔数不符: {magic:#x}（期望 {SKIPPABLE_MAGIC:#x}）");
    }
    let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
    if len as usize != buf.len() - 8 {
        bail!("skippable 帧长度不符: 声明 {len}，实际 {}", buf.len() - 8);
    }
    Ok(&buf[8..])
}

pub fn sidecar_path(container: &Path) -> PathBuf {
    let mut s = container.as_os_str().to_owned();
    s.push(".idx");
    PathBuf::from(s)
}

/// Where the authoritative index lives, per the container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexMode {
    Embedded,
    Sidecar,
}

/// Open the authoritative index for `container`, enforcing AV-3:
/// - embedded mode + sidecar present → both parsed and compared; any
///   disagreement is a hard error naming the first differing key;
/// - embedded region missing/corrupt → hard error (never a silent fallback
///   to the sidecar — that fallback is exactly the stale-cache trap);
/// - sidecar-authoritative mode (255 MiB overflow) → sidecar required.
pub fn open_index(
    container: &Path,
    mode: IndexMode,
    embedded_region: Option<&[u8]>,
) -> Result<ArchiveIndex> {
    let embedded = match embedded_region {
        Some(region) if !region.is_empty() => Some(
            ArchiveIndex::from_json(unpack_skippable(region)?)
                .context("内嵌索引解析失败（fail-closed，不做 sidecar 静默回退）")?,
        ),
        _ => None,
    };
    let sidecar_file = sidecar_path(container);
    let sidecar = if sidecar_file.exists() {
        let bytes = fs::read(&sidecar_file)
            .with_context(|| format!("读取 sidecar 失败: {}", sidecar_file.display()))?;
        Some(ArchiveIndex::from_json(&bytes)?)
    } else {
        None
    };

    match (mode, embedded, sidecar) {
        (_, None, None) => bail!(
            "容器没有可用索引（内嵌缺失且无 sidecar .idx）: {}",
            container.display()
        ),
        (IndexMode::Sidecar, _, None) => bail!(
            "容器为 sidecar 权威模式但 {} 不存在（fail-closed，拒绝猜测）",
            sidecar_file.display()
        ),
        (IndexMode::Sidecar, embedded, Some(s)) => {
            if let Some(e) = embedded {
                if let Some(note) = e.entries.first() {
                    if note.size != 0 || note.ordinal != u64::MAX {
                        // overflow mode stores a sentinel note only
                        bail!("内嵌区在 sidecar 模式下应为占位符，实际含数据条目（容器损坏）");
                    }
                }
            }
            Ok(s)
        }
        (IndexMode::Embedded, Some(e), None) => Ok(e),
        (IndexMode::Embedded, Some(e), Some(s)) => {
            assert_same(&e, &s)?;
            Ok(e)
        }
        (IndexMode::Embedded, None, Some(_)) => bail!(
            "头声明内嵌权威但内嵌索引缺失/损坏，且存在 sidecar —— fail-closed，拒绝静默回退: {}",
            container.display()
        ),
    }
}

/// AV-3 fail-closed comparison: first disagreement on key N is named.
pub fn assert_same(embedded: &ArchiveIndex, sidecar: &ArchiveIndex) -> Result<()> {
    if embedded.entries.len() != sidecar.entries.len() {
        bail!(
            "embedded index vs sidecar idx disagree on key count（embedded {} 条 vs sidecar {} 条）—— fail-closed",
            embedded.entries.len(),
            sidecar.entries.len()
        );
    }
    for (i, (a, b)) in embedded
        .entries
        .iter()
        .zip(sidecar.entries.iter())
        .enumerate()
    {
        if a != b {
            bail!(
                "embedded index vs sidecar idx disagree on key {}（ordinal {}）—— fail-closed，拒绝静默择一",
                i,
                a.ordinal
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(ordinal: u64) -> IndexEntry {
        IndexEntry {
            ordinal,
            path: format!("C:\\data\\file{ordinal}.bin"),
            size: 1000 + ordinal,
            compressed_size: 500 + ordinal,
            offset: HEADER_SIZE + ordinal * 1000,
            mtime_secs: 1_700_000_000,
            mtime_nanos: 123,
            sha256_hex: Some("ab".repeat(32)),
        }
    }

    #[test]
    fn index_json_roundtrip_including_zero_byte_entry() {
        let mut idx = ArchiveIndex::new("embedded");
        // 0-byte entry: empty-content SHA-256 constant (AV-8)
        idx.entries.push(IndexEntry {
            ordinal: 0,
            path: "empty.bin".into(),
            size: 0,
            compressed_size: 9,
            offset: HEADER_SIZE,
            mtime_secs: 0,
            mtime_nanos: 0,
            sha256_hex: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            ),
        });
        idx.entries.push(sample_entry(1));
        let bytes = idx.to_json().unwrap();
        let back = ArchiveIndex::from_json(&bytes).unwrap();
        assert_eq!(idx, back);
        assert!(bytes.len() < 1024, "u64 bookkeeping stays compact");
    }

    #[test]
    fn skippable_pack_unpack_roundtrip_and_oversize_rejected() {
        let payload = b"hello coldstore index".to_vec();
        let packed = pack_skippable(&payload).unwrap();
        assert_eq!(&packed[..4], &SKIPPABLE_MAGIC.to_le_bytes());
        assert_eq!(&packed[4..8], &(payload.len() as u32).to_le_bytes());
        assert_eq!(unpack_skippable(&packed).unwrap(), payload.as_slice());

        let corrupted = {
            let mut c = packed.clone();
            c[4] = 0xFF;
            c
        };
        assert!(
            unpack_skippable(&corrupted).is_err(),
            "declared length mismatch rejected"
        );

        let oversize = vec![0u8; (SKIPPABLE_MAX_CONTENT + 1) as usize];
        assert!(
            pack_skippable(&oversize).is_err(),
            "255 MiB cap enforced (AV-3)"
        );
    }

    #[test]
    fn path_lookup_is_case_insensitive_and_ambiguity_fails_with_candidates() {
        let mut idx = ArchiveIndex::new("embedded");
        // crafted foreign container: two entries differing only by case
        idx.entries.push(IndexEntry {
            ordinal: 0,
            path: "C:\\data\\a.TXT".into(),
            ..sample_entry(0)
        });
        idx.entries.push(IndexEntry {
            ordinal: 1,
            path: "C:\\data\\A.txt".into(),
            ..sample_entry(1)
        });
        let one = idx
            .lookup(&EntryKey::Path("c:\\DATA\\a.txt".into()))
            .unwrap_err();
        let msg = one.to_string();
        assert!(msg.contains("命中多个条目"), "{msg}");
        assert!(
            msg.contains("#0") && msg.contains("#1"),
            "candidates listed: {msg}"
        );

        assert_eq!(
            idx.lookup(&EntryKey::Ordinal(1)).unwrap().path,
            "C:\\data\\A.txt",
            "ordinal is the unambiguous key (path+ordinal double key, card §7)"
        );
        assert!(idx.lookup(&EntryKey::Ordinal(99)).is_err());
    }

    #[test]
    fn embedded_vs_sidecar_disagreement_fails_closed() {
        let mut e = ArchiveIndex::new("embedded");
        e.entries.push(sample_entry(0));
        e.entries.push(sample_entry(1));
        let mut s = e.clone();
        s.entries[1].size += 1; // stale sidecar after external append

        let err = assert_same(&e, &s).unwrap_err().to_string();
        assert!(
            err.starts_with("embedded index vs sidecar idx disagree on key 1"),
            "{err}"
        );

        let mut count_mismatch = s.clone();
        count_mismatch.entries.pop();
        let err = assert_same(&e, &count_mismatch).unwrap_err().to_string();
        assert!(err.contains("disagree on key count"), "{err}");
    }

    #[test]
    fn missing_embedded_never_falls_back_to_sidecar() {
        let s = {
            let mut x = ArchiveIndex::new("sidecar");
            x.entries.push(sample_entry(0));
            x
        };
        // header says embedded-authoritative, embedded region empty,
        // sidecar exists → must fail closed, NOT silently use the sidecar
        let dir = std::env::temp_dir().join("coldstore-idx-fc-test");
        fs::create_dir_all(&dir).unwrap();
        let container = dir.join("fake.coldstore");
        fs::write(sidecar_path(&container), s.to_json().unwrap()).unwrap();
        let err = open_index(&container, IndexMode::Embedded, Some(&[])).unwrap_err();
        assert!(err.to_string().contains("拒绝静默回退"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }
}
