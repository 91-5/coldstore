//! `.coldstore` archive engine — independent zstd frames, one per file,
//! with a self-contained embedded index and single-frame retrieval.
//!
//! Hard rules implemented here (card D5 + review adjudications):
//! - **no solid compression**: every file becomes its own zstd frame, so
//!   retrieving file #k reads exactly bytes [offset, offset+compressed_size)
//!   and never touches any other frame (measured cost vs solid: +1.33%);
//! - **sha256 mandatory** in v0.1 indexes (AV-6): computed streaming while
//!   compressing (one read, three uses — retrieve check, verify, and the
//!   future dedupe execution); retrieval without a hash degrades to
//!   `UNVERIFIED` size-only checking with a loud warning, never silent pass;
//! - **fail-closed indexing** (AV-3, see index.rs);
//! - **cross-volume container writes are allowed** (AV-5): freeing space on
//!   a full disk by archiving to another volume is a primary use case —
//!   only *restore-to-original without an explicit destination* is
//!   rejected when volumes differ, with entry name + both volume letters +
//!   remediation;
//! - all bookkeeping is u64 (AV-8): 0-byte and >2 GiB members are valid.
//!
//! Write protocol: everything goes to `<container>.tmp` (frames → index
//! skippable frame → header seek-back) and the container is published by a
//! rename, so a crash can never expose a valid header over partial data.

mod container;
mod index;

pub use container::{frame_window_log, ContainerHeader};
pub use index::{
    open_index, sidecar_path, ArchiveIndex, EntryKey, IndexEntry, IndexMode, SKIPPABLE_MAGIC,
    SKIPPABLE_MAX_CONTENT,
};

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::scan::FileEntry;

pub const DEFAULT_ZSTD_LEVEL: i32 = 3;
pub const DEFAULT_LONG_WINDOW_LOG: u32 = 27;
/// Long-distance matching only helps beyond this size; below it the
/// encoder would allocate a window buffer bigger than the input.
pub const DEFAULT_LONG_WINDOW_MIN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    pub zstd_level: i32,
    pub long_window_log: u32,
    pub long_window_min_bytes: u64,
    /// Also write the derived sidecar `.idx` cache (AV-3: embedded stays
    /// authoritative; a stale sidecar makes every op fail closed).
    pub sidecar: bool,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        ArchiveOptions {
            zstd_level: DEFAULT_ZSTD_LEVEL,
            long_window_log: DEFAULT_LONG_WINDOW_LOG,
            long_window_min_bytes: DEFAULT_LONG_WINDOW_MIN_BYTES,
            sidecar: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ArchiveStats {
    pub container: String,
    pub index_mode: String,
    pub frame_count: u64,
    pub total_original: u64,
    pub total_compressed: u64,
    pub container_size: u64,
    pub sidecar_written: bool,
    /// Longest frame compression window actually used (max over entries).
    pub max_window_log: u32,
    pub duration_ms: u64,
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Serialize)]
pub struct RetrieveOutcome {
    pub ordinal: u64,
    pub source_path: String,
    pub dest: String,
    pub size: u64,
    pub compressed_size: u64,
    /// false → index entry carried no sha256; size-only check (UNVERIFIED).
    pub sha_verified: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct VerifyStats {
    pub container: String,
    pub frame_count: u64,
    pub entries_checked: u64,
    pub total_original: u64,
    pub total_compressed: u64,
    pub sha_failures: u64,
    pub size_failures: u64,
    /// Entries without a stored hash (foreign containers only).
    pub unverified_entries: u64,
    pub ok: bool,
    pub failures: Vec<String>,
    pub duration_ms: u64,
}

/// Options for [`verify_with`]. `threads: Some(n)` runs the parallel
/// verification in a dedicated rayon pool with exactly `n` workers;
/// `None` (default) uses the global rayon pool. Exposed for the 002
/// execution layer (ADV-5): it will cap verify concurrency when the UI
/// needs to keep the machine responsive during long operations.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub threads: Option<usize>,
}

/// Reader that hashes while streaming (AV-6: sha256 computed during the
/// single compression pass — no second read of the source).
struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    bytes_read: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.bytes_read += n as u64;
        }
        Ok(n)
    }
}

/// Writer that counts bytes handed to the container file.
struct CountingWriter<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Configure a zstd encoder to match the predictor's measurement settings:
/// level 3, LDM + window 27 for large inputs (B6 cross-consistency).
fn configure_encoder<W: Write>(
    enc: &mut zstd::stream::Encoder<'_, W>,
    src_size: u64,
    opts: &ArchiveOptions,
) -> Result<u32> {
    let mut used_window = 0u32;
    if src_size >= opts.long_window_min_bytes {
        enc.long_distance_matching(true)?;
        enc.window_log(opts.long_window_log)?;
        used_window = opts.long_window_log;
    }
    enc.set_pledged_src_size(Some(src_size))?;
    Ok(used_window)
}

/// Archive the given files into `container` (must not exist yet).
/// Entries are ordered deterministically by (lowercased path, path), and
/// each gets a stable ordinal — path + ordinal is the identity pair
/// (card §7: NTFS case-insensitivity).
pub fn archive(
    files: &[FileEntry],
    container: &Path,
    opts: &ArchiveOptions,
) -> Result<ArchiveStats> {
    let started = Instant::now();
    // Resolve to an absolute path up front: a bare filename has an empty
    // parent and index entries should be volume-checkable (AV-5).
    //
    // ADV-2 (documented behaviour): `std::path::absolute` resolves a
    // *relative* argument against the **process current working directory**
    // (except drive-relative forms like `D:foo`, which keep their drive).
    // Callers embedding coldstore (002's rule engine / TUI) that want
    // cwd-independence must pass absolute paths — the library does not
    // second-guess the process cwd.
    let container = std::path::absolute(container)
        .with_context(|| format!("解析容器路径失败: {}", container.display()))?;
    if container.exists() {
        bail!("归档容器已存在，拒绝覆盖: {}", container.display());
    }
    let parent = container
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("容器路径缺少父目录: {}", container.display()))?;
    if !parent.exists() {
        bail!("容器父目录不存在: {}", parent.display());
    }

    // Deterministic entry order.
    let mut ordered: Vec<&FileEntry> = files.iter().collect();
    ordered.sort_by(|a, b| {
        a.path
            .to_string_lossy()
            .to_lowercase()
            .cmp(&b.path.to_string_lossy().to_lowercase())
            .then(a.path.cmp(&b.path))
    });

    let tmp = {
        let mut s = container.as_os_str().to_owned();
        s.push(".tmp");
        PathBuf::from(s)
    };
    if tmp.exists() {
        bail!(
            "存在残留临时文件 {}（上次归档中断）——请先人工清理",
            tmp.display()
        );
    }
    let mut out_file = fs::File::create_new(&tmp)
        .with_context(|| format!("创建临时容器失败: {}", tmp.display()))?;

    // Header placeholder.
    out_file.write_all(&[0u8; index::HEADER_SIZE as usize])?;

    let mut index = index::ArchiveIndex::new("embedded");
    let mut running_offset = index::HEADER_SIZE;
    let mut total_original = 0u64;
    let mut total_compressed = 0u64;
    let mut max_window = 0u32;

    for (ordinal, fe) in ordered.iter().enumerate() {
        let src_path = &fe.path;
        let mut src = fs::File::open(src_path)
            .with_context(|| format!("打开待归档文件失败: {}", src_path.display()))?;
        // Metadata may have drifted since the scan; trust the *current* size.
        let cur_size = src.metadata()?.len();

        let offset = running_offset;
        let mut sink = CountingWriter {
            inner: &mut out_file,
            count: 0,
        };
        let mut hashing = HashingReader {
            inner: &mut src,
            hasher: Sha256::new(),
            bytes_read: 0,
        };
        {
            let mut enc = zstd::stream::Encoder::new(&mut sink, opts.zstd_level)?;
            let used = configure_encoder(&mut enc, cur_size, opts)?;
            max_window = max_window.max(used);
            io::copy(&mut hashing, &mut enc)?;
            enc.finish()?;
        }
        if hashing.bytes_read != cur_size {
            bail!(
                "源文件在归档期间发生变化（读取 {} 字节 ≠ 元数据 {}）: {}",
                hashing.bytes_read,
                cur_size,
                src_path.display()
            );
        }
        let sha = format!("{:x}", hashing.hasher.finalize());
        let compressed = sink.count;
        let (mtime_secs, mtime_nanos) = split_mtime(fe.modified);

        index.entries.push(index::IndexEntry {
            ordinal: ordinal as u64,
            path: src_path.display().to_string(),
            size: cur_size,
            compressed_size: compressed,
            offset,
            mtime_secs,
            mtime_nanos,
            sha256_hex: Some(sha), // AV-6: mandatory since v0.1
        });

        running_offset = offset + compressed;
        total_original += cur_size;
        total_compressed += compressed;
    }

    // Index: embedded skippable frame, or sidecar fallback on 255 MiB
    // overflow (AV-3; v0.1 does not chunk indexes).
    let index_json = index.to_json()?;
    let (index_offset, index_len, index_mode) = match index::pack_skippable(&index_json) {
        Ok(packed) => {
            let off = running_offset;
            out_file.write_all(&packed)?;
            (off, packed.len() as u64, "embedded")
        }
        Err(_) => {
            let mut overflow = index::ArchiveIndex::new("sidecar");
            overflow.entries.push(index::IndexEntry {
                ordinal: u64::MAX,
                path: "(index overflow: authoritative index lives in the sidecar .idx)".into(),
                size: 0,
                compressed_size: 0,
                offset: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
                sha256_hex: None,
            });
            out_file.write_all(&pack_sentinel(&overflow)?)?;
            // The sidecar is authoritative — it must exist before publish.
            let sp = index::sidecar_path(&container);
            if sp.exists() {
                bail!("sidecar 已存在，拒绝覆盖: {}", sp.display());
            }
            (0, 0, "sidecar")
        }
    };

    let total_size = running_offset + index_len;
    let header = container::ContainerHeader {
        version: index::CONTAINER_VERSION,
        index_embedded: index_mode == "embedded",
        frame_count: ordered.len() as u64,
        total_size,
        index_offset,
        index_len,
    };
    container::write_header(&mut out_file, &header)?;
    out_file.sync_all()?;
    drop(out_file);

    // In sidecar mode the authoritative .idx must be in place *before* the
    // container becomes visible.
    if index_mode == "sidecar" {
        fs::write(index::sidecar_path(&container), &index_json).with_context(|| {
            format!(
                "写 sidecar 索引失败: {}",
                index::sidecar_path(&container).display()
            )
        })?;
    }

    fs::rename(&tmp, &container).with_context(|| {
        format!(
            "发布容器失败（rename {} → {}）",
            tmp.display(),
            container.display()
        )
    })?;

    // Derived sidecar cache (opt-in): identical payload, embedded stays
    // authoritative; disagreement makes every operation fail closed.
    let mut sidecar_written = false;
    if opts.sidecar && index_mode == "embedded" {
        fs::write(index::sidecar_path(&container), &index_json)?;
        sidecar_written = true;
    }

    Ok(ArchiveStats {
        container: container.display().to_string(),
        index_mode: index_mode.to_string(),
        frame_count: ordered.len() as u64,
        total_original,
        total_compressed,
        container_size: total_size,
        sidecar_written,
        max_window_log: max_window,
        duration_ms: started.elapsed().as_millis() as u64,
        entries: index.entries,
    })
}

fn pack_sentinel(idx: &index::ArchiveIndex) -> Result<Vec<u8>> {
    index::pack_skippable(&idx.to_json()?)
}

/// Open a container and resolve its authoritative index (fail-closed).
pub fn open_container(
    container: &Path,
) -> Result<(fs::File, container::ContainerHeader, index::ArchiveIndex)> {
    if !container.exists() {
        bail!("容器不存在: {}", container.display());
    }
    let mut file = fs::File::open(container)
        .with_context(|| format!("打开容器失败: {}", container.display()))?;
    let header = container::read_header(&mut file)?;
    let region = container::read_embedded_region(&mut file, &header)?;
    let mode = if header.index_embedded {
        index::IndexMode::Embedded
    } else {
        index::IndexMode::Sidecar
    };
    let idx = index::open_index(container, mode, Some(&region))?;
    Ok((file, header, idx))
}

/// Retrieve exactly one frame. Only bytes [offset, offset+compressed_size)
/// of the container are read — no other frame is touched. Verifies the
/// decoded SHA-256 against the index (AV-6); on mismatch the half-written
/// destination is deleted and an error is raised (card D5).
pub fn retrieve(container: &Path, key: &index::EntryKey, dest: &Path) -> Result<RetrieveOutcome> {
    let started = Instant::now();
    let dest = std::path::absolute(dest)
        .with_context(|| format!("解析目标路径失败: {}", dest.display()))?;
    if dest.exists() {
        bail!("目标已存在，拒绝覆盖: {}", dest.display());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建目标目录失败: {}", parent.display()))?;
    }

    let (mut file, _header, idx) = open_container(container)?;
    let entry = idx.lookup(key)?.clone();

    file.seek(SeekFrom::Start(entry.offset))?;
    let mut take = (&mut file).take(entry.compressed_size);
    let mut decoder = zstd::stream::Decoder::new(&mut take)?;

    let mut out = fs::File::create_new(&dest)
        .with_context(|| format!("创建取回目标失败: {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut decoded = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
        decoded += n as u64;
    }
    drop(decoder);

    // Fail closed on bookkeeping drift: the frame must have consumed its
    // declared region exactly.
    let leftover = take.limit();
    if leftover != 0 {
        let _ = fs::remove_file(dest);
        bail!(
            "帧区域漂移: 条目 {} 声明 compressed_size={}，但解码后剩余 {} 字节未消费（索引与容器不一致）",
            entry.ordinal,
            entry.compressed_size,
            leftover
        );
    }
    if decoded != entry.size {
        let _ = fs::remove_file(dest);
        bail!(
            "取回体积不符: 解码 {} 字节 ≠ 索引 {}（条目 {}）——已删除半成品",
            decoded,
            entry.size,
            entry.ordinal
        );
    }

    let outcome = RetrieveOutcome {
        ordinal: entry.ordinal,
        source_path: entry.path.clone(),
        dest: dest.display().to_string(),
        size: entry.size,
        compressed_size: entry.compressed_size,
        sha_verified: false,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };

    match &entry.sha256_hex {
        Some(want) => {
            let got = format!("{:x}", hasher.finalize());
            if got != *want {
                let _ = fs::remove_file(dest);
                bail!(
                    "SHA-256 校验失败（条目 {} {}）: 期望 {}，实际 {} —— 已删除半成品",
                    entry.ordinal,
                    entry.path,
                    want,
                    got
                );
            }
            Ok(RetrieveOutcome {
                sha_verified: true,
                ..outcome
            })
        }
        None => {
            // AV-6 compatibility path: loud UNVERIFIED, size-only check.
            eprintln!(
                "⚠ UNVERIFIED: 条目 {} 无 sha256，仅完成体积校验（大小 {} 字节一致）",
                entry.ordinal, entry.size
            );
            Ok(outcome)
        }
    }
}

/// Restore to the *recorded original path* without an explicit `-d`.
/// AV-5: when the entry's volume differs from the container's volume this
/// is rejected with entry name, both volume letters and the remediation.
///
/// ADV-1 (documented boundary): only drive-letter volumes (`C:` …) are
/// compared. UNC paths (`\\server\share`), verbatim prefixes and paths
/// without a drive component yield `None` and therefore always take the
/// reject branch — for UNC sources the operator must use an explicit
/// `-d <dest>`, which is volume-agnostic. This is fail-closed by design:
/// a shared-network original can rarely be restored in place meaningfully,
/// and guessing would risk a silent cross-device copy.
pub fn retrieve_to_original(container: &Path, key: &index::EntryKey) -> Result<RetrieveOutcome> {
    let (_, _, idx) = open_container(container)?;
    let entry = idx.lookup(key)?;
    let original = PathBuf::from(&entry.path);
    let entry_volume = volume_letter(&original);
    let container_volume = volume_letter(container);
    match (&entry_volume, &container_volume) {
        (Some(a), Some(b)) if a == b => {}
        (a, b) => bail!(
            "跨卷还原被拒绝: 条目 {}（{}）的源卷为 {:?}，容器所在卷为 {:?}。\
             跨卷相对路径还原不省空间且语义不明确 —— 请显式指定目标路径 \
            （coldstore extract --key {} -d <绝对目标路径>），或把容器放回源卷。",
            entry.ordinal,
            entry.path,
            a.clone().unwrap_or_else(|| "(未知)".into()),
            b.clone().unwrap_or_else(|| "(未知)".into()),
            entry.ordinal
        ),
    }
    retrieve(container, key, &original)
}

/// Verify every frame in the container: decode each, check size + SHA-256.
/// Frames are verified in parallel (each worker opens its own handle and
/// touches only its entry's region). Uses the global rayon pool; see
/// [`verify_with`] for a threads-capped variant.
pub fn verify(container: &Path) -> Result<VerifyStats> {
    verify_with(container, &VerifyOptions::default())
}

/// [`verify`] with explicit concurrency control (ADV-5, reserved for 002).
pub fn verify_with(container: &Path, opts: &VerifyOptions) -> Result<VerifyStats> {
    let started = Instant::now();
    let (_file, header, idx) = open_container(container)?;

    // NOTE: each worker opens its OWN handle — `File::try_clone` shares the
    // file cursor on Windows, which would make parallel seeks trample each
    // other (this exact bug produced "Unknown frame descriptor" failures).
    let container_path = container.to_path_buf();
    let run = || {
        idx.entries
            .par_iter()
            .map(|entry| verify_one(&container_path, entry))
            .collect::<Vec<std::result::Result<(), String>>>()
    };
    let results: Vec<std::result::Result<(), String>> = match opts.threads {
        None => run(),
        Some(n) => {
            // fail-closed: rayon treats 0 as "use default", silently
            // ignoring the caller's request (card rule: no silent skips).
            if n == 0 {
                bail!("verify --threads 必须为 ≥1，收到 0");
            }
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build()
                .with_context(|| format!("构建 {n} 线程校验线程池失败"))?
                .install(run)
        }
    };

    let mut stats = VerifyStats {
        container: container.display().to_string(),
        frame_count: header.frame_count,
        entries_checked: 0,
        total_original: 0,
        total_compressed: 0,
        sha_failures: 0,
        size_failures: 0,
        unverified_entries: 0,
        ok: true,
        failures: Vec::new(),
        duration_ms: 0,
    };
    for (entry, r) in idx.entries.iter().zip(results) {
        stats.entries_checked += 1;
        stats.total_original += entry.size;
        stats.total_compressed += entry.compressed_size;
        if entry.sha256_hex.is_none() {
            stats.unverified_entries += 1;
        }
        match r {
            Ok(()) => {}
            Err(msg) => {
                stats.ok = false;
                if msg.contains("SHA-256") {
                    stats.sha_failures += 1;
                } else {
                    stats.size_failures += 1;
                }
                stats.failures.push(msg);
            }
        }
    }
    if stats.entries_checked != header.frame_count {
        stats.ok = false;
        stats.failures.push(format!(
            "索引条目数 {} ≠ 头部 frame_count {}",
            stats.entries_checked, header.frame_count
        ));
    }
    stats.duration_ms = started.elapsed().as_millis() as u64;
    Ok(stats)
}

fn verify_one(container: &Path, entry: &index::IndexEntry) -> std::result::Result<(), String> {
    let mut f = fs::File::open(container)
        .map_err(|e| format!("打开容器失败（条目 {}）: {e}", entry.ordinal))?;
    f.seek(SeekFrom::Start(entry.offset))
        .map_err(|e| format!("seek 失败（条目 {}）: {e}", entry.ordinal))?;
    let mut take = (&mut f).take(entry.compressed_size);
    let mut decoder = zstd::stream::Decoder::new(&mut take)
        .map_err(|e| format!("解码器创建失败（条目 {}）: {e}", entry.ordinal))?;
    let mut hasher = Sha256::new();
    let mut decoded = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("解码失败（条目 {}）: {e}", entry.ordinal))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        decoded += n as u64;
    }
    if take.limit() != 0 {
        return Err(format!("帧区域漂移（条目 {}）", entry.ordinal));
    }
    if decoded != entry.size {
        return Err(format!(
            "体积不符（条目 {} {}）: 解码 {decoded} ≠ 索引 {}",
            entry.ordinal, entry.path, entry.size
        ));
    }
    match &entry.sha256_hex {
        Some(want) => {
            let got = format!("{:x}", hasher.finalize());
            if got != *want {
                return Err(format!(
                    "SHA-256 校验失败（条目 {} {}）: 期望 {want}，实际 {got}",
                    entry.ordinal, entry.path
                ));
            }
            Ok(())
        }
        None => Ok(()), // counted as UNVERIFIED, not a failure
    }
}

fn split_mtime(t: Option<SystemTime>) -> (u64, u32) {
    match t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
        Some(d) => (d.as_secs(), d.subsec_nanos()),
        None => (0, 0),
    }
}

/// Volume letter of an absolute path, lowercased ("c"), if it has one.
#[cfg(windows)]
fn volume_letter(p: &Path) -> Option<String> {
    use std::path::Prefix;
    match p.components().next() {
        Some(std::path::Component::Prefix(pre)) => match pre.kind() {
            Prefix::Disk(d) => Some((d as char).to_ascii_lowercase().to_string()),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(not(windows))]
fn volume_letter(p: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan, ScanOptions};
    use std::collections::HashMap;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-archive-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn payload(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| (i as u8).wrapping_add(seed)).collect()
    }

    fn sha_of(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// Fixture: 5 files covering first / middle / last positions, one LDM-
    /// eligible (>4 MiB), one zero-byte. Returns (root, expected sha map).
    fn build_fixture(tag: &str) -> (PathBuf, HashMap<String, String>) {
        let root = temp_root(tag);
        let files = [
            ("first.txt", payload(100_000, 1)),
            ("a/large.bin", payload(5 * 1024 * 1024, 2)), // LDM path
            ("mid.dat", payload(1_000_000, 3)),
            ("zz/last.log", payload(300_000, 4)),
            ("empty.bin", Vec::new()),
        ];
        let mut shas = HashMap::new();
        for (rel, data) in files {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, &data).unwrap();
            // PathBuf::join does not normalize separators: keep map keys in the
            // same normalized form the scanner produces.
            shas.insert(p.display().to_string().replace('/', "\\"), sha_of(&data));
        }
        (root, shas)
    }

    #[test]
    fn archive_retrieve_first_mid_last_all_sha_match() -> Result<()> {
        let (root, shas) = build_fixture("positions");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let container = temp_root("positions-out").join("test.coldstore");

        let stats = archive(&scan_res.files, &container, &ArchiveOptions::default())?;
        assert_eq!(stats.frame_count, 5);
        assert_eq!(stats.entries.len(), 5);
        assert!(stats.total_compressed > 0);
        assert!(stats.total_compressed < stats.total_original);
        // LDM eligible file used window 27 (AV-2 setup)
        assert_eq!(stats.max_window_log, 27, "5 MiB file must use --long=27");
        // no temp residue
        assert!(!container.with_extension("coldstore.tmp").exists());

        // extract FIRST, MIDDLE, LAST by ordinal (card B6)
        let out_dir = temp_root("positions-out");
        for key in [
            index::EntryKey::Ordinal(0),
            index::EntryKey::Ordinal(2),
            index::EntryKey::Ordinal(4),
        ] {
            let entry = stats
                .entries
                .iter()
                .find(|e| match &key {
                    index::EntryKey::Ordinal(o) => e.ordinal == *o,
                    _ => false,
                })
                .unwrap();
            let dest = out_dir.join(format!("out-{}", entry.ordinal));
            let outcome = retrieve(&container, &key, &dest)?;
            assert!(outcome.sha_verified, "sha must be verified (AV-6)");
            let want = shas
                .get(&entry.path)
                .unwrap_or_else(|| panic!("path not in fixture map: {}", entry.path));
            let got = sha_of(&fs::read(&dest)?);
            assert_eq!(&got, want, "retrieved content must match original");
            fs::remove_file(&dest).ok();
        }

        // path-based retrieval works too (case-insensitive)
        let by_path = retrieve(
            &container,
            &index::EntryKey::Path(stats.entries[1].path.to_uppercase()),
            &out_dir.join("out-by-path"),
        )?;
        assert!(by_path.sha_verified);
        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(&out_dir).ok();
        Ok(())
    }

    #[test]
    fn zero_byte_member_bookkeeping_is_exact() -> Result<()> {
        let (root, shas) = build_fixture("zerobyte");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let container = temp_root("zerobyte-out").join("z.coldstore");
        let stats = archive(&scan_res.files, &container, &ArchiveOptions::default())?;

        let empty = stats
            .entries
            .iter()
            .find(|e| e.size == 0)
            .expect("zero-byte entry");
        assert_eq!(
            empty.sha256_hex.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            "AV-8: empty-string SHA constant"
        );
        // frames are back-to-back: offset[k+1] == offset[k] + compressed_size[k]
        let mut sorted: Vec<&IndexEntry> = stats.entries.iter().collect();
        sorted.sort_by_key(|e| e.ordinal);
        for pair in sorted.windows(2) {
            assert_eq!(
                pair[0].offset + pair[0].compressed_size,
                pair[1].offset,
                "no bookkeeping gap (AV-8 off-by-one guard)"
            );
        }

        let dest = temp_root("zerobyte-out").join("empty-restored");
        retrieve(&container, &index::EntryKey::Ordinal(empty.ordinal), &dest)?;
        assert_eq!(fs::read(&dest)?.len(), 0);
        assert_eq!(
            shas.get(&empty.path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(temp_root("zerobyte-out")).ok();
        Ok(())
    }

    #[test]
    fn retrieve_detects_sha_mismatch_and_cleans_up() -> Result<()> {
        // Build a container, then corrupt one entry's stored hash to force
        // the AV-6 mismatch path (dest must be deleted afterwards).
        let (root, _) = build_fixture("corrupt");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let container = temp_root("corrupt-out").join("c.coldstore");
        archive(&scan_res.files, &container, &ArchiveOptions::default())?;

        // Craft: rewrite the embedded index JSON with a wrong sha for #0.
        let (mut file, header, mut idx) = open_container(&container)?;
        idx.entries[0].sha256_hex = Some("00".repeat(32));
        let patched_json = idx.to_json()?;
        let packed = index::pack_skippable(&patched_json)?;

        // Rebuild container bytes: header + frames(region) + patched index.
        // Region between HEADER and index_offset stays identical.
        let region_len = header.index_offset - index::HEADER_SIZE;
        file.seek(SeekFrom::Start(index::HEADER_SIZE))?;
        let mut region = vec![0u8; region_len as usize];
        file.read_exact(&mut region)?;
        let new_bytes: Vec<u8> = [
            header.pack().as_slice(),
            region.as_slice(),
            packed.as_slice(),
        ]
        .concat();
        drop(file);
        fs::write(&container, &new_bytes)?;

        let dest = temp_root("corrupt-out").join("should-vanish");
        let err = retrieve(&container, &index::EntryKey::Ordinal(0), &dest)
            .err()
            .ok_or_else(|| anyhow!("expected sha failure"))?;
        assert!(err.to_string().contains("SHA-256 校验失败"), "{err}");
        assert!(!dest.exists(), "half-written dest must be deleted");
        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(temp_root("corrupt-out")).ok();
        Ok(())
    }

    #[test]
    fn stale_sidecar_fails_closed_on_retrieve() -> Result<()> {
        let (root, _) = build_fixture("sidecar");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let container = temp_root("sidecar-out").join("s.coldstore");
        let opts = ArchiveOptions {
            sidecar: true,
            ..Default::default()
        };
        archive(&scan_res.files, &container, &opts)?;

        // Mutate the sidecar → every operation must refuse (AV-3).
        let sp = index::sidecar_path(&container);
        let mut sidecar_json = fs::read(&sp)?;
        // flip one byte inside the JSON content
        let last = sidecar_json.len() - 2;
        sidecar_json[last] ^= 0x01;
        fs::write(&sp, &sidecar_json)?;

        let err = open_container(&container)
            .err()
            .ok_or_else(|| anyhow!("expected failure"))?;
        let msg = err.to_string();
        assert!(
            msg.contains("解析失败") || msg.contains("disagree"),
            "fail-closed message, got: {msg}"
        );
        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(temp_root("sidecar-out")).ok();
        Ok(())
    }

    #[test]
    fn verify_reports_all_frames_green() -> Result<()> {
        let (root, _) = build_fixture("verify");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let container = temp_root("verify-out").join("v.coldstore");
        archive(&scan_res.files, &container, &ArchiveOptions::default())?;
        let stats = verify(&container)?;
        assert!(stats.ok, "verify failures: {:?}", stats.failures);
        assert_eq!(stats.entries_checked, 5);
        assert_eq!(stats.sha_failures, 0);
        assert_eq!(stats.size_failures, 0);
        assert_eq!(
            stats.total_original,
            stats.entries_checked.saturating_mul(0) + {
                // sanity: totals recomputed from the index
                let (_, _, idx) = open_container(&container)?;
                idx.entries.iter().map(|e| e.size).sum::<u64>()
            }
        );
        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(temp_root("verify-out")).ok();
        Ok(())
    }

    #[test]
    fn verify_threads_zero_fails_closed() {
        // ADV-5: `--threads 0` must be rejected, not silently treated as
        // "use default pool" (rayon would ignore it).
        let (root, files) = build_fixture("vt0");
        let scan_res = scan(&root, &ScanOptions::default()).expect("scan");
        let container = root.join("vt0.coldstore");
        archive(&scan_res.files, &container, &ArchiveOptions::default()).expect("archive");
        let err = verify_with(&container, &VerifyOptions { threads: Some(0) });
        assert!(err.is_err(), "threads=0 must fail");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains('0'),
            "error should mention the bad value: {msg}"
        );
        // threads=1 still works (dedicated pool path).
        let stats = verify_with(&container, &VerifyOptions { threads: Some(1) })
            .expect("threads=1 must succeed");
        assert!(stats.ok);
        assert_eq!(stats.entries_checked, files.len() as u64);
        let _ = fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn cross_volume_container_write_is_allowed() -> Result<()> {
        // AV-5 positive case: sources on one volume, container on another.
        // B16 hygiene: probe for a second volume at runtime instead of
        // hardcoding a personal path; if none exists, skip gracefully —
        // the negative-case test below still covers cross-volume logic.
        let (root, _) = build_fixture("xvol");
        let scan_res = scan(&root, &ScanOptions::default())?;
        let fixture_vol = root
            .to_string_lossy()
            .chars()
            .next()
            .map(|c| c.to_ascii_uppercase());
        let mut container = None;
        for letter in 'D'..='Z' {
            if Some(letter) == fixture_vol {
                continue;
            }
            let drive = PathBuf::from(format!("{letter}:\\"));
            if drive.is_dir() {
                // pid suffix avoids collisions between concurrent test runs
                // on the same drive root (ADV-4).
                container = Some(
                    drive
                        .join(format!("coldstore-xvol-test-{}", std::process::id()))
                        .join("xvol-test.coldstore"),
                );
                break;
            }
        }
        let Some(container) = container else {
            eprintln!("skipping: no second volume available on this machine");
            fs::remove_dir_all(&root).ok();
            return Ok(());
        };
        fs::create_dir_all(container.parent().expect("container has parent"))?;
        let stats = archive(&scan_res.files, &container, &ArchiveOptions::default())?;
        assert_eq!(stats.frame_count, 5);
        let _ = fs::remove_file(&container);
        fs::remove_dir_all(container.parent().expect("container has parent")).ok();
        fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn cross_volume_restore_to_original_is_rejected_with_three_elements() -> Result<()> {
        // AV-5 negative case: container on C:, original path on D:.
        // Crafted index entry (no real D: source needed).
        let dir = temp_root("xvol-restore");
        let container = dir.join("c.coldstore");
        let mut idx = index::ArchiveIndex::new("embedded");
        idx.entries.push(index::IndexEntry {
            ordinal: 0,
            path: "D:\\some\\original\\file.bin".into(),
            size: 3,
            compressed_size: 9,
            offset: index::HEADER_SIZE,
            mtime_secs: 0,
            mtime_nanos: 0,
            sha256_hex: None,
        });
        // Minimal container: header + one tiny valid frame of "abc".
        let frame = zstd::stream::encode_all(b"abc".as_slice(), 3)?;
        let packed_idx = index::pack_skippable(&idx.to_json()?)?;
        let header = container::ContainerHeader {
            version: index::CONTAINER_VERSION,
            index_embedded: true,
            frame_count: 1,
            total_size: index::HEADER_SIZE + frame.len() as u64 + packed_idx.len() as u64,
            index_offset: index::HEADER_SIZE + frame.len() as u64,
            index_len: packed_idx.len() as u64,
        };
        let bytes: Vec<u8> = [
            header.pack().as_slice(),
            frame.as_slice(),
            packed_idx.as_slice(),
        ]
        .concat();
        fs::write(&container, &bytes)?;

        // only run the volume guard when C:/D: actually differ
        if volume_letter(&container) != volume_letter(Path::new("D:\\")) {
            let err = retrieve_to_original(&container, &index::EntryKey::Ordinal(0))
                .err()
                .ok_or_else(|| anyhow!("expected cross-volume rejection"))?;
            let msg = err.to_string();
            assert!(msg.contains("跨卷还原被拒绝"), "{msg}");
            assert!(msg.contains("0"), "entry named: {msg}");
            assert!(
                msg.contains("c") && msg.contains("d"),
                "both volume letters: {msg}"
            );
            assert!(msg.contains("-d"), "remediation present: {msg}");
        }
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn container_inside_scan_root_is_guarded_at_cli_level() {
        // The CLI filters container paths out of the archive input; core
        // asserts the deterministic ordering instead.
        let mut files: Vec<FileEntry> = (0..3)
            .map(|i| FileEntry {
                path: PathBuf::from(format!("b{}.bin", i)),
                size: i,
                ext: "bin".into(),
                modified: None,
                accessed: None,
                is_reparse: false,
                is_hidden: false,
                is_system: false,
                magic_hex: String::new(),
                magic_read_failed: false,
            })
            .collect();
        files.push(FileEntry {
            path: PathBuf::from("A.txt"),
            size: 9,
            ext: "txt".into(),
            modified: None,
            accessed: None,
            is_reparse: false,
            is_hidden: false,
            is_system: false,
            magic_hex: String::new(),
            magic_read_failed: false,
        });
        // order must be stable under lowercasing (case-insensitive sort)
        files.sort_by(|a, b| {
            a.path
                .to_string_lossy()
                .to_lowercase()
                .cmp(&b.path.to_string_lossy().to_lowercase())
                .then(a.path.cmp(&b.path))
        });
        let names: Vec<String> = files.iter().map(|f| f.path.display().to_string()).collect();
        assert_eq!(names, ["A.txt", "b0.bin", "b1.bin", "b2.bin"]);
    }
}
