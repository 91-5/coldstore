//! NTFS transparent compression executor (card D3, P3).
//!
//! What this module is:
//! - a **measured** compression executor built on `FSCTL_SET_COMPRESSION`
//!   (see [`sys`]) — no external `compact.exe`, no shell-out, no encoding
//!   games;
//! - **asynchronous and interruptible**: the work runs on a worker pool
//!   ([`CompressHandle::spawn`]) with a cancellation flag the caller owns,
//!   so a 13.93 GB batch at the measured 48 MB/s never blocks the UI and
//!   can be stopped at any file boundary;
//! - **progress-visible**: both a file counter and a byte counter advance
//!   live ([`ProgressSnapshot`]);
//! - **reversible**: the same call with `COMPRESSION_FORMAT_NONE` undoes it
//!   and the file returns to `Compressed=False` with byte-identical content;
//! - **defensive**: already-compressed formats (png/mp4/zip/7z/pdf/docx —
//!   001 measured a ≈0 or negative gain), database / VM-disk / game files
//!   and hardcoded system directories are refused *at the executor level*,
//!   independently of what the rule engine decided.
//!
//! What this module deliberately is **not**: it never deletes, moves or
//! renames anything. NTFS compression only flips a file attribute, so the
//! P2 "all mutations live inside the journaled sequence functions" rule is
//! satisfied vacuously — there is no `fs::remove` / `fs::rename` in this
//! module, and the delivery grep proves it.
//!
//! Resuming: a run that is stopped (or a machine that reboots) is resumed
//! by simply running the same command again — files that already carry
//! `FILE_ATTRIBUTE_COMPRESSED` are skipped, so the second run picks up
//! exactly where the first stopped.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::scan::FileEntry;

mod sys;

/// Default worker count. NTFS compression is done by the file system, so a
/// handful of concurrent requests keep the queue busy without thrashing a
/// single volume.
pub const DEFAULT_THREADS: usize = 4;

/// Directory names that are **never** compressed, at any depth.
///
/// Hardcoded on purpose (card D3): compressing an installed program's
/// files is a well-known source of "the app stopped working" reports.
/// This list is *not* overridable by `--force` — the only supported way
/// to compress such a tree is to point ColdStore at a different root.
pub const EXCLUDED_DIR_NAMES: &[&str] = &[
    "Program Files",
    "Program Files (x86)",
    "Windows",
    "System32",
    "SysWOW64",
    "Recovery",
    "$Recycle.Bin",
    "System Volume Information",
    "Boot",
];

/// Formats that are *already* compressed.
///
/// 001 measured zstd gains of ≈0 (png even grew by 486 B), so compressing
/// them burns CPU and can make the file bigger. The rule engine already
/// vetoes most of them via the predictor; the executor refuses them
/// independently.
pub const PRE_COMPRESSED_EXTENSIONS: &[&str] = &[
    // images
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "avif", "ico",
    // video / audio
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mp3", "flac", "aac", "ogg", "opus",
    "wma", "wav", // containers / archives
    "zip", "7z", "rar", "gz", "bz2", "xz", "zst", "lz4", "cab", "iso", "jar", "war", "apk", "deb",
    "rpm", "msi", "nupkg", // documents (zip-based OOXML / PDF)
    "pdf", "docx", "xlsx", "pptx", "epub", "mobi", // already-compressed payloads
    "woff", "woff2", "ttf", "otf", "eot",
];

/// Formats that must not be compressed even though they are not
/// "already compressed": database files, VM disk images and game data
/// archives can misbehave under NTFS compression.
///
/// Unlike [`PRE_COMPRESSED_EXTENSIONS`] these are overridable with
/// `--force` — the card asks for an explicit user opt-in for them, and
/// the rule engine's `skip` action is the declarative way to express
/// the same thing.
pub const SENSITIVE_EXTENSIONS: &[&str] = &[
    // databases
    "db", "sqlite", "sqlite3", "mdb", "accdb", "ldb", "ldf", "mdf", "ndf", "dbf", "edb",
    // VM disk images
    "vhd", "vhdx", "vmdk", "vdi", "qcow", "qcow2", "vdi", "hds", "pvm",
    // game / engine data
    "pak", "wad", "big", "sav", "save", "dmp", "core", "dump", "gcf", "gdb", "vpk", "bsp",
];

/// Direction of the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    /// Enable NTFS compression (`COMPRESSION_FORMAT_DEFAULT`).
    Enable,
    /// Undo it (`COMPRESSION_FORMAT_NONE`).
    Disable,
}

impl CompressionMode {
    pub fn as_display(self) -> &'static str {
        match self {
            CompressionMode::Enable => "enable",
            CompressionMode::Disable => "disable",
        }
    }

    /// Human label used by the CLI.
    pub fn label(self) -> &'static str {
        match self {
            CompressionMode::Enable => "启用 NTFS 压缩",
            CompressionMode::Disable => "解除 NTFS 压缩",
        }
    }
}

/// Why the executor refused to touch a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// Already carries `FILE_ATTRIBUTE_COMPRESSED`.
    AlreadyCompressed,
    /// Compression is already off (nothing to undo).
    NotCompressed,
    /// Format is already compressed — compressing it buys ≈0.
    PreCompressedFormat,
    /// Database / VM disk / game file — behaviour may break.
    SensitiveFormat,
    /// Inside a hardcoded system directory — never overridable.
    ExcludedPath,
    /// Below the size floor.
    TooSmall,
    /// Zero-length file.
    Empty,
}

impl SkipReason {
    /// Stable key (also the CLI/JSON key).
    pub fn key(self) -> &'static str {
        match self {
            SkipReason::AlreadyCompressed => "already_compressed",
            SkipReason::NotCompressed => "not_compressed",
            SkipReason::PreCompressedFormat => "pre_compressed_format",
            SkipReason::SensitiveFormat => "sensitive_format",
            SkipReason::ExcludedPath => "excluded_path",
            SkipReason::TooSmall => "too_small",
            SkipReason::Empty => "empty",
        }
    }

    /// Human explanation shown in the CLI.
    pub fn reason(self) -> &'static str {
        match self {
            SkipReason::AlreadyCompressed => "已压缩，跳过",
            SkipReason::NotCompressed => "未压缩，无需解除",
            SkipReason::PreCompressedFormat => "已压缩格式（png/mp4/zip/7z/pdf/docx…），收益≈0",
            SkipReason::SensitiveFormat => "数据库/VM 磁盘/游戏文件，默认不压（需显式覆盖）",
            SkipReason::ExcludedPath => "系统目录（Program Files / Windows…），硬编码排除",
            SkipReason::TooSmall => "小于体积下限",
            SkipReason::Empty => "空文件",
        }
    }
}

/// Live progress counters — **file count and byte count** (card D3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgressSnapshot {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// The file currently being worked on (if any).
    pub current: Option<String>,
}

impl ProgressSnapshot {
    pub fn files_fraction(&self) -> f64 {
        if self.files_total == 0 {
            0.0
        } else {
            self.files_done as f64 / self.files_total as f64
        }
    }

    pub fn bytes_fraction(&self) -> f64 {
        if self.bytes_total == 0 {
            0.0
        } else {
            self.bytes_done as f64 / self.bytes_total as f64
        }
    }
}

/// Executor options.
#[derive(Clone)]
pub struct CompressOptions {
    /// Enable or disable compression.
    pub mode: CompressionMode,
    /// Worker threads (default [`DEFAULT_THREADS`]; `0` is rejected).
    pub threads: Option<usize>,
    /// Throughput cap in MiB/s. `None` = uncapped.
    pub rate_limit_mb_s: Option<u64>,
    /// Cancellation flag — the caller owns it and may flip it from another
    /// thread at any time; the batch stops at the next file boundary.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Live progress sink, called after every completed file.
    pub progress: Option<Arc<dyn Fn(ProgressSnapshot) + Send + Sync>>,
    /// Override the *format* skips ([`PRE_COMPRESSED_EXTENSIONS`] and
    /// [`SENSITIVE_EXTENSIONS`]). The hardcoded path exclusions
    /// ([`EXCLUDED_DIR_NAMES`]) are **never** overridable.
    pub force: bool,
    /// Skip files smaller than this many bytes.
    pub min_size_bytes: u64,
}

impl Default for CompressOptions {
    fn default() -> Self {
        CompressOptions {
            mode: CompressionMode::Enable,
            threads: None,
            rate_limit_mb_s: None,
            cancel: None,
            progress: None,
            force: false,
            min_size_bytes: 0,
        }
    }
}

impl std::fmt::Debug for CompressOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompressOptions")
            .field("mode", &self.mode)
            .field("threads", &self.threads)
            .field("rate_limit_mb_s", &self.rate_limit_mb_s)
            .field("force", &self.force)
            .field("min_size_bytes", &self.min_size_bytes)
            .field("cancel", &self.cancel.is_some())
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

/// A single failure (path + reason) — surfaced, never swallowed.
#[derive(Debug, Clone, Serialize)]
pub struct FailureRecord {
    pub path: String,
    pub error: String,
}

/// Result of one batch.
#[derive(Debug, Clone, Serialize)]
pub struct CompressStats {
    pub mode: String,
    /// Candidates that survived the selection rules.
    pub files_total: u64,
    /// Files whose compression state was actually changed.
    pub files_processed: u64,
    /// Logical bytes of the candidate set.
    pub bytes_total: u64,
    /// Logical bytes of the processed files.
    pub bytes_processed: u64,
    /// **Measured** on-disk bytes of the processed files after the run.
    pub bytes_on_disk: u64,
    pub files_skipped: u64,
    pub files_failed: u64,
    /// Skip counts by reason key.
    pub skipped_by_reason: BTreeMap<String, u64>,
    pub failures: Vec<FailureRecord>,
    /// True when the run stopped early because the cancel flag was set.
    pub cancelled: bool,
    pub duration_ms: u64,
}

impl CompressStats {
    /// Measured compression ratio (logical : on-disk). `1.0` = no gain.
    pub fn ratio(&self) -> f64 {
        if self.bytes_on_disk == 0 {
            return 0.0;
        }
        self.bytes_processed as f64 / self.bytes_on_disk as f64
    }

    /// Bytes saved on disk (logical - on-disk); negative means growth.
    pub fn bytes_saved(&self) -> i64 {
        self.bytes_processed as i64 - self.bytes_on_disk as i64
    }
}

/// Result of the read-only selection pass.
#[derive(Debug, Clone)]
pub struct CompressPlan {
    /// Files that will be touched.
    pub files: Vec<FileEntry>,
    /// Logical bytes of those files.
    pub bytes: u64,
    /// Skip counts by reason key.
    pub skipped_by_reason: BTreeMap<String, u64>,
    pub skipped_total: u64,
}

/// Shared, thread-safe progress state.
#[derive(Debug)]
struct ProgressState {
    files_done: AtomicU64,
    bytes_done: AtomicU64,
    files_total: AtomicU64,
    bytes_total: AtomicU64,
    current: Mutex<Option<String>>,
}

impl ProgressState {
    fn new(files_total: u64, bytes_total: u64) -> ProgressState {
        ProgressState {
            files_done: AtomicU64::new(0),
            bytes_done: AtomicU64::new(0),
            files_total: AtomicU64::new(files_total),
            bytes_total: AtomicU64::new(bytes_total),
            current: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            files_done: self.files_done.load(Ordering::Relaxed),
            files_total: self.files_total.load(Ordering::Relaxed),
            bytes_done: self.bytes_done.load(Ordering::Relaxed),
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
            current: self.current.lock().ok().and_then(|g| g.clone()),
        }
    }
}

/// Global throughput cap shared by all workers.
#[derive(Debug)]
struct RateLimiter {
    bytes_per_sec: u64,
    state: Mutex<(Instant, u64)>,
}

impl RateLimiter {
    fn new(mb_per_sec: Option<u64>) -> Option<RateLimiter> {
        let mbps = mb_per_sec?;
        if mbps == 0 {
            return None;
        }
        Some(RateLimiter {
            bytes_per_sec: mbps.saturating_mul(1024 * 1024),
            state: Mutex::new((Instant::now(), 0)),
        })
    }

    /// Block until the accumulated byte count is allowed by the cap.
    fn throttle(&self, bytes: u64) {
        let sleep_for = {
            let mut st = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            st.1 = st.1.saturating_add(bytes);
            let elapsed = st.0.elapsed().as_secs_f64();
            let target = st.1 as f64 / self.bytes_per_sec as f64;
            if target > elapsed {
                Some(Duration::from_secs_f64(target - elapsed))
            } else {
                None
            }
        };
        if let Some(d) = sleep_for {
            std::thread::sleep(d);
        }
    }
}

/// Is this path inside a hardcoded system directory?
pub fn is_excluded_path(path: &Path) -> bool {
    path.components().any(|c| {
        let name = c.as_os_str().to_string_lossy();
        EXCLUDED_DIR_NAMES
            .iter()
            .any(|excluded| excluded.eq_ignore_ascii_case(name.as_ref()))
    })
}

/// Is the file already NTFS-compressed (`FILE_ATTRIBUTE_COMPRESSED`)?
pub fn file_is_compressed(path: &Path) -> std::io::Result<bool> {
    sys::is_compressed(path)
}

/// Real on-disk size of a file (compressed size when it is compressed).
pub fn file_compressed_size(path: &Path) -> std::io::Result<u64> {
    sys::compressed_size(path)
}

/// Pure (no I/O) classification of one candidate.
fn classify_pure(entry: &FileEntry, opts: &CompressOptions) -> Option<SkipReason> {
    if entry.size == 0 {
        return Some(SkipReason::Empty);
    }
    if entry.size < opts.min_size_bytes {
        return Some(SkipReason::TooSmall);
    }
    // Hardcoded system directories: never overridable.
    if is_excluded_path(&entry.path) {
        return Some(SkipReason::ExcludedPath);
    }
    if !opts.force {
        let ext = entry.ext.to_ascii_lowercase();
        if PRE_COMPRESSED_EXTENSIONS.contains(&ext.as_str()) {
            return Some(SkipReason::PreCompressedFormat);
        }
        if SENSITIVE_EXTENSIONS.contains(&ext.as_str()) {
            return Some(SkipReason::SensitiveFormat);
        }
    }
    None
}

/// Read-only selection pass: which files *would* be touched, and why the
/// others are not. Used by the dry-run (default) path and by the executor.
pub fn plan_compression(files: &[FileEntry], opts: &CompressOptions) -> CompressPlan {
    let mut ordered: Vec<&FileEntry> = files.iter().collect();
    ordered.sort_by(|a, b| a.path.cmp(&b.path));

    let mut selected: Vec<FileEntry> = Vec::new();
    let mut skipped_by_reason: BTreeMap<String, u64> = BTreeMap::new();
    let mut skipped_total = 0u64;
    let mut bytes = 0u64;

    for entry in ordered {
        if let Some(reason) = classify_pure(entry, opts) {
            *skipped_by_reason
                .entry(reason.key().to_string())
                .or_insert(0) += 1;
            skipped_total += 1;
            continue;
        }
        // Attribute check — cheap, read-only.
        match sys::is_compressed(&entry.path) {
            Ok(true) if opts.mode == CompressionMode::Enable => {
                *skipped_by_reason
                    .entry(SkipReason::AlreadyCompressed.key().to_string())
                    .or_insert(0) += 1;
                skipped_total += 1;
                continue;
            }
            Ok(false) if opts.mode == CompressionMode::Disable => {
                *skipped_by_reason
                    .entry(SkipReason::NotCompressed.key().to_string())
                    .or_insert(0) += 1;
                skipped_total += 1;
                continue;
            }
            Err(_) => {
                // Unreadable attribute → treat as "not compressed" and let
                // the write attempt report the real error.
            }
            _ => {}
        }
        bytes = bytes.saturating_add(entry.size);
        selected.push(entry.clone());
    }

    CompressPlan {
        files: selected,
        bytes,
        skipped_by_reason,
        skipped_total,
    }
}

/// Outcome of one file.
#[derive(Debug)]
enum Outcome {
    Done { logical: u64, on_disk: u64 },
    Skipped(SkipReason),
    Failed(String, String),
    Cancelled,
}

/// Run the batch synchronously (the caller decides whether to run it on a
/// worker thread — see [`CompressHandle::spawn`]).
pub fn compress_batch(files: &[FileEntry], opts: &CompressOptions) -> Result<CompressStats> {
    let bytes_total: u64 = files.iter().map(|f| f.size).sum();
    let progress = Arc::new(ProgressState::new(files.len() as u64, bytes_total));
    compress_batch_inner(files, opts, progress)
}

/// The actual batch, with an externally owned progress state so a
/// background caller can poll the very same counters the workers advance.
fn compress_batch_inner(
    files: &[FileEntry],
    opts: &CompressOptions,
    progress: Arc<ProgressState>,
) -> Result<CompressStats> {
    let started = Instant::now();
    // Fail closed on a nonsensical thread count *before* anything else —
    // rayon would silently treat 0 as "use the default pool".
    let threads = opts.threads.unwrap_or(DEFAULT_THREADS);
    if threads == 0 {
        bail!("压缩线程数必须为 ≥1（0 会被 rayon 静默当成默认值）");
    }
    let plan = plan_compression(files, opts);

    let mut stats = CompressStats {
        mode: opts.mode.as_display().to_string(),
        files_total: plan.files.len() as u64,
        files_processed: 0,
        bytes_total: plan.bytes,
        bytes_processed: 0,
        bytes_on_disk: 0,
        files_skipped: plan.skipped_total,
        files_failed: 0,
        skipped_by_reason: plan.skipped_by_reason.clone(),
        failures: Vec::new(),
        cancelled: false,
        duration_ms: 0,
    };

    if plan.files.is_empty() {
        stats.duration_ms = started.elapsed().as_millis() as u64;
        return Ok(stats);
    }

    // The plan is authoritative for the denominators.
    progress
        .files_total
        .store(plan.files.len() as u64, Ordering::Relaxed);
    progress.bytes_total.store(plan.bytes, Ordering::Relaxed);

    let limiter = Arc::new(RateLimiter::new(opts.rate_limit_mb_s));

    let run = || {
        use rayon::prelude::*;
        plan.files
            .par_iter()
            .map(|entry| process_one(entry, opts, &progress, limiter.as_ref().as_ref()))
            .collect::<Vec<Outcome>>()
    };

    let outcomes = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .with_context(|| format!("构建 {threads} 线程压缩池失败"))?
        .install(run);

    for outcome in outcomes {
        match outcome {
            Outcome::Done { logical, on_disk } => {
                stats.files_processed += 1;
                stats.bytes_processed = stats.bytes_processed.saturating_add(logical);
                stats.bytes_on_disk = stats.bytes_on_disk.saturating_add(on_disk);
            }
            Outcome::Skipped(reason) => {
                stats.files_skipped += 1;
                *stats
                    .skipped_by_reason
                    .entry(reason.key().to_string())
                    .or_insert(0) += 1;
            }
            Outcome::Failed(path, error) => {
                stats.files_failed += 1;
                stats.failures.push(FailureRecord { path, error });
            }
            Outcome::Cancelled => {
                stats.cancelled = true;
            }
        }
    }

    stats.duration_ms = started.elapsed().as_millis() as u64;
    Ok(stats)
}

/// Debug-only interrupt injection.
///
/// Mirrors P2's `COLDSTORE_CRASH_AFTER` hook: after N completed files the
/// batch asks *itself* to stop, so the interrupt-and-resume path is
/// reproducible for the reviewer instead of depending on a human pressing
/// Ctrl-C at the right second. Harmless unless the variable is set
/// explicitly; disclosed in the delivery doc.
fn stop_after_env() -> Option<u64> {
    static STOP_AFTER: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *STOP_AFTER.get_or_init(|| {
        std::env::var("COLDSTORE_COMPRESS_STOP_AFTER")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
    })
}

/// Per-file worker.
fn process_one(
    entry: &FileEntry,
    opts: &CompressOptions,
    progress: &Arc<ProgressState>,
    limiter: Option<&RateLimiter>,
) -> Outcome {
    // Cancellation is checked at every file boundary — a cancel never
    // interrupts a half-written file, because compression is an attribute
    // flip that the file system performs atomically for us.
    if let Some(flag) = &opts.cancel {
        if flag.load(Ordering::SeqCst) {
            return Outcome::Cancelled;
        }
    }
    if let Ok(mut cur) = progress.current.lock() {
        *cur = Some(entry.path.display().to_string());
    }

    let enable = opts.mode == CompressionMode::Enable;
    // Defensive re-check: the file may have been compressed (or
    // decompressed) between planning and execution.
    match sys::is_compressed(&entry.path) {
        Ok(true) if enable => return Outcome::Skipped(SkipReason::AlreadyCompressed),
        Ok(false) if !enable => return Outcome::Skipped(SkipReason::NotCompressed),
        _ => {}
    }
    if let Err(e) = sys::set_compression(&entry.path, enable) {
        return Outcome::Failed(entry.path.display().to_string(), e.to_string());
    }

    let on_disk = sys::compressed_size(&entry.path).unwrap_or(entry.size);
    if let Some(lim) = limiter {
        lim.throttle(entry.size);
    }

    progress.bytes_done.fetch_add(entry.size, Ordering::Relaxed);
    let done = progress.files_done.fetch_add(1, Ordering::Relaxed) + 1;
    if let Some(limit) = stop_after_env() {
        if done >= limit {
            if let Some(flag) = &opts.cancel {
                flag.store(true, Ordering::SeqCst);
            }
        }
    }
    if let Some(cb) = &opts.progress {
        cb(progress.snapshot());
    }

    Outcome::Done {
        logical: entry.size,
        on_disk,
    }
}

/// Handle to a **background** compression run.
///
/// This is the "异步" half of the card's requirement: the caller keeps
/// rendering progress and keeps answering to Ctrl-C while the batch runs
/// on a worker thread; [`CompressHandle::cancel`] asks the batch to stop
/// at the next file boundary.
pub struct CompressHandle {
    cancel: Arc<AtomicBool>,
    progress: Arc<ProgressState>,
    join: Option<std::thread::JoinHandle<Result<CompressStats>>>,
}

impl CompressHandle {
    /// Spawn the batch on a worker thread.
    pub fn spawn(files: Vec<FileEntry>, opts: CompressOptions) -> CompressHandle {
        let cancel = opts
            .cancel
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let mut opts = opts;
        opts.cancel = Some(cancel.clone());

        let bytes_total: u64 = files.iter().map(|f| f.size).sum();
        let progress = Arc::new(ProgressState::new(files.len() as u64, bytes_total));
        // The worker advances *this* state, so `handle.progress()` and the
        // caller's own progress callback observe the same counters.
        let progress_for_worker = progress.clone();
        let join = std::thread::Builder::new()
            .name("coldstore-ntfs".to_string())
            .spawn(move || compress_batch_inner(&files, &opts, progress_for_worker))
            .expect("spawn compression worker thread");
        CompressHandle {
            cancel,
            progress,
            join: Some(join),
        }
    }

    /// Ask the batch to stop at the next file boundary.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Was cancellation requested?
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Has the worker thread finished?
    pub fn is_finished(&self) -> bool {
        self.join.as_ref().map(|h| h.is_finished()).unwrap_or(true)
    }

    /// Current progress counters.
    pub fn progress(&self) -> ProgressSnapshot {
        self.progress.snapshot()
    }

    /// Wait for the batch to finish and take its result.
    pub fn join(mut self) -> Result<CompressStats> {
        match self.join.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| anyhow::anyhow!("压缩工作线程异常终止"))?,
            None => bail!("压缩任务已被取走"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn entry(path: &str, ext: &str, size: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size,
            ext: ext.to_string(),
            modified: Some(SystemTime::UNIX_EPOCH),
            accessed: None,
            is_reparse: false,
            is_hidden: false,
            is_system: false,
            magic_hex: String::new(),
            magic_read_failed: false,
        }
    }

    #[test]
    fn hardcoded_system_directories_are_never_selected() {
        let opts = CompressOptions {
            force: true, // even with --force the path exclusion holds
            ..Default::default()
        };
        let files = vec![
            entry(r"C:\Program Files\App\a.bin", "bin", 5_000_000),
            entry(r"C:\Windows\System32\drivers\a.sys", "sys", 5_000_000),
            entry(r"D:\proj\target\debug\a.rlib", "rlib", 5_000_000),
        ];
        let plan = plan_compression(&files, &opts);
        assert_eq!(plan.files.len(), 1, "only the non-system path survives");
        assert_eq!(
            plan.skipped_by_reason.get("excluded_path").copied(),
            Some(2)
        );
    }

    #[test]
    fn already_compressed_formats_are_skipped_unless_forced() {
        let files = vec![
            entry(r"D:\x\a.png", "png", 5_000_000),
            entry(r"D:\x\b.mp4", "mp4", 5_000_000),
            entry(r"D:\x\c.zip", "zip", 5_000_000),
            entry(r"D:\x\d.docx", "docx", 5_000_000),
            entry(r"D:\x\e.rlib", "rlib", 5_000_000),
        ];
        let plan = plan_compression(&files, &CompressOptions::default());
        assert_eq!(plan.files.len(), 1);
        assert_eq!(
            plan.skipped_by_reason.get("pre_compressed_format").copied(),
            Some(4)
        );

        let forced = plan_compression(
            &files,
            &CompressOptions {
                force: true,
                ..Default::default()
            },
        );
        assert_eq!(forced.files.len(), 5, "--force overrides the format skip");
    }

    #[test]
    fn sensitive_formats_are_skipped_but_overridable() {
        let files = vec![
            entry(r"D:\x\a.vhdx", "vhdx", 5_000_000),
            entry(r"D:\x\b.sqlite", "sqlite", 5_000_000),
            entry(r"D:\x\c.rlib", "rlib", 5_000_000),
        ];
        let plan = plan_compression(&files, &CompressOptions::default());
        assert_eq!(plan.files.len(), 1);
        assert_eq!(
            plan.skipped_by_reason.get("sensitive_format").copied(),
            Some(2)
        );
        let forced = plan_compression(
            &files,
            &CompressOptions {
                force: true,
                ..Default::default()
            },
        );
        assert_eq!(forced.files.len(), 3);
    }

    #[test]
    fn size_floor_and_empty_files_are_skipped() {
        let files = vec![
            entry(r"D:\x\tiny.rlib", "rlib", 10),
            entry(r"D:\x\empty.rlib", "rlib", 0),
            entry(r"D:\x\big.rlib", "rlib", 100_000),
        ];
        let plan = plan_compression(
            &files,
            &CompressOptions {
                min_size_bytes: 1000,
                ..Default::default()
            },
        );
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.skipped_by_reason.get("too_small").copied(), Some(1));
        assert_eq!(plan.skipped_by_reason.get("empty").copied(), Some(1));
    }

    #[test]
    fn zero_threads_is_rejected_rather_than_silently_defaulted() {
        let opts = CompressOptions {
            threads: Some(0),
            ..Default::default()
        };
        let err = compress_batch(&[], &opts).unwrap_err().to_string();
        assert!(err.contains("≥1"), "{err}");
    }

    #[test]
    fn cancellation_flag_stops_the_batch_before_any_work() {
        let flag = Arc::new(AtomicBool::new(true));
        let opts = CompressOptions {
            cancel: Some(flag),
            ..Default::default()
        };
        // A file that does not exist would fail the write; with the cancel
        // flag already set the worker must bail out *before* touching it.
        let files = vec![entry(r"D:\x\does-not-exist.rlib", "rlib", 10)];
        let stats = compress_batch(&files, &opts).unwrap();
        assert!(stats.cancelled, "batch reports cancellation");
        assert_eq!(stats.files_failed, 0, "no file was attempted");
        assert_eq!(stats.files_processed, 0);
    }

    #[test]
    fn plan_is_deterministic_regardless_of_input_order() {
        let files = vec![
            entry(r"D:\x\b.rlib", "rlib", 30),
            entry(r"D:\x\a.rlib", "rlib", 20),
            entry(r"D:\x\c.rlib", "rlib", 10),
        ];
        let p1 = plan_compression(&files, &CompressOptions::default());
        let mut files2 = files.clone();
        files2.reverse();
        let p2 = plan_compression(&files2, &CompressOptions::default());
        let names1: Vec<_> = p1.files.iter().map(|f| f.path.clone()).collect();
        let names2: Vec<_> = p2.files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(names1, names2);
    }
}
