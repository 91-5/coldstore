//! Filesystem scanner.
//!
//! Enumerates files under a root directory and produces the metadata the
//! downstream stages need. Hard requirements (card OC-20261110-001 D2):
//!
//! - reparse points (junctions / symlinks) are **never followed** by
//!   default — this prevents cycles and prevents escaping the scanned tree
//!   (Windows `Get-ChildItem -Recurse` famously breaks on them). Every
//!   skipped reparse entry is recorded *with its target path* so the audit
//!   trail is visible (AV-4);
//! - `--follow-junction <path>` is an explicit, default-off escape hatch
//!   (AV-4); followed targets are scanned once each (cycle-guarded by a
//!   canonical-path visited set), and a global reparse-point counter acts
//!   as a second anti-cycle gate;
//! - hardcoded blacklist dirs (`.git`, `node_modules`, venv…) are skipped
//!   with an explicit reason (card B13) — a python venv of *any* name is
//!   detected via its `pyvenv.cfg` marker;
//! - `LastAccessTime` is collected but never trusted (system-managed
//!   `DisableLastAccess` may freeze it) — it is informational only;
//! - the first 16 bytes of every file are captured (in parallel) so the
//!   predictor can catch "extension lies" without a second pass.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::magic::{identify, MAGIC_CAPTURE_LEN};

pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Directories never scanned, recorded in `skipped` with a reason (B13).
pub const DEFAULT_BLACKLIST_DIRS: &[&str] =
    &[".git", "node_modules", "__pycache__", ".venv", "venv"];

/// Second anti-cycle gate: total reparse points the scan will even look at.
pub const DEFAULT_MAX_REPARSE_POINTS: usize = 10_000;

/// Marker file identifying a python virtualenv root of any name.
pub const VENV_MARKER_FILE: &str = "pyvenv.cfg";

/// Directory names that mark a "safely deletable cache" for the predictor.
pub const CACHE_DIR_NAMES: &[&str] = &[".cache", "caches", "__pycache__"];

#[cfg(windows)]
fn file_attrs(meta: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt as _;
    meta.file_attributes()
}

#[cfg(not(windows))]
fn file_attrs(_meta: &fs::Metadata) -> u32 {
    0
}

/// One regular file discovered by the scan.
#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    /// Lowercase extension without the dot; empty when the name has none.
    pub ext: String,
    /// Last write time. Primary cold/hot signal (atime is not trusted).
    pub modified: Option<SystemTime>,
    /// Last access time — **low trust**: system-managed
    /// `DisableLastAccess` means Windows may never update it.
    pub accessed: Option<SystemTime>,
    pub is_reparse: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    /// Lowercase hex of the first up-to-16 bytes; empty when unreadable.
    pub magic_hex: String,
    pub magic_read_failed: bool,
}

impl FileEntry {
    /// Magic kind derived from the captured head bytes.
    pub fn magic_kind(&self) -> crate::magic::MagicKind {
        if self.magic_read_failed {
            return crate::magic::MagicKind::Unknown;
        }
        let mut buf = [0u8; MAGIC_CAPTURE_LEN];
        let n = (self.magic_hex.len() / 2).min(MAGIC_CAPTURE_LEN);
        for (i, byte) in buf.iter_mut().take(n).enumerate() {
            *byte = u8::from_str_radix(&self.magic_hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        identify(&buf[..n])
    }
}

/// Why an entry was not scanned. Every variant is user-auditable (B11/B13).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "reason", content = "detail")]
pub enum SkipReason {
    /// Junction/symlink not followed. `target` is recorded so the user can
    /// audit what was *not* scanned (AV-4).
    ReparsePoint {
        target: Option<String>,
        followed: bool,
    },
    /// Reparse-point cap exceeded; further reparse entries were refused.
    ReparseCapExceeded { cap: usize },
    /// Hardcoded blacklist directory (rebuildable / not user content).
    BlacklistedDirectory { name: String },
    /// Directory contains a `pyvenv.cfg` marker (python venv, any name).
    PythonVenv { marker: String },
    /// A follow-junction target had already been scanned once (dedup).
    JunctionTargetAlreadyScanned { target: String },
    /// Non-fatal I/O failure; the scan continues elsewhere.
    IoError { message: String },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::ReparsePoint {
                target: Some(t),
                followed: false,
            } => {
                write!(f, "重解析点未跟随（junction/symlink，目标: {t}）")
            }
            SkipReason::ReparsePoint {
                target: None,
                followed: false,
            } => {
                write!(f, "重解析点未跟随（junction/symlink，目标无法解析）")
            }
            SkipReason::ReparsePoint { followed: true, .. } => {
                write!(f, "重解析点已按 --follow-junction 显式跟随")
            }
            SkipReason::ReparseCapExceeded { cap } => {
                write!(
                    f,
                    "重解析点数量超过上限 {cap}，剩余项拒绝进入（防环第二道闸）"
                )
            }
            SkipReason::BlacklistedDirectory { name } => {
                write!(
                    f,
                    "硬编码黑名单目录（{name}）：可重建/非用户内容，不进入扫描与预测"
                )
            }
            SkipReason::PythonVenv { marker } => {
                write!(f, "Python venv（发现 {marker}），可重建，不进入扫描与预测")
            }
            SkipReason::JunctionTargetAlreadyScanned { target } => {
                write!(
                    f,
                    "junction 目标已扫描过一次（去重），不再重复进入: {target}"
                )
            }
            SkipReason::IoError { message } => write!(f, "IO 错误: {message}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SkipRecord {
    pub path: PathBuf,
    pub reason: SkipReason,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub blacklist_dirs: Vec<String>,
    pub max_reparse_points: usize,
    /// AV-4 escape hatch, default OFF: path prefixes whose junction targets
    /// may be followed. Each target is scanned at most once.
    pub follow_junction: Vec<PathBuf>,
    pub read_magic: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            blacklist_dirs: DEFAULT_BLACKLIST_DIRS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_reparse_points: DEFAULT_MAX_REPARSE_POINTS,
            follow_junction: Vec::new(),
            read_magic: true,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub root: PathBuf,
    pub files: Vec<FileEntry>,
    pub skipped: Vec<SkipRecord>,
    pub total_bytes: u64,
    pub truncated_by_reparse_cap: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct DirRollup {
    pub name: String,
    pub files: u64,
    pub bytes: u64,
}

impl ScanResult {
    /// Volume rollup of first-level subdirectories (depth-1 attribution).
    /// Used by the CLI to show which subtree dominates (B5).
    pub fn dir_rollup(&self) -> Vec<DirRollup> {
        let mut map: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();
        for f in &self.files {
            let key = match f.path.strip_prefix(&self.root) {
                Ok(rel) => match rel.components().next() {
                    Some(c) => c.as_os_str().to_string_lossy().into_owned(),
                    None => "(root)".to_string(),
                },
                Err(_) => "(outside root)".to_string(),
            };
            let e = map.entry(key).or_insert((0, 0));
            e.0 += 1;
            e.1 += f.size;
        }
        let mut rows: Vec<DirRollup> = map
            .into_iter()
            .map(|(name, (files, bytes))| DirRollup { name, files, bytes })
            .collect();
        rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.name.cmp(&b.name)));
        rows
    }

    /// Volume rollup by extension, largest first.
    pub fn ext_rollup(&self) -> Vec<DirRollup> {
        let mut map: std::collections::HashMap<String, (u64, u64)> =
            std::collections::HashMap::new();
        for f in &self.files {
            let key = if f.ext.is_empty() {
                "(no ext)".to_string()
            } else {
                f.ext.clone()
            };
            let e = map.entry(key).or_insert((0, 0));
            e.0 += 1;
            e.1 += f.size;
        }
        let mut rows: Vec<DirRollup> = map
            .into_iter()
            .map(|(name, (files, bytes))| DirRollup { name, files, bytes })
            .collect();
        rows.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.name.cmp(&b.name)));
        rows
    }
}

struct RawEntry {
    path: PathBuf,
    size: u64,
    ext: String,
    modified: Option<SystemTime>,
    accessed: Option<SystemTime>,
    is_reparse: bool,
    is_hidden: bool,
    is_system: bool,
}

struct ScanState {
    opts: ScanOptions,
    files: Vec<RawEntry>,
    skipped: Vec<SkipRecord>,
    reparse_seen: usize,
    cap_hit: bool,
    pending_follow: std::collections::VecDeque<(PathBuf, PathBuf)>,
    followed_targets: HashSet<PathBuf>,
}

/// Scan `root` recursively (read-only; never writes to the scanned tree).
pub fn scan(root: &Path, opts: &ScanOptions) -> Result<ScanResult> {
    let started = Instant::now();
    // Absolute root up front: FileEntry paths (and later archive index
    // entries) must be volume-checkable (AV-5) regardless of CLI cwd.
    let root =
        std::path::absolute(root).with_context(|| format!("解析扫描根失败: {}", root.display()))?;
    if !root.exists() {
        bail!("扫描根目录不存在: {}", root.display());
    }
    let meta =
        fs::metadata(&root).with_context(|| format!("无法读取根目录元数据: {}", root.display()))?;
    if !meta.is_dir() {
        bail!("扫描根不是目录: {}", root.display());
    }

    // B13 root guard: a venv / blacklisted directory is never entered even
    // when pointed at *directly* — it is recorded in `skipped` with its
    // reason and yields an empty scan, so nothing inside it can ever reach
    // an ARCHIVE suggestion.
    let root_name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if opts
        .blacklist_dirs
        .iter()
        .any(|b| b.eq_ignore_ascii_case(&root_name))
    {
        return Ok(ScanResult {
            root: root.clone(),
            files: Vec::new(),
            skipped: vec![SkipRecord {
                path: root.clone(),
                reason: SkipReason::BlacklistedDirectory { name: root_name },
            }],
            total_bytes: 0,
            truncated_by_reparse_cap: false,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }
    if root.join(VENV_MARKER_FILE).exists() {
        return Ok(ScanResult {
            root: root.clone(),
            files: Vec::new(),
            skipped: vec![SkipRecord {
                path: root.clone(),
                reason: SkipReason::PythonVenv {
                    marker: VENV_MARKER_FILE.to_string(),
                },
            }],
            total_bytes: 0,
            truncated_by_reparse_cap: false,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    let state = RefCell::new(ScanState {
        opts: opts.clone(),
        files: Vec::new(),
        skipped: Vec::new(),
        reparse_seen: 0,
        cap_hit: false,
        pending_follow: std::collections::VecDeque::new(),
        followed_targets: HashSet::new(),
    });

    walk_into(&root, &state)?;

    // AV-4 escape hatch: follow explicitly-allowed junction targets, each
    // exactly once, cycle-guarded by the canonical visited set. Targets
    // discovered while walking a target simply extend the queue.
    loop {
        let next = {
            let mut st = state.borrow_mut();
            st.pending_follow.pop_front()
        };
        let Some((junction_path, target)) = next else {
            break;
        };
        let canon = fs::canonicalize(&target).unwrap_or_else(|_| target.clone());
        {
            let mut st = state.borrow_mut();
            if !st.followed_targets.insert(canon.clone()) {
                st.skipped.push(SkipRecord {
                    path: junction_path,
                    reason: SkipReason::JunctionTargetAlreadyScanned {
                        target: canon.display().to_string(),
                    },
                });
                continue;
            }
        }
        walk_into(&canon, &state)?;
    }

    // Parallel magic-head reads: the only per-file open() the scan does.
    let heads: Vec<Head> = if opts.read_magic {
        state
            .borrow()
            .files
            .par_iter()
            .map(|e| read_head(&e.path))
            .collect()
    } else {
        vec![Head::default(); state.borrow().files.len()]
    };

    let (files, skipped, cap_hit) = {
        let mut st = state.borrow_mut();
        let files: Vec<FileEntry> = std::mem::take(&mut st.files)
            .into_iter()
            .zip(heads)
            .map(|(raw, head)| FileEntry {
                path: raw.path,
                size: raw.size,
                ext: raw.ext,
                modified: raw.modified,
                accessed: raw.accessed,
                is_reparse: raw.is_reparse,
                is_hidden: raw.is_hidden,
                is_system: raw.is_system,
                magic_hex: head.hex,
                magic_read_failed: head.read_failed,
            })
            .collect();
        (files, std::mem::take(&mut st.skipped), st.cap_hit)
    };

    let total_bytes = files.iter().map(|f| f.size).sum();
    Ok(ScanResult {
        root: root.to_path_buf(),
        files,
        skipped,
        total_bytes,
        truncated_by_reparse_cap: cap_hit,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[derive(Default, Debug, Clone)]
struct Head {
    hex: String,
    read_failed: bool,
}

fn read_head(path: &Path) -> Head {
    let mut buf = [0u8; MAGIC_CAPTURE_LEN];
    let result = (|| -> std::io::Result<usize> {
        let mut f = fs::File::open(path)?;
        let mut filled = 0;
        while filled < buf.len() {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    })();
    match result {
        Ok(n) => Head {
            hex: hex_lower(&buf[..n]),
            read_failed: false,
        },
        Err(_) => Head {
            hex: String::new(),
            read_failed: true,
        },
    }
    // Note: a tiny 16-byte read of a cloud placeholder file may hydrate it;
    // this is accepted because real reparse *files* are rare outside
    // OneDrive dirs, and reparse *dirs* are never entered by default.
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One walk pass over `root`, appending into `state`. Reused for the main
/// tree and for explicitly followed junction targets.
fn walk_into(root: &Path, state: &RefCell<ScanState>) -> Result<()> {
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Borrows are strictly sequential: the predicate runs inside
            // `next()`, the loop body between `next()` calls.
            let mut st = state.borrow_mut();
            should_enter(e, &mut st)
        });

    for entry in walker {
        match entry {
            Ok(e) => {
                if e.depth() == 0 {
                    continue;
                }
                let ft = e.file_type();
                if ft.is_dir() || ft.is_symlink() {
                    // enterable dirs are not collected; symlinks never get
                    // here (refused by the predicate).
                    continue;
                }
                let mut st = state.borrow_mut();
                let meta = match e.metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        st.skipped.push(SkipRecord {
                            path: e.path().to_path_buf(),
                            reason: SkipReason::IoError {
                                message: format!("metadata: {err}"),
                            },
                        });
                        continue;
                    }
                };
                let attrs = file_attrs(&meta);
                st.files.push(RawEntry {
                    path: e.path().to_path_buf(),
                    size: meta.len(),
                    ext: extension_of(e.path()),
                    modified: meta.modified().ok(),
                    accessed: meta.accessed().ok(),
                    is_reparse: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                    is_hidden: attrs & FILE_ATTRIBUTE_HIDDEN != 0,
                    is_system: attrs & FILE_ATTRIBUTE_SYSTEM != 0,
                });
            }
            Err(err) => {
                let mut st = state.borrow_mut();
                let path = err.path().map(|p| p.to_path_buf()).unwrap_or_default();
                st.skipped.push(SkipRecord {
                    path,
                    reason: SkipReason::IoError {
                        message: err.to_string(),
                    },
                });
            }
        }
    }
    Ok(())
}

fn extension_of(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// Predicate for `filter_entry`: decide whether walkdir may enter/keep an
/// entry, recording skip reasons for everything it refuses.
fn should_enter(e: &DirEntry, st: &mut ScanState) -> bool {
    if e.depth() == 0 {
        return true; // the explicit root is always entered
    }
    let ft = e.file_type();
    let path = e.path().to_path_buf();

    // Name-based blacklist (safe: no filesystem following involved).
    if ft.is_dir() {
        let name = e.file_name().to_string_lossy().into_owned();
        if st
            .opts
            .blacklist_dirs
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&name))
        {
            st.skipped.push(SkipRecord {
                path,
                reason: SkipReason::BlacklistedDirectory { name },
            });
            return false;
        }
    }

    // Any symlink-class entry (junction or symlink): record + refuse.
    // This runs *before* the venv check, because `Path::exists()` follows
    // links and would otherwise peek through the junction.
    if ft.is_symlink() {
        return refuse_reparse(st, path, true);
    }

    if ft.is_dir() {
        // Non-symlink reparse *directory* (cloud placeholders, mounts): the
        // target is outside our knowledge — refuse to descend.
        let attrs = e.metadata().map(|m| file_attrs(&m)).unwrap_or(0);
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return refuse_reparse(st, path, false);
        }
        // Python venv of any name, detected by its marker file.
        if e.path().join(VENV_MARKER_FILE).exists() {
            st.skipped.push(SkipRecord {
                path,
                reason: SkipReason::PythonVenv {
                    marker: VENV_MARKER_FILE.to_string(),
                },
            });
            return false;
        }
    }

    true
}

/// Record a reparse-point skip (or a follow-junction queue entry) and
/// refuse the entry from the main walk. Allowed junctions are re-scanned
/// via their real target after the main walk finishes.
fn refuse_reparse(st: &mut ScanState, path: PathBuf, is_symlink: bool) -> bool {
    st.reparse_seen += 1;
    if st.reparse_seen > st.opts.max_reparse_points {
        st.cap_hit = true;
        st.skipped.push(SkipRecord {
            path,
            reason: SkipReason::ReparseCapExceeded {
                cap: st.opts.max_reparse_points,
            },
        });
        return false;
    }

    let target: Option<PathBuf> = if is_symlink {
        fs::read_link(&path).ok()
    } else {
        None
    };
    let target_str = target.as_ref().map(|t| strip_verbatim(t));

    // AV-4 escape hatch: explicit prefix match queues the real target for
    // a single, cycle-guarded walk.
    if let Some(t) = &target {
        if st
            .opts
            .follow_junction
            .iter()
            .any(|p| path_starts_under(&path, p))
        {
            st.pending_follow.push_back((path.clone(), t.clone()));
            st.skipped.push(SkipRecord {
                path,
                reason: SkipReason::ReparsePoint {
                    target: target_str,
                    followed: true,
                },
            });
            return false;
        }
    }

    st.skipped.push(SkipRecord {
        path,
        reason: SkipReason::ReparsePoint {
            target: target_str,
            followed: false,
        },
    });
    false
}

fn strip_verbatim(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// Case-insensitive, separator-safe prefix test (`path` is under `prefix`).
fn path_starts_under(path: &Path, prefix: &Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    let q = prefix.to_string_lossy().to_lowercase();
    if p == q {
        return true;
    }
    let q = q.trim_end_matches(['\\', '/']);
    p.starts_with(q) && p.as_bytes().get(q.len()) == Some(&b'\\')
}

/// Reusable helper: whether a path lies under a well-known cache directory
/// (relative to the scan root). Used by the predictor to mark `DELETABLE`.
pub struct CachePathCheck {
    root: PathBuf,
}

impl CachePathCheck {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    pub fn is_cache_path(&self, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return false; // outside the scanned tree → not judged
        };
        rel.components().any(|c| {
            let s = c.as_os_str().to_string_lossy().to_lowercase();
            CACHE_DIR_NAMES.contains(&s.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::process::Command;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "coldstore-scan-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_junction(link: &Path, target: &Path) -> bool {
        Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    #[test]
    fn scan_collects_files_and_records_skips() {
        let root = temp_root("main");
        fs::write(root.join("a.txt"), b"hello coldstore").unwrap();
        fs::write(root.join("empty.txt"), b"").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/big.bin"), vec![0xABu8; 512]).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/head"), b"ref").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules/m.js"), b"j").unwrap();
        fs::create_dir_all(root.join("myenv")).unwrap();
        fs::write(root.join("myenv/pyvenv.cfg"), b"home = x").unwrap();
        fs::write(root.join("myenv/lib.py"), b"p").unwrap();
        // junction whose store lives *inside* the tree (pnpm shape):
        fs::create_dir_all(root.join("jt")).unwrap();
        fs::write(root.join("jt/content.bin"), vec![1u8; 100]).unwrap();
        assert!(
            make_junction(&root.join("lnk"), &root.join("jt")),
            "mklink /J must succeed on windows CI/dev box"
        );

        let res = scan(&root, &ScanOptions::default()).unwrap();
        let names: Vec<String> = res
            .files
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        // collected
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"empty.txt".to_string()));
        assert!(names.contains(&"big.bin".to_string()));
        // junction store reachable via its real path, exactly once
        assert_eq!(names.iter().filter(|n| *n == "content.bin").count(), 1);

        // skipped with reasons
        let find_skip = |pfx: &str| {
            res.skipped
                .iter()
                .find(|s| s.path.to_string_lossy().contains(pfx))
                .map(|s| s.reason.clone())
        };
        assert_eq!(
            find_skip(".git"),
            Some(SkipReason::BlacklistedDirectory {
                name: ".git".into()
            })
        );
        assert_eq!(
            find_skip("node_modules"),
            Some(SkipReason::BlacklistedDirectory {
                name: "node_modules".into()
            })
        );
        assert_eq!(
            find_skip("myenv"),
            Some(SkipReason::PythonVenv {
                marker: "pyvenv.cfg".into()
            })
        );
        match find_skip("lnk") {
            Some(SkipReason::ReparsePoint {
                target: Some(t),
                followed: false,
            }) => {
                assert!(t.ends_with("jt"), "junction target recorded, got {t}");
            }
            other => panic!("expected reparse skip with target, got {other:?}"),
        }
        // never followed by default → nothing outside the tree
        assert!(!names.contains(&"outside.bin".to_string()));

        // magic: text file is text, empty file has empty magic
        let a = res
            .files
            .iter()
            .find(|f| f.path.ends_with("a.txt"))
            .unwrap();
        assert_eq!(a.magic_kind(), crate::magic::MagicKind::Text);
        let e = res
            .files
            .iter()
            .find(|f| f.path.ends_with("empty.txt"))
            .unwrap();
        assert_eq!(e.magic_kind(), crate::magic::MagicKind::Empty);
        assert_eq!(e.size, 0);

        fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn reparse_cap_blocks_and_flags() {
        let root = temp_root("cap");
        fs::create_dir_all(root.join("jt")).unwrap();
        fs::write(root.join("jt/x.bin"), b"x").unwrap();
        assert!(make_junction(&root.join("lnk"), &root.join("jt")));

        let opts = ScanOptions {
            max_reparse_points: 0,
            ..Default::default()
        };
        let res = scan(&root, &opts).unwrap();
        assert!(res.truncated_by_reparse_cap);
        assert!(res
            .skipped
            .iter()
            .any(|s| matches!(s.reason, SkipReason::ReparseCapExceeded { cap: 0 })));

        fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn follow_junction_escape_hatch_is_opt_in_and_deduped() {
        let root = temp_root("follow");
        let outside = temp_root("follow-target");
        fs::write(outside.join("outside.bin"), vec![7u8; 64]).unwrap();
        assert!(make_junction(&root.join("lnk1"), &outside));
        assert!(make_junction(&root.join("lnk2"), &outside));
        fs::write(root.join("own.txt"), b"o").unwrap();

        // default: not followed
        let res = scan(&root, &ScanOptions::default()).unwrap();
        assert!(res.files.iter().all(|f| !f.path.ends_with("outside.bin")));

        // opt-in: followed, each target scanned once
        let opts = ScanOptions {
            follow_junction: vec![root.clone()],
            ..Default::default()
        };
        let res = scan(&root, &opts).unwrap();
        assert_eq!(
            res.files
                .iter()
                .filter(|f| f.path.ends_with("outside.bin"))
                .count(),
            1,
            "target scanned exactly once despite two junctions"
        );
        assert!(res
            .skipped
            .iter()
            .any(|s| matches!(s.reason, SkipReason::JunctionTargetAlreadyScanned { .. })));

        fs::remove_dir_all(&root).ok();
        fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn dir_rollup_attributes_volume() {
        let root = temp_root("rollup");
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("target/debug/a.rlib"), vec![0u8; 300]).unwrap();
        fs::write(root.join("target/debug/b.rlib"), vec![0u8; 100]).unwrap();
        fs::write(root.join("top.bin"), vec![0u8; 50]).unwrap();
        let res = scan(&root, &ScanOptions::default()).unwrap();
        let rollup = res.dir_rollup();
        assert_eq!(rollup[0].name, "target");
        assert_eq!(rollup[0].bytes, 400);
        assert_eq!(rollup[0].files, 2);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_guard_refuses_blacklisted_and_venv_roots() {
        // .git as root → recorded in skipped, zero files collected
        let git_root = temp_root("git-root");
        fs::create_dir_all(git_root.join(".git")).unwrap();
        fs::write(git_root.join(".git/HEAD"), b"ref").unwrap();
        let res = scan(&git_root.join(".git"), &ScanOptions::default()).unwrap();
        assert!(res.files.is_empty());
        assert!(matches!(
            res.skipped[0].reason,
            SkipReason::BlacklistedDirectory { ref name } if name == ".git"
        ));

        // venv as root (pyvenv.cfg marker, arbitrary name) → same
        let venv_root = temp_root("venv-root");
        fs::write(venv_root.join("pyvenv.cfg"), b"home = x").unwrap();
        fs::write(venv_root.join("lib.py"), b"p").unwrap();
        let res = scan(&venv_root, &ScanOptions::default()).unwrap();
        assert!(res.files.is_empty());
        assert!(matches!(
            res.skipped[0].reason,
            SkipReason::PythonVenv { .. }
        ));

        fs::remove_dir_all(&git_root).ok();
        fs::remove_dir_all(&venv_root).ok();
    }
}
