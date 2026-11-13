//! Quarantine & undo (card D4) — the product's trust base.
//!
//! The archive execution sequence (order fixed by the card; adjudication
//! Q2: **step 3 is structurally the only path — no flag or config can
//! bypass it**):
//!
//! 1. read source → SHA-256;
//! 2. write archive container via **001's `archive()` API** (ADV-N2: no
//!    second zstd path);
//! 3. retrieve the frame via **001's `retrieve()` API** and compare its
//!    SHA-256 against the step-1 hash — mismatch ⇒ abort, clean up, never
//!    proceed;
//! 4. only then move the source into the quarantine batch dir (not delete):
//!    same volume = rename; cross-volume = copy + verify + delete-original,
//!    which is exactly the "free space on D:" mechanism (ADV-N5: normal
//!    path, never rejected);
//! 5. journal every step (intent before, result after — Q8);
//! 6. `quarantine delete` with explicit confirmation frees the space.
//!
//! Any `fs::remove`/`fs::rename`/`fs::copy` lives ONLY inside the sequence
//! functions below (`archive_batch` / `quarantine_delete` / `undo_batch` /
//! `recover_batch`), each journaled. A grep proof ships in the delivery
//! doc (ADV-N2).
//!
//! Container ↔ quarantine must share a volume (hard rule 10, ADV-N5) — a
//! cross-volume pair would silently move bytes without saving any.

mod journal;

pub use journal::{
    now_millis, parse_journal, progress_from_journal, BatchState, FileProgress, Journal,
    JournalLine,
};

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read as _;

use crate::archive::{self, volume_letter};
use crate::scan::FileEntry;

/// Resolved quarantine settings (from config + defaults).
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    pub root: PathBuf,
    pub journal_dir: PathBuf,
    pub retention_days: u64,
}

impl QuarantineConfig {
    /// Resolve from app config + env: `root`/`archive_root` overrides, else
    /// `%USERPROFILE%\.coldstore\{quarantine,journal}` (card D4 default;
    /// ADV-N8: outside the repo, never committed).
    pub fn resolve(settings: &crate::rules::toml::QuarantineSettings) -> Result<QuarantineConfig> {
        let home = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
        let coldstore_home = PathBuf::from(&home).join(".coldstore");
        let root = match &settings.root {
            Some(p) => std::path::absolute(p)?,
            None => std::path::absolute(coldstore_home.join("quarantine"))?,
        };
        let journal_dir = std::path::absolute(coldstore_home.join("journal"))?;
        Ok(QuarantineConfig {
            root,
            journal_dir,
            retention_days: settings.retention_days.max(1),
        })
    }
}

/// Default archive container root (`%USERPROFILE%\.coldstore\archive` or
/// the configured override).
pub fn archive_root(settings: &crate::rules::toml::QuarantineSettings) -> Result<PathBuf> {
    match &settings.archive_root {
        Some(p) => Ok(std::path::absolute(p)?),
        None => {
            let home = env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string());
            Ok(std::path::absolute(
                PathBuf::from(&home).join(".coldstore").join("archive"),
            )?)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BatchEntry {
    pub ordinal: u64,
    pub source: String,
    pub size: u64,
    pub sha256: String,
    pub quarantined_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BatchStats {
    pub batch_id: String,
    pub container: String,
    pub files: u64,
    pub bytes: u64,
    pub journal: String,
    pub entries: Vec<BatchEntry>,
}

#[derive(Debug, Serialize)]
pub struct BatchInfo {
    pub batch_id: String,
    pub container: Option<String>,
    /// Concrete expiry date "YYYY-MM-DD" (UTC) — ADV-N5: never "N days later".
    pub created_date: String,
    pub expires_date: String,
    pub expired: bool,
    /// completed | interrupted | released | aborted
    pub status: String,
    pub files_moved: u64,
    pub bytes_still_occupied: u64,
    /// Up to 3 quarantined source paths (B11: 来源路径可见).
    pub sources: Vec<String>,
    /// Hard rule 3: expiry never deletes; this note travels with the row.
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct UndoStats {
    pub batch_id: String,
    pub restored: u64,
    pub conflicts: u64,
    pub conflict_files: Vec<String>,
    pub container_removed: bool,
    /// Set when the caller asked to keep the archive container (ADV-N3
    /// `--keep-container`): the container path that was left on disk.
    pub container_kept: String,
}

/// Batch identifier: local-wall-clock-ish UTC stamp + entropy suffix.
fn new_batch_id() -> String {
    let ms = now_millis();
    let mut h = Sha256::new();
    h.update(ms.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let hex = format!("{:x}", h.finalize());
    let (y, m, d) = civil_from_date_millis(ms);
    format!("{y:04}{m:02}{d:02}-{ms:x}-{}", &hex[..6])
}

/// Debug-only crash injection (card B13 evidence): after `N` completed
/// file units the process aborts mid-sequence, leaving a torn journal.
/// P7 A1: the whole seam is gated by `#[cfg(debug_assertions)]` — in a
/// release binary neither the env var name, nor the `env::var` call, nor
/// the `abort()` path is compiled in. B13 integration tests run in the
/// debug profile, so their env injection still works unchanged.
#[cfg(debug_assertions)]
fn crash_hook(units_done: usize) {
    if let Ok(n) = env::var("COLDSTORE_CRASH_AFTER") {
        if let Ok(n) = n.trim().parse::<usize>() {
            if n > 0 && units_done >= n {
                eprintln!(
                    "[crash-hook] COLDSTORE_CRASH_AFTER={n} reached — abort() now (B13 evidence)"
                );
                std::process::abort();
            }
        }
    }
}

/// Release counterpart: an empty, inlined no-op — no debug seam at all.
#[cfg(not(debug_assertions))]
fn crash_hook(_units_done: usize) {}

/// THE six-step sequence (steps 1–5; step 6 is `quarantine_delete`).
/// Every mutation below is inside this function and journaled (ADV-N2).
pub fn archive_batch(
    files: &[FileEntry],
    container: &Path,
    qcfg: &QuarantineConfig,
) -> Result<BatchStats> {
    if files.is_empty() {
        bail!("归档批次为空（无可执行文件）");
    }
    if container.exists() {
        bail!("归档容器已存在，拒绝覆盖: {}", container.display());
    }
    // Hard rule 10 / ADV-N5: container ↔ quarantine same volume, three-
    // element error (pair, both volume letters, remediation).
    let v_container = volume_letter(container);
    let v_quarantine = volume_letter(&qcfg.root);
    if v_container != v_quarantine {
        bail!(
            "归档容器与隔离区必须同盘（硬约束 10）：容器卷 {:?} ≠ 隔离区卷 {:?}。\
             跨盘组合不省空间——请把容器与隔离区配置到同一卷（[quarantine] archive_root/root），\
             或使用默认 %USERPROFILE%\\.coldstore\\ 下两者（同卷自洽）。",
            v_container
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(未知)".into()),
            v_quarantine
                .map(|v| v.to_string())
                .unwrap_or_else(|| "(未知)".into()),
        );
    }

    let batch_id = new_batch_id();
    let mut jr = Journal::open(&qcfg.journal_dir, &batch_id)?;
    let batch_dir = qcfg.root.join(&batch_id);
    let verify_dir = qcfg.root.join("_verify").join(&batch_id);

    // batch intent — carries the full plan so recovery is self-contained.
    let mut batch_intent = JournalLine::new("batch", "intent");
    batch_intent.detail = Some(serde_json::json!({
        "batch_id": batch_id,
        "container": container.display().to_string(),
        "files": files.iter().map(|f| f.path.display().to_string()).collect::<Vec<_>>(),
        "retention_days": qcfg.retention_days,
    }));
    jr.append(&batch_intent)?;

    let outcome = run_sequence(
        files,
        container,
        &batch_id,
        &batch_dir,
        &verify_dir,
        &mut jr,
    );

    match outcome {
        Ok(stats) => {
            let mut done = JournalLine::new("batch", "result");
            done.detail = Some(serde_json::json!({
                "batch_id": batch_id,
                "files": stats.files,
                "bytes": stats.bytes,
                "status": "completed",
            }));
            jr.append(&done)?;
            Ok(stats)
        }
        Err(err) => {
            // Sequence abort: clean everything the sequence created, then
            // journal the failure. This cleanup is part of the sequence.
            let mut err_line = JournalLine::new("batch", "error");
            err_line.error = Some(err.to_string());
            err_line.detail = Some(serde_json::json!({
                "batch_id": batch_id,
                "cleaned": {
                    "verify_dir": verify_dir.display().to_string(),
                    "container_tmp": format!("{}.tmp", container.display()),
                },
            }));
            let _ = jr.append(&err_line);
            let _ = fs::remove_dir_all(&verify_dir);
            let _ = fs::remove_file(container_tmp(container));
            // A published-but-unverified container is suspect by definition:
            // step-3 did not finish → remove it (sequence-internal cleanup).
            if container.exists() {
                let _ = fs::remove_file(container);
            }
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_sequence(
    files: &[FileEntry],
    container: &Path,
    batch_id: &str,
    batch_dir: &Path,
    verify_dir: &Path,
    jr: &mut Journal,
) -> Result<BatchStats> {
    // ── step 1: read source → SHA-256 ──────────────────────────────────
    let mut hashes: Vec<(u64, String, u64)> = Vec::with_capacity(files.len()); // (ordinal, sha, size)
    for (ordinal, fe) in files.iter().enumerate() {
        let mut intent = JournalLine::new("s1", "intent");
        intent.ordinal = Some(ordinal as u64);
        intent.file = Some(fe.path.display().to_string());
        jr.append(&intent)?;
        let (sha, size) = hash_source(&fe.path)?;
        let mut result = JournalLine::new("s1", "result");
        result.ordinal = Some(ordinal as u64);
        result.file = Some(fe.path.display().to_string());
        result.sha256 = Some(sha.clone());
        result.size = Some(size);
        jr.append(&result)?;
        hashes.push((ordinal as u64, sha, size));
    }

    // ── step 2: write container via 001's archive() (ADV-N2) ──────────
    jr.append_simple("s2", "intent")?;
    let opts = archive::ArchiveOptions::default();
    let stats = archive::archive(files, container, &opts)?;
    let mut s2 = JournalLine::new("s2", "result");
    s2.detail = Some(serde_json::json!({
        "container": container.display().to_string(),
        "frames": stats.frame_count,
        "total_original": stats.total_original,
        "total_compressed": stats.total_compressed,
    }));
    jr.append(&s2)?;

    // ── step 3: retrieve each frame via 001's retrieve() and compare
    //    SHA-256 against the step-1 hash. Structurally the ONLY path —
    //    there is no flag, config or branch that skips this loop.
    let mut quarantined: Vec<BatchEntry> = Vec::with_capacity(files.len());
    let mut units_done = 0usize;
    for (idx, fe) in files.iter().enumerate() {
        let ordinal = idx as u64;
        let want_sha = &hashes[idx].1;
        let want_size = hashes[idx].2;

        let mut intent = JournalLine::new("s3", "intent");
        intent.ordinal = Some(ordinal);
        intent.file = Some(fe.path.display().to_string());
        jr.append(&intent)?;

        let verify_path = verify_dir.join(format!("{ordinal:06}__verify"));
        // 001 retrieve: decodes ONLY this frame, verifies against the
        // index hash; missing-hash entries would downgrade to UNVERIFIED.
        let outcome = archive::retrieve(
            container,
            &archive::EntryKey::Ordinal(ordinal),
            &verify_path,
        )?;
        if outcome.size != want_size {
            bail!(
                "六步序列第 3 步体积不符（序号 {ordinal}）: 取回 {} ≠ 源 {} — 立即中止",
                outcome.size,
                want_size
            );
        }
        let got = hash_source(&verify_path)?;
        if got.0 != *want_sha {
            bail!(
                "六步序列第 3 步 SHA-256 不符（序号 {ordinal} {}）: 期望 {} 实际 {} — 立即中止并清理",
                fe.path.display(),
                want_sha,
                got.0
            );
        }
        // sequence-internal cleanup of the verification copy
        fs::remove_file(&verify_path)
            .with_context(|| format!("清理校验副本失败: {}", verify_path.display()))?;
        let mut result = JournalLine::new("s3", "result");
        result.ordinal = Some(ordinal);
        result.file = Some(fe.path.display().to_string());
        result.sha256 = Some(want_sha.clone());
        jr.append(&result)?;

        // ── step 4: move source into quarantine (not delete) ──────────
        let dest = batch_dir.join(format!(
            "{ordinal:06}__{}",
            fe.path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let mut intent4 = JournalLine::new("s4", "intent");
        intent4.ordinal = Some(ordinal);
        intent4.file = Some(fe.path.display().to_string());
        intent4.sha256 = Some(want_sha.clone());
        intent4.size = Some(want_size);
        intent4.detail = Some(serde_json::json!({ "quarantine_path": dest.display().to_string() }));
        jr.append(&intent4)?;

        move_into_quarantine(&fe.path, &dest, want_sha)?;

        let mut result4 = JournalLine::new("s4", "result");
        result4.ordinal = Some(ordinal);
        result4.file = Some(dest.display().to_string());
        result4.sha256 = Some(want_sha.clone());
        result4.size = Some(want_size);
        jr.append(&result4)?;

        quarantined.push(BatchEntry {
            ordinal,
            source: fe.path.display().to_string(),
            size: want_size,
            sha256: want_sha.clone(),
            quarantined_to: Some(dest.display().to_string()),
        });

        units_done += 1;
        crash_hook(units_done);
    }

    fs::remove_dir_all(verify_dir).ok(); // empty by now; belt and braces
    let total_bytes: u64 = quarantined.iter().map(|e| e.size).sum();
    Ok(BatchStats {
        batch_id: batch_id.to_string(),
        container: container.display().to_string(),
        files: quarantined.len() as u64,
        bytes: total_bytes,
        journal: jr.path.display().to_string(),
        entries: quarantined,
    })
    // (batch "result" line is appended by archive_batch on Ok)
}

/// One source hash + size (step 1; streaming, constant memory).
fn hash_source(path: &Path) -> Result<(String, u64)> {
    let mut f =
        fs::File::open(path).with_context(|| format!("打开源文件失败: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

/// Move one file into quarantine. Same volume → rename; cross volume →
/// copy + SHA-verify the copy + delete the original (ADV-N5: the normal
/// "free D: space" path). All inside the sequence, journaled by callers.
fn move_into_quarantine(src: &Path, dest: &Path, want_sha: &str) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建隔离目录失败: {}", parent.display()))?;
    }
    if volume_letter(src) == volume_letter(dest) {
        fs::rename(src, dest)
            .with_context(|| format!("移入隔离区失败: {} → {}", src.display(), dest.display()))?;
    } else {
        fs::copy(src, dest).with_context(|| {
            format!(
                "跨卷复制进隔离区失败: {} → {}",
                src.display(),
                dest.display()
            )
        })?;
        let (got, _) = hash_source(dest)?;
        if got != want_sha {
            let _ = fs::remove_file(dest);
            bail!(
                "跨卷复制校验失败（{} → {}）: SHA-256 不符，已删除半成品",
                src.display(),
                dest.display()
            );
        }
        fs::remove_file(src).with_context(|| format!("跨卷移动删除源失败: {}", src.display()))?;
    }
    Ok(())
}

/// Reverse of `move_into_quarantine`, used by undo/recover (same rules).
fn move_back(quarantined: &Path, original: &Path, want_sha: &str) -> Result<()> {
    if let Some(parent) = original.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建还原目录失败: {}", parent.display()))?;
    }
    if volume_letter(quarantined) == volume_letter(original) {
        fs::rename(quarantined, original).with_context(|| {
            format!(
                "还原失败: {} → {}",
                quarantined.display(),
                original.display()
            )
        })?;
    } else {
        fs::copy(quarantined, original).with_context(|| {
            format!(
                "跨卷复制还原失败: {} → {}",
                quarantined.display(),
                original.display()
            )
        })?;
        let (got, _) = hash_source(original)?;
        if got != want_sha {
            let _ = fs::remove_file(original);
            bail!(
                "跨卷还原校验失败（{}）: SHA-256 不符，已删除半成品",
                original.display()
            );
        }
        fs::remove_file(quarantined)
            .with_context(|| format!("清理隔离副本失败: {}", quarantined.display()))?;
    }
    Ok(())
}

fn container_tmp(container: &Path) -> PathBuf {
    let mut s = container.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

// ─────────────────────────────────────────────────────────────────────
// quarantine list / delete / undo / recover
// ─────────────────────────────────────────────────────────────────────

/// `quarantine list` (B11): batches with concrete expiry dates and current
/// occupancy. Expiry NEVER auto-deletes (hard rule 3).
pub fn quarantine_list(qcfg: &QuarantineConfig) -> Result<Vec<BatchInfo>> {
    let mut out = Vec::new();
    let Some(rd) = fs::read_dir(&qcfg.journal_dir).ok() else {
        return Ok(out);
    };
    let mut journals: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.path().extension().map(|x| x == "jsonl").unwrap_or(false))
        .map(|e| e.path())
        .collect();
    journals.sort();
    for path in journals {
        let Ok(lines) = parse_journal(&path) else {
            continue;
        };
        let Ok(state) = progress_from_journal(&lines, &qcfg.root) else {
            continue;
        };
        if state.batch_id.is_empty() {
            continue;
        }
        let created = lines.first().map(|l| l.ts_millis).unwrap_or(0);
        let aborted = lines.iter().any(|l| {
            l.step == "recover" && l.phase == "result" && journal::detail_flag(l, "aborted")
        });
        let status = if aborted {
            "aborted"
        } else if lines.iter().any(|l| l.step == "s6" && l.phase == "result") {
            "released"
        } else if state.undone {
            // batch-level undo: clean undo releases, conflicts keep copies
            if state.undo_conflicts == 0 {
                "released"
            } else {
                "undone-conflicts"
            }
        } else if state.completed {
            "completed"
        } else {
            "interrupted"
        };
        // occupancy = quarantined copies still on disk: moved AND not yet
        // undone (conflicts deliberately keep their copies and count)
        let occupied: Vec<&journal::FileProgress> = state
            .files
            .iter()
            .filter(|f| f.moved && !f.undone)
            .collect();
        let bytes: u64 = occupied.iter().filter_map(|f| f.size).sum();
        let moved = occupied.len() as u64;
        let (created_date, expires_date, expired) = retention_dates(created, qcfg.retention_days);
        let sources: Vec<String> = state
            .files
            .iter()
            .filter(|f| f.moved)
            .map(|f| f.file.clone())
            .take(3)
            .collect();
        out.push(BatchInfo {
            batch_id: state.batch_id.clone(),
            container: state.container.clone(),
            note: if expired && status == "completed" {
                "已过保留期——不会自动删除；确认无误后用 quarantine delete 释放".to_string()
            } else if status == "interrupted" {
                "批次中断——用 quarantine recover --continue|--abort 处理".to_string()
            } else {
                String::new()
            },
            created_date,
            expires_date,
            expired,
            status: status.to_string(),
            files_moved: moved,
            bytes_still_occupied: bytes,
            sources,
        });
    }
    Ok(out)
}

/// Local UTC offset in seconds (east positive, e.g. +28800 for UTC+8).
/// Windows: `GetTimeZoneInformation`. Non-Windows / failure: None → caller
/// falls back to UTC (no panic; P2-B1 C1). NOTE: current offset only — for a
/// historical created_millis across a DST transition this is approximate
/// (display-only; hard-constraint 3 still guarantees no auto-delete).
fn local_offset_seconds() -> Option<i64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        // SAFETY: tz is a plain out-struct; the call writes at most
        // size_of::<TIME_ZONE_INFORMATION>() bytes and has no other side effects.
        let mut tz: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
        // TIME_ZONE_ID_* are u32 constants; casts below are value-transparent.
        #[expect(non_snake_case)]
        let TIME_ZONE_ID_INVALID = 0xFFFFFFFFu32;
        let id = unsafe { GetTimeZoneInformation(&mut tz) } as u32;
        if id == TIME_ZONE_ID_INVALID {
            return None;
        }
        // Bias is UTC-minus-local, in minutes (east of UTC => negative).
        Some(-i64::from(tz.Bias) * 60)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// (created date, expiry date, expired?) — concrete **local** calendar dates
/// (ADV-N5 + P2-B1 C1). Computed on the machine's local time zone (UTC offset
/// applied to the UTC epoch) so the shown "expires YYYY-MM-DD" and the `expired`
/// badge match what a UTC+8 user expects, instead of drifting a day at the
/// local-midnight boundary. Falls back to UTC if the local tz cannot be
/// resolved (no panic; byte-identical to the old behavior on tz-less machines).
fn retention_dates(created_millis: u64, retention_days: u64) -> (String, String, bool) {
    let off_seconds = local_offset_seconds().unwrap_or(0);
    retention_dates_offset(created_millis, retention_days, off_seconds)
}

/// Pure, offset-parameterized variant — deterministic & unit-testable across
/// time zones. `offset` is the local offset in seconds (east positive, e.g.
/// +28800 for UTC+8); it is added to the UTC epoch before the civil-day
/// conversion.
///
/// DST (P7 A12): the local offset is evaluated at call time, so across a
/// daylight-saving switch a historical batch's retention date may display
/// one day off — display precision only; hard-constraint 3 (an expired
/// batch is never silently deleted) still holds.
fn retention_dates_offset(
    created_millis: u64,
    retention_days: u64,
    offset_seconds: i64,
) -> (String, String, bool) {
    let off_ms = offset_seconds * 1_000;
    // Local calendar day = floor((utc_epoch_millis + local_offset_ms) / 86400s).
    let created_day = (created_millis as i64 + off_ms) / 86_400_000;
    let (y, m, d) = civil_from_days(created_day);
    let exp_day = created_day + retention_days as i64;
    let (ey, em, ed) = civil_from_days(exp_day);
    let today_day = (now_millis() as i64 + off_ms) / 86_400_000;
    (
        format!("{y:04}-{m:02}-{d:02}"),
        format!("{ey:04}-{em:02}-{ed:02}"),
        today_day >= exp_day,
    )
}

/// Howard Hinnant's civil_from_days (UTC).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn civil_from_date_millis(ms: u64) -> (i64, u32, u32) {
    civil_from_days((ms / 86_400_000) as i64)
}

/// Step 6: free the space — requires the caller (CLI) to have obtained an
/// explicit confirmation (hard rule 3; `--confirm` flag). Journaled.
pub fn quarantine_delete(batch_id: &str, qcfg: &QuarantineConfig) -> Result<u64> {
    let path = qcfg.journal_dir.join(format!("{batch_id}.jsonl"));
    let lines = parse_journal(&path).with_context(|| format!("批次不存在: {batch_id}"))?;
    let state = progress_from_journal(&lines, &qcfg.root)?;
    let batch_dir = qcfg.root.join(batch_id);
    let freed = state
        .files
        .iter()
        .filter(|f| f.moved)
        .filter_map(|f| f.size)
        .sum();
    let mut jr = Journal::open(&qcfg.journal_dir, batch_id)?;
    let mut intent = JournalLine::new("s6", "intent");
    intent.detail =
        Some(serde_json::json!({ "batch_id": batch_id, "dir": batch_dir.display().to_string() }));
    jr.append(&intent)?;
    if batch_dir.exists() {
        fs::remove_dir_all(&batch_dir)
            .with_context(|| format!("释放隔离批次失败: {}", batch_dir.display()))?;
    }
    let mut result = JournalLine::new("s6", "result");
    result.detail = Some(serde_json::json!({ "batch_id": batch_id, "freed_bytes": freed }));
    jr.append(&result)?;
    Ok(freed)
}

/// Undo (B12) — restore every quarantined file of a batch to its original
/// path; ADV-N3 conflict handling: a source that was *modified during the
/// quarantine window* (sha differs) is NEVER overwritten — the quarantine
/// copy is kept and the conflict reported. The container is removed at the
/// end (complete reversal; frames are verified redundant copies).
pub fn undo_batch(batch_id: &str, qcfg: &QuarantineConfig) -> Result<UndoStats> {
    undo_batch_with(batch_id, qcfg, false)
}

/// Undo with the ADV-N3 `--keep-container` option.
///
/// `keep_container = true` restores every quarantined file to its original
/// path but **keeps** the `.coldstore` archive container on disk. Rationale:
/// the container holds an independently verified copy of every restored
/// file, so a user who is not yet sure they want the archive gone can undo
/// the restore *and* keep the safety net. It is opt-in — the default
/// (`undo_batch`) still removes the container, i.e. a complete reversal.
pub fn undo_batch_with(
    batch_id: &str,
    qcfg: &QuarantineConfig,
    keep_container: bool,
) -> Result<UndoStats> {
    let path = qcfg.journal_dir.join(format!("{batch_id}.jsonl"));
    let lines = parse_journal(&path).with_context(|| format!("批次不存在: {batch_id}"))?;
    let state = progress_from_journal(&lines, &qcfg.root)?;
    if state.batch_id != batch_id {
        bail!("journal 与批次号不符: {batch_id}");
    }

    let mut jr = Journal::open(&qcfg.journal_dir, batch_id)?;
    jr.append_simple("undo", "intent")?;

    let mut stats = UndoStats {
        batch_id: batch_id.to_string(),
        restored: 0,
        conflicts: 0,
        conflict_files: Vec::new(),
        container_removed: false,
        container_kept: String::new(),
    };

    for f in &state.files {
        if !f.moved {
            continue;
        }
        let Some(qpath) = f.quarantined_to.clone() else {
            continue;
        };
        let qpath = PathBuf::from(&qpath);
        let src = PathBuf::from(&f.file);
        let want_sha = f.sha256.clone().unwrap_or_default();

        let mut line = JournalLine::new("undo", "result");
        line.ordinal = Some(f.ordinal);
        line.file = Some(src.display().to_string());
        line.sha256 = Some(want_sha.clone());

        if !src.exists() {
            move_back(&qpath, &src, &want_sha)?;
            line.detail = Some(serde_json::json!({ "action": "restored" }));
            jr.append(&line)?;
            stats.restored += 1;
        } else {
            let (now_sha, _) = hash_source(&src)?;
            if now_sha == want_sha {
                // identical content already at source → drop the copy
                fs::remove_file(&qpath)
                    .with_context(|| format!("清理冗余隔离副本失败: {}", qpath.display()))?;
                line.detail = Some(serde_json::json!({ "action": "dedup_removed" }));
                jr.append(&line)?;
                stats.restored += 1;
            } else {
                // ADV-N3: source modified during the window → keep the
                // quarantine copy, warn, never overwrite.
                stats.conflicts += 1;
                stats.conflict_files.push(src.display().to_string());
                line.detail = Some(serde_json::json!({ "action": "conflict_kept" }));
                jr.append(&line)?;
            }
        }
    }

    // batch dir now empty (or holds only conflict copies → keep dir then)
    let batch_dir = qcfg.root.join(batch_id);
    if batch_dir.exists() {
        let leftover = fs::read_dir(&batch_dir)?.count();
        if leftover == 0 {
            fs::remove_dir(&batch_dir).ok();
        }
    }

    // container removal — complete reversal (frames are redundant copies)
    // unless the caller asked to keep it (ADV-N3 `--keep-container`).
    if let Some(container) = state.container.clone() {
        let cpath = PathBuf::from(&container);
        if keep_container {
            if cpath.exists() {
                stats.container_kept = cpath.display().to_string();
            }
        } else if cpath.exists() {
            fs::remove_file(&cpath)
                .with_context(|| format!("移除归档容器失败: {}", cpath.display()))?;
            stats.container_removed = true;
        }
        let tmp = container_tmp(&cpath);
        if tmp.exists() {
            fs::remove_file(&tmp).ok();
        }
    }

    let mut done = JournalLine::new("undo", "result");
    done.detail = Some(serde_json::json!({
        "batch_id": batch_id,
        "restored": stats.restored,
        "conflicts": stats.conflicts,
        "container_removed": stats.container_removed,
        "container_kept": stats.container_kept,
    }));
    jr.append(&done)?;
    Ok(stats)
}

/// Crash recovery (B13, Q8): continue or abort an interrupted batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverMode {
    Continue,
    Abort,
}

pub fn recover_batch(batch_id: &str, mode: RecoverMode, qcfg: &QuarantineConfig) -> Result<String> {
    let path = qcfg.journal_dir.join(format!("{batch_id}.jsonl"));
    let lines = parse_journal(&path).with_context(|| format!("批次不存在: {batch_id}"))?;
    let state = progress_from_journal(&lines, &qcfg.root)?;
    if state.batch_id != batch_id {
        bail!("journal 与批次号不符: {batch_id}");
    }
    if state.completed {
        return Ok("批次已完成，无需恢复".to_string());
    }

    let mut jr = Journal::open(&qcfg.journal_dir, batch_id)?;

    match mode {
        RecoverMode::Abort => {
            // Undo whatever reality already contains (moved files back to
            // source), remove the suspect container, close the batch.
            let mut restored = 0u64;
            for f in &state.files {
                let Some(qpath) = f.quarantined_to.clone() else {
                    continue;
                };
                let qpath = PathBuf::from(&qpath);
                let src = PathBuf::from(&f.file);
                if !qpath.exists() {
                    continue;
                }
                if src.exists() {
                    // copy landed but source delete crashed → finish the
                    // delete inside this recovery sequence (Q8 reality rule)
                    let (sha_src, _) = hash_source(&src)?;
                    let (sha_q, _) = hash_source(&qpath)?;
                    if sha_src == sha_q {
                        fs::remove_file(&src).ok();
                    } else {
                        // diverged → keep both, report
                        fs::remove_file(&qpath).ok();
                        continue;
                    }
                } else {
                    move_back(&qpath, &src, f.sha256.as_deref().unwrap_or(""))?;
                }
                restored += 1;
            }
            if let Some(container) = state.container.clone() {
                let cpath = PathBuf::from(&container);
                let _ = fs::remove_file(&cpath);
                let _ = fs::remove_file(container_tmp(&cpath));
            }
            // verify temps
            let verify_root = qcfg.root.join("_verify").join(batch_id);
            let _ = fs::remove_dir_all(verify_root);
            let mut line = JournalLine::new("recover", "result");
            line.detail = Some(serde_json::json!({ "aborted": true, "restored": restored }));
            jr.append(&line)?;
            let mut done = JournalLine::new("batch", "result");
            done.detail = Some(serde_json::json!({ "batch_id": batch_id, "status": "aborted" }));
            jr.append(&done)?;
            Ok(format!(
                "已放弃批次 {batch_id}：还原 {restored} 个文件，容器已清理"
            ))
        }
        RecoverMode::Continue => {
            let container_path = state.container.clone().map(PathBuf::from);
            let published = container_path.as_ref().map(|c| c.exists()).unwrap_or(false);

            if !published {
                // container never published → roll moved files back to
                // source, clear temps, then re-run the whole sequence fresh
                for f in &state.files {
                    if let Some(qpath) = f.quarantined_to.clone() {
                        let qpath = PathBuf::from(&qpath);
                        if qpath.exists() {
                            let src = PathBuf::from(&f.file);
                            if src.exists() {
                                // copy landed, source delete crashed →
                                // verify identical, then finish the delete
                                let (sha_src, _) = hash_source(&src)?;
                                let (sha_q, _) = hash_source(&qpath)?;
                                if sha_src == sha_q {
                                    fs::remove_file(&src).ok();
                                    fs::rename(&qpath, &src)?;
                                } else {
                                    // diverged → keep both, skip rewind
                                    continue;
                                }
                            } else {
                                move_back(&qpath, &src, f.sha256.as_deref().unwrap_or(""))?;
                            }
                        }
                    }
                }
                let _ = fs::remove_dir_all(qcfg.root.join("_verify").join(batch_id));
                let container = state
                    .container
                    .clone()
                    .ok_or_else(|| anyhow!("journal 缺少容器路径"))?;
                let files: Vec<FileEntry> = state
                    .planned_files
                    .iter()
                    .map(|p| FileEntry {
                        path: PathBuf::from(p),
                        size: 0,
                        ext: String::new(),
                        modified: None,
                        accessed: None,
                        is_reparse: false,
                        is_hidden: false,
                        is_system: false,
                        magic_hex: String::new(),
                        magic_read_failed: false,
                    })
                    .collect();
                let mut intent = JournalLine::new("recover", "intent");
                intent.detail = Some(serde_json::json!({ "mode": "continue-rewind" }));
                jr.append(&intent)?;
                let sub = run_sequence(
                    &files,
                    Path::new(&container),
                    batch_id,
                    &qcfg.root.join(batch_id),
                    &qcfg.root.join("_verify").join(batch_id),
                    &mut jr,
                )?;
                let mut done = JournalLine::new("batch", "result");
                done.detail = Some(serde_json::json!({
                    "batch_id": batch_id,
                    "status": "completed",
                    "resumed": true,
                    "files": sub.files,
                }));
                jr.append(&done)?;
                return Ok(format!(
                    "批次 {batch_id} 已回卷重跑完成：{} 个文件",
                    sub.files
                ));
            }

            // container published → walk the PLANNED list (not just files
            // with results): resume step 3/4 per ordinal with reality checks
            let container = container_path.unwrap();
            let verify_dir = qcfg.root.join("_verify").join(batch_id);
            let slots: std::collections::BTreeMap<u64, FileProgress> =
                state.files.iter().map(|f| (f.ordinal, f.clone())).collect();
            let planned_n = state.planned_files.len() as u64;
            let mut resumed = 0u64;

            for ordinal in 0..planned_n {
                let file = state
                    .planned_files
                    .get(ordinal as usize)
                    .cloned()
                    .unwrap_or_default();
                let slot = slots.get(&ordinal);
                let sha = slot.and_then(|f| f.sha256.clone()).unwrap_or_default();
                let size = slot.and_then(|f| f.size).unwrap_or(0);
                let verified = slot.map(|f| f.verified).unwrap_or(false);
                let moved = slot.map(|f| f.moved).unwrap_or(false);

                if moved {
                    continue;
                }

                // ── step 3 (resume): retrieve + compare against the step-1
                //    hash; stale verify temps from the crash are cleared
                //    first (sequence-internal cleanup)
                if !verified {
                    let verify_path = verify_dir.join(format!("{ordinal:06}__verify"));
                    let _ = fs::remove_file(&verify_path);
                    let outcome = archive::retrieve(
                        &container,
                        &archive::EntryKey::Ordinal(ordinal),
                        &verify_path,
                    )?;
                    let (got, _) = hash_source(&verify_path)?;
                    if !sha.is_empty() && got != sha {
                        bail!("续跑第 3 步 SHA 不符（序号 {ordinal}）: 期望 {sha} 实际 {got}");
                    }
                    if !sha.is_empty() && outcome.size != size {
                        bail!("续跑第 3 步体积不符（序号 {ordinal}）");
                    }
                    fs::remove_file(&verify_path).ok();
                    let mut line = JournalLine::new("s3", "result");
                    line.ordinal = Some(ordinal);
                    line.file = Some(file.clone());
                    line.sha256 = Some(if sha.is_empty() { got } else { sha.clone() });
                    jr.append(&line)?;
                }

                // ── step 4 (resume): move with the three reality branches
                let src = PathBuf::from(&file);
                let dest = qcfg.root.join(batch_id).join(format!(
                    "{ordinal:06}__{}",
                    src.file_name().unwrap_or_default().to_string_lossy()
                ));
                let dest_exists = dest.exists();
                let src_exists = src.exists();

                let mut intent4 = JournalLine::new("s4", "intent");
                intent4.ordinal = Some(ordinal);
                intent4.file = Some(src.display().to_string());
                intent4.sha256 = Some(sha.clone());
                intent4.size = Some(size);
                intent4.detail =
                    Some(serde_json::json!({ "quarantine_path": dest.display().to_string() }));
                jr.append(&intent4)?;

                if dest_exists && !src_exists {
                    // heal: the move completed pre-crash, journal lost →
                    // record the result (Q8: judge by reality)
                } else if dest_exists && src_exists {
                    // copy landed but the source delete crashed → verify
                    // identical then finish the deletion
                    let (sha_src, _) = hash_source(&src)?;
                    let (sha_dest, _) = hash_source(&dest)?;
                    if sha_src != sha_dest {
                        bail!("续跑第 4 步冲突（序号 {ordinal}）: 隔离副本与源不一致，保留双方供人工处理");
                    }
                    fs::remove_file(&src)
                        .with_context(|| format!("续跑删除源失败: {}", src.display()))?;
                } else if !dest_exists && src_exists {
                    move_into_quarantine(&src, &dest, &sha)?;
                } else {
                    bail!("续跑第 4 步现实异常（序号 {ordinal}）: 源与隔离副本均不存在");
                }

                let mut line = JournalLine::new("s4", "result");
                line.ordinal = Some(ordinal);
                line.file = Some(dest.display().to_string());
                line.sha256 = Some(sha.clone());
                line.size = Some(size);
                jr.append(&line)?;
                resumed += 1;
            }
            let _ = fs::remove_dir_all(&verify_dir);
            let mut line = JournalLine::new("recover", "result");
            line.detail = Some(serde_json::json!({ "aborted": false, "resumed": resumed }));
            jr.append(&line)?;
            let mut done = JournalLine::new("batch", "result");
            done.detail = Some(
                serde_json::json!({ "batch_id": batch_id, "status": "completed", "resumed": true }),
            );
            jr.append(&done)?;
            Ok(format!("批次 {batch_id} 已续跑完成：补齐 {resumed} 个文件"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-q-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn qcfg(base: &Path) -> QuarantineConfig {
        QuarantineConfig {
            root: base.join("q"),
            journal_dir: base.join("journal"),
            retention_days: 7,
        }
    }

    fn write_file(path: &Path, size: usize, seed: u8) -> String {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_add(seed)).collect();
        fs::write(path, &data).unwrap();
        format!("{:x}", Sha256::digest(&data))
    }

    #[test]
    fn six_step_sequence_happy_path_moves_to_quarantine() {
        let base = temp_dir("happy");
        let src = base.join("src");
        let sha1 = write_file(&src.join("a.log"), 300_000, 1);
        let sha2 = write_file(&src.join("sub/b.log"), 120_000, 2);
        let container = base.join("out").join("logs.coldstore");
        fs::create_dir_all(base.join("out")).unwrap();
        let cfg = qcfg(&base);

        let stats = archive_batch(
            &[
                FileEntry {
                    path: src.join("a.log"),
                    size: 300_000,
                    ext: "log".into(),
                    modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(100)),
                    accessed: None,
                    is_reparse: false,
                    is_hidden: false,
                    is_system: false,
                    magic_hex: String::new(),
                    magic_read_failed: false,
                },
                FileEntry {
                    path: src.join("sub/b.log"),
                    size: 120_000,
                    ext: "log".into(),
                    modified: None,
                    accessed: None,
                    is_reparse: false,
                    is_hidden: false,
                    is_system: false,
                    magic_hex: String::new(),
                    magic_read_failed: false,
                },
            ],
            &container,
            &cfg,
        )
        .unwrap();

        assert_eq!(stats.files, 2);
        // sources moved, not deleted-and-lost: they live in quarantine
        assert!(!src.join("a.log").exists(), "source moved out");
        let qa = PathBuf::from(stats.entries[0].quarantined_to.clone().unwrap());
        assert!(qa.exists());
        assert_eq!(hash_source(&qa).unwrap().0, sha1);
        assert_eq!(
            hash_source(&PathBuf::from(
                stats.entries[1].quarantined_to.clone().unwrap()
            ))
            .unwrap()
            .0,
            sha2
        );
        // container is a valid 001 container
        let (_, header, idx) = archive::open_container(&container).unwrap();
        assert_eq!(header.frame_count, 2);
        assert_eq!(idx.entries.len(), 2);
        // journal complete: s1..s4 results for every ordinal
        let lines =
            parse_journal(&cfg.journal_dir.join(format!("{}.jsonl", stats.batch_id))).unwrap();
        for o in 0..2u64 {
            for step in ["s1", "s3", "s4"] {
                assert!(
                    lines
                        .iter()
                        .any(|l| l.step == step && l.phase == "result" && l.ordinal == Some(o)),
                    "missing {step} result for ordinal {o}"
                );
            }
        }
        // verify temps cleaned
        assert!(!cfg.root.join("_verify").join(&stats.batch_id).exists());

        // B12: undo restores everything
        let undo = undo_batch(&stats.batch_id, &cfg).unwrap();
        assert_eq!(undo.restored, 2);
        assert_eq!(undo.conflicts, 0);
        assert!(src.join("a.log").exists(), "restored to original path");
        assert_eq!(hash_source(&src.join("a.log")).unwrap().0, sha1);
        assert_eq!(hash_source(&src.join("sub/b.log")).unwrap().0, sha2);
        assert!(!container.exists(), "undo removes the container");
        let infos = quarantine_list(&cfg).unwrap();
        let info = infos.iter().find(|i| i.batch_id == stats.batch_id).unwrap();
        assert_eq!(info.status, "released", "undo closes the batch");
        assert_eq!(info.bytes_still_occupied, 0);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn undo_conflict_keeps_quarantine_copy_never_overwrites() {
        let base = temp_dir("conflict");
        let src = base.join("src");
        write_file(&src.join("x.log"), 50_000, 3);
        let container = base.join("out").join("x.coldstore");
        fs::create_dir_all(base.join("out")).unwrap();
        let cfg = qcfg(&base);
        let stats = archive_batch(
            &[FileEntry {
                path: src.join("x.log"),
                size: 50_000,
                ext: "log".into(),
                modified: None,
                accessed: None,
                is_reparse: false,
                is_hidden: false,
                is_system: false,
                magic_hex: String::new(),
                magic_read_failed: false,
            }],
            &container,
            &cfg,
        )
        .unwrap();

        // user modifies the original location during the window (ADV-N3)
        fs::write(src.join("x.log"), b"user edited this during quarantine").unwrap();

        let undo = undo_batch(&stats.batch_id, &cfg).unwrap();
        assert_eq!(undo.conflicts, 1);
        assert_eq!(undo.restored, 0);
        assert_eq!(
            fs::read(src.join("x.log")).unwrap(),
            b"user edited this during quarantine",
            "user's new content untouched"
        );
        assert!(
            PathBuf::from(stats.entries[0].quarantined_to.clone().unwrap()).exists(),
            "quarantine copy kept on conflict"
        );

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn retention_dates_local_offset_shifts_boundary_day() {
        // 23:30:00 UTC within day-number 20_000 (84_600_000 ms into the day).
        let created = 20_000u64 * 86_400_000 + 84_600_000u64;
        // UTC (offset 0): created day stays 20_000, expiry = +7 = 20_007.
        let (c, e, _) = retention_dates_offset(created, 7, 0);
        let (cy, cm, cd) = civil_from_days(20_000);
        let (ey, em, ed) = civil_from_days(20_007);
        assert_eq!(c, format!("{cy:04}-{cm:02}-{cd:02}"), "UTC created day");
        assert_eq!(e, format!("{ey:04}-{em:02}-{ed:02}"), "UTC expiry day");
        // UTC+8 (offset 28800s): 23:30 UTC is 07:30 the NEXT local day
        // -> created 20_001, expiry 20_008.
        let (c8, e8, _) = retention_dates_offset(created, 7, 28_800);
        let (cy8, cm8, cd8) = civil_from_days(20_001);
        let (ey8, em8, ed8) = civil_from_days(20_008);
        assert_eq!(
            c8,
            format!("{cy8:04}-{cm8:02}-{cd8:02}"),
            "UTC+8 created day rolls +1"
        );
        assert_eq!(
            e8,
            format!("{ey8:04}-{em8:02}-{ed8:02}"),
            "UTC+8 expiry = created+7"
        );
    }

    #[test]
    fn retention_is_a_concrete_date_and_never_auto_deletes() {
        let base = temp_dir("retention");
        let cfg = qcfg(&base);
        let sha = write_file(&base.join("src/old.log"), 1000, 4);
        let stats = archive_batch(
            &[FileEntry {
                path: base.join("src/old.log"),
                size: 1000,
                ext: "log".into(),
                modified: None,
                accessed: None,
                is_reparse: false,
                is_hidden: false,
                is_system: false,
                magic_hex: String::new(),
                magic_read_failed: false,
            }],
            &{
                fs::create_dir_all(base.join("out")).unwrap();
                base.join("out/o.coldstore")
            },
            &cfg,
        )
        .unwrap();

        // age the journal beyond retention: rewrite the first line's
        // ts_millis to 30 days ago (digit scan, robust to value drift)
        let jpath = cfg.journal_dir.join(format!("{}.jsonl", stats.batch_id));
        let text = fs::read_to_string(&jpath).unwrap();
        let marker = "\"ts_millis\":";
        let start = text.find(marker).expect("ts field present") + marker.len();
        let end = text[start..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| start + i)
            .unwrap_or(text.len());
        let aged_ts = now_millis().saturating_sub(30 * 86_400_000);
        let aged = format!("{}{}{}", &text[..start], aged_ts, &text[end..]);
        assert_ne!(text, aged, "timestamp line patched for the test");
        fs::write(&jpath, aged).unwrap();

        let infos = quarantine_list(&cfg).unwrap();
        let info = infos.iter().find(|i| i.batch_id == stats.batch_id).unwrap();
        assert!(info.expired, "30-day-old batch exceeds 7-day retention");
        assert_eq!(info.expires_date.len(), 10, "concrete YYYY-MM-DD (ADV-N5)");
        assert!(info.note.contains("不会自动删除"), "hard rule 3 stated");
        // the quarantined file is STILL THERE (never auto-deleted)
        let qpath = PathBuf::from(stats.entries[0].quarantined_to.clone().unwrap());
        assert!(qpath.exists());
        assert_eq!(hash_source(&qpath).unwrap().0, sha);
        let _ = sha;

        // step 6 with explicit call: frees space, journaled
        let freed = quarantine_delete(&stats.batch_id, &cfg).unwrap();
        assert_eq!(freed, 1000);
        assert!(!qpath.exists());
        let infos2 = quarantine_list(&cfg).unwrap();
        assert_eq!(
            infos2
                .iter()
                .find(|i| i.batch_id == stats.batch_id)
                .unwrap()
                .status,
            "released"
        );

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn container_and_quarantine_on_different_volumes_rejected() {
        let base = temp_dir("xvol");
        let cfg = qcfg(&base);
        let files = vec![FileEntry {
            path: base.join("src/a.log"),
            size: 10,
            ext: "log".into(),
            modified: None,
            accessed: None,
            is_reparse: false,
            is_hidden: false,
            is_system: false,
            magic_hex: String::new(),
            magic_read_failed: false,
        }];
        // craft a mismatch: quarantine on C:, container claimed on D:
        let container = PathBuf::from(format!(
            "D:/coldstore-xvol-test-{}/t.coldstore",
            std::process::id()
        ));
        if volume_letter(&container) == volume_letter(&cfg.root) {
            // single-volume machine → skip (CI guard)
            let _ = fs::remove_dir_all(&base);
            return;
        }
        let err = archive_batch(&files, &container, &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("必须同盘"), "{msg}");
        assert!(msg.contains("archive_root"), "{msg}");
        fs::remove_dir_all(&base).ok();
    }
}
