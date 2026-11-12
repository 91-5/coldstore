//! Batch journal (card D4, hard rule 13; adjudication Q8/ADV-N2).
//!
//! One JSONL file per batch at `%USERPROFILE%\.coldstore\journal\<id>.jsonl`.
//! Every mutating step is written **twice**: an `intent` line before the
//! action, a `result` (or `error`) line after it. Replay judges by *result*
//! lines — an intent without a result marks a crashed step and recovery
//! must verify reality before healing (Q8: "journal 写意图再执行，执行后写
//! 结果；重放按结果判定").
//!
//! Journals are **never deleted** (hard rule 13) — they are the audit
//! trail. They live outside the repo (ADV-N8) and `.gitignore` lists the
//! locations explicitly so they can never be committed.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Millis since UNIX epoch (u64 — no overflow until year ~586 million).
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One JSONL line. `phase`: "batch" | "intent" | "result" | "error".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalLine {
    pub step: String,
    pub phase: String,
    pub ts_millis: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JournalLine {
    pub fn new(step: &str, phase: &str) -> Self {
        JournalLine {
            step: step.to_string(),
            phase: phase.to_string(),
            ts_millis: now_millis(),
            ordinal: None,
            file: None,
            sha256: None,
            size: None,
            detail: None,
            error: None,
        }
    }
}

/// Append-only JSONL journal with per-line flush+sync (crash durability).
pub struct Journal {
    file: fs::File,
    pub path: PathBuf,
}

impl Journal {
    /// Create (or append to) the journal for `batch_id` under `journal_dir`.
    pub fn open(journal_dir: &Path, batch_id: &str) -> Result<Journal> {
        fs::create_dir_all(journal_dir)
            .with_context(|| format!("创建 journal 目录失败: {}", journal_dir.display()))?;
        let path = journal_dir.join(format!("{batch_id}.jsonl"));
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("打开 journal 失败: {}", path.display()))?;
        Ok(Journal { file, path })
    }

    /// Append one line, flushed and synced — durable across `abort()`.
    pub fn append(&mut self, line: &JournalLine) -> Result<()> {
        let mut text = serde_json::to_string(line)?;
        text.push('\n');
        self.file.write_all(text.as_bytes())?;
        self.file.flush()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub fn append_simple(&mut self, step: &str, phase: &str) -> Result<()> {
        self.append(&JournalLine::new(step, phase))
    }
}

/// Parse a journal file, tolerating a torn tail line (crash mid-write).
pub fn parse_journal(path: &Path) -> Result<Vec<JournalLine>> {
    let f =
        fs::File::open(path).with_context(|| format!("读取 journal 失败: {}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let Ok(text) = line else { break };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        match serde_json::from_str::<JournalLine>(text) {
            Ok(l) => out.push(l),
            Err(err) => {
                // Only the LAST line may be torn (crash mid-append); a
                // malformed middle line is real corruption → fail closed.
                let is_last = BufReader::new(fs::File::open(path)?)
                    .lines()
                    .skip(i + 1)
                    .all(|l| l.map(|s| s.trim().is_empty()).unwrap_or(true));
                if !is_last {
                    anyhow::bail!("journal 第 {} 行损坏（非末尾）: {err}", i + 1);
                }
            }
        }
    }
    Ok(out)
}

/// Per-file progress inside a batch, derived from *result* lines only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProgress {
    pub ordinal: u64,
    pub file: String,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub quarantined_to: Option<String>,
    /// Reality-grounded state (see `progress_from_journal`).
    pub moved: bool,
    pub verified: bool,
    /// Undo processed this entry (quarantine copy gone).
    pub undone: bool,
    /// ADV-N3: source diverged during the window — copy deliberately kept.
    pub conflict: bool,
}

/// The replay state of one batch (Q8: judge by results, verify reality).
#[derive(Debug)]
pub struct BatchState {
    pub batch_id: String,
    pub container: Option<String>,
    pub planned_files: Vec<String>,
    pub files: Vec<FileProgress>,
    /// true when the batch-intent exists but no batch result line does.
    pub interrupted: bool,
    /// true when a batch "result" line closes the batch.
    pub completed: bool,
    /// true when the batch was closed by an abort/recover action.
    pub aborted: bool,
    /// Batch-level undo result present (no ordinal).
    pub undone: bool,
    pub undo_conflicts: u64,
}

pub fn detail_flag(line: &JournalLine, key: &str) -> bool {
    line.detail
        .as_ref()
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Derive the batch state from journal lines, cross-checking s4 (move)
/// intent-without-result entries against the real filesystem:
/// - quarantine copy exists + source gone → the move completed (heal);
/// - both exist → the copy landed but the source delete crashed (healing
///   deletes the source inside the recovery sequence);
/// - only source → move never happened.
pub fn progress_from_journal(lines: &[JournalLine], quarantine_root: &Path) -> Result<BatchState> {
    let mut state = BatchState {
        batch_id: String::new(),
        container: None,
        planned_files: Vec::new(),
        files: Vec::new(),
        interrupted: false,
        completed: false,
        aborted: false,
        undone: false,
        undo_conflicts: 0,
    };

    let mut order: Vec<u64> = Vec::new();
    let mut map: std::collections::BTreeMap<u64, FileProgress> = std::collections::BTreeMap::new();

    for line in lines {
        match (line.step.as_str(), line.phase.as_str()) {
            ("batch", "intent") => {
                state.batch_id = line
                    .detail
                    .as_ref()
                    .and_then(|d| d.get("batch_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                state.container = line
                    .detail
                    .as_ref()
                    .and_then(|d| d.get("container"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                state.planned_files = line
                    .detail
                    .as_ref()
                    .and_then(|d| d.get("files"))
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            ("batch", "result") => state.completed = true,
            ("batch", "error") => state.aborted = true,
            ("recover", "result") => {
                if detail_flag(line, "aborted") {
                    state.aborted = true;
                }
            }
            ("undo", "result") if line.ordinal.is_none() => {
                state.undone = true;
                state.undo_conflicts = line
                    .detail
                    .as_ref()
                    .and_then(|d| d.get("conflicts"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
            }
            ("undo", "result") => {
                if let Some(o) = line.ordinal {
                    let slot = map.entry(o).or_insert_with(|| FileProgress {
                        ordinal: o,
                        file: line.file.clone().unwrap_or_default(),
                        sha256: line.sha256.clone(),
                        size: line.size,
                        quarantined_to: None,
                        moved: false,
                        verified: false,
                        undone: false,
                        conflict: false,
                    });
                    let action = line
                        .detail
                        .as_ref()
                        .and_then(|d| d.get("action"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    slot.undone = action == "restored" || action == "dedup_removed";
                    slot.conflict = action == "conflict_kept";
                }
            }
            ("s1", "result") => {
                // step-1 results carry every planned file's sha/size — the
                // recovery's source of truth for the remaining work
                if let Some(o) = line.ordinal {
                    let slot = map.entry(o).or_insert_with(|| FileProgress {
                        ordinal: o,
                        file: line.file.clone().unwrap_or_default(),
                        sha256: line.sha256.clone(),
                        size: line.size,
                        quarantined_to: None,
                        moved: false,
                        verified: false,
                        undone: false,
                        conflict: false,
                    });
                    if slot.sha256.is_none() {
                        slot.sha256 = line.sha256.clone();
                    }
                    if slot.size.is_none() {
                        slot.size = line.size;
                    }
                    if slot.file.is_empty() {
                        slot.file = line.file.clone().unwrap_or_default();
                    }
                    if !order.contains(&o) {
                        order.push(o);
                    }
                }
            }
            ("s2", "result") => {}
            ("s3", "result") => {
                if let Some(o) = line.ordinal {
                    let slot = map.entry(o).or_insert_with(|| FileProgress {
                        ordinal: o,
                        file: line.file.clone().unwrap_or_default(),
                        sha256: line.sha256.clone(),
                        size: line.size,
                        quarantined_to: None,
                        moved: false,
                        verified: false,
                        undone: false,
                        conflict: false,
                    });
                    slot.verified = true;
                    if !order.contains(&o) {
                        order.push(o);
                    }
                }
            }
            ("s4", "result") => {
                if let Some(o) = line.ordinal {
                    let slot = map.entry(o).or_insert_with(|| FileProgress {
                        ordinal: o,
                        file: line.file.clone().unwrap_or_default(),
                        sha256: line.sha256.clone(),
                        size: line.size,
                        quarantined_to: None,
                        moved: false,
                        verified: false,
                        undone: false,
                        conflict: false,
                    });
                    slot.moved = true;
                    slot.quarantined_to = line.file.clone();
                    // the slot may have been created by the s3 result (no
                    // size); the s4 result carries it — fill if absent
                    if slot.size.is_none() {
                        slot.size = line.size;
                    }
                    if slot.sha256.is_none() {
                        slot.sha256 = line.sha256.clone();
                    }
                    if !order.contains(&o) {
                        order.push(o);
                    }
                }
            }
            _ => {}
        }
    }

    // s4 intent without result → reality check (Q8).
    let mut by_ordinal: std::collections::BTreeMap<u64, Vec<&JournalLine>> =
        std::collections::BTreeMap::new();
    for line in lines {
        if line.step == "s4" && (line.phase == "intent" || line.phase == "result") {
            if let Some(o) = line.ordinal {
                by_ordinal.entry(o).or_default().push(line);
            }
        }
    }
    for (o, mut ls) in by_ordinal {
        ls.sort_by_key(|l| l.ts_millis);
        let has_result = ls.iter().any(|l| l.phase == "result");
        if has_result {
            continue;
        }
        let intent = ls.last().unwrap();
        if let (Some(dest), Some(src)) = (
            intent
                .detail
                .as_ref()
                .and_then(|d| d.get("quarantine_path"))
                .and_then(|v| v.as_str()),
            intent.file.as_deref(),
        ) {
            let dest_exists = Path::new(dest).exists();
            let src_exists = Path::new(src).exists();
            let slot = map.entry(o).or_insert_with(|| FileProgress {
                ordinal: o,
                file: src.to_string(),
                sha256: intent.sha256.clone(),
                size: intent.size,
                quarantined_to: None,
                moved: false,
                verified: false,
                undone: false,
                conflict: false,
            });
            if dest_exists && !src_exists {
                // move completed, journal lost → heal by result
                slot.moved = true;
                slot.quarantined_to = Some(dest.to_string());
            } else if dest_exists && src_exists {
                // copy landed, source delete crashed → healing must finish
                slot.moved = false;
                slot.quarantined_to = Some(dest.to_string());
                slot.verified = true; // copy already verified before intent
            }
            if !order.contains(&o) {
                order.push(o);
            }
        }
    }

    state.files = order.iter().filter_map(|o| map.get(o).cloned()).collect();
    state.interrupted = !state.batch_id.is_empty() && !state.completed && !state.aborted;
    let _ = quarantine_root;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-journal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn append_parse_roundtrip_and_torn_tail_tolerated() {
        let dir = temp_dir("roundtrip");
        let mut j = Journal::open(&dir, "b1").unwrap();
        let mut l = JournalLine::new("s1", "intent");
        l.ordinal = Some(0);
        l.file = Some("a.bin".into());
        j.append(&l).unwrap();
        j.append_simple("s1", "result").unwrap();

        let lines = parse_journal(&dir.join("b1.jsonl")).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].file.as_deref(), Some("a.bin"));

        // torn tail: half-written line must be tolerated
        let mut text = fs::read_to_string(dir.join("b1.jsonl")).unwrap();
        text.push_str("{\"step\":\"s2\",\"phase\":\"inten");
        fs::write(dir.join("b1.jsonl"), text).unwrap();
        let lines = parse_journal(&dir.join("b1.jsonl")).unwrap();
        assert_eq!(lines.len(), 2, "torn tail skipped");

        // corruption in the MIDDLE fails closed
        let mut text = fs::read_to_string(dir.join("b1.jsonl")).unwrap();
        text = text.replace("{\"step\":\"s1\",\"phase\":\"intent\"", "GARBAGE{{");
        fs::write(dir.join("b1.jsonl"), text).unwrap();
        assert!(parse_journal(&dir.join("b1.jsonl")).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_derivation_interrupted_vs_completed() {
        let dir = temp_dir("state");
        let mut j = Journal::open(&dir, "b2").unwrap();
        let mut batch = JournalLine::new("batch", "intent");
        batch.detail = Some(serde_json::json!({
            "batch_id": "b2",
            "container": "C:/x/arch.coldstore",
            "files": ["a.bin", "b.bin"],
        }));
        j.append(&batch).unwrap();
        let mut s3 = JournalLine::new("s3", "result");
        s3.ordinal = Some(0);
        s3.file = Some("a.bin".into());
        j.append(&s3).unwrap();

        let st =
            progress_from_journal(&parse_journal(&dir.join("b2.jsonl")).unwrap(), &dir).unwrap();
        assert!(st.interrupted, "no batch result → interrupted");
        assert_eq!(st.planned_files, vec!["a.bin", "b.bin"]);
        assert_eq!(st.files.len(), 1);
        assert!(st.files[0].verified);

        j.append_simple("batch", "result").unwrap();
        let st2 =
            progress_from_journal(&parse_journal(&dir.join("b2.jsonl")).unwrap(), &dir).unwrap();
        assert!(st2.completed && !st2.interrupted);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn s4_intent_without_result_is_resolved_by_reality() {
        let dir = temp_dir("reality");
        let root = dir.join("q");
        fs::create_dir_all(&root).unwrap();
        let mut j = Journal::open(&dir, "b3").unwrap();
        let mut batch = JournalLine::new("batch", "intent");
        batch.detail = Some(serde_json::json!({ "batch_id": "b3", "files": [] }));
        j.append(&batch).unwrap();

        // case 1: dest exists, source gone → move completed (heal)
        let src1 = dir.join("a.bin");
        let dest1 = root.join("000000__a.bin");
        fs::write(&dest1, b"x").unwrap();
        let mut s4 = JournalLine::new("s4", "intent");
        s4.ordinal = Some(0);
        s4.file = Some(src1.display().to_string());
        s4.detail = Some(serde_json::json!({ "quarantine_path": dest1.display().to_string() }));
        j.append(&s4).unwrap();

        // case 2: dest exists, source STILL there → copy done, delete crashed
        let src2 = dir.join("b.bin");
        fs::write(&src2, b"y").unwrap();
        let dest2 = root.join("000001__b.bin");
        fs::write(&dest2, b"y").unwrap();
        let mut s4b = JournalLine::new("s4", "intent");
        s4b.ordinal = Some(1);
        s4b.file = Some(src2.display().to_string());
        s4b.detail = Some(serde_json::json!({ "quarantine_path": dest2.display().to_string() }));
        j.append(&s4b).unwrap();

        let st =
            progress_from_journal(&parse_journal(&dir.join("b3.jsonl")).unwrap(), &root).unwrap();
        assert_eq!(st.files.len(), 2);
        assert!(st.files[0].moved, "case 1 healed as moved");
        assert!(
            !st.files[1].moved && st.files[1].verified,
            "case 2 needs source delete"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
