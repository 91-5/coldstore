//! `coldstore mark-cold / mark-hot / mark-clear` — persistent manual
//! temperature overrides (card D6, B18). Stored at
//! `%APPDATA%\coldstore\marks.json`, effective across restarts.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use coldstore_core::coldness::{Mark, MarkStore};
use coldstore_core::predict::format_bytes;
use coldstore_core::rules::toml::config_dir;

pub struct MarkArgs {
    pub path: PathBuf,
}

pub fn mark_cold(args: MarkArgs) -> Result<()> {
    set(args.path, Some(Mark::Cold), "cold")
}

pub fn mark_hot(args: MarkArgs) -> Result<()> {
    set(args.path, Some(Mark::Hot), "hot")
}

pub fn mark_clear(args: MarkArgs) -> Result<()> {
    set(args.path, None, "（清除）")
}

fn set(path: PathBuf, mark: Option<Mark>, label: &str) -> Result<()> {
    let abs =
        std::path::absolute(&path).with_context(|| format!("解析路径失败: {}", path.display()))?;
    if !abs.exists() {
        bail!("标记目标不存在: {}", abs.display());
    }
    let base = config_dir();
    let mut store = MarkStore::load(&base)?;
    store.set(&abs, mark);
    store.save(&base)?;
    println!(
        "已标记 {} → {}（marks.json 现有 {} 条标记）",
        abs.display(),
        label,
        store.len()
    );
    Ok(())
}

/// Quarantine usage note shown by `plan` (hard rule 4: never pretend the
/// space is freed). Quarantine lands with P2; until then the note is
/// informational.
pub fn quarantine_note(quarantine_root: &Path) -> String {
    if !quarantine_root.exists() {
        return "隔离区尚未建立（首次归档时创建）".to_string();
    }
    let mut files = 0u64;
    let mut bytes = 0u64;
    let mut stack = vec![quarantine_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if let Ok(meta) = entry.metadata() {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    format!(
        "隔离区仍占用 {}（{files} 个文件）——归档不等于释放，空间以 quarantine delete 为准",
        format_bytes(bytes)
    )
}
