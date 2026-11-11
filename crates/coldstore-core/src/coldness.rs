//! Cold/hot determination (card D5) — mtime primary, rebuildable path
//! patterns, manual marks. **atime never participates**: this machine's
//! `DisableLastAccess = 2` means Windows may not update it at all.
//!
//! Labels (each with a reason — explainability is a core sell):
//! - `COLD` — untouched for `cold_after_days` (default 30);
//! - `WARM` — modified within the window;
//! - `REBUILDABLE` — lives under a known rebuildable directory (`target/`,
//!   `node_modules/`, …). Deleted content can be regenerated, but slowly —
//!   the product only *marks and reports*, never auto-deletes (hard rule 9);
//! - `UNKNOWN` — no usable mtime.
//!
//! Precedence: manual mark > REBUILDABLE > mtime age.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::rules::toml::{marks_path, ColdnessConfig};
use crate::scan::FileEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Temperature {
    Cold,
    Warm,
    Rebuildable,
    Unknown,
}

impl Temperature {
    pub fn as_display(self) -> &'static str {
        match self {
            Temperature::Cold => "COLD",
            Temperature::Warm => "WARM",
            Temperature::Rebuildable => "REBUILDABLE",
            Temperature::Unknown => "UNKNOWN",
        }
    }
}

/// Manual mark, persisted across restarts (card B18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mark {
    Cold,
    Hot,
}

/// Path → mark store, sorted keys for byte-deterministic JSON (B19 spirit).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MarkStore {
    #[serde(default)]
    marks: BTreeMap<String, Mark>,
}

impl MarkStore {
    pub fn load(base: &Path) -> Result<MarkStore> {
        let path = marks_path(base);
        if !path.exists() {
            return Ok(MarkStore::default());
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("读取标记失败: {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("标记 JSON 损坏: {}", path.display()))
    }

    pub fn save(&self, base: &Path) -> Result<()> {
        fs::create_dir_all(base)?;
        let path = marks_path(base);
        let text = serde_json::to_string_pretty(self)?;
        // atomic: tmp + rename
        let tmp = {
            let mut s = path.as_os_str().to_owned();
            s.push(".tmp");
            PathBuf::from(s)
        };
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &path).with_context(|| format!("发布标记失败: {}", path.display()))?;
        Ok(())
    }

    /// Set (or clear) a mark on an absolute path; NTFS case-insensitive key.
    pub fn set(&mut self, path: &Path, mark: Option<Mark>) {
        let key = normalize_key(path);
        match mark {
            Some(m) => {
                self.marks.insert(key, m);
            }
            None => {
                self.marks.remove(&key);
            }
        }
    }

    pub fn get(&self, path: &Path) -> Option<Mark> {
        self.marks.get(&normalize_key(path)).copied()
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }
}

/// NTFS is case-insensitive: keys lowercased, `/` separators.
fn normalize_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

/// One classification result.
#[derive(Debug, Clone, Serialize)]
pub struct Classified {
    pub temperature: Temperature,
    pub reason: String,
}

/// Classify one file. `now` is injected for deterministic tests; call sites
/// pass `SystemTime::now()`.
pub fn classify(
    entry: &FileEntry,
    marks: &MarkStore,
    cfg: &ColdnessConfig,
    now: SystemTime,
) -> Classified {
    // 1. manual mark overrides everything (B18)
    match marks.get(&entry.path) {
        Some(Mark::Cold) => {
            return Classified {
                temperature: Temperature::Cold,
                reason: "手动标记为 cold".to_string(),
            };
        }
        Some(Mark::Hot) => {
            return Classified {
                temperature: Temperature::Warm,
                reason: "手动标记为 hot".to_string(),
            };
        }
        None => {}
    }

    // 2. rebuildable directory component
    if let Some(component) = rebuildable_component(&entry.path, cfg) {
        return Classified {
            temperature: Temperature::Rebuildable,
            reason: format!(
                "位于可重建目录（{component}/）——删了能重建但重建慢；只标记与提示，绝不自动删"
            ),
        };
    }

    // 3. mtime age (primary signal; atime deliberately absent)
    let Some(modified) = entry.modified else {
        return Classified {
            temperature: Temperature::Unknown,
            reason: "无有效 mtime".to_string(),
        };
    };
    let age_days = match now.duration_since(modified) {
        Ok(d) => d.as_secs() / 86_400,
        Err(_) => 0, // future mtime (clock skew) → treat as fresh
    };
    if age_days >= cfg.cold_after_days {
        Classified {
            temperature: Temperature::Cold,
            reason: format!(
                "超过 {age_days} 天未修改（mtime 主信号，阈值 {} 天）",
                cfg.cold_after_days
            ),
        }
    } else {
        Classified {
            temperature: Temperature::Warm,
            reason: format!("{age_days} 天内修改过（mtime 主信号）"),
        }
    }
}

fn rebuildable_component(path: &Path, cfg: &ColdnessConfig) -> Option<String> {
    for comp in path.components() {
        let name = comp.as_os_str().to_string_lossy().to_lowercase();
        if cfg
            .rebuildable_dirs
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&name))
        {
            return Some(name);
        }
    }
    None
}

/// Aggregate distribution over a scan (deterministic: sorted by label).
#[derive(Debug, Serialize)]
pub struct TemperatureRollup {
    pub temperature: Temperature,
    pub files: u64,
    pub bytes: u64,
    /// One representative reason (the most common would need counting;
    /// first-seen reason per label in scan order is deterministic).
    pub reason_sample: String,
}

pub fn rollup(
    scan: &crate::scan::ScanResult,
    marks: &MarkStore,
    cfg: &ColdnessConfig,
    now: SystemTime,
) -> Vec<TemperatureRollup> {
    // BTreeMap keyed by label rank → deterministic COLD/WARM/…/UNKNOWN order.
    let mut map: BTreeMap<u8, (u64, u64, String)> = BTreeMap::new();
    for f in &scan.files {
        let c = classify(f, marks, cfg, now);
        let key = rank(c.temperature);
        let slot = map.entry(key).or_insert_with(|| (0, 0, c.reason.clone()));
        slot.0 += 1;
        slot.1 += f.size;
    }
    map.into_iter()
        .map(|(k, (files, bytes, reason_sample))| TemperatureRollup {
            temperature: unrank(k),
            files,
            bytes,
            reason_sample,
        })
        .collect()
}

fn rank(t: Temperature) -> u8 {
    match t {
        Temperature::Cold => 0,
        Temperature::Warm => 1,
        Temperature::Rebuildable => 2,
        Temperature::Unknown => 3,
    }
}

fn unrank(k: u8) -> Temperature {
    match k {
        0 => Temperature::Cold,
        1 => Temperature::Warm,
        2 => Temperature::Rebuildable,
        _ => Temperature::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::toml::ColdnessConfig;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    fn entry(path: &str, age_days: Option<u64>) -> FileEntry {
        let modified = age_days.map(|d| {
            UNIX_EPOCH
                + Duration::from_secs(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .saturating_sub(d * 86_400),
                )
        });
        FileEntry {
            path: PathBuf::from(path),
            size: 100,
            ext: "bin".into(),
            modified,
            accessed: None,
            is_reparse: false,
            is_hidden: false,
            is_system: false,
            magic_hex: String::new(),
            magic_read_failed: false,
        }
    }

    fn cfg(days: u64) -> ColdnessConfig {
        ColdnessConfig {
            cold_after_days: days,
            ..Default::default()
        }
    }

    #[test]
    fn mtime_is_the_primary_signal() {
        let marks = MarkStore::default();
        let now = SystemTime::now();
        let cold = classify(&entry(r"D:\x\old.bin", Some(45)), &marks, &cfg(30), now);
        assert_eq!(cold.temperature, Temperature::Cold);
        let warm = classify(&entry(r"D:\x\new.bin", Some(2)), &marks, &cfg(30), now);
        assert_eq!(warm.temperature, Temperature::Warm);
        let unknown = classify(&entry(r"D:\x\none.bin", None), &marks, &cfg(30), now);
        assert_eq!(unknown.temperature, Temperature::Unknown);
    }

    #[test]
    fn rebuildable_overrides_mtime_and_never_auto_deletes() {
        let marks = MarkStore::default();
        let now = SystemTime::now();
        // old file inside target/ → REBUILDABLE (not COLD)
        let c = classify(
            &entry(r"D:\proj\target\debug\old.rlib", Some(400)),
            &marks,
            &cfg(30),
            now,
        );
        assert_eq!(c.temperature, Temperature::Rebuildable);
        assert!(c.reason.contains("绝不自动删"), "reason: {}", c.reason);
    }

    #[test]
    fn manual_marks_override_everything_and_persist() {
        let base = std::env::temp_dir().join(format!(
            "coldstore-marks-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut marks = MarkStore::default();
        marks.set(Path::new(r"D:\x\keep.bin"), Some(Mark::Cold));
        marks.set(Path::new(r"D:\x\hot.bin"), Some(Mark::Hot));
        marks.save(&base).unwrap();

        // reload from disk → still effective (B18)
        let reloaded = MarkStore::load(&base).unwrap();
        assert_eq!(reloaded.len(), 2);
        let now = SystemTime::now();
        // marked cold beats rebuildable + ancient mtime
        let e = entry(r"D:\X\KEEP.bin", Some(4000));
        assert_eq!(
            classify(&e, &reloaded, &cfg(30), now).temperature,
            Temperature::Cold
        );
        let h = classify(
            &entry(r"D:\x\hot.bin", Some(4000)),
            &reloaded,
            &cfg(30),
            now,
        );
        assert_eq!(h.temperature, Temperature::Warm, "manual hot → WARM");

        // clear works
        let mut m2 = reloaded;
        m2.set(Path::new(r"D:\x\keep.bin"), None);
        assert_eq!(m2.len(), 1);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rollup_is_deterministic() {
        let scan = crate::scan::ScanResult {
            root: PathBuf::from("D:/x"),
            files: vec![
                entry(r"D:\x\target\a.rlib", Some(400)),
                entry(r"D:\x\old.bin", Some(400)),
                entry(r"D:\x\new.bin", Some(1)),
            ],
            skipped: vec![],
            total_bytes: 300,
            truncated_by_reparse_cap: false,
            duration_ms: 0,
        };
        let marks = MarkStore::default();
        let now = SystemTime::now();
        let r1 = rollup(&scan, &marks, &cfg(30), now);
        let r2 = rollup(&scan, &marks, &cfg(30), now);
        assert_eq!(
            serde_json::to_string(&r1).unwrap(),
            serde_json::to_string(&r2).unwrap()
        );
        assert_eq!(r1.len(), 3, "REBUILDABLE + COLD + WARM present");
    }
}
