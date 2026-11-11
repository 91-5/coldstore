//! Rule engine (card D1): declarative TOML rules → per-file action.
//!
//! Semantics nailed down by the card + review adjudications:
//! - **first-match-wins by `priority` (descending)**; ties broken by rule
//!   name (deterministic) — a low-priority wide glob can never swallow a
//!   higher-priority specific rule, but *is* visible in dry-run stats
//!   (ADV-N7);
//! - all match conditions AND (`match_path` globs, `match_ext`, `min_size_mb`);
//!   a rule with no matchers matches everything (explicit user choice);
//! - **four actions only**: `ntfs_compress | archive | dedupe_hardlink | skip`;
//! - **the predictor holds the final veto**: a rule can only narrow the
//!   candidate set — a file whose measured prediction is SKIP is never
//!   executed, even if an `archive` rule matches it (the png-at-100%
//!   counterexample closes here);
//! - glob matching is case-insensitive with `/` as the separator (Windows
//!   paths are normalized before matching).
//!
//! Read-only semantics (ADV-N4): evaluating rules never touches the disk;
//! `--execute` is the only write switch anywhere in the CLI.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::scan::{FileEntry, ScanResult};

pub mod toml;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    NtfsCompress,
    Archive,
    DedupeHardlink,
    Skip,
}

impl RuleAction {
    pub fn as_display(self) -> &'static str {
        match self {
            RuleAction::NtfsCompress => "ntfs_compress",
            RuleAction::Archive => "archive",
            RuleAction::DedupeHardlink => "dedupe_hardlink",
            RuleAction::Skip => "skip",
        }
    }
}

fn default_enabled() -> bool {
    true
}

/// One declarative rule. All match conditions AND.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub priority: i64,
    /// Glob patterns against the full path (`/` separators, `**` spans
    /// directories, case-insensitive).
    #[serde(default)]
    pub match_path: Vec<String>,
    /// Lowercase extensions without the dot.
    #[serde(default)]
    pub match_ext: Vec<String>,
    /// Minimum size in MB (None = any size).
    #[serde(default)]
    pub min_size_mb: Option<u64>,
    pub action: RuleAction,
    /// Defaults to true when omitted; the *shipped defaults* are all false.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// A rule with its globs pre-compiled.
#[derive(Debug)]
pub struct CompiledRule {
    pub rule: Rule,
    path_globset: Option<GlobSet>,
    exts: Option<Vec<String>>,
}

impl CompiledRule {
    /// All specified conditions must match. Unspecified = wildcard.
    fn matches(&self, path_lower_slash: &str, ext: &str, size: u64) -> bool {
        if let Some(gs) = &self.path_globset {
            if !gs.is_match(path_lower_slash) {
                return false;
            }
        }
        if let Some(exts) = &self.exts {
            if !exts.iter().any(|e| e == ext) {
                return false;
            }
        }
        if let Some(mb) = self.rule.min_size_mb {
            if size < mb.saturating_mul(1024 * 1024) {
                return false;
            }
        }
        true
    }
}

/// Compiled, deterministically-ordered rule set.
#[derive(Debug)]
pub struct RuleSet {
    /// priority DESC, name ASC — `evaluate` returns the first match.
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Only `enabled = true` rules participate (governs plan / run).
    EnabledOnly,
    /// All rules participate as-if enabled (governs `rule test` preview).
    AllRules,
}

impl RuleSet {
    /// Compile and order the rules. Invalid glob → error naming the rule.
    pub fn build(rules: Vec<Rule>) -> Result<RuleSet> {
        let mut compiled: Vec<CompiledRule> = Vec::with_capacity(rules.len());
        for rule in rules {
            let path_globset = if rule.match_path.is_empty() {
                None
            } else {
                let mut builder = GlobSetBuilder::new();
                for pat in &rule.match_path {
                    let glob = GlobBuilder::new(pat)
                        .literal_separator(true)
                        .case_insensitive(true)
                        .build()
                        .with_context(|| format!("规则 {} 的 glob 非法: {pat}", rule.name))?;
                    builder.add(glob);
                }
                Some(
                    builder
                        .build()
                        .with_context(|| format!("规则 {} 的 glob 集编译失败", rule.name))?,
                )
            };
            let exts = if rule.match_ext.is_empty() {
                None
            } else {
                Some(rule.match_ext.iter().map(|e| e.to_lowercase()).collect())
            };
            compiled.push(CompiledRule {
                rule,
                path_globset,
                exts,
            });
        }
        // Deterministic order: priority DESC, name ASC.
        compiled.sort_by(|a, b| {
            b.rule
                .priority
                .cmp(&a.rule.priority)
                .then(a.rule.name.cmp(&b.rule.name))
        });
        Ok(RuleSet { rules: compiled })
    }

    /// First matching rule for one file under `mode`, else None.
    pub fn evaluate(&self, entry: &FileEntry, mode: MatchMode) -> Option<&CompiledRule> {
        let path_lower_slash = entry
            .path
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        let path_lower_slash = path_lower_slash.as_str();
        self.rules.iter().find(|cr| {
            if mode == MatchMode::EnabledOnly && !cr.rule.enabled {
                return false;
            }
            cr.matches(path_lower_slash, &entry.ext, entry.size)
        })
    }
}

/// Aggregate hit statistics for one rule (card ADV-N7: dry-run must show
/// per-rule file count, total size and examples).
#[derive(Debug, Serialize)]
pub struct RuleHit {
    pub rule_name: String,
    pub action: RuleAction,
    pub enabled: bool,
    pub priority: i64,
    pub files: u64,
    pub bytes: u64,
    /// How many of these the predictor would veto (measured SKIP class) —
    /// the rule narrows candidates, the predictor decides (card D1).
    pub predictor_vetoed: u64,
    /// Up to 3 example paths, sorted (deterministic, B19).
    pub example_paths: Vec<String>,
}

/// Evaluate every file, aggregate per-rule stats.
///
/// Files matching no rule land in no bucket at all (the caller reports the
/// un-ruled remainder from the total).
pub fn evaluate_all(
    scan: &ScanResult,
    ruleset: &RuleSet,
    mode: MatchMode,
    skip_verdicts: &BTreeMap<String, bool>,
) -> Vec<RuleHit> {
    let mut hits: BTreeMap<String, RuleHit> = BTreeMap::new();
    for entry in &scan.files {
        let Some(cr) = ruleset.evaluate(entry, mode) else {
            continue;
        };
        let slot = hits.entry(cr.rule.name.clone()).or_insert_with(|| RuleHit {
            rule_name: cr.rule.name.clone(),
            action: cr.rule.action,
            enabled: cr.rule.enabled,
            priority: cr.rule.priority,
            files: 0,
            bytes: 0,
            predictor_vetoed: 0,
            example_paths: Vec::new(),
        });
        slot.files += 1;
        slot.bytes += entry.size;
        if slot.example_paths.len() < 3 {
            slot.example_paths.push(entry.path.display().to_string());
            slot.example_paths.sort();
        }
        // Predictor veto: measured-SKIP class → never executed.
        if let Some(true) = skip_verdicts.get(&entry.ext) {
            slot.predictor_vetoed += 1;
        }
    }
    hits.into_values().collect()
}

/// Normalize a scan path to the lowercase `/`-separated form used for
/// matching (exposed for tests).
pub fn match_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileEntry;
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

    fn rule(name: &str, priority: i64, paths: &[&str], exts: &[&str], action: RuleAction) -> Rule {
        Rule {
            name: name.to_string(),
            priority,
            match_path: paths.iter().map(|s| s.to_string()).collect(),
            match_ext: exts.iter().map(|s| s.to_string()).collect(),
            min_size_mb: None,
            action,
            enabled: true,
        }
    }

    #[test]
    fn first_match_wins_by_priority_then_name() {
        let set = RuleSet::build(vec![
            rule("wide", 5, &["**/*.rlib"], &[], RuleAction::Archive),
            rule(
                "specific",
                10,
                &["**/target/debug/**"],
                &["rlib"],
                RuleAction::NtfsCompress,
            ),
        ])
        .unwrap();
        let e = entry(r"D:\proj\target\debug\foo.rlib", "rlib", 1000);
        let hit = set.evaluate(&e, MatchMode::EnabledOnly).unwrap();
        assert_eq!(hit.rule.name, "specific", "higher priority wins");
        // equal priority → name ASC decides deterministically
        let set2 = RuleSet::build(vec![
            rule("bbb", 5, &["**/*.rlib"], &[], RuleAction::Archive),
            rule("aaa", 5, &["**/*.rlib"], &[], RuleAction::Skip),
        ])
        .unwrap();
        assert_eq!(
            set2.evaluate(&e, MatchMode::EnabledOnly).unwrap().rule.name,
            "aaa"
        );
    }

    #[test]
    fn conditions_and_disable_semantics() {
        let mut r = rule(
            "sized",
            10,
            &["**/target/**"],
            &["rlib"],
            RuleAction::NtfsCompress,
        );
        r.min_size_mb = Some(10);
        let set = RuleSet::build(vec![r]).unwrap();

        // size condition ANDs with path+ext
        let small = entry(r"D:\t\target\debug\tiny.rlib", "rlib", 1024);
        let big = entry(r"D:\t\target\debug\big.rlib", "rlib", 11 * 1024 * 1024);
        assert!(set.evaluate(&small, MatchMode::EnabledOnly).is_none());
        assert_eq!(
            set.evaluate(&big, MatchMode::EnabledOnly)
                .unwrap()
                .rule
                .name,
            "sized"
        );

        // disabled rules invisible in EnabledOnly, visible in AllRules
        let mut set =
            RuleSet::build(vec![rule("off", 1, &["**/*.rlib"], &[], RuleAction::Skip)]).unwrap();
        set.rules[0].rule.enabled = false;
        assert!(set.evaluate(&big, MatchMode::EnabledOnly).is_none());
        assert_eq!(
            set.evaluate(&big, MatchMode::AllRules).unwrap().rule.name,
            "off"
        );
    }

    #[test]
    fn case_insensitive_windows_matching() {
        let set = RuleSet::build(vec![rule(
            "t",
            1,
            &["**/TARGET/DEBUG/**"],
            &["RLIB"],
            RuleAction::Skip,
        )])
        .unwrap();
        let e = entry(r"D:\Proj\Target\Debug\Foo.RLIB", "rlib", 1);
        assert!(set.evaluate(&e, MatchMode::EnabledOnly).is_some());
    }

    #[test]
    fn empty_matchers_catch_all_and_veto_counts() {
        let set = RuleSet::build(vec![rule("all", 1, &[], &[], RuleAction::Skip)]).unwrap();
        let scan = crate::scan::ScanResult {
            root: PathBuf::from("D:/x"),
            files: vec![
                entry(r"D:\x\a.png", "png", 100),
                entry(r"D:\x\b.png", "png", 100),
                entry(r"D:\x\c.txt", "txt", 100),
            ],
            skipped: vec![],
            total_bytes: 300,
            truncated_by_reparse_cap: false,
            duration_ms: 0,
        };
        // png measured SKIP → vetoed
        let mut veto = BTreeMap::new();
        veto.insert("png".to_string(), true);
        veto.insert("txt".to_string(), false);
        let hits = evaluate_all(&scan, &set, MatchMode::EnabledOnly, &veto);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].files, 3);
        assert_eq!(hits[0].bytes, 300);
        assert_eq!(hits[0].predictor_vetoed, 2, "png files vetoed by predictor");
    }

    #[test]
    fn invalid_glob_is_an_error_naming_the_rule() {
        let mut r = rule("bad", 1, &["[invalid"], &[], RuleAction::Skip);
        r.enabled = true;
        let err = RuleSet::build(vec![r]).unwrap_err().to_string();
        assert!(err.contains("bad"), "{err}");
    }
}
