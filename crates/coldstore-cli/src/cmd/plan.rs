//! `coldstore plan` — one screen: usage attribution + rule hits + savings
//! + cold/hot distribution (card B5). Read-only; byte-reproducible (B19).
//!
//! ADV-N7: the plan shows per-rule hit counts, sizes, examples and the
//! predictor veto, plus the ADV-N7 confirmation threshold so the user sees
//! the second-confirmation gate *before* any `run --execute`.
//!
//! Hard rule 4: the plan always states quarantine occupancy reality —
//! archiving does NOT free space until `quarantine delete`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use serde::Serialize;

use coldstore_core::coldness::{self, TemperatureRollup};
use coldstore_core::predict::{format_bytes, predict, PredictOptions, ReportSummary, Verdict};
use coldstore_core::rules::toml::load_config;
use coldstore_core::rules::{evaluate_all, MatchMode, RuleAction, RuleHit, RuleSet};
use coldstore_core::scan::{self, DirRollup};

pub struct PlanArgs {
    pub path: PathBuf,
    pub json: bool,
}

#[derive(Serialize)]
pub struct PlanReport {
    pub root: String,
    pub config_source: String,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub rules_total: usize,
    pub rules_enabled: usize,
    /// Governing hits from *enabled* rules (what `run --execute` acts on).
    pub rule_hits: Vec<RuleHit>,
    pub unruled_files: u64,
    pub unruled_bytes: u64,
    /// ADV-N7: bytes hit by write-capable actions (non-skip).
    pub actionable_bytes: u64,
    pub confirm_threshold_gb: u64,
    pub requires_confirmation: bool,
    pub prediction: ReportSummary,
    /// First few measured-SKIP classes with their reasons (B5: png →
    /// SKIP with the "已压缩格式" phrase visible on one screen).
    pub skip_examples: Vec<SkipExample>,
    /// Top extensions by volume (分类归因).
    pub class_attribution: Vec<DirRollup>,
    pub coldness: Vec<TemperatureRollup>,
    /// Hard rule 4 / ADV-N5: quarantine occupancy stated explicitly.
    pub quarantine_note: String,
}

#[derive(Serialize)]
pub struct SkipExample {
    pub ext: String,
    pub reason: String,
}

pub fn run(args: PlanArgs) -> Result<()> {
    let report = build(&args.path)?;
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        print_plan(&report);
    }
    Ok(())
}

pub fn build(path: &Path) -> Result<PlanReport> {
    let scan_res = scan::scan(path, &Default::default())?;
    let base = coldstore_core::rules::toml::config_dir();
    let (cfg, source) = load_config(&base)?;
    let ruleset = RuleSet::build(cfg.rules.clone())?;
    let prediction = predict(&scan_res, &PredictOptions::default())?;

    // measured-SKIP classes → predictor veto map (card D1: predictor wins)
    let mut skip_verdicts: BTreeMap<String, bool> = BTreeMap::new();
    for c in &prediction.classes {
        skip_verdicts.insert(c.ext.clone(), c.verdict == Verdict::Skip);
    }

    let rule_hits = evaluate_all(&scan_res, &ruleset, MatchMode::EnabledOnly, &skip_verdicts);
    let hit_files: u64 = rule_hits.iter().map(|h| h.files).sum();
    let hit_bytes: u64 = rule_hits.iter().map(|h| h.bytes).sum();
    let actionable_bytes: u64 = rule_hits
        .iter()
        .filter(|h| h.action != RuleAction::Skip)
        .map(|h| h.bytes)
        .sum();
    let requires_confirmation =
        actionable_bytes > cfg.confirm_threshold_gb.saturating_mul(1024 * 1024 * 1024);

    let marks = coldstore_core::coldness::MarkStore::load(&base)?;
    let coldness_rollup = coldness::rollup(&scan_res, &marks, &cfg.coldness, SystemTime::now());

    let quarantine_root = std::path::absolute(
        std::env::var("USERPROFILE")
            .map(|u| PathBuf::from(u).join(".coldstore").join("quarantine"))
            .unwrap_or_else(|_| PathBuf::from(".coldstore").join("quarantine")),
    )?;

    Ok(PlanReport {
        root: scan_res.root.display().to_string(),
        config_source: source.describe(),
        scanned_files: scan_res.files.len() as u64,
        scanned_bytes: scan_res.total_bytes,
        rules_total: cfg.rules.len(),
        rules_enabled: cfg.rules.iter().filter(|r| r.enabled).count(),
        unruled_files: scan_res.files.len() as u64 - hit_files,
        unruled_bytes: scan_res.total_bytes - hit_bytes,
        rule_hits,
        actionable_bytes,
        confirm_threshold_gb: cfg.confirm_threshold_gb,
        requires_confirmation,
        prediction: prediction.summary,
        skip_examples: {
            // B5 names png specifically: prefer prefilter classes whose
            // reason carries the "已压缩格式" phrase, then fill with other
            // measured-SKIP classes (deterministic ext order in both passes).
            let mut preferred: Vec<SkipExample> = prediction
                .classes
                .iter()
                .filter(|c| c.verdict == Verdict::Skip && c.reason.contains("已压缩格式"))
                .take(3)
                .map(|c| SkipExample {
                    ext: c.ext.clone(),
                    reason: c.reason.clone(),
                })
                .collect();
            for c in prediction
                .classes
                .iter()
                .filter(|c| c.verdict == Verdict::Skip && !c.reason.contains("已压缩格式"))
            {
                if preferred.len() == 3 {
                    break;
                }
                preferred.push(SkipExample {
                    ext: c.ext.clone(),
                    reason: c.reason.clone(),
                });
            }
            preferred
        },
        class_attribution: scan_res.ext_rollup().into_iter().take(10).collect(),
        coldness: coldness_rollup,
        quarantine_note: super::mark::quarantine_note(&quarantine_root),
    })
}

fn print_plan(r: &PlanReport) {
    println!("规划报告（只读）: {}", r.root);
    println!("  配置: {}", r.config_source);
    println!(
        "  总占用: {}（{} 个文件）   规则 {} 条（启用 {}）",
        format_bytes(r.scanned_bytes),
        r.scanned_files,
        r.rules_total,
        r.rules_enabled
    );
    println!();
    println!("  分类归因 Top（按扩展名）:");
    for d in &r.class_attribution {
        println!(
            "    {:<10} {:>6} 个文件  {:>10}",
            d.name,
            d.files,
            format_bytes(d.bytes)
        );
    }
    println!();
    println!("  规则命中（生效规则，first-match-wins）:");
    if r.rule_hits.is_empty() {
        println!("    （无启用规则命中）");
    }
    for h in &r.rule_hits {
        println!(
            "    [{}] action={} — 命中 {} 个 / {}（预测器否决 {}）",
            h.rule_name,
            h.action.as_display(),
            h.files,
            format_bytes(h.bytes),
            h.predictor_vetoed
        );
        for ex in &h.example_paths {
            println!("        例: {ex}");
        }
    }
    println!(
        "    未命中任何规则的文件: {} 个 / {}",
        r.unruled_files,
        format_bytes(r.unruled_bytes)
    );
    println!();
    println!(
        "  预测: ARCHIVE {} / SKIP {} / UNSURE {} / DELETABLE {}   预计可省 {} – {}",
        r.prediction.archive_classes,
        r.prediction.skip_classes,
        r.prediction.unsure_classes,
        r.prediction.deletable_classes,
        format_bytes(r.prediction.est_savings_low),
        format_bytes(r.prediction.est_savings_high)
    );
    println!();
    if !r.skip_examples.is_empty() {
        println!("  SKIP 类样例（预测器实测否决，不进入执行）:");
        for s in &r.skip_examples {
            println!("    [SKIP] {} — {}", s.ext, s.reason);
        }
        println!();
    }
    println!("  冷热分布（mtime 主信号 + 可重建目录 + 手动标记；atime 永不参与）:");
    for t in &r.coldness {
        println!(
            "    {:<12} {:>6} 个文件  {:>10}   {}",
            t.temperature.as_display(),
            t.files,
            format_bytes(t.bytes),
            t.reason_sample
        );
    }
    println!();
    println!(
        "  确认门（ADV-N7）: 可执行动作命中总量 {}，阈值 {} GB → {}",
        format_bytes(r.actionable_bytes),
        r.confirm_threshold_gb,
        if r.requires_confirmation {
            "超阈——run --execute 前必须二次确认"
        } else {
            "无需二次确认"
        }
    );
    println!("  隔离区: {}", r.quarantine_note);
}
