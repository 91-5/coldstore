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

use coldstore_core::coldness::{self, RebuildableGroup, TemperatureRollup};
use coldstore_core::predict::{format_bytes, predict, PredictOptions, ReportSummary, Verdict};
use coldstore_core::rules::toml::load_config;
use coldstore_core::rules::{evaluate_all, MatchMode, RuleAction, RuleHit, RuleSet};
use coldstore_core::scan::{self, DirRollup};

/// How many analysis rows the JSON report carries at most (the human view
/// shows fewer). Keeps the output bounded on huge trees while staying
/// byte-deterministic.
const MAX_ANALYSIS_ROWS: usize = 200;

pub struct PlanArgs {
    pub path: PathBuf,
    pub json: bool,
    /// Config directory override (default: `%APPDATA%\coldstore`).
    pub config_dir: Option<PathBuf>,
}

#[derive(Serialize)]
pub struct PlanReport {
    pub root: String,
    /// **Stable** identity of the configuration that produced this report:
    /// the config file path. The *provenance* ("首次运行，已写入默认配置" vs
    /// "已加载用户配置") changes between the very first run and every later
    /// one, so it must not leak into the machine-readable output — the plan
    /// has to be byte-reproducible across runs (card B19 / B-plan).
    pub config_source: String,
    /// Provenance note (human view only; volatile by nature).
    #[serde(skip)]
    pub config_note: String,
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
    /// **Per-group analysis rows** — every row carries a temperature label,
    /// its reason and the estimated saving (card D5 / B-plan: "每行标签+
    /// 理由+预计节省可见").
    pub analysis: Vec<AnalysisRow>,
    /// True when `analysis` was truncated at [`MAX_ANALYSIS_ROWS`].
    pub analysis_truncated: bool,
    /// Files carrying a manual mark (B18 / B-mark: the flipped label and
    /// its reason are listed explicitly, with the real path).
    pub manual_marks: Vec<ManualMark>,
    /// Total number of marks in the store (may exceed `manual_marks.len()`
    /// when a mark points outside the scanned tree).
    pub manual_marks_total: u64,
    /// Rebuildable groups with their **rebuild cost** (D5: the cost of
    /// regenerating must be visible — deleting is the user's decision).
    pub rebuildable: Vec<RebuildableGroup>,
    /// Hard rule 4 / ADV-N5: quarantine occupancy stated explicitly.
    pub quarantine_note: String,
}

/// One analysis row: a group of files sharing a label, a reason and a
/// format class.
#[derive(Serialize)]
pub struct AnalysisRow {
    /// `COLD` / `WARM` / `REBUILDABLE` / `UNKNOWN`.
    pub temperature: String,
    /// Why this label (always populated — explainability is the point).
    pub reason: String,
    /// Stable machine key of the reason.
    pub reason_key: String,
    /// Extension class (lowercase, no dot).
    pub ext: String,
    pub files: u64,
    pub bytes: u64,
    /// Estimated saving, pro-rated from the measured class estimate.
    pub est_savings_low: u64,
    pub est_savings_high: u64,
    /// Governing rule (first-match-wins) for this group, if any.
    pub rule: Option<String>,
    /// That rule's action.
    pub action: Option<String>,
    /// True when the predictor measured this format class as SKIP — the
    /// row is never executed, whatever the rule says (card D1).
    pub predictor_vetoed: bool,
    /// One representative path.
    pub example_path: Option<String>,
}

/// A manually marked file inside the scanned tree.
#[derive(Serialize)]
pub struct ManualMark {
    pub path: String,
    /// `cold` / `hot`.
    pub mark: String,
    pub temperature: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct SkipExample {
    pub ext: String,
    pub reason: String,
}

pub fn run(args: PlanArgs) -> Result<()> {
    let report = build(&args.path, args.config_dir.as_deref())?;
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        print_plan(&report);
    }
    Ok(())
}

/// Build the plan for `path`.
///
/// `config_dir` overrides the config/marks location; `None` uses
/// `%APPDATA%\coldstore`. Both the CLI and the TUI call this function —
/// they therefore cannot show different numbers (card D6 / B-tui).
pub fn build(path: &Path, config_dir: Option<&Path>) -> Result<PlanReport> {
    let scan_res = scan::scan(path, &Default::default())?;
    let base = match config_dir {
        Some(d) => std::path::absolute(d)?,
        None => coldstore_core::rules::toml::config_dir(),
    };
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
    let now = SystemTime::now();
    let coldness_rollup = coldness::rollup(&scan_res, &marks, &cfg.coldness, now);
    let rebuildable_groups = coldness::rebuildable_groups(&scan_res, &marks, &cfg.coldness, now);

    let (analysis, analysis_truncated, manual_marks) = build_analysis(
        &scan_res,
        &ruleset,
        &skip_verdicts,
        &prediction,
        &marks,
        &cfg.coldness,
        now,
    );

    let quarantine_root = std::path::absolute(
        std::env::var("USERPROFILE")
            .map(|u| PathBuf::from(u).join(".coldstore").join("quarantine"))
            .unwrap_or_else(|_| PathBuf::from(".coldstore").join("quarantine")),
    )?;

    Ok(PlanReport {
        root: scan_res.root.display().to_string(),
        config_source: coldstore_core::rules::toml::config_path(&base)
            .display()
            .to_string(),
        config_note: source.describe(),
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
        analysis,
        analysis_truncated,
        manual_marks,
        manual_marks_total: marks.len() as u64,
        rebuildable: rebuildable_groups,
        quarantine_note: super::mark::quarantine_note(&quarantine_root),
    })
}

/// Build the per-group analysis rows.
///
/// Determinism: the files are sorted by path before grouping, so the
/// representative reason / example path of a group never depends on the
/// order the scanner happened to walk the tree in (B-plan: two runs must
/// be byte-identical).
type GroupKey = (u8, &'static str, String);

#[allow(clippy::too_many_arguments)]
fn build_analysis(
    scan_res: &scan::ScanResult,
    ruleset: &RuleSet,
    skip_verdicts: &BTreeMap<String, bool>,
    prediction: &coldstore_core::predict::PredictionReport,
    marks: &coldstore_core::coldness::MarkStore,
    coldness_cfg: &coldstore_core::rules::toml::ColdnessConfig,
    now: SystemTime,
) -> (Vec<AnalysisRow>, bool, Vec<ManualMark>) {
    // Per-extension class savings (measured by the predictor).
    let mut class_savings: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for c in &prediction.classes {
        class_savings.insert(
            c.ext.clone(),
            (
                c.est_savings_low.unwrap_or(0),
                c.est_savings_high.unwrap_or(0),
                c.total_bytes,
            ),
        );
    }

    let mut files: Vec<&coldstore_core::scan::FileEntry> = scan_res.files.iter().collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));

    struct Acc {
        temperature: String,
        reason: String,
        reason_key: &'static str,
        ext: String,
        files: u64,
        bytes: u64,
        rule: Option<String>,
        action: Option<String>,
        example_path: Option<String>,
    }

    let mut groups: BTreeMap<GroupKey, Acc> = BTreeMap::new();
    let mut manual_marks: Vec<ManualMark> = Vec::new();

    for f in &files {
        let classified = coldness::classify(f, marks, coldness_cfg, now);
        let rank = match classified.temperature {
            coldness::Temperature::Cold => 0u8,
            coldness::Temperature::Warm => 1,
            coldness::Temperature::Rebuildable => 2,
            coldness::Temperature::Unknown => 3,
        };
        let key: GroupKey = (rank, classified.reason_key, f.ext.clone());

        let governing = ruleset.evaluate(f, MatchMode::EnabledOnly);
        let (rule_name, action) = match governing {
            Some(cr) => (
                Some(cr.rule.name.clone()),
                Some(cr.rule.action.as_display().to_string()),
            ),
            None => (None, None),
        };

        let slot = groups.entry(key).or_insert_with(|| Acc {
            temperature: classified.temperature.as_display().to_string(),
            reason: classified.reason.clone(),
            reason_key: classified.reason_key,
            ext: f.ext.clone(),
            files: 0,
            bytes: 0,
            rule: rule_name.clone(),
            action: action.clone(),
            example_path: Some(f.path.display().to_string()),
        });
        slot.files += 1;
        slot.bytes += f.size;

        // A manually marked file is listed explicitly with its real path
        // and the reason that flipped its label (B-mark).
        if classified.reason_key == "manual_cold" || classified.reason_key == "manual_hot" {
            manual_marks.push(ManualMark {
                path: f.path.display().to_string(),
                mark: if classified.reason_key == "manual_cold" {
                    "cold".to_string()
                } else {
                    "hot".to_string()
                },
                temperature: classified.temperature.as_display().to_string(),
                reason: classified.reason.clone(),
            });
        }
    }

    let mut rows: Vec<AnalysisRow> = groups
        .into_values()
        .map(|acc| {
            // Pro-rate the measured class saving across the groups that
            // share the extension class, so the rows sum up to the class
            // estimate instead of multiplying it.
            let (low, high, class_bytes) =
                class_savings.get(&acc.ext).copied().unwrap_or((0, 0, 0));
            let (low, high) = match class_bytes {
                0 => (0, 0),
                class_bytes => (
                    low.saturating_mul(acc.bytes) / class_bytes,
                    high.saturating_mul(acc.bytes) / class_bytes,
                ),
            };
            let vetoed = skip_verdicts.get(&acc.ext).copied().unwrap_or(false);
            AnalysisRow {
                temperature: acc.temperature,
                reason: acc.reason,
                reason_key: acc.reason_key.to_string(),
                ext: acc.ext,
                files: acc.files,
                bytes: acc.bytes,
                // A measured-SKIP class never executes — so it never saves
                // anything either; show 0 rather than a phantom estimate.
                est_savings_low: if vetoed { 0 } else { low },
                est_savings_high: if vetoed { 0 } else { high },
                rule: acc.rule,
                action: acc.action,
                predictor_vetoed: vetoed,
                example_path: acc.example_path,
            }
        })
        .collect();

    let truncated = rows.len() > MAX_ANALYSIS_ROWS;
    rows.truncate(MAX_ANALYSIS_ROWS);
    (rows, truncated, manual_marks)
}

fn print_plan(r: &PlanReport) {
    println!("规划报告（只读）: {}", r.root);
    println!("  配置: {}（{}）", r.config_source, r.config_note);
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
        if let Some(note) = &h.note {
            println!("        说明: {note}");
        }
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
    if !r.manual_marks.is_empty() {
        println!("  手动标记（B18：标签由标记翻转，重启后仍生效）:");
        for m in &r.manual_marks {
            println!(
                "    [{}] {:<12} {} — {}",
                m.mark, m.temperature, m.path, m.reason
            );
        }
        if r.manual_marks_total > r.manual_marks.len() as u64 {
            println!(
                "    （另有 {} 条标记不在本次扫描范围内）",
                r.manual_marks_total - r.manual_marks.len() as u64
            );
        }
        println!();
    }
    if !r.rebuildable.is_empty() {
        println!("  可重建目录（D5：重建成本必须可见——删不删由你决定，工具永不自动删）:");
        for g in &r.rebuildable {
            println!(
                "    {:<14} {:>6} 个文件  {:>10}   重建 ≈ {}   重建命令: {}",
                g.kind,
                g.files,
                format_bytes(g.bytes),
                coldness::format_duration(g.rebuild_seconds_estimate),
                g.rebuild_command
            );
            println!("        估算依据: {}", g.estimate_basis);
        }
        println!();
    }
    println!("  分析明细（每行：标签 + 理由 + 预计节省）:");
    if r.analysis.is_empty() {
        println!("    （无文件）");
    }
    for row in &r.analysis {
        let saving = if row.est_savings_high > 0 {
            format!(
                "预计可省 {} – {}",
                format_bytes(row.est_savings_low),
                format_bytes(row.est_savings_high)
            )
        } else {
            "预计可省 —（无实测收益）".to_string()
        };
        let rule = match (&row.rule, &row.action) {
            (Some(r), Some(a)) => format!("规则 {r}/{a}"),
            _ => "不受规则约束".to_string(),
        };
        let veto = if row.predictor_vetoed {
            "（预测器实测否决，不进入执行）"
        } else {
            ""
        };
        println!(
            "    {:<12} {:<10} {:>6} 个文件  {:>10}   {}   {}{}",
            row.temperature,
            if row.ext.is_empty() {
                "(无扩展名)"
            } else {
                &row.ext
            },
            row.files,
            format_bytes(row.bytes),
            saving,
            rule,
            veto
        );
        println!("        理由: {}", row.reason);
        if let Some(ex) = &row.example_path {
            println!("        例: {ex}");
        }
    }
    if r.analysis_truncated {
        println!("    （明细行数超过上限，已截断）");
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
