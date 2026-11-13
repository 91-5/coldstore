//! `coldstore run` — execute one rule's action (card D6).
//!
//! ADV-N4 hard semantics: **default dry-run; `--execute` is the only write
//! switch**. ADV-N7: hit total above `confirm_threshold_gb` requires the
//! second confirmation flag `--yes` before executing.
//!
//! P2 executes the `archive` action through the six-step sequence
//! (quarantine::archive_batch → 001 archive/retrieve APIs). P3 added the
//! `ntfs_compress` action. `dedupe_hardlink` is still plan-only.
//!
//! ## Structured API (card D6 / TUI)
//!
//! The command is split into three pieces so that the TUI and the CLI
//! share **one** data source and **one** execution path:
//!
//! - [`plan_run`] — read-only: resolve the rule, scan, apply the predictor
//!   veto, collect the candidates, evaluate the ADV-N7 gate;
//! - [`execute_run`] — the only part that writes; it dispatches to the
//!   audited sequence functions (`quarantine::archive_batch` for the
//!   six-step archive, `ntfs` for the compression batch);
//! - [`run`] — the CLI front-end: plan → print (human or JSON) → execute →
//!   print.
//!
//! The TUI calls `plan_run` / `execute_run` directly — it never touches the
//! filesystem itself.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::Serialize;

use coldstore_core::ntfs::{self, CompressOptions, CompressStats, CompressionMode};
use coldstore_core::predict::{format_bytes, predict, PredictOptions, Verdict};
use coldstore_core::quarantine::{self, QuarantineConfig};
use coldstore_core::rules::toml::{load_config, AppConfig};
use coldstore_core::rules::{MatchMode, Rule, RuleAction, RuleSet};
use coldstore_core::scan::{self, FileEntry};

pub struct RunArgs {
    pub path: PathBuf,
    pub rule: String,
    pub execute: bool,
    pub yes: bool,
    pub container: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub quarantine_root: Option<PathBuf>,
    pub journal_dir: Option<PathBuf>,
    /// Machine-readable output (card D6: every subcommand supports --json).
    pub json: bool,
}

/// The read-only plan for one rule (what `run` would do).
#[derive(Debug, Clone, Serialize)]
pub struct RunPlan {
    pub rule: String,
    pub action: String,
    /// The rule's note (the built-in Chinese-ecosystem rules carry advice).
    pub note: Option<String>,
    pub candidates: u64,
    pub candidate_bytes: u64,
    /// Files dropped because the predictor measured their format as SKIP.
    pub predictor_vetoed: u64,
    /// Files governed by a higher-priority rule instead.
    pub claimed_elsewhere: u64,
    /// ADV-N7: the batch is above the confirmation threshold.
    pub needs_confirmation: bool,
    pub confirm_threshold_gb: u64,
    /// The rule's action is `skip` — nothing to execute.
    pub skip_action: bool,
    pub example_paths: Vec<String>,
    /// True when `--execute` was requested (the only write switch).
    pub execute_requested: bool,
}

/// The result of an execution.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RunOutcome {
    /// The six-step archive sequence completed.
    Archive {
        batch_id: String,
        files: u64,
        bytes: u64,
        /// Quarantine still occupies this much — archiving is not releasing.
        quarantine_still_occupied: u64,
        expires_date: String,
        container: String,
    },
    /// The NTFS compression batch completed.
    NtfsCompress { stats: CompressStats },
    /// Nothing to do (no candidates / skip action).
    NothingToDo { reason: String },
}

/// Plan a rule run. Read-only — never writes anything.
pub fn plan_run(args: &RunArgs) -> Result<RunPlan> {
    let cfg = load_config_from(&args.config_dir)?;
    let rule = resolve_rule(&cfg, &args.rule)?;
    if !rule.enabled {
        bail!(
            "规则 {} 已停用——先用 `coldstore rule enable {}` 显式启用",
            rule.name,
            rule.name
        );
    }

    let scan_res = scan::scan(&args.path, &Default::default())?;
    let ruleset = RuleSet::build(cfg.rules.clone())?;
    let prediction = predict(&scan_res, &PredictOptions::default())?;

    // predictor's final veto (card D1): measured-SKIP classes never execute
    let mut skip_verdicts: BTreeMap<String, bool> = BTreeMap::new();
    for c in &prediction.classes {
        skip_verdicts.insert(c.ext.clone(), c.verdict == Verdict::Skip);
    }

    // candidates: files this rule *governs* (first-match-wins globally) and
    // that survive the predictor veto
    let mut candidates: Vec<FileEntry> = Vec::new();
    let mut vetoed = 0u64;
    let mut claimed_elsewhere = 0u64;
    for f in &scan_res.files {
        let governing = ruleset.evaluate(f, MatchMode::EnabledOnly);
        if governing.map(|g| g.rule.name.as_str()) != Some(rule.name.as_str()) {
            if governing.is_some() {
                claimed_elsewhere += 1;
            }
            continue;
        }
        if skip_verdicts.get(&f.ext).copied().unwrap_or(false) {
            vetoed += 1;
            continue;
        }
        candidates.push(f.clone());
    }
    let candidate_bytes: u64 = candidates.iter().map(|f| f.size).sum();

    // ADV-N7 confirmation gate
    let threshold_bytes = cfg.confirm_threshold_gb.saturating_mul(1024 * 1024 * 1024);

    Ok(RunPlan {
        rule: rule.name.clone(),
        action: rule.action.as_display().to_string(),
        note: rule.note.clone(),
        candidates: candidates.len() as u64,
        candidate_bytes,
        predictor_vetoed: vetoed,
        claimed_elsewhere,
        needs_confirmation: candidate_bytes > threshold_bytes,
        confirm_threshold_gb: cfg.confirm_threshold_gb,
        skip_action: rule.action == RuleAction::Skip,
        example_paths: candidates
            .iter()
            .take(5)
            .map(|f| f.path.display().to_string())
            .collect(),
        execute_requested: args.execute,
    })
}

/// Execute a planned rule run. This is the **only** function in the CLI
/// that writes user data, and it dispatches exclusively to the audited
/// sequence functions.
pub fn execute_run(args: &RunArgs) -> Result<RunOutcome> {
    let cfg = load_config_from(&args.config_dir)?;
    let rule = resolve_rule(&cfg, &args.rule)?;
    if !rule.enabled {
        bail!(
            "规则 {} 已停用——先用 `coldstore rule enable {}` 显式启用",
            rule.name,
            rule.name
        );
    }

    let scan_res = scan::scan(&args.path, &Default::default())?;
    let ruleset = RuleSet::build(cfg.rules.clone())?;
    let prediction = predict(&scan_res, &PredictOptions::default())?;
    let mut skip_verdicts: BTreeMap<String, bool> = BTreeMap::new();
    for c in &prediction.classes {
        skip_verdicts.insert(c.ext.clone(), c.verdict == Verdict::Skip);
    }

    let mut candidates: Vec<FileEntry> = Vec::new();
    for f in &scan_res.files {
        let governing = ruleset.evaluate(f, MatchMode::EnabledOnly);
        if governing.map(|g| g.rule.name.as_str()) != Some(rule.name.as_str()) {
            continue;
        }
        if skip_verdicts.get(&f.ext).copied().unwrap_or(false) {
            continue;
        }
        candidates.push(f.clone());
    }
    let candidate_bytes: u64 = candidates.iter().map(|f| f.size).sum();

    if rule.action == RuleAction::Skip {
        return Ok(RunOutcome::NothingToDo {
            reason: format!(
                "规则 {} 的动作是 skip（显式保护）——没有可执行内容",
                rule.name
            ),
        });
    }
    if rule.action == RuleAction::DedupeHardlink {
        bail!("dedupe_hardlink 执行尚未落地——本阶段仅支持 dry-run");
    }
    if candidates.is_empty() {
        return Ok(RunOutcome::NothingToDo {
            reason: format!(
                "规则 {} 无候选文件（全部被预测器否决或无命中）——无事可做",
                rule.name
            ),
        });
    }

    let threshold_bytes = cfg.confirm_threshold_gb.saturating_mul(1024 * 1024 * 1024);
    if candidate_bytes > threshold_bytes && !args.yes {
        bail!(
            "ADV-N7 二次确认: 候选总量 {} 超过阈值 {} GB —— 确认无误请追加 --yes 再执行",
            format_bytes(candidate_bytes),
            cfg.confirm_threshold_gb
        );
    }

    match rule.action {
        RuleAction::Archive => execute_archive(&rule, &candidates, candidate_bytes, &cfg, args),
        RuleAction::NtfsCompress => execute_ntfs_compress(&rule, &candidates),
        RuleAction::DedupeHardlink => {
            bail!("dedupe_hardlink 执行尚未落地——本阶段仅支持 dry-run")
        }
        RuleAction::Skip => Ok(RunOutcome::NothingToDo {
            reason: format!("规则 {} 的动作是 skip（显式保护）", rule.name),
        }),
    }
}

/// The CLI front-end: plan → print → (optionally) execute → print.
pub fn run(args: RunArgs) -> Result<()> {
    let plan = plan_run(&args)?;

    if !args.execute {
        if args.json {
            println!("{}", serde_json::to_string(&plan)?);
        } else {
            print_plan(&plan);
        }
        return Ok(());
    }

    let outcome = execute_run(&args)?;
    if args.json {
        println!("{}", serde_json::to_string(&outcome)?);
    } else {
        print_outcome(&outcome);
    }
    Ok(())
}

fn resolve_rule(cfg: &AppConfig, name: &str) -> Result<Rule> {
    cfg.rules
        .iter()
        .find(|r| r.name == name)
        .cloned()
        .ok_or_else(|| {
            let names: Vec<&str> = cfg.rules.iter().map(|r| r.name.as_str()).collect();
            anyhow::anyhow!("规则不存在: {}（现有规则: {}）", name, names.join(", "))
        })
}

fn print_plan(plan: &RunPlan) {
    println!(
        "DRY-RUN（默认只读；--execute 才会写盘——ADV-N4）: 规则 {} action={}",
        plan.rule, plan.action
    );
    println!(
        "  候选: {} 个文件 / {}（预测器否决 {} 个，被更高优先级规则接管 {} 个）",
        plan.candidates,
        format_bytes(plan.candidate_bytes),
        plan.predictor_vetoed,
        plan.claimed_elsewhere
    );
    if let Some(note) = &plan.note {
        println!("  规则说明: {note}");
    }
    for f in &plan.example_paths {
        println!("    例: {f}");
    }
    println!(
        "  确认门: 候选总量 {} vs 阈值 {} GB → {}",
        format_bytes(plan.candidate_bytes),
        plan.confirm_threshold_gb,
        if plan.needs_confirmation {
            "超阈——execute 需追加 --yes"
        } else {
            "无需二次确认"
        }
    );
    println!("  本次运行磁盘零改动（B6 语义）");
}

fn print_outcome(outcome: &RunOutcome) {
    match outcome {
        RunOutcome::Archive {
            batch_id,
            files,
            bytes,
            quarantine_still_occupied,
            expires_date,
            container,
        } => {
            println!(
                "  批次 {batch_id} 完成: {files} 个文件已移入隔离区（SHA-256 全部经第 3 步取回校验）"
            );
            println!(
                "  隔离区仍占用 {}（硬约束 4：归档≠释放）",
                format_bytes(*quarantine_still_occupied)
            );
            println!("  容器: {container}");
            println!("  保留期至 {expires_date}；到期不会自动删除，确认后 `coldstore quarantine delete {batch_id} --confirm` 释放");
            let _ = bytes;
        }
        RunOutcome::NtfsCompress { stats } => {
            super::compress::print_stats(stats, false);
        }
        RunOutcome::NothingToDo { reason } => {
            println!("{reason}");
        }
    }
}

/// The P2 archive path — the six-step sequence (unchanged by P3/P4).
fn execute_archive(
    rule: &Rule,
    candidates: &[FileEntry],
    candidate_bytes: u64,
    cfg: &AppConfig,
    args: &RunArgs,
) -> Result<RunOutcome> {
    let mut qcfg = QuarantineConfig::resolve(&cfg.quarantine)?;
    if let Some(r) = &args.quarantine_root {
        qcfg.root = std::path::absolute(r)?;
    }
    if let Some(j) = &args.journal_dir {
        qcfg.journal_dir = std::path::absolute(j)?;
    }
    let container = match &args.container {
        Some(c) => std::path::absolute(c)?,
        None => quarantine::archive_root(&cfg.quarantine)?.join(format!(
            "archive-{:x}.coldstore",
            coldstore_core::quarantine::now_millis()
        )),
    };

    println!(
        "执行归档（六步序列）: 规则 {} → {} 个文件 / {} → 容器 {}",
        rule.name,
        candidates.len(),
        format_bytes(candidate_bytes),
        container.display()
    );
    let stats = quarantine::archive_batch(candidates, &container, &qcfg)?;
    let expiry = expiry_note(&stats.batch_id, &qcfg)?;
    Ok(RunOutcome::Archive {
        batch_id: stats.batch_id,
        files: stats.files,
        bytes: stats.bytes,
        quarantine_still_occupied: stats.bytes,
        expires_date: expiry,
        container: container.display().to_string(),
    })
}

/// The P3 NTFS-compression path.
///
/// NTFS compression only flips a file attribute — it never deletes,
/// moves or renames anything — so the P2 "every mutation lives inside a
/// journaled sequence function" rule is satisfied vacuously: this path
/// performs no filesystem deletion or renaming at all.
fn execute_ntfs_compress(rule: &Rule, candidates: &[FileEntry]) -> Result<RunOutcome> {
    let opts = CompressOptions {
        mode: CompressionMode::Enable,
        ..Default::default()
    };
    let plan = ntfs::plan_compression(candidates, &opts);
    if plan.files.is_empty() {
        let mut reason = format!(
            "规则 {} 的候选全部被执行器级规则跳过（已压缩格式 / 系统目录 / 敏感格式）——无事可做",
            rule.name
        );
        for (r, count) in &plan.skipped_by_reason {
            reason.push_str(&format!("\n  跳过 {count} 个 — {r}"));
        }
        return Ok(RunOutcome::NothingToDo { reason });
    }
    println!(
        "执行 NTFS 透明压缩: 规则 {} → {} 个文件 / {}（异步执行，Ctrl-C 可安全中断并续做）",
        rule.name,
        plan.files.len(),
        format_bytes(plan.bytes)
    );
    let stats = super::compress::execute(plan.files, opts, false)?;
    Ok(RunOutcome::NtfsCompress { stats })
}

fn expiry_note(batch_id: &str, qcfg: &QuarantineConfig) -> Result<String> {
    let infos = quarantine::quarantine_list(qcfg)?;
    let info = infos
        .iter()
        .find(|i| i.batch_id == batch_id)
        .ok_or_else(|| anyhow::anyhow!("批次信息缺失: {batch_id}"))?;
    Ok(info.expires_date.clone())
}

fn load_config_from(dir: &Option<PathBuf>) -> Result<AppConfig> {
    match dir {
        Some(d) => Ok(load_config(d)?.0),
        None => {
            let base = coldstore_core::rules::toml::config_dir();
            Ok(load_config(&base)?.0)
        }
    }
}
