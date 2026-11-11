//! `coldstore run` — execute one rule's action (card D6).
//!
//! ADV-N4 hard semantics: **default dry-run; `--execute` is the only write
//! switch**. ADV-N7: hit total above `confirm_threshold_gb` requires the
//! second confirmation flag `--yes` before executing.
//!
//! P2 executes the `archive` action through the six-step sequence
//! (quarantine::archive_batch → 001 archive/retrieve APIs). `ntfs_compress`
//! and `dedupe_hardlink` land with P3/P4 and refuse `--execute` until then.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Result};

use coldstore_core::predict::{format_bytes, predict, PredictOptions, Verdict};
use coldstore_core::quarantine::{self, QuarantineConfig};
use coldstore_core::rules::toml::{load_config, AppConfig};
use coldstore_core::rules::{MatchMode, RuleAction, RuleSet};
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
}

pub fn run(args: RunArgs) -> Result<()> {
    let cfg = load_config_from(&args.config_dir)?;
    let rule = cfg
        .rules
        .iter()
        .find(|r| r.name == args.rule)
        .ok_or_else(|| {
            let names: Vec<&str> = cfg.rules.iter().map(|r| r.name.as_str()).collect();
            anyhow::anyhow!(
                "规则不存在: {}（现有规则: {}）",
                args.rule,
                names.join(", ")
            )
        })?
        .clone();
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

    match rule.action {
        RuleAction::Skip => {
            println!(
                "规则 {} 的动作是 skip（显式保护）——没有可执行内容",
                rule.name
            );
            return Ok(());
        }
        RuleAction::NtfsCompress if args.execute => {
            bail!("ntfs_compress 执行将在 P3（NTFS 压缩执行）落地——本阶段仅支持 dry-run");
        }
        RuleAction::DedupeHardlink if args.execute => {
            bail!("dedupe_hardlink 执行将在 P4（去重执行）落地——本阶段仅支持 dry-run");
        }
        _ => {}
    }

    // ADV-N7 confirmation gate
    let threshold_bytes = cfg.confirm_threshold_gb.saturating_mul(1024 * 1024 * 1024);
    let needs_confirm = candidate_bytes > threshold_bytes;

    if !args.execute {
        println!(
            "DRY-RUN（默认只读；--execute 才会写盘——ADV-N4）: 规则 {} action={}",
            rule.name,
            rule.action.as_display()
        );
        println!(
            "  候选: {} 个文件 / {}（预测器否决 {} 个，被更高优先级规则接管 {} 个）",
            candidates.len(),
            format_bytes(candidate_bytes),
            vetoed,
            claimed_elsewhere
        );
        for f in candidates.iter().take(5) {
            println!("    例: {}", f.path.display());
        }
        println!(
            "  确认门: 候选总量 {} vs 阈值 {} GB → {}",
            format_bytes(candidate_bytes),
            cfg.confirm_threshold_gb,
            if needs_confirm {
                "超阈——execute 需追加 --yes"
            } else {
                "无需二次确认"
            }
        );
        println!("  本次运行磁盘零改动（B6 语义）");
        return Ok(());
    }

    // execute path (only action == Archive reaches here in P2)
    if rule.action != RuleAction::Archive {
        bail!("内部状态错误: 非归档动作不应到达执行路径");
    }
    if candidates.is_empty() {
        println!(
            "规则 {} 无候选文件（全部被预测器否决或无命中）——无事可做",
            rule.name
        );
        return Ok(());
    }
    if needs_confirm && !args.yes {
        bail!(
            "ADV-N7 二次确认: 候选总量 {} 超过阈值 {} GB —— 确认无误请追加 --yes 再执行",
            format_bytes(candidate_bytes),
            cfg.confirm_threshold_gb
        );
    }

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
    let stats = quarantine::archive_batch(&candidates, &container, &qcfg)?;
    println!(
        "  批次 {} 完成: {} 个文件已移入隔离区（SHA-256 全部经第 3 步取回校验）",
        stats.batch_id, stats.files
    );
    let expiry = expiry_note(&stats.batch_id, &qcfg, &cfg)?;
    println!(
        "  隔离区仍占用 {}（硬约束 4：归档≠释放）",
        format_bytes(stats.bytes)
    );
    println!("  保留期至 {expiry}；到期不会自动删除，确认后 `coldstore quarantine delete {} --confirm` 释放", stats.batch_id);
    Ok(())
}

fn expiry_note(batch_id: &str, qcfg: &QuarantineConfig, _cfg: &AppConfig) -> Result<String> {
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
