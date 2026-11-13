//! `coldstore rule` — list / enable / disable / test (card D6, B16).
//!
//! `rule test` only *shows* what each rule would hit; no action runs
//! (card B16). Disabled rules are previewed as-if-enabled so the user can
//! judge opt-ins before flipping them on.

use std::path::{Path, PathBuf};

use anyhow::Result;

use coldstore_core::predict::{format_bytes, predict, PredictOptions, Verdict};
use coldstore_core::rules::toml::{load_config, set_rule_enabled};
use coldstore_core::rules::{evaluate_all, MatchMode, RuleSet};
use coldstore_core::scan;
use std::collections::BTreeMap;

pub enum RuleCmd {
    List {
        json: bool,
        config_dir: Option<PathBuf>,
    },
    Enable {
        name: String,
        json: bool,
        config_dir: Option<PathBuf>,
    },
    Disable {
        name: String,
        json: bool,
        config_dir: Option<PathBuf>,
    },
    Test {
        path: PathBuf,
        json: bool,
    },
}

pub fn run(cmd: RuleCmd) -> Result<()> {
    match cmd {
        RuleCmd::List { json, config_dir } => list(json, config_dir.as_deref()),
        RuleCmd::Enable {
            name,
            json,
            config_dir,
        } => set_enabled(&name, true, json, config_dir.as_deref()),
        RuleCmd::Disable {
            name,
            json,
            config_dir,
        } => set_enabled(&name, false, json, config_dir.as_deref()),
        RuleCmd::Test { path, json } => test(&path, json),
    }
}

fn list(json: bool, config_dir: Option<&Path>) -> Result<()> {
    let base = match config_dir {
        Some(d) => std::path::absolute(d)?,
        None => coldstore_core::rules::toml::config_dir(),
    };
    let (cfg, source) = load_config(&base)?;
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "config_dir": base.display().to_string(),
                "config_source": source.describe(),
                "rules": cfg.rules.iter().map(|r| serde_json::json!({
                    "name": r.name,
                    "priority": r.priority,
                    "action": r.action.as_display(),
                    "enabled": r.enabled,
                    "note": r.note,
                    "match_path": r.match_path,
                    "match_ext": r.match_ext,
                    "min_size_mb": r.min_size_mb,
                })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }
    println!("规则配置（{}）: {}", base.display(), source.describe());
    println!(
        "  {:>3}  {:<16} {:<16} {:<8} 条件",
        "pri", "名称", "动作", "启用"
    );
    for r in &cfg.rules {
        let mut cond = String::new();
        if !r.match_path.is_empty() {
            cond.push_str(&format!("路径×{} ", r.match_path.len()));
        }
        if !r.match_ext.is_empty() {
            cond.push_str(&format!("扩展名×{} ", r.match_ext.len()));
        }
        if let Some(mb) = r.min_size_mb {
            cond.push_str(&format!("≥{mb}MB "));
        }
        if cond.is_empty() {
            cond.push_str("全部文件");
        }
        println!(
            "  {:>3}  {:<16} {:<16} {:<8} {}",
            r.priority,
            r.name,
            r.action.as_display(),
            if r.enabled { "是" } else { "否" },
            cond.trim_end()
        );
        if let Some(note) = &r.note {
            println!("        说明: {note}");
        }
    }
    Ok(())
}

fn set_enabled(name: &str, enabled: bool, json: bool, config_dir: Option<&Path>) -> Result<()> {
    let base = match config_dir {
        Some(d) => std::path::absolute(d)?,
        None => coldstore_core::rules::toml::config_dir(),
    };
    let cfg = set_rule_enabled(&base, name, enabled)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "rule": name,
                "enabled": enabled,
                "enabled_count": cfg.rules.iter().filter(|r| r.enabled).count(),
                "rules_total": cfg.rules.len(),
                "config_dir": base.display().to_string(),
            })
        );
        return Ok(());
    }
    println!(
        "已{}规则 {}（当前启用 {} / {} 条）",
        if enabled { "启用" } else { "停用" },
        name,
        cfg.rules.iter().filter(|r| r.enabled).count(),
        cfg.rules.len()
    );
    Ok(())
}

fn test(path: &Path, json: bool) -> Result<()> {
    let base = coldstore_core::rules::toml::config_dir();
    let (cfg, source) = load_config(&base)?;
    let scan_res = scan::scan(path, &Default::default())?;
    let prediction = predict(&scan_res, &PredictOptions::default())?;
    let ruleset = RuleSet::build(cfg.rules.clone())?;

    // measured-SKIP classes → the predictor's final veto (card D1)
    let mut skip_verdicts: BTreeMap<String, bool> = BTreeMap::new();
    for c in &prediction.classes {
        skip_verdicts.insert(c.ext.clone(), c.verdict == Verdict::Skip);
    }

    // Preview: every rule as-if-enabled, first-match-wins (B16).
    let hits = evaluate_all(&scan_res, &ruleset, MatchMode::AllRules, &skip_verdicts);
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "config_source": source.describe(),
                "scanned_files": scan_res.files.len(),
                "hits": hits,
            }))?
        );
        return Ok(());
    }

    println!(
        "规则试算（只展示命中，不执行任何动作——B16）: {}",
        scan_res.root.display()
    );
    println!("  配置: {}", source.describe());
    println!(
        "  扫描 {} 个文件 / {}；规则 {} 条（启用 {}）",
        scan_res.files.len(),
        format_bytes(scan_res.total_bytes),
        cfg.rules.len(),
        cfg.rules.iter().filter(|r| r.enabled).count()
    );
    println!();
    for h in &hits {
        println!(
            "  [{}] {} pri={} action={} — 命中 {} 个 / {}（预测器否决 {}）",
            if h.enabled { "启用" } else { "未启用" },
            h.rule_name,
            h.priority,
            h.action.as_display(),
            h.files,
            format_bytes(h.bytes),
            h.predictor_vetoed
        );
        for ex in &h.example_paths {
            println!("      例: {ex}");
        }
    }
    let covered: u64 = hits.iter().map(|h| h.files).sum();
    println!();
    println!(
        "  覆盖合计: {covered} / {} 个文件（其余 {} 个不受任何规则约束）",
        scan_res.files.len(),
        scan_res.files.len() as u64 - covered
    );
    Ok(())
}
