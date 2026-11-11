//! `coldstore dedupe` — duplicate plan (001 semantics: plan-only here;
//! execution lands with the 002 execution layer).

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::dedupe;
use coldstore_core::predict::format_bytes;
use coldstore_core::scan;

pub struct DedupeArgs {
    pub path: PathBuf,
    pub plan_only: bool,
    pub min_size_kb: u64,
    pub keep: Option<String>,
    pub json: bool,
}

pub fn run(args: DedupeArgs) -> Result<()> {
    let _ = args.plan_only; // 001 的 dedupe 只出计划，永远 plan-only
    let scan_res = scan::scan(&args.path, &Default::default())?;
    let policy = match args.keep.as_deref() {
        None | Some("oldest") => dedupe::KeepPolicy::Oldest,
        Some("newest") => dedupe::KeepPolicy::Newest,
        Some(p) => dedupe::KeepPolicy::KeepPath(PathBuf::from(p)),
    };
    let opts = dedupe::DedupeOptions {
        min_size: args.min_size_kb * 1024,
        policy,
    };
    let plan = dedupe::dedupe(&scan_res, &opts)?;
    if args.json {
        println!("{}", serde_json::to_string(&plan)?);
    } else {
        print_dedupe(&plan);
    }
    Ok(())
}

fn print_dedupe(plan: &dedupe::DedupePlan) {
    println!(
        "去重计划（仅识别，不执行 —— 硬链接替换属 002 执行层）: 策略 {}，阈值 ≥ {}",
        plan.policy,
        format_bytes(plan.min_size)
    );
    println!(
        "  扫描 {} 个文件，入桶 {}，哈希成功 {}（失败 {}），重复组 {} 个",
        plan.scanned_files,
        plan.bucketed_files,
        plan.hashed_files,
        plan.hash_failures,
        plan.groups.len()
    );
    println!(
        "  预计可回收: {}   （已完全硬链接的组: {} 个——AV-N1，节省 0MB）",
        format_bytes(plan.total_reclaimable_bytes),
        plan.fully_hardlinked_groups
    );
    for (n, g) in plan.groups.iter().enumerate() {
        println!(
            "  [组 {}] sha256={}… 体积 {}  保留: {}（mtime {}）",
            n + 1,
            &g.sha256_hex[..16.min(g.sha256_hex.len())],
            format_bytes(g.size),
            g.keep.path.display(),
            super::fmt_time(g.keep.modified)
        );
        for d in &g.duplicates {
            let mark = if d.same_data_as_keep {
                "已硬链接（同一份数据，节省 0MB）"
            } else {
                "独立副本（可回收）"
            };
            println!("      副本: {} — {}", d.path.display(), mark);
        }
    }
}
