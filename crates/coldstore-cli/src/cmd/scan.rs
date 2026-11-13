//! `coldstore scan` — read-only scan with a full skip audit trail.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::predict::format_bytes;
use coldstore_core::scan::{self, ScanResult};

pub struct ScanArgs {
    pub path: PathBuf,
    pub json: bool,
    pub follow_junction: Vec<PathBuf>,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let opts = scan::ScanOptions {
        follow_junction: args.follow_junction,
        ..Default::default()
    };
    let res = scan::scan(&args.path, &opts)?;
    if args.json {
        println!("{}", serde_json::to_string(&res)?);
    } else {
        print_scan(&res);
    }
    Ok(())
}

fn print_scan(res: &ScanResult) {
    println!("扫描完成: {}", res.root.display());
    println!(
        "  文件数: {}   总体积: {}   耗时: {} ms",
        res.files.len(),
        format_bytes(res.total_bytes),
        res.duration_ms
    );
    if res.truncated_by_reparse_cap {
        println!("  ⚠ 重解析点上限已触发，部分子树被拒绝进入（见 skipped）");
    }

    println!("  目录占用 Top（深度 1）:");
    for d in res.dir_rollup().iter().take(10) {
        println!(
            "    {:<24} {:>6} 个文件  {:>10}",
            d.name,
            d.files,
            format_bytes(d.bytes)
        );
    }

    println!("  扩展名 Top:");
    for d in res.ext_rollup().iter().take(10) {
        println!(
            "    {:<24} {:>6} 个文件  {:>10}",
            d.name,
            d.files,
            format_bytes(d.bytes)
        );
    }

    // Skip audit trail: grouped by reason, with examples.
    println!("  跳过项: {} 个（原因分布）:", res.skipped.len());
    let mut grouped: BTreeMap<String, usize> = BTreeMap::new();
    for s in &res.skipped {
        *grouped.entry(s.reason.to_string()).or_default() += 1;
    }
    for (reason, n) in &grouped {
        println!("    [{n:>5}] {reason}");
    }
    let shown = res.skipped.len().min(10);
    if shown > 0 {
        println!("  跳过项示例（前 {shown} 条）:");
        for s in res.skipped.iter().take(shown) {
            println!("    {} — {}", s.path.display(), s.reason);
        }
    }
}
