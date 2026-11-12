//! `coldstore compress` / `coldstore decompress` — NTFS transparent
//! compression execution (card D3, P3).
//!
//! Semantics inherited from the whole product:
//! - **default dry-run** — `--execute` is the only write switch (ADV-N4);
//! - **ADV-N7** — a batch above `confirm_threshold_gb` needs `--yes`;
//! - **asynchronous + interruptible** — the batch runs on a worker thread
//!   ([`coldstore_core::ntfs::CompressHandle`]), the terminal keeps
//!   rendering progress (file count + byte count) and Ctrl-C asks the
//!   batch to stop at the next file boundary instead of killing it;
//! - **reversible** — `decompress` is the same call with
//!   `COMPRESSION_FORMAT_NONE` and restores `Compressed=False`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use coldstore_core::ntfs::{
    self, CompressHandle, CompressOptions, CompressPlan, CompressStats, CompressionMode,
    ProgressSnapshot,
};
use coldstore_core::predict::{format_bytes, predict, PredictOptions, Verdict};
use coldstore_core::rules::toml::{config_dir, load_config};
use coldstore_core::scan::{self, FileEntry};

use crate::ctrlc;

pub struct CompressArgs {
    pub path: PathBuf,
    pub mode: CompressionMode,
    /// The *only* write switch (ADV-N4).
    pub execute: bool,
    /// ADV-N7 second confirmation.
    pub yes: bool,
    pub threads: Option<usize>,
    /// Throughput cap in MiB/s.
    pub rate_limit: Option<u64>,
    /// Override the executor's *format* skips (never the path exclusions).
    pub force: bool,
    pub min_size_kb: u64,
    pub config_dir: Option<PathBuf>,
    pub json: bool,
}

/// Scan `path` and apply the predictor's final veto (card D1: the rule
/// engine only narrows the candidate set, the predictor decides).
///
/// Read-only — nothing is written.
pub fn collect_candidates(path: &Path) -> Result<(Vec<FileEntry>, u64, u64)> {
    let scan_res = scan::scan(path, &Default::default())?;
    let prediction = predict(&scan_res, &PredictOptions::default())?;
    let mut skip_verdicts: BTreeMap<String, bool> = BTreeMap::new();
    for c in &prediction.classes {
        skip_verdicts.insert(c.ext.clone(), c.verdict == Verdict::Skip);
    }
    let mut kept: Vec<FileEntry> = Vec::new();
    let mut vetoed = 0u64;
    for f in &scan_res.files {
        if skip_verdicts.get(&f.ext).copied().unwrap_or(false) {
            vetoed += 1;
            continue;
        }
        kept.push(f.clone());
    }
    Ok((kept, vetoed, scan_res.total_bytes))
}

pub fn run(args: CompressArgs) -> Result<()> {
    let opts = CompressOptions {
        mode: args.mode,
        threads: args.threads,
        rate_limit_mb_s: args.rate_limit,
        cancel: None,
        progress: None,
        force: args.force,
        min_size_bytes: args.min_size_kb.saturating_mul(1024),
    };

    let (candidates, vetoed, scanned_bytes) = collect_candidates(&args.path)?;
    let plan = ntfs::plan_compression(&candidates, &opts);

    if !args.execute {
        print_plan(&args, &plan, vetoed, scanned_bytes)?;
        return Ok(());
    }

    // ADV-N7: a large batch needs the second confirmation.
    let threshold_gb = confirm_threshold_gb(&args.config_dir)?;
    let threshold_bytes = threshold_gb.saturating_mul(1024 * 1024 * 1024);
    if plan.bytes > threshold_bytes && !args.yes {
        bail!(
            "ADV-N7 二次确认: 批次总量 {} 超过阈值 {} GB —— 确认无误请追加 --yes 再执行",
            format_bytes(plan.bytes),
            threshold_gb
        );
    }

    if plan.files.is_empty() {
        println!("没有可处理的文件（全部被规则/预测器/执行器跳过）——磁盘零改动");
        return Ok(());
    }

    println!(
        "{}: {} 个文件 / {}（跳过 {} 个）——异步执行中，Ctrl-C 可安全中断并续做",
        args.mode.label(),
        plan.files.len(),
        format_bytes(plan.bytes),
        plan.skipped_total
    );

    let stats = execute(plan.files, opts, args.json)?;
    print_stats(&stats, args.json);
    Ok(())
}

/// Run the batch on a worker thread while the terminal keeps rendering
/// progress. Shared by `compress` / `decompress` and `run --rule`.
pub fn execute(files: Vec<FileEntry>, opts: CompressOptions, json: bool) -> Result<CompressStats> {
    ctrlc::install();
    ctrlc::reset();

    let rate_limit = opts.rate_limit_mb_s;
    let handle = CompressHandle::spawn(files, opts);
    let mut last_render = Instant::now() - Duration::from_secs(1);
    let mut announced = false;

    loop {
        let snap = handle.progress();
        if !json && last_render.elapsed() >= Duration::from_millis(200) {
            render_progress(&snap, rate_limit);
            last_render = Instant::now();
        }
        if ctrlc::cancel_requested() && !handle.is_cancelled() {
            handle.cancel();
            if !json && !announced {
                println!(
                    "\n收到中断信号——将在当前文件处理完后停止；重新运行同一命令即可续做（已压缩文件会被跳过）。"
                );
                announced = true;
            }
        }
        if handle.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(80));
    }

    let stats = handle.join()?;
    if !json {
        println!();
    }
    Ok(stats)
}

/// Live progress line: **file count and byte count** side by side.
fn render_progress(snap: &ProgressSnapshot, rate_limit: Option<u64>) {
    let fpct = (snap.files_fraction() * 100.0).round() as u64;
    let bpct = (snap.bytes_fraction() * 100.0).round() as u64;
    let cap = match rate_limit {
        Some(mb) => format!(" 限速 {mb} MiB/s"),
        None => String::new(),
    };
    let current = match &snap.current {
        Some(p) => format!(" · {}", short_tail(p)),
        None => String::new(),
    };
    print!(
        "\r  文件 {}/{} ({fpct}%)  字节 {}/{} ({bpct}%){cap}{current}   ",
        snap.files_done,
        snap.files_total,
        format_bytes(snap.bytes_done),
        format_bytes(snap.bytes_total),
    );
    let _ = std::io::stdout().flush();
}

/// Last two path components — enough to tell files apart, short enough
/// for one line.
fn short_tail(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit(['\\', '/']).take(2).collect();
    let mut it = parts.into_iter().rev();
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => format!("{b}\\{a}"),
        (Some(a), None) => a.to_string(),
        _ => path.to_string(),
    }
}

fn print_plan(
    args: &CompressArgs,
    plan: &CompressPlan,
    vetoed: u64,
    scanned_bytes: u64,
) -> Result<()> {
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "mode": args.mode.as_display(),
                "dry_run": true,
                "scanned_bytes": scanned_bytes,
                "predictor_vetoed": vetoed,
                "candidates": plan.files.len(),
                "candidate_bytes": plan.bytes,
                "skipped": plan.skipped_total,
                "skipped_by_reason": plan.skipped_by_reason,
            }))?
        );
        return Ok(());
    }
    println!(
        "DRY-RUN（默认只读；--execute 才会写盘——ADV-N4）: {} — {}",
        args.mode.label(),
        args.path.display()
    );
    println!(
        "  扫描 {}（{}）",
        format_bytes(scanned_bytes),
        args.path.display()
    );
    println!(
        "  候选: {} 个文件 / {}（预测器否决 {} 个；执行器级跳过 {} 个）",
        plan.files.len(),
        format_bytes(plan.bytes),
        vetoed,
        plan.skipped_total
    );
    for (reason, count) in &plan.skipped_by_reason {
        println!("    跳过 {count} 个 — {reason}");
    }
    for f in plan.files.iter().take(5) {
        println!("    例: {}", f.path.display());
    }
    if plan.files.len() > 5 {
        println!("    … 其余 {} 个", plan.files.len() - 5);
    }
    println!("  本次运行磁盘零改动（dry-run 语义）");
    Ok(())
}

pub fn print_stats(stats: &CompressStats, json: bool) {
    if json {
        println!("{}", serde_json::to_string(stats).unwrap_or_default());
        return;
    }
    println!();
    println!(
        "{}完成: 处理 {} 个文件 / {}（{} 个跳过，{} 个失败）",
        if stats.mode == "enable" {
            "压缩"
        } else {
            "解除压缩"
        },
        stats.files_processed,
        format_bytes(stats.bytes_processed),
        stats.files_skipped,
        stats.files_failed
    );
    if stats.files_processed > 0 {
        println!(
            "  实测压缩比: {:.2}:1（逻辑 {} → 磁盘 {}，节省 {}）",
            stats.ratio(),
            format_bytes(stats.bytes_processed),
            format_bytes(stats.bytes_on_disk),
            format_bytes(stats.bytes_saved().max(0) as u64)
        );
    }
    println!(
        "  用时 {} ms{}",
        stats.duration_ms,
        if stats.cancelled {
            "（已按中断请求停止——重新运行同一命令即可续做）"
        } else {
            ""
        }
    );
    for (reason, count) in &stats.skipped_by_reason {
        println!("  跳过 {count} 个 — {reason}");
    }
    for f in stats.failures.iter().take(10) {
        println!("  失败: {} — {}", f.path, f.error);
    }
    if stats.failures.len() > 10 {
        println!("  … 其余 {} 个失败", stats.failures.len() - 10);
    }
}

/// ADV-N7 threshold from the app config (default 10 GB).
fn confirm_threshold_gb(dir: &Option<PathBuf>) -> Result<u64> {
    let base = match dir {
        Some(d) => d.clone(),
        None => config_dir(),
    };
    let (cfg, _source) = load_config(&base)?;
    Ok(cfg.confirm_threshold_gb)
}
