//! ColdStore CLI front-end.
//!
//! Hard rule (card OC-20261110-001 §6.1): scan / predict are read-only and
//! never write to disk; error output always carries path + reason.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use coldstore_core::predict::{self, format_bytes, PredictionReport, Verdict};
use coldstore_core::scan::{self, ScanResult};
use coldstore_core::{archive, dedupe};

#[derive(Parser)]
#[command(
    name = "coldstore",
    version,
    about = "ColdStore 引擎 CLI —— 默认只读，绝不删除用户文件"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 只读扫描：枚举文件元数据，跳过项全部带原因
    Scan {
        path: PathBuf,
        /// 输出完整 JSON（供规则引擎/TUI 消费）
        #[arg(long)]
        json: bool,
        /// 显式允许跟随的 junction 路径前缀（默认不跟随）
        #[arg(long = "follow-junction", value_name = "PATH")]
        follow_junction: Vec<PathBuf>,
    },
    /// 收益预测：先算账再动手，不写任何盘
    Predict {
        path: PathBuf,
        /// 每类抽样预算上限（默认 8）
        #[arg(long)]
        sample: Option<usize>,
        /// 候选文件最小体积（KB，默认 256）
        #[arg(long, default_value_t = 256)]
        min_candidate_kb: u64,
        /// 输出完整 JSON（逐字节可复现）
        #[arg(long)]
        json: bool,
    },
    /// 去重识别：大小分桶 + SHA-256，只出计划、绝不执行（执行属 002 执行层）
    Dedupe {
        path: PathBuf,
        /// 兼容卡片 CLI 形态；001 的 dedupe 本就永远 plan-only
        #[arg(long)]
        plan_only: bool,
        /// 入桶最小体积（KB，默认 4）
        #[arg(long, default_value_t = 4)]
        min_size_kb: u64,
        /// 保留策略：oldest（默认）/ newest / 指定保留路径
        #[arg(long)]
        keep: Option<String>,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 归档：写入 .coldstore 容器（独立 zstd 帧 + 内嵌索引；不动源文件）
    Archive {
        path: PathBuf,
        /// 容器输出路径
        #[arg(short, long = "output")]
        output: PathBuf,
        /// 只归档这些扩展名（逗号分隔，如 rlib,pdb）
        #[arg(long = "include-ext", value_delimiter = ',')]
        include_ext: Vec<String>,
        /// 最小体积（KB，0=不限）
        #[arg(long, default_value_t = 0)]
        min_size_kb: u64,
        /// 同时写派生 sidecar .idx 缓存（内嵌索引仍为唯一事实源）
        #[arg(long)]
        sidecar: bool,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 单文件取回：只解压目标帧，SHA-256 校验后落盘
    Extract {
        container: PathBuf,
        /// 序号（数字）或路径（大小写不敏感）
        #[arg(long)]
        key: String,
        /// 显式目标路径（任意卷均可）
        #[arg(short = 'd', long = "dest")]
        dest: Option<PathBuf>,
        /// 还原到记录的原路径（跨卷将被拒绝——AV-5）
        #[arg(long)]
        to_original: bool,
    },
    /// 列出容器内容（索引 fail-closed）
    List {
        container: PathBuf,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 全量校验：逐帧解码 + SHA-256 比对
    Verify {
        container: PathBuf,
        /// 并行校验线程数（默认 = 全局线程池）
        #[arg(long)]
        threads: Option<usize>,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("错误: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Scan {
            path,
            json,
            follow_junction,
        } => {
            let opts = scan::ScanOptions {
                follow_junction,
                ..Default::default()
            };
            let res = scan::scan(&path, &opts)?;
            if json {
                println!("{}", serde_json::to_string(&res)?);
            } else {
                print_scan(&res);
            }
            Ok(())
        }
        Cmd::Predict {
            path,
            sample,
            min_candidate_kb,
            json,
        } => {
            let scan_res = scan::scan(&path, &Default::default())?;
            let mut opts = predict::PredictOptions::default();
            if let Some(s) = sample {
                opts.per_class_sample_budget = s;
            }
            opts.min_candidate_bytes = min_candidate_kb * 1024;
            let report = predict::predict(&scan_res, &opts)?;
            if json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print_predict(&report);
            }
            Ok(())
        }
        Cmd::Dedupe {
            path,
            plan_only,
            min_size_kb,
            keep,
            json,
        } => {
            let _ = plan_only; // 001 的 dedupe 只出计划，永远 plan-only
            let scan_res = scan::scan(&path, &Default::default())?;
            let policy = match keep.as_deref() {
                None | Some("oldest") => dedupe::KeepPolicy::Oldest,
                Some("newest") => dedupe::KeepPolicy::Newest,
                Some(p) => dedupe::KeepPolicy::KeepPath(PathBuf::from(p)),
            };
            let opts = dedupe::DedupeOptions {
                min_size: min_size_kb * 1024,
                policy,
            };
            let plan = dedupe::dedupe(&scan_res, &opts)?;
            if json {
                println!("{}", serde_json::to_string(&plan)?);
            } else {
                print_dedupe(&plan);
            }
            Ok(())
        }
        Cmd::Archive {
            path,
            output,
            include_ext,
            min_size_kb,
            sidecar,
            json,
        } => {
            let scan_res = scan::scan(&path, &Default::default())?;
            let include: Vec<String> = include_ext
                .iter()
                .map(|s| s.trim().to_lowercase())
                .collect();
            let out_lower = output.to_string_lossy().to_lowercase();
            let tmp_lower = format!("{out_lower}.tmp");
            let excluded_self = scan_res
                .files
                .iter()
                .filter(|f| {
                    let p = f.path.to_string_lossy().to_lowercase();
                    p == out_lower || p == tmp_lower || p.starts_with(&format!("{out_lower}."))
                })
                .count();
            if excluded_self > 0 {
                eprintln!("⚠ 已排除 {excluded_self} 个与容器自身重名的文件");
            }
            let picked: Vec<&coldstore_core::scan::FileEntry> = scan_res
                .files
                .iter()
                .filter(|f| {
                    let p = f.path.to_string_lossy().to_lowercase();
                    if p == out_lower || p == tmp_lower || p.starts_with(&format!("{out_lower}.")) {
                        return false;
                    }
                    if !include.is_empty() && !include.contains(&f.ext) {
                        return false;
                    }
                    f.size >= min_size_kb * 1024
                })
                .collect();
            let picked: Vec<coldstore_core::scan::FileEntry> =
                picked.into_iter().cloned().collect();
            let opts = archive::ArchiveOptions {
                sidecar,
                ..Default::default()
            };
            let stats = archive::archive(&picked, &output, &opts)?;
            if json {
                println!("{}", serde_json::to_string(&stats)?);
            } else {
                print_archive(&stats);
            }
            Ok(())
        }
        Cmd::Extract {
            container,
            key,
            dest,
            to_original,
        } => {
            let parsed = if key.chars().all(|c| c.is_ascii_digit()) {
                archive::EntryKey::Ordinal(key.parse::<u64>()?)
            } else {
                archive::EntryKey::Path(key)
            };
            let outcome = match dest {
                Some(d) => archive::retrieve(&container, &parsed, &d)?,
                None if to_original => archive::retrieve_to_original(&container, &parsed)?,
                None => anyhow::bail!(
                    "必须提供 -d/--dest 或 --to-original（拒绝把取回目标猜到默认位置）"
                ),
            };
            println!(
                "取回完成: 条目 {} ← {} → {}（{} 字节，压缩 {} 字节，SHA-256 {}，耗时 {} ms）",
                outcome.ordinal,
                outcome.source_path,
                outcome.dest,
                outcome.size,
                outcome.compressed_size,
                if outcome.sha_verified {
                    "已校验一致"
                } else {
                    "UNVERIFIED（无哈希）"
                },
                outcome.elapsed_ms
            );
            Ok(())
        }
        Cmd::List { container, json } => {
            let (_file, header, idx) = archive::open_container(&container)?;
            if json {
                println!("{}", serde_json::to_string(&(&header, &idx))?);
            } else {
                print_list(&header, &idx);
            }
            Ok(())
        }
        Cmd::Verify {
            container,
            threads,
            json,
        } => {
            let opts = archive::VerifyOptions { threads };
            let stats = archive::verify_with(&container, &opts)?;
            if json {
                println!("{}", serde_json::to_string(&stats)?);
            } else {
                print_verify(&stats);
            }
            std::process::exit(if stats.ok { 0 } else { 1 });
        }
    }
}

fn print_archive(stats: &archive::ArchiveStats) {
    println!(
        "归档完成: {}（索引模式 {}）",
        stats.container, stats.index_mode
    );
    println!(
        "  帧数 {}   原始 {} → 压缩 {}（占比 {:.1}%）   容器 {}   最长窗口 {}   耗时 {} ms",
        stats.frame_count,
        format_bytes(stats.total_original),
        format_bytes(stats.total_compressed),
        if stats.total_original > 0 {
            stats.total_compressed as f64 / stats.total_original as f64 * 100.0
        } else {
            0.0
        },
        format_bytes(stats.container_size),
        stats.max_window_log,
        stats.duration_ms
    );
    println!("  源文件未移动、未删除（可逆执行属 002 执行层）");
    if stats.sidecar_written {
        println!("  sidecar .idx 已写入（派生缓存；内嵌索引仍为唯一事实源）");
    }
}

fn print_list(header: &archive::ContainerHeader, idx: &archive::ArchiveIndex) {
    println!(
        "容器 {} 帧共 {} 个（{}），索引条目 {} 条:",
        header.frame_count,
        header.frame_count,
        if header.index_embedded {
            "内嵌索引权威"
        } else {
            "sidecar 权威"
        },
        idx.entries.len()
    );
    println!(
        "  {:>4}  {:>10}  {:>10}  {:>12}  {:<14}  路径",
        "#", "原始", "压缩", "offset", "sha256[:12]"
    );
    for e in &idx.entries {
        println!(
            "  {:>4}  {:>10}  {:>10}  {:>12}  {:<14}  {}",
            e.ordinal,
            format_bytes(e.size),
            format_bytes(e.compressed_size),
            e.offset,
            e.sha256_hex
                .as_deref()
                .unwrap_or("UNVERIFIED")
                .get(..12)
                .unwrap_or(""),
            e.path
        );
    }
}

fn print_verify(stats: &archive::VerifyStats) {
    println!(
        "校验完成: {}   帧数 {}   已检 {} 条   原始 {} / 压缩 {}",
        stats.container,
        stats.frame_count,
        stats.entries_checked,
        format_bytes(stats.total_original),
        format_bytes(stats.total_compressed)
    );
    println!(
        "  SHA-256 失败 {}   体积不符 {}   UNVERIFIED {}   结论: {}   耗时 {} ms",
        stats.sha_failures,
        stats.size_failures,
        stats.unverified_entries,
        if stats.ok {
            "全部通过 ✓"
        } else {
            "存在失败 ✗"
        },
        stats.duration_ms
    );
    for f in &stats.failures {
        println!("    - {f}");
    }
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
            fmt_time(g.keep.modified)
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

/// Human-readable mtime for plan output (epoch seconds; "未知" when absent).
fn fmt_time(t: Option<std::time::SystemTime>) -> String {
    match t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
        Some(d) => format!("{} s", d.as_secs()),
        None => "未知".to_string(),
    }
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

fn print_predict(report: &PredictionReport) {
    let s = &report.summary;
    println!(
        "收益预测（策略 {}，zstd {}）: {}",
        report.policy_version, report.zstd_version, report.root
    );
    println!(
        "  扫描: {} 个文件 / {}   类别: {} 个",
        report.scanned_files,
        format_bytes(report.scanned_bytes),
        report.classes.len()
    );
    println!(
        "  预计可省: {} – {}（仅 ARCHIVE 类累计，基于实测压缩比）",
        format_bytes(s.est_savings_low),
        format_bytes(s.est_savings_high)
    );
    println!(
        "  判定分布: ARCHIVE {} / SKIP {} / UNSURE {} / DELETABLE {}",
        s.archive_classes, s.skip_classes, s.unsure_classes, s.deletable_classes
    );
    println!();
    for c in &report.classes {
        let verdict = match c.verdict {
            Verdict::Deletable => "DELETABLE",
            Verdict::Archive => "ARCHIVE",
            Verdict::Skip => "SKIP",
            Verdict::Unsure => "UNSURE",
        };
        println!(
            "  [{verdict}] {} — 文件 {} / 体积 {} / 样本 {}{}",
            c.ext,
            c.total_files,
            format_bytes(c.total_bytes),
            c.sample_count,
            if c.failed_samples > 0 {
                format!("（{} 个样本读取失败）", c.failed_samples)
            } else {
                String::new()
            }
        );
        println!("      理由: {}", c.reason);
    }
}
