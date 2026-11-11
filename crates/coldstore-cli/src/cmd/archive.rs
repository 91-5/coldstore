//! `coldstore archive` — write a .coldstore container (sources untouched).

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::{archive, predict::format_bytes, scan};

pub struct ArchiveArgs {
    pub path: PathBuf,
    pub output: PathBuf,
    pub include_ext: Vec<String>,
    pub min_size_kb: u64,
    pub sidecar: bool,
    pub json: bool,
}

pub fn run(args: ArchiveArgs) -> Result<()> {
    let scan_res = scan::scan(&args.path, &Default::default())?;
    let include: Vec<String> = args
        .include_ext
        .iter()
        .map(|s| s.trim().to_lowercase())
        .collect();
    let out_lower = args.output.to_string_lossy().to_lowercase();
    let tmp_lower = format!("{out_lower}.tmp");
    let idx_lower = format!("{out_lower}.idx");
    let excluded_self = scan_res
        .files
        .iter()
        .filter(|f| {
            let p = f.path.to_string_lossy().to_lowercase();
            p == out_lower
                || p == tmp_lower
                || p == idx_lower
                || p.starts_with(&format!("{out_lower}."))
        })
        .count();
    if excluded_self > 0 {
        eprintln!("⚠ 已排除 {excluded_self} 个与容器自身重名的文件");
    }
    let picked: Vec<&scan::FileEntry> = scan_res
        .files
        .iter()
        .filter(|f| {
            let p = f.path.to_string_lossy().to_lowercase();
            if p == out_lower
                || p == tmp_lower
                || p == idx_lower
                || p.starts_with(&format!("{out_lower}."))
            {
                return false;
            }
            if !include.is_empty() && !include.contains(&f.ext) {
                return false;
            }
            f.size >= args.min_size_kb * 1024
        })
        .collect();
    let picked: Vec<scan::FileEntry> = picked.into_iter().cloned().collect();
    let opts = archive::ArchiveOptions {
        sidecar: args.sidecar,
        ..Default::default()
    };
    let stats = archive::archive(&picked, &args.output, &opts)?;
    if args.json {
        println!("{}", serde_json::to_string(&stats)?);
    } else {
        print_archive(&stats);
    }
    Ok(())
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
