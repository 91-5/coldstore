//! `coldstore verify` — full-container frame decode + SHA-256 check.

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::archive;
use coldstore_core::predict::format_bytes;

pub struct VerifyArgs {
    pub container: PathBuf,
    pub threads: Option<usize>,
    pub json: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let opts = archive::VerifyOptions {
        threads: args.threads,
    };
    let stats = archive::verify_with(&args.container, &opts)?;
    if args.json {
        println!("{}", serde_json::to_string(&stats)?);
    } else {
        print_verify(&stats);
    }
    std::process::exit(if stats.ok { 0 } else { 1 });
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
