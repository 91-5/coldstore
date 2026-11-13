//! `coldstore list` — container contents (fail-closed index).

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::archive::{self, ArchiveIndex, ContainerHeader};
use coldstore_core::predict::format_bytes;

pub struct ListArgs {
    pub container: PathBuf,
    pub json: bool,
}

pub fn run(args: ListArgs) -> Result<()> {
    let (_file, header, idx) = archive::open_container(&args.container)?;
    if args.json {
        println!("{}", serde_json::to_string(&(&header, &idx))?);
    } else {
        print_list(&header, &idx);
    }
    Ok(())
}

fn print_list(header: &ContainerHeader, idx: &ArchiveIndex) {
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
