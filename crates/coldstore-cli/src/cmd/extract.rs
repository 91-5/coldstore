//! `coldstore extract` — single-frame retrieval with SHA-256 verification.

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::archive;

pub struct ExtractArgs {
    pub container: PathBuf,
    pub key: String,
    pub dest: Option<PathBuf>,
    pub to_original: bool,
    /// Machine-readable output (card D6: every subcommand supports --json).
    pub json: bool,
}

pub fn run(args: ExtractArgs) -> Result<()> {
    let parsed = if args.key.chars().all(|c| c.is_ascii_digit()) {
        archive::EntryKey::Ordinal(args.key.parse::<u64>()?)
    } else {
        archive::EntryKey::Path(args.key)
    };
    let outcome = match args.dest {
        Some(d) => archive::retrieve(&args.container, &parsed, &d)?,
        None if args.to_original => archive::retrieve_to_original(&args.container, &parsed)?,
        None => anyhow::bail!("必须提供 -d/--dest 或 --to-original（拒绝把取回目标猜到默认位置）"),
    };
    if args.json {
        println!("{}", serde_json::to_string(&outcome)?);
        return Ok(());
    }
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
