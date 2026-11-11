//! `coldstore undo <batch-id>` — restore a batch (card D6, B12).
//!
//! ADV-N3: a source modified during the quarantine window is NEVER
//! overwritten — the conflict is reported and the quarantine copy kept.

use anyhow::{bail, Result};

use coldstore_core::quarantine::{self, QuarantineConfig};
use coldstore_core::rules::toml::load_config;

pub struct UndoArgs {
    pub batch: String,
}

pub fn run(args: UndoArgs) -> Result<()> {
    let base = coldstore_core::rules::toml::config_dir();
    let cfg = load_config(&base)?.0;
    let mut qcfg = QuarantineConfig::resolve(&cfg.quarantine)?;
    if let Ok(r) = std::env::var("COLDSTORE_QROOT") {
        qcfg.root = std::path::absolute(r)?;
    }
    if let Ok(j) = std::env::var("COLDSTORE_JDIR") {
        qcfg.journal_dir = std::path::absolute(j)?;
    }

    let stats = quarantine::undo_batch(&args.batch, &qcfg)?;
    println!(
        "撤销批次 {}: 还原 {} 个文件到原路径（SHA-256 一致），隔离区对应项已清除，容器{}",
        args.batch,
        stats.restored,
        if stats.container_removed {
            "已移除"
        } else {
            "不存在/已清理"
        }
    );
    if stats.conflicts > 0 {
        bail!(
            "发现 {} 处撤销冲突（ADV-N3）——以下文件在隔离期内被修改，隔离区副本已保留、\
             原文件未被覆盖，请人工处理: {}",
            stats.conflicts,
            stats.conflict_files.join("; ")
        );
    }
    Ok(())
}
