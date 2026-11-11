//! `coldstore quarantine` — list / delete / recover (card D6).
//!
//! `delete` requires `--confirm` (hard rule 3: never a silent deletion).
//! `recover` resolves an interrupted batch: `--continue` resumes, `--abort`
//! rolls everything back (B13, Q8).

use anyhow::{bail, Result};

use coldstore_core::predict::format_bytes;
use coldstore_core::quarantine::{self, QuarantineConfig, RecoverMode};
use coldstore_core::rules::toml::{load_config, AppConfig};

pub enum QuarantineCmd {
    List,
    Delete {
        batch: String,
        confirm: bool,
    },
    Recover {
        batch: String,
        cont: bool,
        abort: bool,
    },
}

pub fn run(cmd: QuarantineCmd) -> Result<()> {
    let cfg = load_default()?;
    let mut qcfg = QuarantineConfig::resolve(&cfg.quarantine)?;
    // CLI overrides (test seams / power users)
    if let Ok(r) = std::env::var("COLDSTORE_QROOT") {
        qcfg.root = std::path::absolute(r)?;
    }
    if let Ok(j) = std::env::var("COLDSTORE_JDIR") {
        qcfg.journal_dir = std::path::absolute(j)?;
    }
    match cmd {
        QuarantineCmd::List => list(&qcfg),
        QuarantineCmd::Delete { batch, confirm } => delete(&batch, confirm, &qcfg),
        QuarantineCmd::Recover { batch, cont, abort } => {
            if cont == abort {
                bail!("quarantine recover 需要 --continue 或 --abort（二者选一）");
            }
            let mode = if cont {
                RecoverMode::Continue
            } else {
                RecoverMode::Abort
            };
            let msg = quarantine::recover_batch(&batch, mode, &qcfg)?;
            println!("{msg}");
            Ok(())
        }
    }
}

fn load_default() -> Result<AppConfig> {
    let base = coldstore_core::rules::toml::config_dir();
    Ok(load_config(&base)?.0)
}

fn list(qcfg: &QuarantineConfig) -> Result<()> {
    let infos = quarantine::quarantine_list(qcfg)?;
    if infos.is_empty() {
        println!("隔离区为空（无批次）");
        return Ok(());
    }
    let total: u64 = infos.iter().map(|i| i.bytes_still_occupied).sum();
    println!(
        "隔离区（{}）: {} 个批次，仍占用 {}（硬约束 4：归档≠释放，空间以 delete 为准）",
        qcfg.root.display(),
        infos.len(),
        format_bytes(total)
    );
    for i in &infos {
        println!(
            "  [{}] {}   占用 {}（{} 个文件）   创建 {}   保留期至 {}{}",
            i.status,
            i.batch_id,
            format_bytes(i.bytes_still_occupied),
            i.files_moved,
            i.created_date,
            i.expires_date,
            if i.expired {
                "（已过期——不会自动删除）"
            } else {
                ""
            }
        );
        if !i.sources.is_empty() {
            for src in &i.sources {
                println!("      来源: {src}");
            }
        }
        if !i.note.is_empty() {
            println!("      {}", i.note);
        }
    }
    Ok(())
}

fn delete(batch: &str, confirm: bool, qcfg: &QuarantineConfig) -> Result<()> {
    if !confirm {
        let infos = quarantine::quarantine_list(qcfg)?;
        let Some(info) = infos.iter().find(|i| i.batch_id == batch) else {
            bail!("批次不存在: {batch}");
        };
        bail!(
            "硬约束 3：绝不静默删除。批次 {batch} 占用 {}（{} 个文件，保留期至 {}）——\
             确认无误请追加 --confirm 执行释放",
            format_bytes(info.bytes_still_occupied),
            info.files_moved,
            info.expires_date
        );
    }
    let freed = quarantine::quarantine_delete(batch, qcfg)?;
    println!(
        "已释放批次 {batch}：回收 {}（空间已真正下降——B10）",
        format_bytes(freed)
    );
    Ok(())
}
