//! `coldstore quarantine` — list / restore / delete / recover (card D6).
//!
//! `delete` requires `--confirm` (hard rule 3: never a silent deletion).
//! `recover` resolves an interrupted batch: `--continue` resumes, `--abort`
//! rolls everything back (B13, Q8).
//! `restore` puts a batch's files back where they came from while keeping
//! the archive container — the difference to `undo` is deliberate:
//!
//! - `undo <batch>` = **complete reversal**: the files go back *and* the
//!   archive container is removed (the archive operation is undone);
//! - `quarantine restore <batch>` = the files go back *and* the container
//!   stays on disk, so the verified copy is still there as a safety net.
//!
//! Both go through the same audited, journaled sequence function
//! (`quarantine::undo_batch_with`) — this command adds no new mutation path.

use anyhow::{bail, Result};
use serde::Serialize;

use coldstore_core::predict::format_bytes;
use coldstore_core::quarantine::{self, QuarantineConfig, RecoverMode};
use coldstore_core::rules::toml::{load_config, AppConfig};

pub enum QuarantineCmd {
    List {
        json: bool,
    },
    Restore {
        batch: String,
        /// Keep the archive container (default for this subcommand).
        keep_container: bool,
        json: bool,
    },
    Delete {
        batch: String,
        confirm: bool,
        json: bool,
    },
    Recover {
        batch: String,
        cont: bool,
        abort: bool,
        json: bool,
    },
}

/// Machine-readable shape of `quarantine list`.
#[derive(Serialize)]
struct ListReport<'a> {
    root: String,
    batches: u64,
    bytes_still_occupied: u64,
    note: String,
    items: &'a [coldstore_core::quarantine::BatchInfo],
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
        QuarantineCmd::List { json } => list(&qcfg, json),
        QuarantineCmd::Restore {
            batch,
            keep_container,
            json,
        } => restore(&batch, keep_container, &qcfg, json),
        QuarantineCmd::Delete {
            batch,
            confirm,
            json,
        } => delete(&batch, confirm, &qcfg, json),
        QuarantineCmd::Recover {
            batch,
            cont,
            abort,
            json,
        } => {
            if cont == abort {
                bail!("quarantine recover 需要 --continue 或 --abort（二者选一）");
            }
            let mode = if cont {
                RecoverMode::Continue
            } else {
                RecoverMode::Abort
            };
            let msg = quarantine::recover_batch(&batch, mode, &qcfg)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "batch": batch,
                        "mode": if cont { "continue" } else { "abort" },
                        "message": msg,
                    })
                );
            } else {
                println!("{msg}");
            }
            Ok(())
        }
    }
}

fn load_default() -> Result<AppConfig> {
    let base = coldstore_core::rules::toml::config_dir();
    Ok(load_config(&base)?.0)
}

fn list(qcfg: &QuarantineConfig, json: bool) -> Result<()> {
    let infos = quarantine::quarantine_list(qcfg)?;
    let total: u64 = infos.iter().map(|i| i.bytes_still_occupied).sum();
    if json {
        let report = ListReport {
            root: qcfg.root.display().to_string(),
            batches: infos.len() as u64,
            bytes_still_occupied: total,
            note: "隔离区仍占用空间——归档≠释放，空间以 delete 为准（硬约束 4）".to_string(),
            items: &infos,
        };
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    if infos.is_empty() {
        println!("隔离区为空（无批次）");
        return Ok(());
    }
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

/// Put a batch's files back where they came from.
///
/// `keep_container` defaults to **true** here (that is what makes this
/// "restore" rather than "undo"): the archive container stays on disk as a
/// verified safety net. `--remove-container` turns it into a complete
/// reversal instead.
fn restore(batch: &str, keep_container: bool, qcfg: &QuarantineConfig, json: bool) -> Result<()> {
    let stats = quarantine::undo_batch_with(batch, qcfg, keep_container)?;
    if json {
        println!("{}", serde_json::to_string(&stats)?);
        return Ok(());
    }
    let container_note = if !stats.container_kept.is_empty() {
        format!("已保留: {}", stats.container_kept)
    } else if stats.container_removed {
        "已移除".to_string()
    } else {
        "不存在/已清理".to_string()
    };
    println!(
        "已取回批次 {}: {} 个文件回到原路径（SHA-256 一致），隔离区对应项已清除，容器{}",
        batch, stats.restored, container_note
    );
    if stats.conflicts > 0 {
        bail!(
            "发现 {} 处取回冲突（ADV-N3）——以下文件在隔离期内被修改，隔离区副本已保留、\
             原文件未被覆盖，请人工处理: {}",
            stats.conflicts,
            stats.conflict_files.join("; ")
        );
    }
    Ok(())
}

fn delete(batch: &str, confirm: bool, qcfg: &QuarantineConfig, json: bool) -> Result<()> {
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
    if json {
        println!(
            "{}",
            serde_json::json!({
                "batch": batch,
                "freed_bytes": freed,
                "note": "空间已真正下降（B10）",
            })
        );
        return Ok(());
    }
    println!(
        "已释放批次 {batch}：回收 {}（空间已真正下降——B10）",
        format_bytes(freed)
    );
    Ok(())
}
