//! `coldstore predict` — gain prediction, writes nothing.

use std::path::PathBuf;

use anyhow::Result;

use coldstore_core::predict::{self, format_bytes, PredictionReport, Verdict};
use coldstore_core::scan;

pub struct PredictArgs {
    pub path: PathBuf,
    pub sample: Option<usize>,
    pub min_candidate_kb: u64,
    pub json: bool,
}

pub fn run(args: PredictArgs) -> Result<()> {
    let scan_res = scan::scan(&args.path, &Default::default())?;
    let mut opts = predict::PredictOptions::default();
    if let Some(s) = args.sample {
        opts.per_class_sample_budget = s;
    }
    opts.min_candidate_bytes = args.min_candidate_kb * 1024;
    let report = predict::predict(&scan_res, &opts)?;
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        print_predict(&report);
    }
    Ok(())
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
