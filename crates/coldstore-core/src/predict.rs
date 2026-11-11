//! Compression gain predictor — the product's core: *measure before acting*.
//!
//! Layered judgment, cheapest first (card D3):
//!
//! 1. **extension pre-filter**: known incompressible types (png, mp4, zip…)
//!    are skipped without any sampling — measured real-corpus ratios for
//!    these are ≈0.9–1.0 (png 100.0%, mp3 92.9%), so "compress everything"
//!    would gain nothing;
//! 2. **magic re-check**: a pre-filtered file whose *content* is not an
//!    incompressible kind is an "extension lie" and re-enters sampling; a
//!    normal-extension file whose content IS a compressed container is
//!    excluded from candidates;
//! 3. **stratified sampling** (AV-1): candidates per extension class are
//!    sorted by (size, path), split into three *volume* bands (small /
//!    medium / large), and the per-class sample budget scales with class
//!    volume up to a configurable cap. Sample picks use a midpoint rule —
//!    fully deterministic (AV-7), never HashMap-order;
//! 4. **volume-weighted extrapolation** with a confidence interval:
//!    savings = candidate volume × (1 − ratio), reported as an interval
//!    [low, high]. A class is downgraded to `UNSURE` when samples < 3
//!    (card hard rule 9), when the interval straddles zero gain, or when
//!    the interval spans an order of magnitude.
//!
//! Reproducibility (card B9): grouping uses a `BTreeMap`, samples are
//! picked from sorted vectors, ratios are reduced serially in fixed order,
//! and the report contains no timestamps — two runs over the same tree
//! produce byte-identical JSON.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;

use crate::magic::MagicKind;
use crate::scan::{CachePathCheck, FileEntry, ScanResult, CACHE_DIR_NAMES};

/// Card D3 layer-1 list: extensions whose real-world zstd ratios measured
/// ≈ 0.9–1.0 on the 2026-11-10 corpus (png 100.0%, mp3 92.9%).
pub const PREFILTER_INCOMPRESSIBLE_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "mp4", "mkv", "mov", "avi", "mp3", "flac", "aac", "zip",
    "7z", "rar", "gz", "bz2", "xz", "zst", "pdf", "docx", "pptx", "xlsx",
];

pub const DEFAULT_POLICY_VERSION: &str = "coldstore-predict/v0.1";
/// Per-class sample cap (card D3: "每类 ≤ 8 个样本，预算可配").
pub const DEFAULT_PER_CLASS_SAMPLE_BUDGET: usize = 8;
/// Global sample cap across all classes ("总样本预算可配").
pub const DEFAULT_TOTAL_SAMPLE_BUDGET: usize = 1024;
/// Files below this size never become archive candidates: per-file frame
/// overhead and bookkeeping dominate the possible gain.
pub const DEFAULT_MIN_CANDIDATE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;
pub const DEFAULT_LONG_WINDOW_LOG: u32 = 27;
/// Long-distance matching only pays off beyond this size; below it the
/// encoder would allocate a window buffer larger than the input.
pub const DEFAULT_LONG_WINDOW_MIN_BYTES: u64 = 4 * 1024 * 1024;
/// Card hard rule 9: fewer samples than this → `UNSURE`, never actionable.
pub const DEFAULT_MIN_CONFIDENT_SAMPLES: usize = 3;
/// AV-1: candidates are stratified into this many volume bands.
pub const VOLUME_BANDS: usize = 3;
/// Measured ratio at or above this → SKIP ("收益≈0").
const SKIP_RATIO_THRESHOLD: f64 = 0.9;
/// AV-1 downgrade: interval wider than this factor → UNSURE.
const INTERVAL_SPAN_DOWNGRADE_FACTOR: u64 = 10;

#[derive(Debug, Clone)]
pub struct PredictOptions {
    pub zstd_level: i32,
    pub long_window_log: u32,
    pub long_window_min_bytes: u64,
    pub min_candidate_bytes: u64,
    pub per_class_sample_budget: usize,
    pub total_sample_budget: usize,
    pub min_confident_samples: usize,
    pub policy_version: String,
}

impl Default for PredictOptions {
    fn default() -> Self {
        PredictOptions {
            zstd_level: DEFAULT_ZSTD_LEVEL,
            long_window_log: DEFAULT_LONG_WINDOW_LOG,
            long_window_min_bytes: DEFAULT_LONG_WINDOW_MIN_BYTES,
            min_candidate_bytes: DEFAULT_MIN_CANDIDATE_BYTES,
            per_class_sample_budget: DEFAULT_PER_CLASS_SAMPLE_BUDGET,
            total_sample_budget: DEFAULT_TOTAL_SAMPLE_BUDGET,
            min_confident_samples: DEFAULT_MIN_CONFIDENT_SAMPLES,
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
        }
    }
}

/// Card D3 verdicts, uppercase in JSON.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    /// Rebuildable cache content — deletion is safe regardless of ratio.
    Deletable,
    /// High measured gain, confident interval → suggest archiving.
    Archive,
    /// Measured gain ≈ 0 (or nothing worth measuring) → do not touch.
    Skip,
    /// Insufficient samples / interval too wide → do not touch.
    Unsure,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    High,
    Low,
}

#[derive(Debug, Serialize)]
pub struct ClassVerdict {
    /// Extension (lowercase, no dot); `"(no ext)"` for extensionless files.
    pub ext: String,
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub total_files: u64,
    pub total_bytes: u64,
    /// Files that entered the measured candidate pool (after magic and
    /// size-threshold filters).
    pub candidate_files: u64,
    pub candidate_bytes: u64,
    /// Files excluded because their magic bytes reveal a compressed
    /// container (or, for prefiltered extensions, confirm one).
    pub magic_skipped_files: u64,
    pub magic_skipped_bytes: u64,
    pub sample_count: usize,
    pub failed_samples: usize,
    /// compressed/original, 1.0 = no gain.
    pub mean_ratio: Option<f64>,
    pub ratio_interval_low: Option<f64>,
    pub ratio_interval_high: Option<f64>,
    /// Extrapolated archive savings over the candidate volume.
    pub est_savings_low: Option<u64>,
    pub est_savings_high: Option<u64>,
    /// For `DELETABLE`: the volume that deleting would free.
    pub est_delete_bytes: Option<u64>,
    /// Hard rule 8: every suggestion carries a reason.
    pub reason: String,
    pub cache_dominated: bool,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub archive_classes: u64,
    pub skip_classes: u64,
    pub unsure_classes: u64,
    pub deletable_classes: u64,
    pub est_savings_low: u64,
    pub est_savings_high: u64,
}

#[derive(Debug, Serialize)]
pub struct PredictionReport {
    pub policy_version: String,
    pub zstd_version: String,
    pub root: String,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub classes: Vec<ClassVerdict>,
    pub summary: ReportSummary,
}

/// Deterministic xorshift32 filler for test fixtures (no rand dependency).
#[cfg(test)]
pub(crate) fn xorshift_fill(buf: &mut [u8], seed: u32) {
    let mut x = seed.max(1);
    let (words, tail) = buf.as_chunks_mut::<4>();
    for chunk in words {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *chunk = x.to_le_bytes();
    }
    let mut t = 1u8;
    for byte in tail {
        *byte = t;
        t = t.wrapping_add(1);
    }
}

/// Run the prediction over a scan result. Read-only: samples are streamed
/// through zstd into a counting sink; nothing is written to disk.
pub fn predict(scan: &ScanResult, opts: &PredictOptions) -> Result<PredictionReport> {
    // Group files by extension deterministically.
    let mut classes: BTreeMap<&str, Vec<&FileEntry>> = BTreeMap::new();
    for f in &scan.files {
        let key = if f.ext.is_empty() {
            "(no ext)"
        } else {
            f.ext.as_str()
        };
        classes.entry(key).or_default().push(f);
    }

    // Pass 1: build the candidate pool of every class, then hand out the
    // global sample budget by candidate volume (largest classes first;
    // ties by extension for determinism).
    let mut works: Vec<ClassWork> = classes
        .into_iter()
        .map(|(ext, files)| ClassWork::build(ext, files, scan, opts))
        .collect();

    let mut remaining = opts.total_sample_budget.clamp(1, 4096);
    let mut order: Vec<usize> = (0..works.len()).collect();
    order.sort_by(|&a, &b| {
        works[b]
            .candidate_bytes
            .cmp(&works[a].candidate_bytes)
            .then(works[a].ext.cmp(&works[b].ext))
    });
    for &i in &order {
        let w = &mut works[i];
        if w.candidates.is_empty() {
            w.sample_budget = 0;
            continue;
        }
        let scaled = scaled_budget(w.candidate_bytes, opts.per_class_sample_budget);
        let granted = scaled.min(remaining);
        w.sample_budget = granted;
        remaining -= granted;
    }

    // Pass 2: sample, measure, and judge — output in extension order
    // (works were built in BTreeMap order and only `order` is a view).
    let mut out = Vec::with_capacity(works.len());
    for mut w in works {
        out.push(w.judge(opts));
    }

    let summary = {
        let mut s = ReportSummary {
            archive_classes: 0,
            skip_classes: 0,
            unsure_classes: 0,
            deletable_classes: 0,
            est_savings_low: 0,
            est_savings_high: 0,
        };
        for c in &out {
            match c.verdict {
                Verdict::Archive => {
                    s.archive_classes += 1;
                    s.est_savings_low += c.est_savings_low.unwrap_or(0);
                    s.est_savings_high += c.est_savings_high.unwrap_or(0);
                }
                Verdict::Skip => s.skip_classes += 1,
                Verdict::Unsure => s.unsure_classes += 1,
                Verdict::Deletable => s.deletable_classes += 1,
            }
        }
        s
    };

    Ok(PredictionReport {
        policy_version: opts.policy_version.clone(),
        zstd_version: zstd_version_string(),
        root: scan.root.display().to_string(),
        scanned_files: scan.files.len() as u64,
        scanned_bytes: scan.total_bytes,
        classes: out,
        summary,
    })
}

fn zstd_version_string() -> String {
    // Wrapped so a downstream API change has a single place to fix.
    zstd::zstd_safe::version_string().to_string()
}

struct ClassWork<'a> {
    ext: String,
    candidates: Vec<&'a FileEntry>,
    magic_skipped: Vec<&'a FileEntry>,
    below_threshold_files: u64,
    total_files: u64,
    total_bytes: u64,
    candidate_bytes: u64,
    cache_bytes: u64,
    cache_dominated: bool,
    prefiltered: bool,
    sample_budget: usize,
}

impl<'a> ClassWork<'a> {
    fn build(
        ext: &str,
        files: Vec<&'a FileEntry>,
        scan: &ScanResult,
        opts: &PredictOptions,
    ) -> Self {
        let total_files = files.len() as u64;
        let total_bytes: u64 = files.iter().map(|f| f.size).sum();
        let prefiltered = PREFILTER_INCOMPRESSIBLE_EXTS.contains(&ext);

        let cache_check = CachePathCheck::new(&scan.root);
        let cache_bytes: u64 = files
            .iter()
            .filter(|f| cache_check.is_cache_path(&f.path))
            .map(|f| f.size)
            .sum();
        let cache_dominated = total_bytes > 0 && cache_bytes * 100 >= total_bytes * 90;

        let mut candidates: Vec<&FileEntry> = Vec::new();
        let mut magic_skipped: Vec<&FileEntry> = Vec::new();
        for f in &files {
            let kind = f.magic_kind();
            let incompressible = kind.is_incompressible();
            let identifiable = kind != MagicKind::Empty && kind != MagicKind::Unknown;
            if prefiltered {
                // Layer 2 on a prefiltered class: only content that is
                // *not* an incompressible kind (and is identifiable) counts
                // as an extension lie worth measuring.
                if identifiable && !incompressible {
                    candidates.push(f);
                } else {
                    magic_skipped.push(f);
                }
            } else if incompressible {
                // Normal extension but the content is a compressed
                // container — exclude from candidates.
                magic_skipped.push(f);
            } else {
                candidates.push(f);
            }
        }

        let below_threshold = candidates
            .iter()
            .filter(|f| f.size < opts.min_candidate_bytes)
            .count() as u64;
        let candidates: Vec<&FileEntry> = candidates
            .into_iter()
            .filter(|f| f.size >= opts.min_candidate_bytes)
            .collect();
        let candidate_bytes = candidates.iter().map(|f| f.size).sum();

        ClassWork {
            ext: ext.to_string(),
            candidates,
            magic_skipped,
            below_threshold_files: below_threshold,
            total_files,
            total_bytes,
            candidate_bytes,
            cache_bytes,
            cache_dominated,
            prefiltered,
            sample_budget: 0,
        }
    }

    fn judge(&mut self, opts: &PredictOptions) -> ClassVerdict {
        // Stratified sample (AV-1) — deterministic (AV-7).
        let mut ratios: Vec<Option<f64>> = Vec::new();
        let mut failed = 0usize;
        let mut sample_count = 0usize;
        if !self.candidates.is_empty() && self.sample_budget > 0 {
            let picks = stratified_sample(&self.candidates, self.sample_budget);
            sample_count = picks.len();
            let measured: Vec<Option<f64>> = picks
                .par_iter()
                .map(|&i| measure(self.candidates[i], opts).ok())
                .collect();
            for m in measured {
                match m {
                    Some(r) => ratios.push(Some(r)),
                    None => failed += 1,
                }
            }
        }

        // Serial reduction in fixed order → byte-identical across runs.
        let measured: Vec<f64> = ratios.iter().filter_map(|r| *r).collect();
        let (mean, stddev) = if measured.is_empty() {
            (0.0, 0.0)
        } else {
            let n = measured.len() as f64;
            let m = measured.iter().sum::<f64>() / n;
            let var = measured.iter().map(|r| (r - m) * (r - m)).sum::<f64>() / n;
            (m, var.sqrt())
        };
        let ratio_low = (mean - stddev).max(0.0);
        let ratio_high = (mean + stddev).min(1.0);

        // Savings over the candidate volume only (prefiltered / below-
        // threshold / magic-skipped mass is honestly excluded).
        let savings_low = ((1.0 - ratio_high) * self.candidate_bytes as f64) as u64;
        let savings_high = ((1.0 - ratio_low) * self.candidate_bytes as f64) as u64;

        // ---- verdict ----
        let mut reason_parts: Vec<String> = Vec::new();
        let (verdict, confidence);

        if self.cache_dominated {
            verdict = Verdict::Deletable;
            confidence = if measured.len() >= opts.min_confident_samples {
                Confidence::High
            } else {
                Confidence::Low
            };
            let cache_dirs = CACHE_DIR_NAMES.join("/");
            if measured.is_empty() {
                reason_parts.push(format!(
                    "位于可重建缓存目录（{cache_dirs}），可安全删除释放 {}（依据路径语义，未实测压缩比）",
                    format_bytes(self.cache_bytes)
                ));
            } else {
                reason_parts.push(format!(
                    "位于可重建缓存目录（{cache_dirs}），可安全删除释放 {}；实测压缩比 {}（如需保留可归档）",
                    format_bytes(self.cache_bytes),
                    pct(mean)
                ));
            }
        } else if measured.is_empty() {
            // Nothing measurable: decide between the honest skip reasons.
            confidence = Confidence::Low;
            if self.candidates.is_empty() {
                if self.prefiltered {
                    verdict = Verdict::Skip;
                    reason_parts.push(format!(
                        "已压缩格式（.{ext}）：实测 zstd-3 压缩比 ≈100%、预计节省 ≈0（真实语料 2026-11-10 实测 png 100.0% / mp3 92.9%），不进入抽样",
                        ext = self.ext
                    ));
                } else if self.below_threshold_files == self.total_files {
                    verdict = Verdict::Skip;
                    reason_parts.push(format!(
                        "全部文件小于 {}，逐文件归档开销大于收益，跳过",
                        format_bytes(opts.min_candidate_bytes)
                    ));
                } else {
                    verdict = Verdict::Skip;
                    reason_parts.push("无实测候选（magic 字节显示为已压缩容器），跳过".to_string());
                }
            } else {
                // candidates exist but the sample budget was exhausted by
                // bigger classes → do not pretend confidence.
                verdict = Verdict::Unsure;
                reason_parts.push("总样本预算已被更大的类耗尽，本类未实测，不动".to_string());
            }
        } else if measured.len() < opts.min_confident_samples {
            verdict = Verdict::Unsure;
            confidence = Confidence::Low;
            reason_parts.push(format!(
                "样本数 {n} < {min}，置信不足，不动（实测均值 {mean} 仅作参考）",
                n = measured.len(),
                min = opts.min_confident_samples,
                mean = pct(mean)
            ));
        } else if mean >= SKIP_RATIO_THRESHOLD {
            verdict = Verdict::Skip;
            confidence = Confidence::High;
            reason_parts.push(format!(
                "实测压缩比 {mean}，收益 ≈0，不要碰（样本 {n} 个）",
                mean = pct(mean),
                n = measured.len()
            ));
        } else if savings_low == 0 {
            // interval straddles "no gain"
            verdict = Verdict::Unsure;
            confidence = Confidence::Low;
            reason_parts.push(format!(
                "置信区间包含零收益（节省下限 ≈0，实测均值 {mean}，样本 {n} 个），置信不足，不动",
                mean = pct(mean),
                n = measured.len()
            ));
        } else if savings_high > savings_low.saturating_mul(INTERVAL_SPAN_DOWNGRADE_FACTOR) {
            verdict = Verdict::Unsure;
            confidence = Confidence::Low;
            reason_parts.push(format!(
                "节省区间跨度过大（下限 {low}，上限 {high}），置信不足，不动",
                low = format_bytes(savings_low),
                high = format_bytes(savings_high)
            ));
        } else {
            verdict = Verdict::Archive;
            confidence = Confidence::High;
            reason_parts.push(format!(
                "{ext} 类，实测压缩比 {mean}（区间 {low}–{high}，样本 {n} 个），预计节省 {s}（区间 {sl}–{sh}，基于候选体积 {base}）",
                ext = self.ext,
                mean = pct(mean),
                low = pct(ratio_low),
                high = pct(ratio_high),
                n = measured.len(),
                s = format_bytes(savings_high),
                sl = format_bytes(savings_low),
                sh = format_bytes(savings_high),
                base = format_bytes(self.candidate_bytes)
            ));
        }

        // Contextual parts appended after the verdict reason. Skipped when
        // the threshold note already *is* the main reason (empty candidates
        // on an all-small class) to avoid saying the same thing twice.
        if !self.magic_skipped.is_empty() && !self.prefiltered {
            reason_parts.push(format!(
                "另有 {k} 个文件（{b}）magic 字节显示为已压缩容器，已从候选剔除",
                k = self.magic_skipped.len(),
                b = format_bytes(self.magic_skipped_bytes())
            ));
        }
        if self.below_threshold_files > 0 && !self.candidates.is_empty() {
            reason_parts.push(format!(
                "另有 {k} 个文件小于 {m}，低于候选下限，不计入预计节省",
                k = self.below_threshold_files,
                m = format_bytes(opts.min_candidate_bytes)
            ));
        }

        ClassVerdict {
            ext: self.ext.clone(),
            verdict,
            confidence,
            total_files: self.total_files,
            total_bytes: self.total_bytes,
            candidate_files: self.candidates.len() as u64,
            candidate_bytes: self.candidate_bytes,
            magic_skipped_files: self.magic_skipped.len() as u64,
            magic_skipped_bytes: self.magic_skipped_bytes(),
            sample_count,
            failed_samples: failed,
            mean_ratio: if measured.is_empty() {
                None
            } else {
                Some(mean)
            },
            ratio_interval_low: if measured.is_empty() {
                None
            } else {
                Some(ratio_low)
            },
            ratio_interval_high: if measured.is_empty() {
                None
            } else {
                Some(ratio_high)
            },
            est_savings_low: if verdict == Verdict::Archive {
                Some(savings_low)
            } else {
                None
            },
            est_savings_high: if verdict == Verdict::Archive {
                Some(savings_high)
            } else {
                None
            },
            est_delete_bytes: if verdict == Verdict::Deletable {
                Some(self.cache_bytes)
            } else {
                None
            },
            reason: reason_parts.join("；"),
            cache_dominated: self.cache_dominated,
        }
    }

    fn magic_skipped_bytes(&self) -> u64 {
        self.magic_skipped.iter().map(|f| f.size).sum()
    }
}

/// AV-1: sample budget scales with class volume, capped by the configured
/// per-class budget, never below the confidence minimum when possible.
fn scaled_budget(candidate_bytes: u64, per_class_cap: usize) -> usize {
    if per_class_cap == 0 {
        return 0;
    }
    let gib = 1024 * 1024 * 1024u64;
    let extra = candidate_bytes.div_ceil(gib) as usize;
    (DEFAULT_MIN_CONFIDENT_SAMPLES + extra).min(per_class_cap)
}

/// AV-1 stratified sampling over candidates already sorted ascending by
/// (size, path): split into `VOLUME_BANDS` equal-volume bands, guarantee
/// one sample per non-empty band, distribute the rest by band volume
/// (largest remainder, ties by band index), pick midpoints inside a band.
fn stratified_sample(candidates: &[&FileEntry], budget: usize) -> Vec<usize> {
    let n = candidates.len();
    if n == 0 || budget == 0 {
        return Vec::new();
    }
    if n <= budget {
        return (0..n).collect();
    }

    let total: u64 = candidates.iter().map(|f| f.size).sum();
    // volume boundaries on the sorted list
    let mut bounds: Vec<usize> = Vec::with_capacity(VOLUME_BANDS + 1);
    bounds.push(0);
    if total > 0 {
        let mut cum = 0u64;
        let mut k = 1usize;
        for (i, f) in candidates.iter().enumerate() {
            cum += f.size;
            while k < VOLUME_BANDS && cum >= total * k as u64 / VOLUME_BANDS as u64 {
                bounds.push(i + 1);
                k += 1;
            }
        }
    }
    while bounds.len() < VOLUME_BANDS + 1 {
        bounds.push(n);
    }
    bounds[VOLUME_BANDS] = n;

    let bands: Vec<(usize, usize, u64)> = (0..VOLUME_BANDS)
        .map(|k| {
            let (s, e) = (bounds[k], bounds[k + 1]);
            let vol: u64 = candidates[s..e].iter().map(|f| f.size).sum();
            (s, e, vol)
        })
        .collect();

    let vols: Vec<u64> = bands.iter().map(|b| b.2).collect();
    let alloc = allocate_samples(budget, &vols);

    let mut picks: Vec<usize> = Vec::with_capacity(budget);
    for (k, (s, e, _)) in bands.iter().enumerate() {
        picks.extend(pick_indices(*s, *e, alloc[k]));
    }
    picks.sort_unstable();
    picks.dedup();
    picks
}

/// `1` to every non-empty band, remainder by volume share (largest
/// remainder method, ties by band index). Budget < non-empty bands →
/// concentrate on the largest bands (ties: earlier index).
fn allocate_samples(budget: usize, vols: &[u64]) -> Vec<usize> {
    let mut alloc = vec![0usize; vols.len()];
    if budget == 0 {
        return alloc;
    }
    let total: u64 = vols.iter().sum();

    let mut by_vol: Vec<usize> = (0..vols.len()).collect();
    by_vol.sort_by(|&a, &b| vols[b].cmp(&vols[a]).then(a.cmp(&b)));

    let mut used = 0usize;
    for &i in &by_vol {
        if used >= budget {
            break;
        }
        if vols[i] > 0 {
            alloc[i] += 1;
            used += 1;
        }
    }

    let remaining = budget.saturating_sub(used);
    if remaining > 0 && total > 0 {
        let rem = remaining as u128;
        let tot = total as u128;
        let mut assigned: u128 = 0;
        let mut whole = vec![0u128; vols.len()];
        let mut frac: Vec<(u128, usize)> = Vec::with_capacity(vols.len());
        for i in 0..vols.len() {
            let q = rem * vols[i] as u128 / tot;
            whole[i] = q;
            assigned += q;
            frac.push((rem * vols[i] as u128 % tot, i));
        }
        frac.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut leftover = rem - assigned;
        let mut fi = 0usize;
        while leftover > 0 && fi < frac.len() {
            let i = frac[fi].1;
            if vols[i] > 0 {
                whole[i] += 1;
                leftover -= 1;
            }
            fi += 1;
        }
        for i in 0..vols.len() {
            alloc[i] += whole[i] as usize;
        }
    }
    alloc
}

/// Midpoint rule inside a band: evenly spread picks, deterministic, and
/// distinct whenever `alloc <= n`.
fn pick_indices(start: usize, end: usize, alloc: usize) -> Vec<usize> {
    let n = end - start;
    if alloc == 0 || n == 0 {
        return Vec::new();
    }
    if alloc >= n {
        return (start..end).collect();
    }
    let mut out = Vec::with_capacity(alloc);
    for j in 0..alloc {
        let idx = start + (((2 * (j as u64) + 1) * n as u64) / (2 * alloc as u64)) as usize;
        out.push(idx);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Stream-compress one sample through zstd into a counting sink — constant
/// memory, nothing written to disk. The pledged source size caps the
/// window allocation and turns stat/read races into honest failures.
fn measure(f: &FileEntry, opts: &PredictOptions) -> Result<f64> {
    let file = fs::File::open(&f.path)
        .with_context(|| format!("样本文件打开失败: {}", f.path.display()))?;
    let mut sink = CountingSink::default();
    {
        let mut enc = zstd::stream::Encoder::new(&mut sink, opts.zstd_level)?;
        if f.size >= opts.long_window_min_bytes {
            // Equivalent of the zstd CLI's `--long=27` (card A8/A9 setup):
            // long-distance matching on, window capped at 2^27.
            enc.long_distance_matching(true)?;
            enc.window_log(opts.long_window_log)?;
        }
        enc.set_pledged_src_size(Some(f.size))?;
        let mut reader = file;
        io::copy(&mut reader, &mut enc)?;
        enc.finish()?;
    }
    if sink.count == 0 {
        anyhow::bail!("压缩输出为空（异常）: {}", f.path.display());
    }
    Ok(sink.count as f64 / f.size as f64)
}

#[derive(Default)]
struct CountingSink {
    count: u64,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.count += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn format_bytes(v: u64) -> String {
    const UNIT: f64 = 1024.0;
    let b = v as f64;
    if b < UNIT {
        format!("{v} B")
    } else if b < UNIT * UNIT {
        format!("{:.1} KB", b / UNIT)
    } else if b < UNIT * UNIT * UNIT {
        format!("{:.1} MB", b / (UNIT * UNIT))
    } else {
        format!("{:.2} GB", b / (UNIT * UNIT * UNIT))
    }
}

pub(crate) fn pct(v: f64) -> String {
    format!("{:.1}%", v * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan, ScanOptions};
    use std::fs;
    use std::path::{Path, PathBuf};

    const TEXT_LINE: &str = "coldstore predict fixture line 1234567890 abcdefg\n";

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-predict-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fill_text(path: &Path, approx_size: usize) {
        let unit = TEXT_LINE.as_bytes();
        let reps = approx_size.div_ceil(unit.len());
        let mut buf = Vec::with_capacity(reps * unit.len());
        for _ in 0..reps {
            buf.extend_from_slice(unit);
        }
        fs::write(path, buf).unwrap();
    }

    fn fill_noise(path: &Path, size: usize) {
        let mut buf = vec![0u8; size];
        xorshift_fill(&mut buf, 0x9E37_79B9);
        fs::write(path, buf).unwrap();
    }

    fn build_fixture(tag: &str) -> PathBuf {
        let root = temp_root(tag);
        // txt: 4 confident compressible files + 1 below threshold
        for i in 0..4 {
            fill_text(&root.join(format!("t{i}.txt")), 300 * 1024);
        }
        fs::write(root.join("small.txt"), TEXT_LINE).unwrap();
        // png: one real (magic agrees with extension) + one text liar
        let mut png = vec![0x89u8, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend(std::iter::repeat_n(0u8, 64 * 1024));
        fs::write(root.join("real.png"), png).unwrap();
        fill_text(&root.join("fake.png"), 300 * 1024);
        // jpg: prefiltered with agreeing magic, tiny
        fs::write(root.join("real.jpg"), [0xFFu8, 0xD8, 0xFF, 0xE0, 0, 0]).unwrap();
        // bin under .cache → deletable
        fs::create_dir_all(root.join(".cache")).unwrap();
        fill_text(&root.join(".cache/c.bin"), 300 * 1024);
        // mix: two compressible + two noise → interval straddles zero
        fill_text(&root.join("m1.mix"), 300 * 1024);
        fill_text(&root.join("m2.mix"), 300 * 1024);
        fill_noise(&root.join("m3.mix"), 300 * 1024);
        fill_noise(&root.join("m4.mix"), 300 * 1024);
        root
    }

    fn verdict_of<'a>(report: &'a PredictionReport, ext: &str) -> &'a ClassVerdict {
        report
            .classes
            .iter()
            .find(|c| c.ext == ext)
            .unwrap_or_else(|| panic!("class {ext} missing"))
    }

    #[test]
    fn layered_verdicts_match_card_expectations() {
        let root = build_fixture("layered");
        let scan_res = scan(&root, &ScanOptions::default()).unwrap();
        let report = predict(&scan_res, &PredictOptions::default()).unwrap();

        // txt → ARCHIVE, savings over candidate volume
        let txt = verdict_of(&report, "txt");
        assert_eq!(txt.verdict, Verdict::Archive);
        assert_eq!(txt.candidate_files, 4, "small.txt excluded by threshold");
        assert_eq!(txt.total_files, 5);
        assert!(txt.est_savings_low.unwrap_or(0) > 0);
        assert!(txt.mean_ratio.unwrap() < 0.5);
        assert!(txt.reason.contains("预计节省"), "reason: {}", txt.reason);

        // png → prefiltered + liar: liar measured, 1 sample < 3 → UNSURE
        let png = verdict_of(&report, "png");
        assert_eq!(png.verdict, Verdict::Unsure);
        assert_eq!(png.sample_count, 1, "only the magic-lie file is sampled");
        assert_eq!(png.candidate_files, 1);

        // jpg → prefilter skip with the card-required reason phrase
        let jpg = verdict_of(&report, "jpg");
        assert_eq!(jpg.verdict, Verdict::Skip);
        assert!(jpg.reason.contains("已压缩格式"), "reason: {}", jpg.reason);
        assert_eq!(jpg.sample_count, 0);

        // .cache bin → DELETABLE
        let bin = verdict_of(&report, "bin");
        assert_eq!(bin.verdict, Verdict::Deletable);
        assert_eq!(bin.est_delete_bytes, Some(300 * 1024));
        assert!(bin.reason.contains("缓存"));

        // mix → interval straddles zero → UNSURE
        let mix = verdict_of(&report, "mix");
        assert_eq!(mix.verdict, Verdict::Unsure);
        assert!(mix.reason.contains("置信不足"), "reason: {}", mix.reason);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prediction_is_byte_identical_across_runs() {
        let root = build_fixture("determinism");
        let json1 = {
            let s = scan(&root, &ScanOptions::default()).unwrap();
            let r = predict(&s, &PredictOptions::default()).unwrap();
            serde_json::to_string(&r).unwrap()
        };
        let json2 = {
            let s = scan(&root, &ScanOptions::default()).unwrap();
            let r = predict(&s, &PredictOptions::default()).unwrap();
            serde_json::to_string(&r).unwrap()
        };
        assert_eq!(json1, json2, "B9: two runs must be byte-identical");
        assert!(
            json1.contains("coldstore-predict/v0.1"),
            "policy version recorded"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn budget_allocation_is_deterministic_and_bounded() {
        // 8 samples over bands 1GB / 100MB / 10MB: all bands ≥1, big gets most
        let vols = [1024 * 1024 * 1024u64, 100 * 1024 * 1024, 10 * 1024 * 1024];
        let a1 = allocate_samples(8, &vols);
        let a2 = allocate_samples(8, &vols);
        assert_eq!(a1, a2);
        assert_eq!(a1.iter().sum::<usize>(), 8);
        assert!(a1.iter().all(|&a| a >= 1));
        assert_eq!(a1[0], 6, "largest band gets the bulk: {a1:?}");

        // budget smaller than non-empty bands → top bands only
        let a3 = allocate_samples(2, &vols);
        assert_eq!(a3.iter().sum::<usize>(), 2);
        assert_eq!(a3[0], 1);
        assert_eq!(a3[1], 1);
        assert_eq!(a3[2], 0);
    }

    #[test]
    fn stratified_sample_covers_all_volume_bands() {
        // 30 files: sizes 1..30 MB → three volume bands
        let mb = 1024 * 1024u64;
        let files: Vec<FileEntry> = (1..=30u64)
            .map(|i| FileEntry {
                path: PathBuf::from(format!("f{i:02}.bin")),
                size: i * mb,
                ext: "bin".into(),
                modified: None,
                accessed: None,
                is_reparse: false,
                is_hidden: false,
                is_system: false,
                magic_hex: String::new(),
                magic_read_failed: false,
            })
            .collect();
        let refs: Vec<&FileEntry> = files.iter().collect();
        let picks = stratified_sample(&refs, 8);
        assert_eq!(picks.len(), 8);
        assert!(picks[0] < 10, "small band represented: {picks:?}");
        assert!(
            picks.iter().any(|&p| (10..25).contains(&p)),
            "mid band: {picks:?}"
        );
        assert!(picks.iter().any(|&p| p >= 25), "large band: {picks:?}");
    }
}
