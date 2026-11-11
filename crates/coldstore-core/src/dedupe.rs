//! Duplicate detection — **plan only** (card D4).
//!
//! Two phases: ① bucket by file size (only files ≥ the threshold, default
//! 4 KiB) ② exact SHA-256 match inside each bucket. The planner reports
//! duplicate groups with an explicit keep entry per retention policy, but
//! *never* modifies anything: replacing duplicates with hardlinks is a
//! write action owned by the execution layer (card OC-20261110-002).
//!
//! AV-N1 (pnpm trap): before counting savings every group member's
//! `(volume, file-index)` identity is resolved; copies that already share
//! the keep entry's inode are reported as "already hardlinked, saves 0
//! bytes" instead of fake savings. Groups where *all* duplicates are
//! already hardlinked are counted separately
//! (`fully_hardlinked_groups`) so a pnpm tree shows up as "looked at,
//! nothing to reclaim" rather than a wall of phantom groups.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use anyhow::{bail, Result};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::fsinfo::{file_identity, FileIdentity};
use crate::scan::ScanResult;

/// Card D4: bucket threshold default 4 KiB.
pub const DEFAULT_MIN_SIZE_BYTES: u64 = 4 * 1024;

/// Which duplicate survives on paper. Execution is out of scope here.
#[derive(Debug, Clone)]
pub enum KeepPolicy {
    /// Default (card D4): keep the earliest-modified copy.
    Oldest,
    Newest,
    /// Keep the exact path given by the user; error when absent.
    KeepPath(PathBuf),
}

impl KeepPolicy {
    fn as_display(&self) -> String {
        match self {
            KeepPolicy::Oldest => "oldest".to_string(),
            KeepPolicy::Newest => "newest".to_string(),
            KeepPolicy::KeepPath(p) => format!("path:{}", p.display()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DedupeOptions {
    pub min_size: u64,
    pub policy: KeepPolicy,
}

impl Default for DedupeOptions {
    fn default() -> Self {
        DedupeOptions {
            min_size: DEFAULT_MIN_SIZE_BYTES,
            policy: KeepPolicy::Oldest,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DupeMember {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub link_count: Option<u64>,
    /// True when this copy resolves to the same stored data as the keep
    /// entry (AV-N1) — reclaiming it would save 0 bytes.
    pub same_data_as_keep: bool,
}

#[derive(Debug, Serialize)]
pub struct DupeGroup {
    pub sha256_hex: String,
    pub size: u64,
    pub keep: DupeMember,
    /// Path-sorted duplicates (always non-empty).
    pub duplicates: Vec<DupeMember>,
    /// All duplicates already share the keep entry's inode (AV-N1).
    pub fully_hardlinked: bool,
    /// `size × duplicates holding an independent copy`.
    pub reclaimable_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct DedupePlan {
    pub scanned_files: u64,
    pub min_size: u64,
    pub policy: String,
    pub bucketed_files: u64,
    pub hashed_files: u64,
    pub hash_failures: u64,
    /// Members whose identity could not be resolved via handle info.
    pub identity_failures: u64,
    pub groups: Vec<DupeGroup>,
    pub total_reclaimable_bytes: u64,
    /// Groups whose duplicates are all already hardlinked (AV-N1).
    pub fully_hardlinked_groups: u64,
    /// Honesty note for the pnpm scenario: these groups reclaim nothing.
    /// Kept out of the serialized plan so JSON output is byte-identical
    /// across runs (determinism, B9 spirit).
    #[serde(skip_serializing)]
    pub duration_ms: u64,
}

/// Build the duplicate plan from a scan result. Read-only: hashing reads
/// file content, identities are queried with attribute-only handles.
pub fn dedupe(scan: &ScanResult, opts: &DedupeOptions) -> Result<DedupePlan> {
    let started = Instant::now();
    if opts.min_size == 0 {
        bail!("去重入桶阈值不能为 0（会把所有文件都拖进哈希）");
    }

    // Phase ①: size buckets, deterministic order.
    let mut buckets: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, f) in scan.files.iter().enumerate() {
        if f.size >= opts.min_size {
            buckets.entry(f.size).or_default().push(i);
        }
    }
    let bucketed: Vec<usize> = buckets.into_values().flatten().collect();
    let bucketed_files = bucketed.len() as u64;

    // Phase ②: SHA-256 inside the buckets (parallel per file).
    let hashes: Vec<Option<String>> = bucketed
        .par_iter()
        .map(|&i| hash_file(&scan.files[i].path).ok())
        .collect();
    let hash_failures = hashes.iter().filter(|h| h.is_none()).count() as u64;
    let hashed_files = (hashes.len() - hash_failures as usize) as u64;

    // Group by (size, hash): BTreeMap → deterministic iteration.
    let mut groups: BTreeMap<(u64, String), Vec<usize>> = BTreeMap::new();
    for (slot, hash) in hashes.iter().enumerate() {
        if let Some(h) = hash {
            let i = bucketed[slot];
            groups
                .entry((scan.files[i].size, h.clone()))
                .or_default()
                .push(i);
        }
    }
    let mut groups: Vec<_> = groups.into_iter().filter(|(_, v)| v.len() >= 2).collect();
    // Largest waste first; ties by hash for determinism.
    groups.sort_by(|a, b| b.0 .0.cmp(&a.0 .0).then(a.0 .1.cmp(&b.0 .1)));

    let mut out: Vec<DupeGroup> = Vec::with_capacity(groups.len());
    let mut total_reclaimable = 0u64;
    let mut fully_linked_groups = 0u64;
    let mut identity_failures = 0u64;

    for ((size, hash), member_idx) in groups {
        let members: Vec<&crate::scan::FileEntry> =
            member_idx.iter().map(|&i| &scan.files[i]).collect();

        // Resolve identities in parallel (AV-N1).
        let ids: Vec<Option<FileIdentity>> = members
            .par_iter()
            .map(|m| file_identity(&m.path).ok())
            .collect();
        identity_failures += ids.iter().filter(|x| x.is_none()).count() as u64;

        let keep_pos = pick_keep(&members, &opts.policy)?;
        let keep_id = ids[keep_pos];

        let member = |pos: usize, same: bool| DupeMember {
            path: members[pos].path.clone(),
            size: members[pos].size,
            modified: members[pos].modified,
            link_count: ids[pos].map(|id| id.link_count),
            same_data_as_keep: same,
        };
        let keep = member(keep_pos, false);

        let mut dups = Vec::with_capacity(members.len() - 1);
        let mut independent = 0u64;
        for (pos, _) in members.iter().enumerate() {
            if pos == keep_pos {
                continue;
            }
            let same = match (keep_id, ids[pos]) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if !same {
                independent += 1;
            }
            dups.push(member(pos, same));
        }
        dups.sort_by(|a, b| a.path.cmp(&b.path));

        let fully = independent == 0;
        let reclaimable = if fully { 0 } else { size * independent };
        if fully {
            fully_linked_groups += 1;
        }
        total_reclaimable += reclaimable;

        out.push(DupeGroup {
            sha256_hex: hash,
            size,
            keep,
            duplicates: dups,
            fully_hardlinked: fully,
            reclaimable_bytes: reclaimable,
        });
    }

    Ok(DedupePlan {
        scanned_files: scan.files.len() as u64,
        min_size: opts.min_size,
        policy: opts.policy.as_display(),
        bucketed_files,
        hashed_files,
        hash_failures,
        identity_failures,
        total_reclaimable_bytes: total_reclaimable,
        fully_hardlinked_groups: fully_linked_groups,
        duration_ms: started.elapsed().as_millis() as u64,
        groups: out,
    })
}

/// Retention policy → index into the (stable) member slice. Ties resolved
/// by path so the plan is reproducible (card D4 + B9 spirit).
fn pick_keep(members: &[&crate::scan::FileEntry], policy: &KeepPolicy) -> Result<usize> {
    let key = |f: &crate::scan::FileEntry| -> (u128, String) {
        (
            f.modified
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            f.path.to_string_lossy().into_owned(),
        )
    };
    match policy {
        KeepPolicy::Oldest => Ok((0..members.len())
            .min_by(|&a, &b| key(members[a]).cmp(&key(members[b])))
            .unwrap()),
        KeepPolicy::Newest => {
            // max by mtime, ties → smallest path
            let mut best = 0;
            for i in 1..members.len() {
                let (bt, bp) = key(members[best]);
                let (t, p) = key(members[i]);
                if t > bt || (t == bt && p < bp) {
                    best = i;
                }
            }
            Ok(best)
        }
        KeepPolicy::KeepPath(want) => members
            .iter()
            .position(|m| same_path(&m.path, want))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "指定保留路径不在重复组中: {}（组内成员: {}）",
                    want.display(),
                    members
                        .iter()
                        .map(|m| m.path.display().to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }),
    }
}

/// NTFS is case-insensitive; compare accordingly.
fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{dedupe, DedupeOptions, KeepPolicy};
    use crate::scan::{scan, ScanOptions};
    use anyhow::{anyhow, Result};
    use std::fs;
    use std::path::PathBuf;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-dedupe-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn content(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    fn group(plan: &super::DedupePlan) -> &super::DupeGroup {
        plan.groups.first().expect("one duplicate group expected")
    }

    #[test]
    fn duplicates_are_planned_with_hardlink_trap() -> Result<()> {
        let root = temp_root("main");
        let payload = content(8 * 1024);
        // a: original; c: hardlink OF a (same inode); b: independent copy;
        // d: unique content; tiny.bin: below threshold.
        fs::write(root.join("a.bin"), &payload).unwrap();
        fs::hard_link(root.join("a.bin"), root.join("c_hardlink.bin"))?;
        fs::write(root.join("b_copy.bin"), &payload).unwrap();
        fs::write(root.join("d_unique.bin"), content(9 * 1024)).unwrap();
        fs::write(root.join("tiny.bin"), b"toosmall").unwrap();

        let scan_res = scan(&root, &ScanOptions::default())?;
        let plan = dedupe(&scan_res, &DedupeOptions::default())?;

        // a/c/b share content → one group; d unique; tiny not bucketed.
        let g = group(&plan);
        assert_eq!(g.size, 8 * 1024);
        assert_eq!(
            g.keep.path.file_name().unwrap(),
            "a.bin",
            "oldest kept by default"
        );
        assert_eq!(g.duplicates.len(), 2, "b (independent) + c (hardlink)");

        let dup = |name: &str| {
            g.duplicates
                .iter()
                .find(|m| m.path.to_string_lossy().ends_with(name))
                .expect(name)
        };
        assert!(
            !dup("b_copy.bin").same_data_as_keep,
            "independent copy is reclaimable"
        );
        assert!(
            dup("c_hardlink.bin").same_data_as_keep,
            "AV-N1: hardlink must be flagged same-data"
        );
        assert_eq!(dup("c_hardlink.bin").link_count, Some(2));
        // AV-N1 honesty: only the independent copy counts.
        assert_eq!(g.reclaimable_bytes, 8 * 1024);
        assert!(!g.fully_hardlinked);
        assert_eq!(plan.fully_hardlinked_groups, 0);
        assert_eq!(plan.total_reclaimable_bytes, 8 * 1024);
        assert_eq!(
            plan.hashed_files, 4,
            "tiny.bin below threshold; a/b/c/d bucketed"
        );
        assert_eq!(plan.groups.len(), 1);

        fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn fully_hardlinked_group_reclaims_zero() -> Result<()> {
        let root = temp_root("pnpm");
        let payload = content(8 * 1024);
        fs::create_dir_all(root.join("pkg")).unwrap();
        fs::write(root.join("pkg/index.js"), &payload).unwrap();
        // pnpm shape: both visible paths are hardlinks of one store file
        fs::hard_link(root.join("pkg/index.js"), root.join("alias1.js"))?;
        fs::hard_link(root.join("pkg/index.js"), root.join("alias2.js"))?;

        let scan_res = scan(&root, &ScanOptions::default())?;
        let plan = dedupe(&scan_res, &DedupeOptions::default())?;
        let g = group(&plan);
        assert_eq!(g.duplicates.len(), 2);
        assert!(g.fully_hardlinked, "all duplicates share the inode");
        assert_eq!(g.reclaimable_bytes, 0, "AV-N1: 节省 0MB，不许虚增");
        assert_eq!(plan.fully_hardlinked_groups, 1);
        assert_eq!(plan.total_reclaimable_bytes, 0);

        fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn keep_policies_oldest_newest_and_path() -> Result<()> {
        let root = temp_root("policy");
        let payload = content(6 * 1024);
        fs::write(root.join("old.bin"), &payload).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(root.join("new.bin"), &payload).unwrap();

        let scan_res = scan(&root, &ScanOptions::default())?;

        let oldest = dedupe(&scan_res, &DedupeOptions::default())?;
        assert_eq!(group(&oldest).keep.path.file_name().unwrap(), "old.bin");

        let newest = dedupe(
            &scan_res,
            &DedupeOptions {
                policy: KeepPolicy::Newest,
                ..Default::default()
            },
        )?;
        assert_eq!(group(&newest).keep.path.file_name().unwrap(), "new.bin");

        let want = root.join("new.bin");
        let by_path = dedupe(
            &scan_res,
            &DedupeOptions {
                policy: KeepPolicy::KeepPath(want.clone()),
                ..Default::default()
            },
        )?;
        assert_eq!(group(&by_path).keep.path, want);

        // keep-path pointing outside the group errors with the group roster
        let missing = dedupe(
            &scan_res,
            &DedupeOptions {
                policy: KeepPolicy::KeepPath(root.join("not_there.bin")),
                ..Default::default()
            },
        );
        let err = missing.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("不在重复组中"));

        fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn files_below_threshold_never_bucketed() -> Result<()> {
        let root = temp_root("small");
        fs::write(root.join("a.txt"), b"same").unwrap();
        fs::write(root.join("b.txt"), b"same").unwrap();
        let scan_res = scan(&root, &ScanOptions::default())?;
        let plan = dedupe(&scan_res, &DedupeOptions::default())?;
        assert_eq!(plan.bucketed_files, 0);
        assert!(plan.groups.is_empty());

        fs::remove_dir_all(&root).ok();
        Ok(())
    }

    #[test]
    fn plan_is_deterministic() -> Result<()> {
        let root = temp_root("determinism");
        let payload = content(16 * 1024);
        for name in ["x1.bin", "x2.bin", "x3.bin"] {
            fs::write(root.join(name), &payload).unwrap();
        }
        fs::write(root.join("y.bin"), content(16 * 1024)).unwrap();

        let scan_res = scan(&root, &ScanOptions::default())?;
        let p1 = dedupe(&scan_res, &DedupeOptions::default())?;
        let p2 = dedupe(&scan_res, &DedupeOptions::default())?;
        assert_eq!(
            serde_json::to_string(&p1)?,
            serde_json::to_string(&p2)?,
            "same input → byte-identical plan"
        );

        fs::remove_dir_all(&root).ok();
        Ok(())
    }
}
