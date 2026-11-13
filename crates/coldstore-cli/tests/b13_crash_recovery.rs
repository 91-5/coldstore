//! B13 crash-recovery evidence: the child process runs `run --execute`
//! with the debug crash hook (`COLDSTORE_CRASH_AFTER`), aborts mid-sequence,
//! and the parent verifies journal-based recovery (continue/abort) without
//! any half-broken state.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "coldstore-b13-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha_of(path: &Path) -> String {
    let mut h = Sha256::new();
    let data = fs::read(path).unwrap();
    h.update(&data);
    format!("{:x}", h.finalize())
}

fn write_file(path: &Path, size: usize, seed: u8) -> String {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_add(seed)).collect();
    fs::write(path, &data).unwrap();
    format!("{:x}", Sha256::digest(&data))
}

/// A temp config dir whose config enables one catch-all archive rule.
fn make_config_dir(tag: &str) -> PathBuf {
    let dir = temp_dir(tag);
    let config = r#"
[[rule]]
name = "__test_all_archive__"
priority = 1
action = "archive"
enabled = true
"#;
    fs::write(dir.join("config.toml"), config).unwrap();
    dir
}

fn crash_run(
    exe: &Path,
    container: &Path,
    root: &Path,
    cfg_dir: &Path,
    qroot: &Path,
    jdir: &Path,
    crash_after: &str,
) {
    let status = Command::new(exe)
        .args([
            "run",
            "--rule",
            "__test_all_archive__",
            "--execute",
            "--yes",
            "--container",
        ])
        .arg(container)
        .arg("--config-dir")
        .arg(cfg_dir)
        .arg("--quarantine-root")
        .arg(qroot)
        .arg("--journal-dir")
        .arg(jdir)
        .arg(root)
        .env("COLDSTORE_CRASH_AFTER", crash_after)
        .status()
        .expect("spawn child");
    assert!(!status.success(), "child must die by abort() mid-sequence");
}

#[test]
fn b13_crash_then_abort_recovers_everything() {
    let base = temp_dir("abort");
    let src = base.join("src");
    let cfg_dir = make_config_dir("abort-cfg");
    let qroot = base.join("q");
    let jdir = base.join("journal");
    let container = base.join("out").join("c.coldstore");
    fs::create_dir_all(base.join("out")).unwrap();

    let mut shas = Vec::new();
    for i in 0..4u8 {
        // ≥256KB so the predictor samples them and does NOT veto (measured
        // patterned content → ARCHIVE verdict)
        shas.push(write_file(
            &src.join(format!("f{i}.log")),
            300_000 + i as usize * 1_000,
            i,
        ));
    }

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_coldstore"));
    crash_run(&exe, &container, &src, &cfg_dir, &qroot, &jdir, "2");

    // quarantine list sees the interrupted batch with exactly 2 moved files
    let out = Command::new(&exe)
        .args(["quarantine", "list"])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("interrupted"),
        "list shows interrupted: {text}"
    );
    assert!(text.contains("2 个文件"), "two files moved: {text}");
    assert!(
        text.contains("保留期至"),
        "concrete retention date (ADV-N5)"
    );

    // batch id from list output
    // list line: "  [interrupted] <batch-id>   占用 ..."
    let batch_id = text
        .lines()
        .find(|l| l.contains("interrupted"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("batch id token")
        .to_string();

    // --abort: every file back at source, container gone
    let out = Command::new(&exe)
        .args(["quarantine", "recover", &batch_id, "--abort"])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover abort: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for (i, want) in shas.iter().enumerate() {
        let p = src.join(format!("f{i}.log"));
        assert!(p.exists(), "f{i} restored");
        assert_eq!(sha_of(&p), *want, "f{i} content intact");
    }
    assert!(!container.exists(), "suspect container removed");

    // list shows aborted with zero occupancy
    let out = Command::new(&exe)
        .args(["quarantine", "list"])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("aborted"), "{text}");

    fs::remove_dir_all(&base).ok();
    fs::remove_dir_all(&qroot).ok();
    fs::remove_dir_all(&jdir).ok();
    fs::remove_dir_all(&cfg_dir).ok();
    std::thread::sleep(Duration::from_millis(10));
}

#[test]
fn b13_crash_then_continue_completes_the_sequence() {
    let base = temp_dir("continue");
    let src = base.join("src");
    let cfg_dir = make_config_dir("continue-cfg");
    let qroot = base.join("q");
    let jdir = base.join("journal");
    let container = base.join("out").join("c2.coldstore");
    fs::create_dir_all(base.join("out")).unwrap();

    for i in 0..4u8 {
        write_file(
            &src.join(format!("g{i}.log")),
            300_000 + i as usize * 1_500,
            40 + i,
        );
    }

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_coldstore"));
    crash_run(&exe, &container, &src, &cfg_dir, &qroot, &jdir, "2");

    let out = Command::new(&exe)
        .args(["quarantine", "list"])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let batch_id = text
        .lines()
        .find(|l| l.contains("interrupted"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .expect("batch id token")
        .to_string();

    // --continue resumes from the journal state: remaining files verified
    // and moved, batch closed
    let out = Command::new(&exe)
        .args(["quarantine", "recover", &batch_id, "--continue"])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "recover continue: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // all four sources moved into quarantine; container has 4 frames
    for i in 0..4usize {
        assert!(!src.join(format!("g{i}.log")).exists(), "g{i} moved");
    }
    let out = Command::new(&exe)
        .args(["list", &container.to_string_lossy()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("4 个") || text.contains("共 4"), "{text}");

    // undo the whole batch: sources restored (B12 through the resumed batch)
    let out = Command::new(&exe)
        .args(["undo", &batch_id])
        .env("COLDSTORE_QROOT", &qroot)
        .env("COLDSTORE_JDIR", &jdir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "undo: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for i in 0..4usize {
        assert!(
            src.join(format!("g{i}.log")).exists(),
            "g{i} restored by undo"
        );
    }

    fs::remove_dir_all(&base).ok();
    fs::remove_dir_all(&qroot).ok();
    fs::remove_dir_all(&jdir).ok();
    fs::remove_dir_all(&cfg_dir).ok();
    std::thread::sleep(Duration::from_millis(10));
}
