//! P7 / ADV-B25-W1: a fresh %TEMP% fixture with NO `.coldstore/archive/`
//! directory. `run --rule logs <fixture> --execute` must exit 0, finish the
//! six-step sequence, land the container, and a single frame must retrieve
//! with a SHA-256 identical to the pre-archive file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "coldstore-p7w1-{tag}-{}-{}",
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
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

#[test]
fn run_logs_creates_missing_container_parent() {
    let base = temp_dir("run");
    let src = base.join("logs");
    fs::create_dir_all(&src).unwrap();
    let data: Vec<u8> = (0..300_000usize)
        .map(|i| (i as u8).wrapping_add(11))
        .collect();
    let src_file = src.join("sample.log");
    fs::write(&src_file, &data).unwrap();
    let want_sha = sha_of(&src_file);

    // Isolated config dir: the built-in `logs` rule ships disabled, so the
    // fixture enables it explicitly. No other rule governs the fixture.
    let cfg_dir = temp_dir("cfg");
    fs::write(
        cfg_dir.join("config.toml"),
        r#"
[[rule]]
name = "logs"
priority = 5
match_ext = ["log"]
action = "archive"
enabled = true
"#,
    )
    .unwrap();

    let qroot = base.join("q");
    let jdir = base.join("journal");
    // Deliberately nested AND absent: the whole point of ADV-B25-W1.
    let parent = base.join("coldstore-home").join("archive");
    let container = parent.join("c.coldstore");
    assert!(!parent.exists(), "fixture must start with no archive dir");

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_coldstore"));
    let out = Command::new(&exe)
        .args(["run", "--rule", "logs", "--execute", "--yes", "--container"])
        .arg(&container)
        .arg("--config-dir")
        .arg(&cfg_dir)
        .arg("--quarantine-root")
        .arg(&qroot)
        .arg("--journal-dir")
        .arg(&jdir)
        .arg(&src)
        .output()
        .expect("spawn child");
    assert!(
        out.status.success(),
        "run --execute must exit 0: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "explicit exit code 0");
    assert!(parent.is_dir(), "container parent auto-created");
    assert!(container.is_file(), "container landed on disk");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("六步序列"),
        "six-step sequence completed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Single-frame retrieval; compare against the pre-archive SHA-256.
    let out_dir = temp_dir("out");
    let dest = out_dir.join("sample.log");
    let out = Command::new(&exe)
        .args(["extract"])
        .arg(&container)
        .args(["--key", "0", "-d"])
        .arg(&dest)
        .output()
        .expect("spawn extract");
    assert!(
        out.status.success(),
        "extract: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(sha_of(&dest), want_sha, "retrieved frame SHA must match");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("已校验一致"),
        "extractor verified the frame SHA"
    );

    fs::remove_dir_all(&base).ok();
    fs::remove_dir_all(&cfg_dir).ok();
    fs::remove_dir_all(&out_dir).ok();
    std::thread::sleep(Duration::from_millis(10));
}
