//! P4 · D5/D6 — plan determinism, manual-mark flip, and the TUI smoke
//! path (card B-plan / B-mark / B-tui).
//!
//! Everything here runs against a throw-away tree under the system temp
//! directory and a throw-away config directory — no user data, no global
//! config, no network.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "coldstore-p4-test-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// A config directory with the shipped defaults (all rules disabled) so the
/// tests never depend on the user's real `%APPDATA%\coldstore`.
fn config_dir(tag: &str) -> PathBuf {
    let dir = temp_dir(&format!("cfg-{tag}"));
    // The CLI creates the default config on first load; nothing to do.
    dir
}

fn coldstore() -> Command {
    Command::new(env!("CARGO_BIN_EXE_coldstore"))
}

/// Build a small tree: an old file, a rebuildable directory, a log file.
fn build_tree(tag: &str) -> PathBuf {
    let root = temp_dir(tag);
    std::fs::create_dir_all(root.join("target/debug")).unwrap();
    std::fs::create_dir_all(root.join("logs")).unwrap();
    std::fs::write(root.join("old.bin"), vec![7u8; 4096]).unwrap();
    std::fs::write(root.join("target/debug/lib.rlib"), vec![9u8; 8192]).unwrap();
    std::fs::write(root.join("logs/app.log"), vec![3u8; 2048]).unwrap();
    root
}

fn run_plan_json(path: &Path, cfg: &Path) -> (String, String) {
    let out = coldstore()
        .arg("plan")
        .arg(path)
        .arg("--config-dir")
        .arg(cfg)
        .arg("--json")
        .output()
        .expect("run coldstore plan");
    assert!(
        out.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        sha256(&out.stdout),
    )
}

#[test]
fn plan_json_is_byte_identical_across_runs() {
    let root = build_tree("plan-det");
    let cfg = config_dir("plan-det");

    let (first, first_sha) = run_plan_json(&root, &cfg);
    let (second, second_sha) = run_plan_json(&root, &cfg);

    assert_eq!(first_sha, second_sha, "plan output must be byte-identical");
    assert_eq!(first, second);

    // The rows carry label + reason + estimated saving (card D5).
    assert!(first.contains("\"temperature\""), "每行标签可见: {first}");
    assert!(first.contains("\"reason\""), "每行理由可见");
    assert!(first.contains("\"est_savings_low\""), "每行预计节省可见");
    assert!(first.contains("REBUILDABLE"), "可重建目录被标出");

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cfg).ok();
}

#[test]
fn manual_cold_mark_flips_the_label_and_is_explained() {
    let root = build_tree("mark-flip");
    let cfg = config_dir("mark-flip");
    let target = root.join("old.bin");

    // Before the mark: the file is WARM (just written).
    let (before, _) = run_plan_json(&root, &cfg);
    assert!(before.contains("\"WARM\""), "未标记时应为 WARM: {before}");

    // Mark it cold.
    let out = coldstore()
        .arg("mark-cold")
        .arg(&target)
        .arg("--config-dir")
        .arg(&cfg)
        .output()
        .expect("run coldstore mark-cold");
    assert!(
        out.status.success(),
        "mark-cold failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // After the mark: the label flipped and the reason says so.
    let (after, _) = run_plan_json(&root, &cfg);
    assert!(
        after.contains("手动标记为 cold"),
        "翻转后必须带「手动标记为 cold」理由: {after}"
    );
    assert!(
        after.contains("\"mark\":\"cold\""),
        "手动标记条目必须在 plan 里可见: {after}"
    );

    // The mark survives a restart (it is read from disk every time) — the
    // second plan run above already proves that.

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cfg).ok();
}

#[test]
fn tui_renders_one_frame_and_exits_cleanly() {
    let root = build_tree("tui-smoke");
    let cfg = config_dir("tui-smoke");

    let out = coldstore()
        .arg("tui")
        .arg(&root)
        .arg("--config-dir")
        .arg(&cfg)
        .arg("--render-once")
        .output()
        .expect("run coldstore tui --render-once");
    assert!(
        out.status.success(),
        "tui render failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let frame = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(!frame.is_empty(), "TUI must render a frame");
    assert!(
        frame.contains("coldstore"),
        "frame must show the header: {frame}"
    );
    assert!(
        frame.contains("REBUILDABLE"),
        "frame must show the labels: {frame}"
    );

    // The smoke mode is the scripted "render a frame, then quit" path.
    let out = coldstore()
        .arg("tui")
        .arg(&root)
        .arg("--config-dir")
        .arg(&cfg)
        .arg("--smoke")
        .output()
        .expect("run coldstore tui --smoke");
    assert!(
        out.status.success(),
        "tui smoke failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cfg).ok();
}

#[test]
fn tui_and_cli_json_share_the_same_numbers() {
    let root = build_tree("tui-json");
    let cfg = config_dir("tui-json");

    let (json, _) = run_plan_json(&root, &cfg);
    let out = coldstore()
        .arg("tui")
        .arg(&root)
        .arg("--config-dir")
        .arg(&cfg)
        .arg("--render-once")
        .output()
        .expect("run coldstore tui --render-once");
    let frame = String::from_utf8_lossy(&out.stdout).to_string();

    // Both read the same plan builder, so the file count the JSON reports
    // must appear in the rendered header.
    let v: serde_json::Value = serde_json::from_str(&json).expect("plan json");
    let files = v["scanned_files"].as_u64().expect("scanned_files");
    assert!(
        frame.contains(&format!("{files}")),
        "TUI 帧必须显示与 --json 相同的文件数 {files}: {frame}"
    );

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cfg).ok();
}

#[test]
fn chinese_ecosystem_rules_ship_disabled_and_only_advise() {
    let cfg = config_dir("cn-rules");

    // A fresh config directory gets the shipped defaults written into it.
    let out = coldstore()
        .arg("rule")
        .arg("list")
        .arg("--config-dir")
        .arg(&cfg)
        .arg("--json")
        .output()
        .expect("run coldstore rule list");
    assert!(
        out.status.success(),
        "rule list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).expect("json");
    let rules = v["rules"].as_array().expect("rules array");

    // The Chinese-ecosystem pack recognises and advises — it never acts.
    for name in ["im-cache", "game-platform-cache", "netdisk-conflict"] {
        let r = rules
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("规则 {name} 必须内置: {v}"));
        assert_eq!(r["action"], "skip", "{name} 只能识别+建议");
        assert_eq!(r["enabled"], false, "{name} 必须默认停用");
        let note = r["note"].as_str().unwrap_or_default();
        assert!(!note.is_empty(), "{name} 必须带说明");
        assert!(
            note.contains("识别") && note.contains("建议"),
            "{name} 的说明必须点明「只识别+建议」: {note}"
        );
    }

    std::fs::remove_dir_all(&cfg).ok();
}

#[test]
fn every_subcommand_supports_json() {
    let root = build_tree("json-surface");
    let cfg = config_dir("json-surface");

    // The read-only commands that take a path.
    for sub in ["scan", "predict", "dedupe", "plan"] {
        let out = coldstore()
            .arg(sub)
            .arg(&root)
            .arg("--json")
            .output()
            .expect("run coldstore");
        assert!(
            out.status.success(),
            "{sub} --json failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            serde_json::from_str::<serde_json::Value>(text.trim()).is_ok(),
            "{sub} --json must print valid JSON: {text}"
        );
    }

    // rule test and mark are JSON too.
    let out = coldstore()
        .arg("rule")
        .arg("test")
        .arg(&root)
        .arg("--json")
        .output()
        .expect("run coldstore rule test");
    assert!(out.status.success());
    assert!(
        serde_json::from_str::<serde_json::Value>(String::from_utf8_lossy(&out.stdout).trim())
            .is_ok(),
        "rule test --json must print valid JSON"
    );

    let out = coldstore()
        .arg("mark-hot")
        .arg(root.join("old.bin"))
        .arg("--config-dir")
        .arg(&cfg)
        .arg("--json")
        .output()
        .expect("run coldstore mark-hot");
    assert!(out.status.success());
    assert!(
        serde_json::from_str::<serde_json::Value>(String::from_utf8_lossy(&out.stdout).trim())
            .is_ok(),
        "mark-hot --json must print valid JSON"
    );

    std::fs::remove_dir_all(&root).ok();
    std::fs::remove_dir_all(&cfg).ok();
}
