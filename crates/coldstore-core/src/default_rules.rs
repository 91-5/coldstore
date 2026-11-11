//! Built-in default rule table, shipped as TOML text.
//!
//! Card D1: the defaults encode what the 2026-11-10 measurements taught us
//! about this class of machine (rust `target/` dominates, already-compressed
//! media must never be touched, logs archive well). **Every default rule is
//! `enabled = false`** — the user opts in explicitly, nothing auto-runs.

/// Default `%APPDATA%\coldstore\config.toml` content (first run / reset).
pub const DEFAULT_CONFIG_TOML: &str = r#"# coldstore 配置 —— 默认全部关闭；显式 enabled = true 才会参与 run --execute
# 语义：默认只读；--execute 是唯一写盘开关（ADV-N4，无第二套写盘路径）

[coldness]
# 多少天未修改算 COLD（主信号是 mtime；atime 永不参与——本机 DisableLastAccess=2）
cold_after_days = 30
# 可重建目录组件（命中即标 REBUILDABLE，只标记提示，绝不自动删）
rebuildable_dirs = ["target", "node_modules", ".venv", "venv", "__pycache__", ".cache", "dist", "build"]

# ADV-N7：--execute 前命中总量超过该值（GB）必须二次确认
confirm_threshold_gb = 10

# ── 默认规则（全部 enabled = false）──────────────────────────────────

[[rule]]
name = "rust-target"
priority = 10
match_path = ["**/target/debug/**", "**/target/release/**"]
match_ext = ["rlib", "rmeta", "pdb", "o", "exe", "dll"]
min_size_mb = 10
action = "ntfs_compress"
enabled = false

[[rule]]
name = "dev-caches"
priority = 5
match_path = ["**/node_modules/**", "**/.venv/**", "**/venv/**", "**/__pycache__/**", "**/.cache/**"]
action = "skip"
enabled = false

[[rule]]
name = "logs"
priority = 5
match_path = ["**/logs/**"]
match_ext = ["log"]
action = "archive"
enabled = false

[[rule]]
name = "media"
priority = 5
match_ext = ["jpg", "png", "mp4", "mp3", "pdf", "zip", "7z"]
action = "skip"
enabled = false
"#;
