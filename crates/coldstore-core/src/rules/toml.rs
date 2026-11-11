//! TOML configuration at `%APPDATA%\coldstore\config.toml` (card D1).
//!
//! B17 semantics, locked: a **corrupt config file is never overwritten** —
//! loading reports the parse error, keeps the file untouched and falls
//! back to the built-in defaults *in memory* so read-only commands keep
//! working. Writes go through `save_config` (tmp + rename), used only by
//! explicit `rule enable/disable`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::default_rules::DEFAULT_CONFIG_TOML;
use crate::rules::Rule;

/// D5 cold/hot configuration: mtime is the primary signal; atime never
/// participates (system-managed `DisableLastAccess` makes it untrustworthy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColdnessConfig {
    /// Days without modification → COLD.
    #[serde(default = "default_cold_after_days")]
    pub cold_after_days: u64,
    /// Directory-name components that mark REBUILDABLE content.
    #[serde(default = "default_rebuildable_dirs")]
    pub rebuildable_dirs: Vec<String>,
}

fn default_cold_after_days() -> u64 {
    30
}

fn default_rebuildable_dirs() -> Vec<String> {
    [
        "target",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".cache",
        "dist",
        "build",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for ColdnessConfig {
    fn default() -> Self {
        ColdnessConfig {
            cold_after_days: default_cold_after_days(),
            rebuildable_dirs: default_rebuildable_dirs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigToml {
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
    #[serde(default)]
    coldness: Option<ColdnessConfig>,
    /// ADV-N7: hit total above this (GB) forces a second confirmation
    /// before `--execute`.
    #[serde(default = "default_confirm_threshold_gb")]
    confirm_threshold_gb: u64,
}

fn default_confirm_threshold_gb() -> u64 {
    10
}

/// Fully-resolved application config (what the engine consumes).
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub rules: Vec<Rule>,
    pub coldness: ColdnessConfig,
    pub confirm_threshold_gb: u64,
}

/// Where the loaded configuration came from — surfaced in CLI output so a
/// fallback is never silent (B17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// File did not exist; defaults were written (first run).
    CreatedDefaults,
    /// Parsed from disk.
    Loaded,
    /// File exists but is corrupt: defaults used *in memory*, file kept.
    /// Carries the parse error for display.
    FallbackDefaults(String),
}

impl ConfigSource {
    pub fn describe(&self) -> String {
        match self {
            ConfigSource::CreatedDefaults => {
                "首次运行，已写入默认配置（全部规则 disabled）".to_string()
            }
            ConfigSource::Loaded => "已加载用户配置".to_string(),
            ConfigSource::FallbackDefaults(err) => format!(
                "配置解析失败：保留原文件不动，本次运行使用内置默认规则（B17）。原因: {err}"
            ),
        }
    }
}

/// `%APPDATA%` (fallback: `%USERPROFILE%\AppData\Roaming`) + `coldstore`.
pub fn config_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE").map(|u| PathBuf::from(u).join("AppData").join("Roaming"))
        })
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("coldstore")
}

pub fn config_path(base: &Path) -> PathBuf {
    base.join("config.toml")
}

pub fn marks_path(base: &Path) -> PathBuf {
    base.join("marks.json")
}

/// Parse a config TOML string into `AppConfig`.
pub fn parse_config(text: &str) -> Result<AppConfig> {
    let raw: ConfigToml = toml::from_str(text).context("TOML 解析失败")?;
    Ok(AppConfig {
        rules: raw.rules,
        coldness: raw.coldness.unwrap_or_default(),
        confirm_threshold_gb: raw.confirm_threshold_gb,
    })
}

/// Serialize an `AppConfig` back to TOML (used by save + round-trip test).
pub fn to_toml(cfg: &AppConfig) -> Result<String> {
    let raw = ConfigToml {
        rules: cfg.rules.clone(),
        coldness: Some(cfg.coldness.clone()),
        confirm_threshold_gb: cfg.confirm_threshold_gb,
    };
    toml::to_string_pretty(&raw).context("TOML 序列化失败")
}

/// Load the configuration from `base/config.toml` (B17 semantics).
pub fn load_config(base: &Path) -> Result<(AppConfig, ConfigSource)> {
    let path = config_path(base);
    if !path.exists() {
        fs::create_dir_all(base)
            .with_context(|| format!("创建配置目录失败: {}", base.display()))?;
        fs::write(&path, DEFAULT_CONFIG_TOML)
            .with_context(|| format!("写默认配置失败: {}", path.display()))?;
        let cfg = parse_config(DEFAULT_CONFIG_TOML)?;
        return Ok((cfg, ConfigSource::CreatedDefaults));
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("读取配置失败: {}", path.display()))?;
    match parse_config(&text) {
        Ok(cfg) => Ok((cfg, ConfigSource::Loaded)),
        Err(err) => {
            // B17: report, keep the file, fall back to defaults in memory.
            let cfg = parse_config(DEFAULT_CONFIG_TOML)?;
            Ok((cfg, ConfigSource::FallbackDefaults(err.to_string())))
        }
    }
}

/// Atomic config write: `<file>.tmp` + rename (never a torn config).
pub fn save_config(base: &Path, cfg: &AppConfig) -> Result<()> {
    fs::create_dir_all(base)?;
    let path = config_path(base);
    let text = to_toml(cfg)?;
    let tmp = {
        let mut s = path.as_os_str().to_owned();
        s.push(".tmp");
        PathBuf::from(s)
    };
    fs::write(&tmp, &text).with_context(|| format!("写临时配置失败: {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("发布配置失败: {}", path.display()))?;
    Ok(())
}

/// Flip `enabled` on one rule by name; error names the missing rule.
pub fn set_rule_enabled(base: &Path, name: &str, enabled: bool) -> Result<AppConfig> {
    // Strict load: a corrupt file BLOCKS mutation (never overwrite, B17).
    let path = config_path(base);
    let text =
        fs::read_to_string(&path).with_context(|| format!("读取配置失败: {}", path.display()))?;
    let mut cfg = parse_config(&text)?;
    let pos = cfg
        .rules
        .iter()
        .position(|r| r.name == name)
        .ok_or_else(|| {
            let names: Vec<&str> = cfg.rules.iter().map(|r| r.name.as_str()).collect();
            anyhow::anyhow!("规则不存在: {name}（现有规则: {}）", names.join(", "))
        })?;
    cfg.rules[pos].enabled = enabled;
    save_config(base, &cfg)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-cfg-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn defaults_parse_and_all_rules_disabled() {
        let cfg = parse_config(DEFAULT_CONFIG_TOML).unwrap();
        assert!(!cfg.rules.is_empty(), "default rule table present");
        assert!(
            cfg.rules.iter().all(|r| !r.enabled),
            "card D1: every default rule ships disabled"
        );
        assert_eq!(cfg.confirm_threshold_gb, 10);
        assert_eq!(cfg.coldness.cold_after_days, 30);
        assert!(cfg
            .coldness
            .rebuildable_dirs
            .contains(&"target".to_string()));
    }

    #[test]
    fn toml_roundtrip_preserves_rules() {
        let cfg = parse_config(DEFAULT_CONFIG_TOML).unwrap();
        let text = to_toml(&cfg).unwrap();
        let back = parse_config(&text).unwrap();
        assert_eq!(cfg.rules.len(), back.rules.len());
        for (a, b) in cfg.rules.iter().zip(back.rules.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.action, b.action);
            assert_eq!(a.priority, b.priority);
            assert_eq!(a.enabled, b.enabled);
            assert_eq!(a.match_path, b.match_path);
            assert_eq!(a.match_ext, b.match_ext);
        }
        assert_eq!(cfg.confirm_threshold_gb, back.confirm_threshold_gb);
    }

    #[test]
    fn missing_config_creates_defaults_b17_never_overwrites_corrupt() {
        let base = temp_base("create");
        let (cfg, src) = load_config(&base).unwrap();
        assert_eq!(src, ConfigSource::CreatedDefaults);
        assert!(!cfg.rules.is_empty());
        assert!(config_path(&base).exists());

        // Now corrupt the file; load must NOT rewrite it and must fall back.
        let corrupt = "this is not toml {{{{";
        let path = config_path(&base);
        fs::write(&path, corrupt).unwrap();
        let before = fs::read(&path).unwrap();
        let (_cfg2, src2) = load_config(&base).unwrap();
        assert!(
            matches!(src2, ConfigSource::FallbackDefaults(_)),
            "B17: fall back, not crash"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "B17: original file byte-identical"
        );

        // And mutation is refused on a corrupt file (never overwrite).
        let err = set_rule_enabled(&base, "logs", true).unwrap_err();
        assert!(err.to_string().contains("TOML 解析失败"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before, "still untouched");

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn enable_disable_roundtrip_is_atomic_and_persistent() {
        let base = temp_base("enable");
        load_config(&base).unwrap(); // creates defaults
        let cfg = set_rule_enabled(&base, "logs", true).unwrap();
        assert!(cfg.rules.iter().find(|r| r.name == "logs").unwrap().enabled);

        // Persisted: reload from disk sees the flip.
        let (cfg2, src) = load_config(&base).unwrap();
        assert_eq!(src, ConfigSource::Loaded);
        assert!(
            cfg2.rules
                .iter()
                .find(|r| r.name == "logs")
                .unwrap()
                .enabled
        );
        assert!(
            !cfg2
                .rules
                .iter()
                .find(|r| r.name == "media")
                .unwrap()
                .enabled
        );

        // Unknown rule → named error listing the roster.
        let err = set_rule_enabled(&base, "nope", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("规则不存在: nope"), "{err}");

        fs::remove_dir_all(&base).ok();
    }
}
