# Changelog

All notable changes to ColdStore are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-11-12

First public shape of the tool: engine layer + execution layer.

### Engine layer

- **Scanner** — recursive enumeration with per-file metadata, reparse
  points (junction/symlink) never followed, every skipped entry reported
  with a reason.
- **Gain predictor** — stratified sampling with real zstd-3 runs →
  per-class measured ratios, savings intervals and a verdict
  (`ARCHIVE` / `SKIP` / `UNSURE` / `DELETABLE`). Extension pre-filter
  plus a magic-header re-check, so a `.png` that is really a zip is
  caught.
- **Duplicate detection** — size bucketing plus exact SHA-256, reported
  as a plan; never executed silently.
- **`.coldstore` container** — one independent zstd frame per file, an
  embedded skippable-frame index as the single source of truth, a
  derived `.idx` sidecar cache that fails closed on disagreement, and a
  mandatory SHA-256 per entry.
- **Single-file retrieval** — decode exactly one frame and verify it
  against the recorded hash.
- **Cold/hot classification** — `mtime` as the primary signal, known
  rebuildable directories, manual marks; `LastAccessTime` never
  participates.

### Execution layer

- **Rule engine** — declarative TOML rules, four actions
  (`ntfs_compress` / `archive` / `dedupe_hardlink` / `skip`),
  priority-desc first-match-wins, and the predictor holding the final
  veto. Built-in rules ship disabled; the Chinese-ecosystem pack
  (WeChat/QQ, Steam/WeGame/Epic, netdisk conflict copies) recognises and
  advises only.
- **Six-step archive sequence** — hash → write container → retrieve the
  frame and compare SHA-256 → only then move the source into the
  quarantine → journal → explicit confirmation before anything is
  really deleted. Step 3 is structurally the only path; there is no flag
  that skips it.
- **Quarantine + undo** — batches with concrete expiry dates, a
  journaled, replayable log, and an undo that restores files to their
  original paths without ever overwriting a file that changed during the
  quarantine window. `undo --keep-container` keeps the verified archive
  as a safety net.
- **NTFS transparent compression** — `FSCTL_SET_COMPRESSION` via
  `DeviceIoControl` (no external `compact.exe`): asynchronous,
  interruptible at file boundaries, resumable by re-running the same
  command, reversible with `COMPRESSION_FORMAT_NONE`, with a measured
  compression ratio and hardcoded exclusions for system directories and
  already-compressed formats.
- **CLI** — the full command surface with `--json` on every
  subcommand, `run`/`compress`/`decompress` defaulting to dry-run, and
  a second-confirmation gate above 10 GB.
- **TUI** (`coldstore tui`) — scan → analysis → selection → execution,
  rendered over the same plan data source as `coldstore plan --json`.
  The TUI never touches a file itself; all writes go through the audited
  sequence functions.

### Measured results (this machine, 2026-11-10 / 2026-11-12)

- Independent frames vs solid `tar.zst` on `glasspill/src`: **−0.23%**.
- NTFS compression via `FSCTL_SET_COMPRESSION` on rust build artifacts:
  **2.50:1** over 653.6 MB (rule-selected) and **2.07:1** over 2.36 GB
  (whole debug tree).
- Compression round trip: 18/18 sampled files byte-identical after
  compress → decompress.

[Unreleased]: https://github.com/91-5/coldstore/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/91-5/coldstore/releases/tag/v0.1.0
