# ColdStore architecture (working notes)

> Living document; updated as each milestone lands. Scope for the engine
> layer is card OC-20261110-001; the execution layer (rule engine,
> quarantine, undo, TUI) is a follow-up and must not leak into the core
> crate.

## Layout

```
crates/
  coldstore-core/     engine logic, pure library, no CLI/UI
  coldstore-cli/      command-line front-end (bin: coldstore)
```

## Components

| Component | Crate module | Responsibility |
|---|---|---|
| Scanner | `scan` | enumerate files, metadata, reparse-point safety, skip reasons |
| Magic | `magic` | file-header sniffing to catch extension lies |
| Predictor | `predict` | stratified sampling + measured zstd ratios → per-class savings |
| Dedup | `dedupe` | size-bucket + SHA-256 duplicate detection → plan only |
| Archive | `archive` | `.coldstore` container: independent zstd frames + index |
| Retrieval | `archive` | single-frame decode + SHA-256 verification |

## Key invariants

1. **Read-only by default.** Only `archive` (writes container) and
   `extract` (writes destination) touch disk.
2. **No solid compression.** One independent zstd frame per file. Measured
   cost of independence vs solid `tar.zst` on a real 38 MB corpus: +1.33%.
3. **Reparse points are never followed** (junction/symlink) by default:
   prevents cycles and escaping the scanned tree. Skipped entries are
   reported with their target path so the audit trail is visible.
4. **atime is low-trust.** Windows may not update `LastAccessTime`
   (system-managed `DisableLastAccess`); it is collected but never used as
   the sole cold/hot signal.
5. **Predictions are measured, not assumed.** Extension pre-filter → magic
   header re-check → stratified sampling with real zstd -3 runs → volume-
   weighted extrapolation with confidence intervals.
6. **Fail-closed indexing.** The embedded skippable-frame index is the
   single source of truth; a sidecar `.idx` is derived and any mismatch
   between them is an error, never a silent pick.
