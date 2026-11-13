# ColdStore architecture

> Living document; updated as each milestone lands. The engine layer is
> card OC-20261110-001, the execution layer is OC-20261110-002 (P1 rule
> engine + D5 cold/hot, P2 quarantine/undo, P3 NTFS compression, P4 CLI/TUI
> + resource files).

## Layout

```
crates/
  coldstore-core/     engine + execution logic, pure library, no CLI/UI
  coldstore-cli/      command-line front-end (bin: coldstore) + TUI
docs/                 format specification and these notes
```

The core crate never depends on the CLI crate; the CLI crate never
re-implements engine logic.

## Components

| Component | Crate module | Responsibility |
|---|---|---|
| Scanner | `scan` | enumerate files, metadata, reparse-point safety, skip reasons |
| Magic | `magic` | file-header sniffing to catch extension lies |
| Predictor | `predict` | stratified sampling + measured zstd ratios → per-class savings |
| Dedup | `dedupe` | size-bucket + SHA-256 duplicate detection → plan only |
| Archive | `archive` | `.coldstore` container: independent zstd frames + index |
| Retrieval | `archive` | single-frame decode + SHA-256 verification |
| Rules | `rules` | TOML rules → per-file action (priority, first-match-wins) |
| Coldness | `coldness` | `COLD`/`WARM`/`REBUILDABLE`/`UNKNOWN` + reasons + manual marks |
| Quarantine | `quarantine` | the six-step archive sequence, journal, undo, recovery |
| NTFS | `ntfs` | `FSCTL_SET_COMPRESSION` executor: async, cancellable, reversible |

## The six-step archive sequence

The trust base of the product. The order is fixed, and **step 3 has no
escape hatch** — no flag, no config, no branch skips it.

1. Read the source → SHA-256.
2. Write the archive container via 001's `archive()` API.
3. Retrieve the frame via 001's `retrieve()` API and compare its SHA-256
   against step 1. A mismatch aborts immediately and cleans up.
4. Only then move the source into the quarantine batch directory (same
   volume = rename; cross-volume = copy + verify + delete source).
5. Journal every step (intent before, result after).
6. `quarantine delete --confirm` — and only then does the space actually
   drop.

Every `fs::remove` / `fs::rename` / `fs::copy` in the codebase lives
inside these sequence functions (`archive_batch`, `quarantine_delete`,
`undo_batch`, `recover_batch`). The delivery notes ship a `git grep`
proof of that mapping.

## The NTFS compression path

Deliberately *not* a sequence function, because it mutates nothing but a
file attribute: it never deletes, moves or renames. That is why the
"all mutations belong to a sequence" invariant holds for it vacuously.

- `FSCTL_SET_COMPRESSION` + `DeviceIoControl`
  (`COMPRESSION_FORMAT_DEFAULT` to enable, `COMPRESSION_FORMAT_NONE` to
  undo) — no external `compact.exe`.
- The batch runs on a worker pool; the caller keeps rendering progress
  and can cancel at any file boundary.
- Already-compressed files are skipped, which is what makes an
  interrupted run resumable by simply running it again.
- The ratio is measured (`GetCompressedFileSizeW`), not estimated.

## TUI ↔ CLI

The TUI is a *view*, never an actor:

```
plan::build(path) ──┬──► coldstore plan --json   (the contract)
                    └──► TUI state                (the same numbers)

run::plan_run()  ──► run::execute_run()  ──► the audited sequence functions
      ▲                    ▲
      └──── TUI selection ─┘
```

`execute_run` is the only function in the CLI that writes user data, and
it dispatches exclusively to `quarantine::archive_batch` or the NTFS
batch. The TUI calls the very same functions — it cannot drift from the
CLI and it cannot write on its own.

## Key invariants

1. **Read-only by default.** `--execute` is the only write switch, and
   there is exactly one such path per action.
2. **No solid compression.** One independent zstd frame per file. Measured
   cost of independence vs solid `tar.zst` on a real 38 MB corpus: +1.33%
   (and −0.23% on the 36.4 MB `glasspill/src` corpus).
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
7. **The plan is reproducible.** `coldstore plan --json` is byte-identical
   across runs; volatile provenance (e.g. "this run created the config")
   never leaks into the machine-readable output.
8. **A label always carries a reason.** Every temperature label, every
   rule hit and every analysis row explains itself — the tool never says
   "cold" without saying why.
