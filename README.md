# coldstore

Predict, archive, retrieve — a space-saving engine for Windows NTFS drives.

**Status: 0.1.0, engine layer complete (card OC-20261110-001, P0–P3 +
P4 CLI).** The execution layer (rule engine, quarantine, undo — card
OC-20261110-002) is a separate, later deliverable. See
`docs/architecture.md` for design notes and `docs/format.md` for the
container format specification.

## What it is

ColdStore answers three questions before touching a single byte:

1. **Which files are worth compressing?** A gain predictor measures real
   zstd compression ratios on stratified samples instead of trusting file
   extensions.
2. **Which files are duplicates?** Size-bucketed SHA-256 exact detection,
   reported as a plan, never executed silently.
3. **How do I get one file back?** Archives are streams of independent
   zstd frames (one frame per file) with a self-contained index, so a
   single file is retrieved by decompressing exactly one frame and
   verifying its SHA-256.

## Measured gains (real corpora, zstd level 3)

Independent-frame archives trade ~1–2% of ratio for single-file random
retrieval. Solid `.tar.zst` vs per-file frames on the same corpus
(`glasspill/src`, 27 files, 36.4 MB): **−0.23%** (frames slightly
*smaller*). Cross-checking the two encodings:

| Corpus | Files | solid tar.zst | per-file frames | delta |
|---|---|---|---|---|
| `glasspill/src` (36.4 MB) | 27 | baseline | −0.23% | ≤ ±5% design gate ✅ |

Frame-level retrieval works even for very large frames
(`window_log = 27`, LDM): retrieving a 19 MB file from the *middle* of a
136 MB, 7-frame archive took **58 ms** with a byte-exact SHA-256 match.
The frame
header self-describes its window size, and every retrieval is
cross-checkable with the stock `zstd` CLI:

```
# decode any single frame without coldstore (independent verification)
zstd -D none -c archive.coldstore 2>/dev/null   # stream decode (frames are plain zstd)
```

Per-format reality on real corpora (predictor samples, not extension
tables):

| Format | measured ratio | verdict |
|---|---|---|
| `.rlib` (Rust build) | 10.3% | archive-worthy |
| `.log` | 4.3% | archive-worthy |
| `.pdb` | 17.7% | archive-worthy |
| `.exe` | 30.6% | archive-worthy |
| `.mp3` | 92.9% | not worth it |
| `.png` | **100.0%** (grew 486 B) | **skipped** — already compressed |

The predictor classifies pre-compressed formats (png/mp4/zip/docx/…)
as `SKIP` before spending any CPU on them.

## Install

From source (the only channel in 0.1):

```
git clone https://github.com/91-5/coldstore
cd coldstore
cargo build --release
# binary at target/release/coldstore.exe
```

Requires a stable Rust toolchain. Windows 10/11 (NTFS) is the target
platform; the engine compiles anywhere Rust does, but drive-letter
volume logic is Windows-specific (UNC paths are accepted for containers
but `extract --to-original` rejects them — see ADV-1 notes in the code).

## Usage

```
coldstore scan <path> [--json]              # read-only scan, skips carry reasons
coldstore predict <path> [--sample N]       # gain forecast, writes nothing
coldstore dedupe <path> [--plan-only]       # duplicate plan, never executes
coldstore archive <path> -o <container>     # archive (never touches sources)
coldstore extract <container> --key <k> -d <dest>  # single-file retrieval
coldstore list <container>                  # list archive contents
coldstore verify <container> [--threads N]  # full integrity check
```

Everything except `archive` and `extract` is strictly read-only.
**No command deletes or moves user files** — deletion/quarantine is the
execution layer's job (card OC-20261110-002), not the engine's.

Every command supports `--json` for machine consumption (the rule
engine and TUI of card 002 build on it).

`verify --threads N` runs the parallel integrity check in a dedicated
pool of exactly N workers (`0` fails closed with an error, never
silently falling back to the default pool).

### Container format in one paragraph

A `.coldstore` file is a header, then one **independent zstd frame per
file** back to back, then a self-describing index (embedded as a zstd
skippable frame). The embedded index is the single source of truth; a
`.idx` sidecar (opt-in via `archive --sidecar`) is a derived cache — if
the two disagree, the engine fails closed. SHA-256 is **mandatory** in
0.1 (written at archive time, checked at every `extract` and `verify`).
Full field-by-field spec: `docs/format.md`.

## What it is not

- Not a general disk-space analyzer (gdu / WizTree / czkawka do that well).
- Not a file organizer — it never moves or renames user files.
- Not a solid archiver — per-file frames cost ~1–2% versus solid archives
  (measured) and buy single-file random retrieval.
- Not an execution layer: no quarantine, no undo, no deletion. That is
  card OC-20261110-002.

## Boundaries

- **Read-only by default.** Only the explicit `archive` and `extract`
  commands write to disk. No command deletes or moves user files.
- **Fully local.** No network access, no telemetry, no update checks.
- **No LLM/semantic classification.** Decisions come from measured
  ratios and byte-level hashing, not model guesses.

## License

MIT — see [LICENSE](LICENSE).
