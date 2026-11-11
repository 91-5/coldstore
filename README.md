# coldstore

Predict, archive, retrieve — a space-saving engine for Windows NTFS drives.

**Status: under construction (0.1.0, engine layer in development).** This
README will be completed when the CLI surface is finalized. See
`docs/architecture.md` for the working design notes and `docs/format.md`
for the container format specification.

## What it is

ColdStore answers three questions before touching a single byte:

1. **Which files are worth compressing?** A gain predictor measures real
   zstd compression ratios on stratified samples instead of trusting file
   extensions (compressing a `.png` with zstd yields ~100% of its original
   size — measured on real corpora).
2. **Which files are duplicates?** Size-bucketed SHA-256 exact detection,
   reported as a plan, never executed silently.
3. **How do I get one file back?** Archives are streams of independent
   zstd frames (one frame per file) with a self-contained index, so a
   single file is retrieved by decompressing exactly one frame and
   verifying its SHA-256.

## What it is not

- Not a general disk-space analyzer (gdu / WizTree / czkawka do that well).
- Not a file organizer — it never moves or renames user files.
- Not a solid archiver — per-file frames cost ~1–2% versus solid archives
  (measured) and buy single-file random retrieval.

## Boundaries

- **Read-only by default.** Only the explicit `archive` and `extract`
  commands write to disk. No command deletes or moves user files.
- **Fully local.** No network access, no telemetry, no update checks.

## Building

Requires a Rust toolchain (stable).

```
cargo build --release
```

## License

MIT — see [LICENSE](LICENSE).
