# Contributing to ColdStore

Thanks for looking at ColdStore. This document is short on purpose: the
project has one idea, and the rules below exist to protect it.

## The one idea

**预测 → 规则 → 可逆执行。** ColdStore decides *before* it touches a
file, and every write it performs can be taken back.

If a change makes the tool more willing to delete, move or rename
user data, it is the wrong change — even if it is convenient.

## Hard rules

These are not style preferences. A pull request that breaks one of them
will not be merged.

1. **Read-only by default.** `--execute` is the only write switch. Never
   introduce a second path that writes.
2. **Never delete silently.** Every deletion needs a journal record, a
   way back, and an explicit confirmation.
3. **Archiving is not releasing.** Anything that shows the user a
   "space saved" number must also state what still occupies the disk.
4. **`LastAccessTime` is never the sole cold/hot signal.** Windows may
   not update it at all (`DisableLastAccess = 2`).
5. **REBUILDABLE content is never deleted automatically.** The tool
   points at it and shows the rebuild cost; the user decides.
6. **All file mutations live inside the journaled sequence functions.**
   A stray `fs::remove` / `fs::rename` outside the quarantine/undo
   sequences is a bug, not a style issue. The delivery notes ship a
   `git grep` proof of this.
7. **No network.** No telemetry, no update checks, no cloud anything.
   The whole tool must work with the cable unplugged.
8. **No resident processes.** No background daemons, no autostart
   entries, no page-file tuning. ColdStore runs when you run it.
9. **Measure, don't guess.** Claims about ratios, savings or speeds come
   from a real measurement with a stated corpus and date. A heuristic
   must be labelled as a heuristic.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must be green before a review.

- **Tests live next to the thing they test** (`#[cfg(test)] mod tests`),
  except for cross-process or end-to-end scenarios, which go into
  `crates/coldstore-cli/tests/`.
- **Test fixtures live under the system temp directory** and are cleaned
  up. Never write into a user's real directories, and never touch
  `glasssuite` / `glassdesk` / `glasspill` — those are read-only corpora
  (zero writes, always).
- **No hard-coded personal paths.** Use `std::env::temp_dir()` and
  `config_dir()`; the repo is checked for `C:\Users\<someone>` patterns.
- **Determinism matters.** `coldstore plan --json` must be byte-identical
  across runs — a report that changes between two identical invocations
  is a bug. If you add a field, ask whether it is stable.

## Adding a rule or an action

- The four actions (`ntfs_compress`, `archive`, `dedupe_hardlink`,
  `skip`) are deliberately the *only* ones. Adding a fifth means the
  product lost its predictability — propose it as an issue first.
- Built-in rules ship **disabled**. The user opts in explicitly.
- A rule that only *recognises* something (the Chinese-ecosystem pack)
  must use `action = "skip"` and carry a `note` explaining what it
  found and what the user might want to do about it.

## Commit and review

- One stage per commit; the message says **why**, not just what.
- Every acceptance criterion in the delivery note must carry the real
  command and its real output, including the exit code.
- "It should work" is not evidence. Run it, paste the output.

## Reporting a bug

Please include: the command, the exit code, the output, your Windows
version, and the filesystem of the affected path (NTFS vs FAT32/exFAT
changes what is possible).
