# `.coldstore` container format (draft, v0.1)

> Finalized with the archive milestone; this draft records the committed
> design so downstream work can code against it.

## Layout

```
+--------------------------------------------------+
| Header: magic "COLDSTR\0" + format version + flags|
+--------------------------------------------------+
| Frame 0: independent zstd frame (file 0)          |
| Frame 1: independent zstd frame (file 1)          |
| ...                                               |
| Frame N: independent zstd frame (file N)          |
| Skippable frame: embedded index (source of truth) |
+--------------------------------------------------+
```

## Rules

1. **One file = one independent zstd frame.** No solid blocks. Any file is
   retrievable by seeking to its frame offset and decoding exactly one
   frame.
2. **Embedded index (single source of truth)** rides in a zstd *skippable*
   frame (magic `0x184D2A50..0x184D2A5F`) appended after the data frames.
   It is written atomically with the container and travels with it.
3. **Sidecar `.idx` is a derived cache** for fast listing without parsing
   the frame area. If both exist and disagree on any key, operations fail
   with `embedded index vs sidecar idx disagree on key <N>` — never a
   silent preference.
4. **Skippable frame content is limited to 255 MiB** (32-bit content
   length field). Indexes beyond the limit must fall back to a sidecar
   `.idx` (no index chunking in v0.1); the container header records which
   mode is authoritative.
5. **Every index entry stores the SHA-256 of the original file** (mandatory
   since v0.1). Retrieval verifies it; a missing hash in an entry forces an
   `UNVERIFIED` warning with size-only checking.
6. **Offsets and sizes are u64** throughout (files > 2 GiB are valid
   members).
7. Index entries record the original path, original size, compressed size,
   frame offset, mtime and sha256; path + ordinal is the identity pair
   (NTFS is case-insensitive, so paths alone are not unique keys).
8. Cross-volume container writes are allowed (freeing space on the source
   volume by archiving to another disk is a primary use case). Cross-volume
   *relative-path restore* is rejected with the entry name, both volume
   letters and the remediation.
