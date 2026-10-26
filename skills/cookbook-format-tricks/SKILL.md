---
name: cookbook-format-tricks
description: Use when identify() kind is surprising and you need a magic-byte first-move. DO NOT USE to forge file formats or malware droppers.
---

# cookbook-format-tricks

Settle **what this artifact is** before inventory. A first-pass classifier will
miss nested containers and whole regions. Recover identity from a short prefix,
then stop if that prefix is not a kind `identify` actually names.

Source: local methodology PDF `references/courseware/reversing/Reverse Engineer's Cookbook.pdf`
(gitignored). Original wording only. Do not paste slides, scripts, or byte recipes
from that file. Do not grow `TargetKind`.

Sibling for commands: `skills/reveng-debug/SKILL.md`. Parser:
`src/reveng_debug/router/identify.py`.

## Hard rules

| Do | Never |
|---|---|
| Run `reveng-debug identify PATH` and treat its `kind` as the router oracle | Rename, prepend headers, or “fix” the file so a later identify agrees |
| Read at most the first 64 bytes of the **session copy** when kind looks wrong | Dump the rest of the file, carve payloads, or write a polyglot |
| Map a prefix only onto `pe` / `elf` / `macho` / `javascript` / `electron` / `website` | Invent zip, pdf, java, .NET, go, firmware, or “packed PE” kinds |
| Label **seen** (prefix or suffix identify used), **inferred** (suffix-before-magic), **unknown** | Upgrade unknown because `file`, a guess, or an inner segment “looks like” another format |
| Leave unknown kinds unknown; inventory then reports `engine: none` | Run Ghidra / dumpbin / `app-re` to “confirm” a kind identify did not emit |
| Work only on software the operator is authorized to inspect | Forge containers, droppers, malformed headers, or unpack-as-attack |

`identify` is not a full container walk. Mach-O segments, PE import tables, and
embedded app archives are **inner layout**. They are not a second `TargetKind`.

## What identify actually consults

Order in `identify_target` (do not reorder it in your head):

1. Missing path → `unknown`.
2. **Directory:** `package.json` containing `electron` → `electron`; any other
   `package.json` → `javascript`; no `package.json` → `unknown` (even if the
   tree holds an `.exe`).
3. **Suffix before any header:** `.asar` → `electron`; `.html`/`.htm` →
   `website`; `.json` with `"kind": "website-capture"` → `website`;
   `.js`/`.mjs`/`.cjs`/`.ts` → `javascript`. These paths **do not read magic**.
4. **Header (first 64 bytes):** stripped HTML doctype/`<html>` → `website`;
   `MZ` → `pe`; `\x7fELF` → `elf`; Mach-O / fat prefixes (`\xca\xfe\xba\xbe`,
   `\xcf\xfa\xed\xfe`, `\xce\xfa\xed\xfe`, `\xfe\xed\xfa\xce`,
   `\xfe\xed\xfa\xcf`) → `macho`.
5. **Suffix fallback after magic missed:** `.exe`/`.dll`/`.sys` → `pe`.
6. Else `unknown`.

A surprising kind is usually suffix-first winning over bytes, or a prefix that
collides (fat Mach-O vs other `CAFEBABE` files). Record the conflict. Do not
correct the bytes.

## Workflow

1. **Authorize.** Named owner and a path. Do not execute the target.

   ```powershell
   reveng-debug doctor
   reveng-debug identify .\target
   ```

   Keep `kind`. Do not inventory yet if that value disagrees with the operator’s
   expectation.

2. **Name the surprise.** One line: expected vs `identify` vs the rule that
   fired (suffix-first, magic, directory `package.json`, or fallback `.exe`).
   Suffix-first kinds are **inferred** from policy, not **seen** magic.

3. **Bounded prefix, copy only.** If you still need the bytes, admit a copy via
   `reveng-debug inventory` (it copies even for unknown) or inspect the existing
   session copy. Sixteen bytes is enough:

   ```powershell
   Format-Hex -Path .\copy -Count 16
   ```

   Map that prefix with the table above. No match → `unknown`. Do not keep
   reading “until it looks familiar.”

4. **Outer kind only.** A PE that later contains an `.asar`, or a Mach-O that
   later contains ObjC metadata, stays the outer kind. Inventory the kind
   identify returned. Inner members are findings, not a kind change.

5. **Stop on unknown.** Inventory JSON will say `target_kind: unknown`,
   `status: unknown`, `engine: none`, limitation `kind unknown; no adapter ran`.
   That is a complete answer. Do not add a `TargetKind`. Do not fetch a richer
   identifier. Do not mint a header so the next run says `pe`.

## Output contract

```
path: <operator path>
kind: pe|elf|macho|javascript|electron|website|unknown
rule: suffix-first | magic | directory | exe-fallback | none
prefix: <≤16 hex bytes or unknown>
surprise: <expected vs kind, or none>
confidence: seen | inferred | unknown
next: inventory this kind | stop (unknown)
```

One sentence on what you still cannot know (inner container, colliding prefix,
unread suffix-first file). Quote at most the prefix. Never paste a reconstructed
file format.

## Siblings

- `reveng-debug` — CLI router; `identify` is the first move
- `cookbook-static-first` — cheapest probes **after** kind is settled
- `eilam-windows-formats` / `goppit-pe-layout` — PE layout only when kind is `pe`
- `packer-detection` — packing is inferred from inventory, not a new kind
- `rce-process` — observe / hypothesize / verify after identity is honest
