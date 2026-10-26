---
name: rce-artifacts
description: Use when managing RE artifacts (inventory JSON, ledger, optional Ghidra JSON) for an authorized session. DO NOT USE to hide artifacts or destroy evidence.
---

# rce-artifacts

Keep one session workspace. Prefer named fields (strings, imports, exports, symbols) over walls of text. If a listing is required, dump it **once** into that workspace, then `slice`. Never paste a whole minified file or a whole disassembly into chat.

Source idea: local gitignored PDF `references/courseware/reversing/Reverse Code Engineering (RCE).pdf`. That paper hunts names, then stares at assembly, then appends a payload. Keep the name-first / listing-as-file habit. Drop the debugger run, the crash recipe, and the appendix. Original wording only — do not quote or reconstruct the PDF.

## Hard rules

| Do | Never |
|---|---|
| Work under `%TEMP%\reveng-debug\<session>\` (or `$env:REVENG_DEBUG_STATE_ROOT`) | Mutate the original; write dumps next to the source tree |
| Read `inventory` JSON + `ledger.jsonl` first | `cat` / `Get-Content` a minified bundle or a full listing |
| Dump disassembly **once**, opt-in: `reveng-debug ghidra` (or a future objdump adapter) | Re-dump the same binary each turn; invent dumpbin/Ghidra/objdump output |
| Query saved dumps with `reveng-debug slice PATH NEEDLE --session-id ID` | Hide, wipe, rewrite, or “clean” the ledger / artifacts to drop a finding |
| Label claims **seen** / **inferred** / **unknown** | Treat a string or symbol as proof it executed |

Missing optional engines are **unsupported** or **unknown**. Run `reveng-debug doctor`. `dynamic_attach` is unsupported. Do not execute the target.

## Session layout

`reveng-debug inventory PATH` admits a copy and opens the session:

```
%TEMP%\reveng-debug\<session_id>\
  work\              admitted copy (only tree you may touch)
  artifacts\         derived files (Ghidra JSON, extracts, any listing you persist)
  session.json       index of admitted originals → workspace paths
  ledger.jsonl       append-only evidence
```

Reuse `--session-id` on later `inventory`, `slice`, `ghidra`. `reveng-debug session show ID` is the receipt. Do not start a second session to bury the first.

## What counts as an artifact

| Kind | Where it already lives | How to read it |
|---|---|---|
| Strings | `findings.strings` on PE/ELF/Mach-O inventory (printable run, capped) | **seen** if present in that array. Not listed → **unknown**, not absent (cap is 200) |
| Symbols / names | PE `imports` / `exports`; ELF/Mach-O `exported_symbols` / `dynamic_symbols`; JS `package` / `ipc_hits` | **seen** as names on disk. Not a call trace |
| Disassembly / functions | Opt-in `artifacts/ghidra_functions.json` after `reveng-debug ghidra` | Function list is **seen**. Full listing is **unknown** until a listing file exists |
| Evidence | `ledger.jsonl` (also echoed on inventory / `session show`) | Append. Do not edit old lines |
| Text slices | `reveng-debug slice` hits (`window` 200, `limit` 20) | **seen** for the window; outside the window is **unknown** |

`slice` is for **text** (saved JSON, JS, a persisted listing). Do not treat a PE/ELF/Mach-O copy as a source file and dump its bytes. Use inventory fields for native strings/symbols.

## Dump once, then slice

1. **Index, don’t dump.** `reveng-debug identify PATH` then `inventory PATH`. Record `session_id`. Read `coverage` and `engine` (`pefile` is thinner than LIEF). Copy only the fields you will cite.
2. **Needles from names.** Pick strings, import/export names, or IPC markers from that JSON. Run `reveng-debug slice <workspace-file> NEEDLE --session-id ID`. New needles on the same files; do not re-inventory to “refresh.”
3. **One listing, if the operator opts in.** `reveng-debug ghidra PATH --session-id ID` writes `artifacts/ghidra_functions.json` (capped function export, static, target not executed). If `analyzeHeadless` is missing, status is **unsupported** — stop; do not fake functions. There is **no** `reveng-debug objdump` yet. `llvm-objdump` / `dumpbin` may show as present on `doctor`; do not run them into chat. If the operator later adds a listing, save it **once** under `artifacts/` and slice that file.
4. **Minified / huge text.** Never open the whole file. Slice. Inventory already sampled JS (first 80 files, sourcemap / IPC regex).
5. **Stop.** Answer from cited artifacts. Do not delete `work\`, `artifacts\`, `session.json`, or `ledger.jsonl` because a finding is inconvenient. Retention is the operator’s call, not the agent’s.

Ghidra project paths must not contain `.`-prefixed segments; the adapter already relocates those. Point BYO tools at the **session copy**, never the original.

## Output contract

```
Session: <id>  root: %TEMP%\reveng-debug\<id>\
Authority: owned | authorized | refused
Index: identify=... inventory=engine/coverage  (seen fields: strings|imports|exports|symbols)
Listing: none | ghidra_functions.json | unsupported | operator-saved artifacts/<file>
Slices: <needle> → hits|empty  (empty = unknown, not absent)
Ledger: appended | not touched
Redactions: none (do not hide)
Result: <what the artifacts support, labeled seen/inferred/unknown>
```

Cap at 2–4 tool calls unless the operator expands the question.

## Siblings

- `reveng-debug` — command router (`doctor`, `identify`, `inventory`, `slice`, `session show`, `ghidra`)
- `rce-process` — observe / hypothesize / verify; this skill is the file hygiene for that loop
- `cookbook-static-first` — cheapest probe order
- `eilam-reversing-foundations` — cheap reversing before decompile
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
