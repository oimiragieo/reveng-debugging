---
name: cookbook-static-first
description: Use when you need the cheapest static probes for an authorized binary before decompile. DO NOT USE for cracking or exploit recipes.
---

# cookbook-static-first

Cheap structural work first. A first-pass parser is a sketch, not a map. Organize
what inventory already returned, then ask one narrow question with a bounded
slice. Decompile (`reveng-debug ghidra`) is operator-opt-in and last.

Source: local methodology PDF `references/courseware/reversing/Reverse Engineer's Cookbook.pdf`
(gitignored). Original wording only. Do not paste slides or scripts from that file.

## Hard rules

| Do | Never |
|---|---|
| Copy via `inventory` into `%TEMP%\reveng-debug\<session>\` | Mutate the original |
| `identify` then `inventory`, then at most two `slice` needles | Open Ghidra / dumpbin / `app-re` unless the operator asked |
| Read `findings.imports`, `exports`, `sections`, capped `strings` | Treat a missing name as “this binary has none” |
| `reveng-debug slice PATH NEEDLE` (window 200, 20 hits) | `cat`, `Get-Content`, or Read a whole file / minified bundle |
| Label every claim **seen**, **inferred**, or **unknown** | Claim a call happened; inventory is linkage, not execution |
| Stop after 2–4 CLI calls once the question has evidence | Walk every function, recurse graphs, or “just pretty-print it all” |
| Work only on software the operator is authorized to inspect | Cracking, keygen, patch, unpack, or exploit recipes |

`slice` is a text window, not a Mach-O fat-binary architecture list. Those live
under inventory `findings.slices` when LIEF reports them.

## Workflow

1. **Authorize and copy.** Confirm the target is in scope. Do not execute it.

   ```powershell
   reveng-debug doctor
   reveng-debug identify .\target
   reveng-debug inventory .\target
   ```

   Keep `session_id` and `workspace_path`. Later probes hit the copy.

2. **Sort the cheap tables.** From inventory JSON only:

   | Kind | Look at | Question it answers |
   |---|---|---|
   | PE / ELF / Mach-O | `imports` (dll + names, already truncated) | Which libraries exist on the IAT / dynamic table |
   | | `exports` (capped) | What this module advertises |
   | | `sections` | Layout sketch; size mismatch is **inferred**, not packing proof |
   | | `strings` (max 200) | Debug / log / format hints for a later needle |
   | JS / Electron | `package`, `sourcemaps`, `ipc_hits`, file list (capped) | Entry + IPC surface without opening bundles |
   | Unknown kind | `limitations` | Adapter did not run — **unknown**, not empty |

   A first inventory pass will miss symbols, recover incomplete names, and
   truncate lists. Record the engine (`lief` vs `pefile`) and `coverage`. Do not
   invent dumpbin or Ghidra rows when `doctor` did not mark them present.

3. **Name from cheap metadata, not decompile.** Prefer strings and import names
   the inventory already showed: log / assert text, `OutputDebugString`-style
   messages, ObjC / Mach-O metadata fields if present, `package.json` `main`.
   One naming pass on those hits is enough. Do not write a universal
   “backtrace every operand” loop.

4. **One needle, then stop.** Pick the operator’s question (a symbol, an IPC
   channel, a library name). Slice the **session copy**, never the original:

   ```powershell
   reveng-debug slice .\copy NEEDLE --session-id <id>
   ```

   Empty `hits` is **unknown** (not sampled, or not text), not “absent”.
   Do not raise the window. Do not dump the rest of the file “for context”.
   A second needle is allowed; a third needs a new operator question.

5. **Do not graduate yet.** Recursion, full call graphs, and recovered
   prototypes wait for an explicit `ghidra` / `app-re` opt-in on the same
   session copy. This skill ends at organized inventory plus capped slices.

## Output contract

Return a short table, not a transcript:

```
session: <id>
kind: <identify>
engine / coverage: <from inventory>
probe  | result                         | confidence
------ | ------------------------------ | -----------
IAT/libs | <few dll or so names>        | seen
exports  | <count or unknown>           | seen|unknown
needle   | <slice hit count, 0–20>      | seen|unknown
```

Two to four bullets of what you still cannot know (unlisted imports past the
cap, unread sections, no runtime). Quote at most one slice snippet if it
answers the question; never paste inventory `strings` in full.

## Siblings

- `reveng-debug` — CLI router (`doctor` / `identify` / `inventory` / `slice`)
- `cookbook-format-tricks` — magic-byte identify only
- `eilam-reversing-foundations` — cheap reversing before decompile
- `pe-iat-capability-map` — import names as capability buckets, not calls
- `rce-process` — observe / hypothesize / verify after this pass
- `rce-artifacts` — session artifacts when you must keep a slice receipt
