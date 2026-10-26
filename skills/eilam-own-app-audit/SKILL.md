---
name: eilam-own-app-audit
description: Use when auditing an operator-owned shipped binary for bugs via static inventory. DO NOT USE on third-party products or to weaponize findings.
---

# eilam-own-app-audit

Static bug hunt of a **shipped artifact the operator owns**. The binary (or bundle)
is the thing customers run; source review does not replace reading what actually
shipped. Start at inbound data, then ask whether length, conversion, and copy
stay consistent. Do not patch. Do not execute. Do not produce a PoC.

Source ideas (paraphrase only, never paste): Eldad Eilam, *Reversing: Secrets of
Reverse Engineering* (Wiley, 2005), Chapter 7 “Auditing Program Binaries” —
defect classes that begin at untrusted input. Drop the live-product case study
and every exploit walkthrough. Original wording only.

This skill is the inventory half of `skills/investigations/bug-hunt.md`
(SPEC-RD-006). That prompt compares a **named feature** to expected behavior.
Here the same session copy answers: which inbound surfaces exist, and which
copy/alloc/length facts are **seen** versus still **unknown**.

## Hard rules

| Do | Never |
|----|-------|
| Confirm the operator owns or ships the target before any probe | Audit a competitor, vendor binary, or “the IIS sample from the book” |
| `reveng-debug identify` then `inventory` on a copy under `%TEMP%\reveng-debug\<session>\` | Mutate the original; run the native target; attach (`dynamic_attach` is unsupported) |
| Map inbound surfaces from imports, IPC hits, and capped strings | Treat an IAT name as a call that happened |
| Slice one named feature or one defect-class needle (`reveng-debug slice PATH NEEDLE`) | Dump a minified file, reconstruct a third-party product, or paste courseware listings |
| Label every claim **seen**, **inferred**, or **unknown** | Upgrade “strcpy is imported” into “this overflows” |
| Stop at a report the operator can fix in **their** source | Crash recipes, heap-unlink stories, shellcode, Unicode-payload tricks, ROP |

If authority is unclear, stop. Ask. Do not “proceed statically anyway.”

## What this audit is for

A defect that matters here is a **mistake on a path that accepts data from
outside the process** (CLI, file, socket, registry, environment, renderer IPC)
and then sizes, converts, or copies that data. The question is not “can a
stranger own this box.” The question is: **does our shipped build still honor
the bounds we think we wrote?**

You will not prove control-flow hijack from inventory. You may:

- **See** that an inbound or copy API is declared, that a feature string exists,
  that `NX_COMPAT` / `ASLR` / `GUARD_CF` bits are set or clear.
- **Infer** that a named feature likely touches those APIs because a slice
  window sits near both.
- Leave **unknown** anything that needs runtime, a heap walk, or a decompiler
  you did not run.

Mitigation bits are compile-time marks, not a clean bill of health. A set
`NX_COMPAT` bit does not mean a length bug is gone. A clear bit is not itself
a CVE. See `eilam-windows-formats` for how to speak about `security_flags`.

## Defect-class lenses (questions, not payloads)

Use these as column headers. Do not implement the corresponding attacks.

| Lens | Inventory / slice clue | Honest ceiling without Ghidra |
|------|------------------------|-------------------------------|
| **Copy vs bound** | Imported unbounded or caller-length copies (`strcpy`, `sprintf`, `memcpy`, `wcscpy`, `lstrcpy`, JS `Buffer.copy`); safer siblings (`strcpy_s`, `StringCchCopy`) if present | **Seen**: name in IAT or slice. **Inferred**: feature may use it. Overflow: **unknown** |
| **Alloc size from inbound** | `malloc` / `realloc` / `HeapAlloc` / `Buffer.alloc` / `Buffer.allocUnsafe` plus a length-ish string or export | **Seen**: alloc family declared. Whether size equals inbound length: **unknown** until opted-in listing |
| **Integer width / wrap** | Needles `cb`, `cch`, `len`, `size`, `count`, `ntohl`; a compare immediate next to a copy in an opt-in listing | Signed vs unsigned, add-before-alloc wrap: **inferred** at best from names. Do not invent a failing input |
| **Conversion** | `MultiByteToWideChar`, `WideCharToMultiByte`, `mbstowcs`; character count used as byte count | Encoding expansion is **inferred** from API presence. Do not reconstruct encoding-hostile payloads |
| **Inbound surface** | `recv`, `ReadFile`, `ReadConsole`, `RegQueryValue*`, `InternetReadFile`; JS `ipcMain.handle` / `contextBridge.exposeInMainWorld` | Surface **seen**. That bytes arrived in production: **unknown** (static is not traffic) |

JS/Electron: `inventory` already samples `ipc_hits` and `sourceMappingURL`.
Slice the handler name from the operator’s feature, not the whole renderer
bundle.

## Numbered workflow

1. **Authority and question.** Operator-owned path. Either a named feature
   (“export CSV drops the last row”) per `bug-hunt.md`, or an explicit
   “static defect-class pass on *this* build.” No question → no session.
2. **Doctor.** `reveng-debug doctor`. Missing dumpbin/Ghidra is `unsupported`
   or `unknown`, not “absent.”
3. **Identify then inventory.**

   ```powershell
   reveng-debug identify .\target
   reveng-debug inventory .\target
   ```

   Record `session_id`, `workspace_path`, `engine`, `coverage`. `pefile`
   coverage is thinner than LIEF. Do not invent dumpbin rows.
4. **Surface map (observe).** From inventory JSON only: inbound-capable
   imports, copy/alloc names, `security_flags` if PE, JS `ipc_hits` /
   `package`. Cap discussion; do not paste all 200 `strings`.
5. **Named-feature slice (if the operator named one).** Pick needles from
   UI copy, export names, or IPC channel strings. `reveng-debug slice PATH
   NEEDLE` on the **session copy**. Empty hits = **unknown**, not “feature
   absent.” At most two needles unless the operator expands the question.
6. **Defect-class table.** One row per lens above. Cite the inventory field
   or slice window. Do not fill empty rows with folklore.
7. **Live UI only if already running.** If the operator already has the
   **owned** app on localhost, `bug-hunt.md` allows gotcontext-chrome to
   observe the mismatch. New tab (`tabs_create_mcp`). Do not fuzz, bypass
   auth, or hit third-party hosts. Native attach remains **unsupported**.
8. **Ghidra last, opt-in.** Only to follow a **length into a copy** on the
   session copy when inventory+slice cannot answer: `reveng-debug ghidra PATH`.
   Missing `analyzeHeadless` → `unsupported`. Still no PoC.
9. **Stop.** Report. Do not change code. Do not “confirm” by crashing.

## Output contract

```
Authority: owned-and-shipped | refused
Question: <named feature or defect-class pass>
Session / engine / coverage:
Inbound surfaces (seen): <imports | ipc_hits | strings cited>
Feature slice: <needles, hit counts, or unknown>
Defect-class table:
  lens | evidence | seen|inferred|unknown
  copy-vs-bound | ... | ...
  alloc-from-inbound | ... | ...
  integer-width | ... | ...
  conversion | ... | ...
PE marks (if any): ASLR= NX_COMPAT= GUARD_CF=  (bits, not a signature)
Live UI: not-run | localhost-observed | unsupported
Ghidra: not-requested | unsupported | opted-in (still no PoC)
Fixes: point at operator source / build flags — no patch of the binary
```

Every row carries a confidence tag. Missing evidence is **unknown**, not
absent. Static reading is not observed execution.

## Refuse in one short sentence

- Third-party products, including reconstructing the book’s IIS indexing case
  (`AddExtensionControlBlock` / URL-unescape paths) or any vendor app.
- Weaponizing a finding: overflow inputs, heap metadata writes, shellcode,
  encoding-smuggled payloads, ROP.
- Cracking, DRM, unpack-as-attack, competing-product clones.
- “Audit” framed as a CTF, pwn lab, or unauthorized target.

Point the operator at `reveng-debug` inventory on **their** build, or stop.

## Siblings

- `skills/investigations/bug-hunt.md` — named-feature expected vs observed
- `skills/investigations/security-leak-check.md` — secrets in the artifact, not
  length bugs
- `reveng-debug` — `doctor` / `identify` / `inventory` / `slice` / opt-in `ghidra`
- `eilam-reversing-foundations` — cheap reversing before decompile
- `eilam-windows-formats` — PE `security_flags` as DllCharacteristics, not Authenticode
- `pe-iat-capability-map` — imports as capability buckets, not calls
- `cookbook-static-first` — 2–4 cheap probes
- `rce-process` — observe / hypothesize / verify on the same copy
- `docs/support/honesty-rules.md` — seen / inferred / unknown
