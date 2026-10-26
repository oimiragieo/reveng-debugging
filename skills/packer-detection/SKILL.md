---
name: packer-detection
description: Use when deciding whether an authorized PE looks packed from static inventory. DO NOT USE to unpack, dump, or write a packer.
---

# packer-detection

Decide whether an authorized PE **looks packed** from `reveng-debug inventory` JSON. Brand leftovers in section names or strings are **seen**. “This file is packed” / “this family” is **inferred**. Missing fields are **unknown**, not absent.

Source ideas (local gitignored PDFs; original wording only — do not quote or reconstruct them): `references/courseware/reversing/Analysis and Visualization of Common Packers.pdf`, `HistoryofPackingTechnology.pdf`, `packers.pdf`. Those papers also describe loaders, original-entry recovery, IAT rebuild, anti-debug, and dump defense. **Drop all of that.** This skill stops at static inventory tells.

## Hard rules

| Do | Never |
|---|---|
| Work on the session copy `inventory` already made under `%TEMP%\reveng-debug\<session>\` | Mutate the original; run, attach, dump, or unpack the target |
| Treat packing and family as **inferred** even when brand strings are **seen** | Call a PE “UPX/ASPack/…” as fact from a string match |
| Count imports, compare section `virtual_size` vs `sizeof_raw_data`, scan `strings` | Invent Shannon entropy, OEP, or section characteristics this JSON does not emit |
| Stop after a packed / not-packed / unknown call | Reconstruct IAT, follow an original entry point, write a packer, or bypass anti-debug |

`HIGH_ENTROPY_VA` in `findings.security_flags` is a PE `DllCharacteristics` bit for 64-bit ASLR. It is **not** section entropy. Do not reuse that flag as a packing score.

## What inventory emits today

PE `findings` (LIEF, or `pefile` fallback with declared thinner coverage): `machine`, `sections[]` (`name`, `virtual_size`, `sizeof_raw_data`), `imports[]` (`dll`, `names`), `exports`, `security_flags`, `strings` (printable ASCII, min length 4, **first 200 only**).

Not in the JSON (leave **unknown** unless the operator supplies an external measurement and you cite it as operator-supplied): Shannon entropy, section characteristics / permissions, entry-point RVA, raw pointers, `SizeOfImage`, overlay, Authenticode.

## Signals (detect only)

Score what you actually received. One signal is a hint. Two or more independent hints → packing **inferred**. Zero hints → not-packed **inferred** only if the table looks compiler-typical **and** no brand leftover showed up in the 200-string window; otherwise **unknown**.

1. **Tiny import table (seen count → inferred packing).** Sum named imports across `findings.imports`. A stub that only lists a handful of names (often one `kernel32` DLL, sometimes just loader-style names such as `LoadLibraryA` / `GetProcAddress`, sometimes even fewer) is a packing tell: the on-disk table is a placeholder, not the program’s real capability set. A compiler-typical GUI/console image usually lists many DLLs and dozens-to-hundreds of names. Do not treat the stub list as a runtime call trace (`pe-iat-capability-map`).
2. **Section names and size mismatch (seen numbers → inferred packing).** Odd or branded names (`UPX0`/`UPX1`, `.aspack`, `.nsp*`, `FSG`, `MPRESS1`, `pec1`/`pec2`, `.themida`, and similar leftovers) are **seen**. `virtual_size` much larger than `sizeof_raw_data`, or `sizeof_raw_data == 0` with a large `virtual_size`, is **seen** and often means “workspace on disk is tiny / empty, virtual image is not.” Compilers also emit BSS-like empty sections — this hint alone is not a family ID. Very few sections after a merge can be a hint; a normal `.text`/`.rdata`/`.data`/`.rsrc` set is not.
3. **Packer strings in inventory (seen text → inferred family).** Search `findings.strings` and section `name`s for brand leftovers (`UPX`, `ASPack`, `PECompact`, `FSG`, `Themida`, `VMProtect`, `MPRESS`, `Upack`, and similar). A hit is **seen** text. Naming the packer remains **inferred**. No hit in the 200-string window is **unknown**, not “no packer” — later printable runs were never inventoried. Do not `cat` the whole file; `reveng-debug slice PATH NEEDLE` if you need one more branded token.
4. **Entropy.** This toolkit does **not** emit per-section entropy. Leave entropy **unknown**. Do not compute a number to fill the gap. If the operator already has an external entropy report, quote it as operator-supplied and still label packing **inferred**. High-entropy-looking *behavior* is approximated here by the size-mismatch and string-destruction tells, not by a fake score.

Visual / VM / protector families (Themida, VMProtect, Armadillo, and similar) can look packed *and* import-poor *without* a friendly brand string. If signals 1–2 fire and 3 does not, report `family=unknown`, `packed=inferred`.

## Workflow

1. **Scope.** Named path, owned or explicitly authorized PE. If authority is missing, stop (`authorized-scope-ethics`).
2. **Observe.** `reveng-debug identify PATH` then `reveng-debug inventory PATH`. Non-`pe` kinds: this skill does not apply. Read `coverage` / `engine`. `pefile` fallback is thinner than LIEF — do not invent the missing bits.
3. **Tally.** Import-name count; section name list; each section’s `virtual_size` vs `sizeof_raw_data`; brand leftovers in `strings` (remember the 200 cap).
4. **Call.** Packed / not-packed / unknown, every clause labeled. Family only if a leftover was **seen**, and still **inferred**.
5. **Stop.** Do not decompile to “confirm.” Do not opt into Ghidra for unpacking. Do not execute. If the operator’s real ask is dump, OEP, or writing a packer, refuse.

## Output contract

```
Target: <path>  kind=pe  engine=lief|pefile  coverage=<as emitted>
Authority: owned | authorized | refused
Imports (seen): dlls=<n> named=<n>  note=<stub-like|compiler-typical|unknown>
Sections (seen): names=[...]  size_mismatch=<which> | none
Brand leftovers (seen): <string or section name> | none-in-window (unknown, not absent)
Entropy: unknown (not in inventory)
Packed: inferred-yes | inferred-no | unknown
Family: inferred <name> | unknown
Next: stop | one slice for a branded needle | hand off to packer-honesty-limits
```

Cap at 2–4 tool calls unless the operator expands the question.

## Siblings

- `reveng-debug` — `doctor` / `identify` / `inventory` / `slice`
- `packer-honesty-limits` — do not invent entropy or over-claim family
- `pma-packing-signals` — PMA-lab packing tells; same “never unpack” rule
- `pe-iat-capability-map` — import names as capability buckets, not calls
- `goppit-pe-layout` — map inventory onto PE structure; unknown fields stay unknown
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
