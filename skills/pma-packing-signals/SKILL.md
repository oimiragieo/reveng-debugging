---
name: pma-packing-signals
description: Use when inventory looks packed or import-poor and you must label packing as inferred not proven. DO NOT USE to unpack, decrypt, or execute samples.
---

# PMA packing signals (inferred, never proven)

Ideas distilled from Practical Malware Analysis packing/obfuscation chapters. Original wording. Static inventory only. The packed image on disk is a wrapper plus transformed payload; `reveng-debug inventory` sees the wrapper, not restored original code.

## Hard rules

| Do | Never |
|---|---|
| Read `findings` from `reveng-debug inventory` on the session copy | Unpack, dump process memory, hunt OEP, write unpackers, or run the file |
| Label packing **inferred** when several static clues agree | Say “packed” as a **seen** fact |
| Keep Shannon/byte **entropy** as **unknown** unless a field named entropy appears in this inventory JSON | Invent entropy scores, histograms, or “high entropy = 7.2” |
| Treat `security_flags.HIGH_ENTROPY_VA` as a PE ASLR capability bit | Confuse that flag with compressed/encrypted payload entropy |
| Count imports and strings with the documented caps | Treat a truncated list as “few” |
| Stop at a packing label plus what static analysis cannot see | Decrypt, reconstruct IAT, or “just try UPX/PEiD” |

If `identify` is not PE, this skill does not apply. ELF/Mach-O inventory has library names and section sizes, not PE virtual-vs-raw packing clues.

## What inventory actually emits

PE `findings` (LIEF, or pefile fallback with declared coverage):

- `sections[]`: `name`, `virtual_size`, `sizeof_raw_data` — **seen**
- `imports[]`: `{dll, names}` with **at most 200 names per DLL** — **seen**
- `strings[]`: printable ASCII, length ≥ 4, **first 200 only** — **seen** (Unicode is **unknown**)
- `exports[]`, `security_flags`, `machine`
- Coverage string: `pe-headers,imports,exports,sections,dll-characteristics,strings` (pefile adds `; no authenticode`)
- Limitation: static parse; the target was not executed

There is **no** entropy field. Missing field → **unknown**, not zero.

## Workflow

1. `reveng-debug identify PATH` then `reveng-debug inventory PATH`. Work only on the session copy. If status is `failed` / `unsupported`, packing is **unknown** (parse failure is not a packer).
2. Count **seen** imports: number of DLL rows, named functions per row (note the 200 cap), and whether the surviving names are mostly loader resolvers (`LoadLibrary`, `GetProcAddress`, `LdrLoadDll`, `LdrGetProcAddress`) without a rich API surface.
3. Read **seen** sections: unusual names (packer-family tokens such as `UPX0`), and size mismatch (`sizeof_raw_data` 0 or tiny while `virtual_size` is large). That layout is consistent with a stub that expands into allocated image space; it does not prove a named packer.
4. Read **seen** strings: if `len(strings) == 200`, the extractor hit its cap — **do not** call the file string-poor. If the list is short *and* under the cap, record string poverty as **inferred**, remembering ASCII-only and min-length 4. Random-looking short runs are not evidence.
5. Entropy: write **unknown**. Related things to look at *instead of a fake number*: section raw vs virtual sizes, import poverty, string poverty under the cap. Those are not entropy.
6. Combine clues. One clue is weak. Several together → packing **inferred**. Conflicting or incomplete JSON → **unknown**. A normal import table and ordinary section names/sizes → **not-indicated** (still not a proof of “unpacked”).
7. State the static-analysis consequence: capability guessing from imports/strings applies to the **stub**, not the hidden payload. Do not proceed to unpacking. Optional later static work stays on inventory/`slice` of the same copy.

## Signal table (inferred unless marked seen)

| Clue | How to read inventory | False friends |
|---|---|---|
| Import-poor | Few DLL rows, or names dominated by runtime resolvers | Some wrappers keep one import per library — a non-empty table does not clear packing. Ordinal-only names look empty; still **seen** as unnamed imports, not “no APIs”. Cap 200/DLL. |
| Section layout | Raw size ≪ virtual size, empty `.text` raw, extra stub sections, packer-like names | Resource-only or overlay-heavy files can look odd. Names are not a packer ID. |
| String-poor | Short `strings` list **below** the 200 cap | Cap hit, Unicode-only text, or a tiny legitimate binary. |
| High entropy | **unknown** (not computed) | `HIGH_ENTROPY_VA`. Homemade scripts. “Looks random” without a toolkit field. |
| Tiny recognized surface | Sparse imports + stub-like sections + few ASCII strings | Failed parse, truncated JSON, or stripped-but-unpacked code. |

Packing/obfuscation **hides** the original strings and IAT from this static pass. That is why the label is inferred: you observed wrapper symptoms, not the packed payload’s behavior.

## Output contract

```
packing: inferred | unknown | not-indicated
entropy: unknown
imports: <dll count>, <named-function count or "capped">, notable resolver names (seen)
sections: names + virtual_size vs sizeof_raw_data (seen)
strings: <count>/200 ASCII extracted; poverty inferred only if count < 200
cannot_see: original IAT, original strings, decompressed image (unknown until a future inventory field exists)
next: stop, or continue static inventory/slice on the copy — never unpack or execute
```

Every claim stays **seen** / **inferred** / **unknown**. Do not upgrade inferred packing to seen.

## Siblings

- `reveng-debug` — run identify/inventory first.
- `pma-static-triage` — cheaper PE first-move when packing is not the question.
- Do not route here for live debugging, dumpers, or “how do I unpack this.”
