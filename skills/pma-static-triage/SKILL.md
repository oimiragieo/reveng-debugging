---
name: pma-static-triage
description: Use when statically triaging an authorized Windows PE or similar binary with reveng-debug before any decompile. DO NOT USE for malware execution, unpacking exploits, or unauthorized targets.
---

# PMA static first-move (reveng-debug)

Static-only overlay for `reveng-debug`. Distilled from **Practical Malware Analysis** (title only). Do not paste, quote, or reconstruct that book. Do not run the target. Do not unpack. Do not write malware.

Sibling router: `skills/reveng-debug/SKILL.md`.

## Hard rules

| Do | Never |
|----|-------|
| Work on the session copy `inventory` creates | Touch or overwrite the original |
| Label every claim **seen**, **inferred**, or **unknown** | Treat a missing field as “absent” |
| Treat imports as a capability map, not a run log | Claim what the process will do at runtime |
| Stop when packing is only a *signal* | Unpack, dump, or “fix” the image |
| Stay on authorized targets | Execute, attach, or author samples |

`reveng-debug` does not execute natives. `ghidra` / `app-re` are out of this skill. Dynamic attach is **unsupported**.

## Confidence

- **seen** — bytes or JSON fields this session actually returned (kind, section names/sizes, import names, string bytes, workspace path).
- **inferred** — a reading of those facts (network-capable, packed-looking). Say so.
- **unknown** — not in the inventory (digest, authenticode, resources, runtime). Missing tool → `unsupported` / `unknown` via `doctor`, never “absent”.

## Workflow

1. **Gate.** Confirm the operator owns or is allowed to inspect the file. If not, stop.

2. **Identify kind (no copy yet).**
   ```powershell
   reveng-debug identify PATH
   ```
   `kind: pe` plus `MZ` is **seen**. Other kinds: hand back to `reveng-debug`. Unknown kind: stop; do not guess PE.

3. **Copy + cheapest inventory.**
   ```powershell
   reveng-debug inventory PATH
   ```
   This copies into `%TEMP%\reveng-debug\<session>\` (or `$env:REVENG_DEBUG_STATE_ROOT`). Record `session_id`, `workspace_path`, `engine`, `coverage`, `limitations`. Prefer LIEF coverage; `pefile` fallback is reduced — do not fill gaps. Never mutate `original_path`.

4. **Digest if present.** This CLI does not hash. If JSON or the operator already has a digest, label it **seen** and use it only as an id. Otherwise digest is **unknown**. Do not invent MD5/SHA.

5. **Strings as hints, not proof.** Read `findings.strings` (bounded ASCII from the adapter). URLs, paths, registry-looking text, error phrases, and library names are **seen** as bytes. What they *mean* is **inferred**. Few printable strings is **inferred** obfuscation/packing — not a reason to unpack. Wide/UTF-16 text not in the list is **unknown**.

6. **Imports as a capability map.** For each `findings.imports` entry, keep DLL + names **seen**. Group **inferred** classes without claiming they ran:
   - file / path APIs → filesystem
   - socket / WinINet-style names → network
   - registry APIs → persistence/config (inferred)
   - process / thread / virtual-memory APIs → process or memory
   - crypto APIs → crypto use (inferred)
   A tiny IAT, or mostly loader-style names, is **inferred** packed/stub. Exports, if any, are **seen** names only. `Ex` / `A`/`W` suffixes are naming noise; map to the base API when inferring class.

7. **PE sections.** `findings.sections` names, `virtual_size`, and `sizeof_raw_data` are **seen**. Unusual names, execute-looking layout, or raw size much smaller than virtual size are **inferred** packing or overlay — still do not unpack. Section name is a label, not a permission bit. Resources and authenticode are **unknown** unless `coverage` says otherwise.

8. **Slice, do not dump.** For each high-value needle from strings or imports (URL host, mutex-like token, export name):
   ```powershell
   reveng-debug slice PATH NEEDLE --session-id ID
   ```
   Hits are **seen**; no hits stay **unknown**. Never print a whole binary or minified blob.

9. **Stop.** Write the output contract. Do not execute, unpack, patch, or decompile. If the operator later wants disassembly, that is a separate opt-in (`reveng-debug ghidra`) outside this skill.

## Output contract

```text
target: <original_path>
kind: pe|...          # seen from identify
session: <id> copy: <workspace_path>
digest: <hex|unknown>
engine/coverage: <from inventory>
strings_of_interest: [{text, why, seen|inferred}]
capability_map: [{dll, names, class, seen|inferred}]
sections: [{name, virtual_size, raw_size, note?}]
packing_stance: unpacked-looking | packed-looking | unknown
open: [unknown questions]
limits: static parse only; not executed; not unpacked
```

Packing stance is **inferred**. Packed-looking ends the static first-move; next step is operator choice, not this skill.

## Out of scope

Virus-scanner uploads, VM execution, unpackers, exploits, lab reproductions, and writing or dropping malicious code.
