---
name: memory-static-indicators
description: >-
  Use when relating PE security_flags and sections to possible memory layout
  without attaching. DO NOT USE to debug live malware or dump process memory
  without authorization and an explicit opt-in.
---

# Memory static indicators

On-disk PE inventory is a **mapping recipe**, not a snapshot of RAM. Bits in
`findings.security_flags` are **seen**. The addresses a loader would choose
this run are **unknown**. Attach, dump, and live scan are **unsupported**.

Courseware idea (local PDF `references/courseware/reversing/Reverse Engineering_ Memory Analysis.pdf`,
gitignored): a running process has an address space you can only inspect after
opening that process. This CLI never opens a process. Keep the section-vs-live
distinction. Drop every attach, poke, heap-walk, and mutate recipe. Original
wording only — do not quote the paper or reconstruct its dumps.

## Hard rules

| Do | Never |
|---|---|
| Quote `security_flags` and `sections` from `reveng-debug inventory` | Invent a load address, slide, heap base, or VAD |
| Label each claim `seen` / `inferred` / `unknown` | Treat ASLR/NX bits as proof of this-run policy |
| Treat `dynamic_attach` as `unsupported` | ptrace, procfs, Read/WriteProcessMemory, Volatility, memgrep, debugger |
| Stop at the session copy under `%TEMP%\reveng-debug\<session>\` | Execute the target, dump a process, or “just attach to confirm” |
| For ELF/Mach-O, say ASLR/NX `unknown` (no `security_flags` field) | Copy PE DllCharacteristics onto other formats |
| Work only on authorized, non-malware targets | Live malware debugging, credential hunting, or memory-patch cheats |

Missing live view is **unknown**, not absent. A flag that is false is **seen
false**, not “the OS has no ASLR.”

## What inventory can say (seen)

PE adapter (`src/reveng_debug/adapters/pe.py`) records
`optional_header.dll_characteristics` as booleans:

| Field | Bit meaning on disk | Ceiling |
|---|---|---|
| `security_flags.ASLR` | Image asked for a relocatable base (`DYNAMIC_BASE`) | **seen** request |
| `security_flags.NX_COMPAT` | Image asked for non-executable data/stack (`NX_COMPAT`) | **seen** request |
| `security_flags.HIGH_ENTROPY_VA` | Image asked for a high-entropy 64-bit range | **seen** request |
| `security_flags.GUARD_CF` | Image marked Control Flow Guard | **seen** request |
| `sections[].name` | Section title in the file | **seen** name |
| `sections[].virtual_size` | Claimed mapped size of that section | **seen** claim |
| `sections[].sizeof_raw_data` | Bytes stored in the file for that section | **seen** claim |

Inventory `limitations` already say static parse only; the target was not
executed. pefile vs LIEF: both emit these flags; still no runtime.

**Not in this JSON (always `unknown`):** preferred `ImageBase`, section
R/W/X characteristics, actual load base, ASLR slide, whether NX/CFG were
enforced, heap/stack maps, live pointers, BSS contents, other processes.

## What those fields cannot say

The paper’s useful split: **predict** layout from the image, **locate** objects
only in a live map. This skill does the first half from inventory. The second
half needs attach, which this product does not do.

| Tempting sentence | Honest label |
|---|---|
| “ASLR is on, so it loaded at a random address” | Flag **seen**; this-run base **unknown** |
| “NX is enabled, so the stack is non-executable” | Bit **seen**; page permissions **unknown** |
| “HIGH_ENTROPY_VA means 64-bit entropy happened” | Bit **seen**; entropy of this mapping **unknown** |
| “`.data` / `.bss` live at …” | Section name/size **seen**; VA **unknown** (no ImageBase, no attach) |
| `virtual_size` ≫ `sizeof_raw_data` | Extra zeroed VA **requested** (**seen** sizes). Pages present **unknown** |
| “This string is at 0x…” | String may be **seen** in the file; its runtime address **unknown** |
| “Heap object / linked list at …” | **unknown**; locating needs a live scan |
| ELF PIE / GNU_STACK / Mach-O slide | **unknown** — those flags are not inventoried |

Compiler padding, pointer-looking integers, and “array vs list from a hex
dump” are live-memory guesses. Without a dump they stay **unknown**. Do not
fill them from courseware examples.

A 2003-style “search for a known value then chase its address” assumes a
stable map you can read. ASLR makes last-run addresses non-portable even if
someone later attaches. Here you never attach, so do not quote fake VAs.

## Workflow

1. **Authorize.** Named owner or explicit opt-in. Refuse live malware, process
   dumps, and unscoped attach. Copy happens inside `inventory`; do not mutate
   the original.
2. **Inventory only.**

   ```powershell
   reveng-debug doctor
   reveng-debug identify .\target
   reveng-debug inventory .\target
   ```

   If identify is not PE, emit ASLR/NX as `unknown` and stop this skill.
3. **Quote flags.** Copy the four `security_flags` booleans. Each is **seen**.
   Write one inferred sentence max: “if this image is loaded by a cooperating
   loader, it *requested* relocatable base / NX.” Do not upgrade to observed.
4. **Quote sections.** Name, `virtual_size`, `sizeof_raw_data`. A size mismatch
   is a **seen** pair and an **inferred** “asks for extra VA.” It is not a live
   allocation and not a packing verdict (that is `packer-honesty-limits`).
5. **Refuse locate.** Operator asks for heap walk, pointer tree, known-value
   scan, `/proc/pid/mem`, or a debugger: one sentence — `dynamic_attach` is
   **unsupported**; runtime addresses remain **unknown**. Do not supply API
   sequences.
6. **Emit the card** below. Hand runtime-claim grading to
   `memory-evidence-labels`.

## Output contract

```text
memory_static:
  kind: <identify>
  engine / coverage: <from inventory>
  security_flags: {ASLR, NX_COMPAT, HIGH_ENTROPY_VA, GUARD_CF}  # seen | n/a
  sections_cited: [<name virtual_size sizeof_raw_data>]         # seen
  requested_policy (inferred): <one sentence or none>
  runtime_base: unknown
  runtime_page_perms: unknown
  attach: unsupported
```

## Red flags

| About to say | Write instead |
|---|---|
| “Loaded at 0x00400000 / slide X” | `runtime_base: unknown` |
| “DEP/NX is active on this process” | `NX_COMPAT` **seen**; enforcement **unknown** |
| “ASLR is off because I know ImageBase” | ImageBase is not inventoried; bit is **seen** true/false |
| ELF “PIE/NX from PE flags” | `unknown` for that kind |
| Hex dump, heap enum, pointer chase | refuse; unsupported |
| Volatility / live malware dump | refuse; out of scope |

## Siblings

- `memory-evidence-labels` — grade heap/stack/module *claims* after this card
- `goppit-pe-layout` / `eilam-windows-formats` — PE structure from the same JSON
- `packer-honesty-limits` — size mismatch as packing-adjacent, not a live map
- `reveng-debug` — `doctor` / `identify` / `inventory` only
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
