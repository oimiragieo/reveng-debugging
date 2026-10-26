---
name: rce-process
description: Use when structuring an authorized reverse-engineering investigation as observe/hypothesize/verify. DO NOT USE as a cracking or pwn playbook.
---

# rce-process

Three beats, then stop. **Observe** is a static inventory. A story about unseen behavior is **inferred**. **Verify** is another static slice, or opt-in Ghidra if the operator asked. This host does not run the target.

Source idea: local gitignored PDF `references/courseware/reversing/Reverse Code Engineering (RCE).pdf`. That paper mixes a look-guess-check loop with live debugging and a payload appendix. Keep the loop. Drop the debugger run and the appendix. Original wording only — do not quote or reconstruct the PDF.

## Hard rules

| Do | Never |
|---|---|
| Work on the session copy `inventory` already made under `%TEMP%\reveng-debug\<session>\` | Mutate the original; execute or attach to the target |
| Record every claim as **seen**, **inferred**, or **unknown** | Treat an import/export list as a runtime call trace |
| Verify with `reveng-debug slice` or operator-opt-in `reveng-debug ghidra` | Default decompile, unpack, or “just run it and watch” |
| Stay on the named feature question | Crash recipes, shellcode, overflow how-tos, pwn labs |
| Refuse if the operator did not authorize the target | Follow courseware that opens system binaries under a debugger |

Missing optional engines are **unsupported** or **unknown**. Run `reveng-debug doctor`. Do not invent dumpbin or Ghidra output. Static reading is not observed execution.

## Mapping

| Beat | What it means here | Tool / label |
|---|---|---|
| Observe | Cheapest picture of *what the artifact is*: type, headers, imports, exports, strings, extracted tree | `reveng-debug doctor` → `identify PATH` → `inventory PATH`. Facts copied from that JSON are **seen** (cite field / symbol / path) |
| Hypothesize | A working story of *how the named feature might work* | One or two sentences, marked **inferred**. Cite the inventory rows that suggested it. “This import exists” is not “this function ran” |
| Verify | Independent static evidence for or against that story | More `reveng-debug slice PATH NEEDLE` (new needles, not the same dump). Opt-in `reveng-debug ghidra PATH` only when the operator asks; missing `analyzeHeadless` → **unsupported**, never a fake function list |

`dynamic_attach` is **unsupported**. `app-re` is a separate opt-in and still must not execute the target.

## Workflow

1. **Scope.** Named path, named question, named authority (owned or explicitly authorized). If authority is missing, stop.
2. **Observe.** Do not skip identify. Read inventory coverage notes (`pefile` fallback is thinner than LIEF). Copy-backed fields you actually received are **seen**. Fields not in the JSON are **unknown**, not absent. Help text and version strings inside the inventory count as documentation of intent, not as runtime proof.
3. **Hypothesize.** Write the inferred story *before* opening a decompiler. Bound it: which feature, which import/string/export suggested it, what would count as a confirming slice.
4. **Verify.** Slice the hypothesized needle (API name, IPC channel, error string, export). A matching slice upgrades only the backed clause to **seen**. A conflicting slice revises the hypothesis — do not keep the old story. If slices are still thin *and* the operator opts in, run Ghidra on the session copy for names/pseudocode. Do not start Ghidra on your own.
5. **Stop.** Answer the question. Do not re-inventory what you already saw. Do not launch the binary to “confirm.” If the operator’s real ask is how to crash, bypass, or weaponize, refuse.

## What observe may not smuggle in

Inventory can show that a name is imported, that a string exists, that a section looks unusual. It cannot show that a copy walked off a buffer, that a register was overwritten, or that a process crashed. Those claims need runtime evidence this product does not collect; leave them **unknown**. Do not fill the gap with a debugger script.

## Output contract

```
Question:
Authority: owned | authorized | refused
Observe (seen):   <inventory fields, paths, symbols>
Hypothesis (inferred): <one working story + what would confirm it>
Verify: slices=<needles> | ghidra=opted-in|unsupported|not-requested
Result: confirmed | revised | unknown
Next: stop | one more slice | wait for operator ghidra opt-in
```

Cap at 2–4 tool calls unless the operator expands the question.

## Siblings

- `reveng-debug` — command router (`doctor`, `identify`, `inventory`, `slice`, `ghidra`)
- `rce-artifacts` — session copy, slice dumps, what not to `cat`
- `cookbook-static-first` — cheapest probe order
- `eilam-reversing-foundations` — cheap reversing before decompile
- `pe-iat-capability-map` — imports as capability buckets
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
