---
name: program-understanding-questions
description: >-
  Use when scoping an authorized RE question so you do not over-decompile.
  DO NOT USE as an excuse to skip doctor/identify.
---

# program-understanding-questions

Write the question **before** you pick a heavier probe. Imports, strings, and an extracted tree usually answer “what does this do.” A decompiler answers control-flow you still cannot name after that. This host does not run the target, so live “does it actually do X” stays **unknown**.

Source idea: local gitignored PDF `references/courseware/reversing/Reverse Engineering and Program Understanding.pdf`. That chapter catalogs debuggers, input injectors, decompilers, and attack-oriented tracing. Keep the *question-first* habit and the cheap-static-before-decompile order. Drop runtime attach, malformed-input probing, bulk scans of system binaries, and anything that teaches a crash or a bypass. Original wording only — do not quote or reconstruct the PDF.

## Hard rules

| Do | Never |
|---|---|
| One named question, one named path, named authority | “Explain the whole program”; decompile to go fishing |
| `reveng-debug doctor` then `reveng-debug identify PATH` on every new target | Skip either because the question “looks simple” or the file extension “is obvious” |
| Spend the remaining budget on `inventory` and at most one `slice` | Default `ghidra`, `app-re`, whole-file dumps, or a second inventory |
| Mark every claim **seen**, **inferred**, or **unknown** | Treat an import list as a call trace or a string as proof it ran |
| Stop when the named question has evidence | Re-probe what the JSON already showed |

Missing optional engines are **unsupported** or **unknown**. Do not invent dumpbin or Ghidra output. Static reading is not observed execution. Refuse cracking, copy-protection removal, exploit construction, and unauthorized targets.

## Question checklist → command

Answer these in order. Stop at the first command that can close the question.

| # | Ask this | If the answer is… | Command / label |
|---|---|---|---|
| 0 | Who authorized this path, and what **one** sentence is the ask? | Missing authority, or the ask is crash/bypass/weaponize | Stop. Do not tool. |
| 1 | Are the local engines even present? | Unknown until probed | `reveng-debug doctor` — **required**. Coverage notes (LIEF vs `pefile`, dumpbin present/not) bind later claims |
| 2 | What *kind* of artifact is this? | Magic/extension unknown | `reveng-debug identify PATH` — **required**. Route from bytes, not from the filename story |
| 3 | Which libraries, exports, resources, protocols, or files show up? | “What can it talk to / load / expose?” | `reveng-debug inventory PATH` (session copy under `%TEMP%\reveng-debug\<session>\`). Dumpbin `/IMPORTS` `/EXPORTS` `/HEADERS` only if doctor already showed dumpbin |
| 4 | Where does **this** name live (API, IPC channel, error string, export)? | You already have a needle from the ask or from inventory | `reveng-debug slice PATH NEEDLE` — one needle, bounded. Never `cat` a minified or disasm dump |
| 5 | Do I still need function names or reconstructed high-level logic? | Cheaper probes did not close the question **and** the operator opted in | `reveng-debug ghidra PATH` on the session copy. Missing `analyzeHeadless` → **unsupported**, never a fake function list |
| 6 | Is the ask about live behavior (does it run, crash, accept this input)? | Yes | **unsupported**. `dynamic_attach` is not a fallback. Do not fill the gap with a debugger or an input fuzzer |
| 7 | Is the ask a visible website structure? | Authorized URL or local capture | `reveng-debug clone-website` (static HTML/JSON) or gotcontext-chrome capture then clone. Not a decompile problem |

`app-re` is a separate operator opt-in on the session copy. It does not replace doctor/identify and still must not execute the target.

White-box-style static reading (inventory, slice, optional Ghidra) is in scope. Black-box runtime probing is not. Mixing them — attach plus crafted input — is not.

## Cost profile (2–4 tool calls)

Turns cost more than extra bytes. Default budget:

1. `doctor`
2. `identify PATH`
3. `inventory PATH` — skip only if the question was solely “what kind of file is this” and identify already closed it
4. At most one `slice PATH NEEDLE` — skip if inventory already named the answer

That is the whole first move. Do not start Ghidra inside this budget. Do not re-run doctor/identify/inventory because you distrust a JSON you already read. If the operator expands the question, start a **new** budget; do not silently grow this one.

Reuse an existing session copy when `session show` already has it. Copying the original again is not a new insight.

## Workflow

1. **Write the question.** Feature, artifact path, authority. Shrink “how does this binary work” to one user-visible behavior or one import/string the operator named.
2. **Doctor, then identify.** Always. Extension is not a substitute for magic bytes. If doctor shows a thinner inventory path (`pefile` vs LIEF), say so when you quote fields.
3. **Match the question to one row in the table.** If row 3 would answer it, inventory and stop. If row 4, inventory then one slice. If row 5, *ask* before Ghidra.
4. **Inventory on a copy.** Cite fields you actually received (**seen**). Fields not in the JSON are **unknown**, not absent. “This import exists” is not “this function ran.”
5. **Slice only with a needle the question needs.** New needle, not a second dump of the same hit. Hidden bundler dirs (`.webpack/`, `.vite/`) are in play on extracted trees.
6. **Answer and stop.** Remaining curiosity is a new question, not a reason to decompile.

## Output contract

```
Question: <one sentence>
Authority: owned | authorized | refused
Doctor: engines cited | limitations
Identify: kind=<...> (seen)
Cheapest probe that can close it: inventory | slice | ghidra-opt-in | unsupported
Calls used: doctor, identify, [inventory], [slice]   (cap 4)
Seen: <fields / symbols / paths>
Inferred: <at most one working story>
Unknown: <live behavior, missing engines, unprobed paths>
Next: stop | wait for operator ghidra opt-in | new question
```

If you cannot fill `Question` and `Cheapest probe` *before* call 3, you are not ready for inventory, let alone Ghidra.

## Siblings

- `reveng-debug` — command router (`doctor`, `identify`, `inventory`, `slice`, `ghidra`)
- `program-understanding-map` — structure of an authorized program, after this scope exists
- `rce-process` — observe / hypothesize / verify once the question is named
- `cookbook-static-first` — cheapest probe order
- `eilam-reversing-foundations` — cheap reversing before decompile
- `pe-iat-capability-map` — imports as capability buckets
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
