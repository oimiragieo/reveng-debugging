# Skills

Project skills for authorized debugging / software archaeology.

## Fast path
- [`reveng-debug/SKILL.md`](reveng-debug/SKILL.md) — Windows-first CLI router.

## Investigations (own app)
- [`investigations/bug-hunt.md`](investigations/bug-hunt.md)
- [`investigations/performance-checkup.md`](investigations/performance-checkup.md)
- [`investigations/security-leak-check.md`](investigations/security-leak-check.md)
- [`investigations/clone-website.md`](investigations/clone-website.md)

## Courseware methodology (original distillations)

Agents wrote these from local gitignored PDFs under `references/courseware/`.
They must **not** contain copied book text. They must **not** teach exploits.
CEH attack modules (scanning, SQLi, wireless, DoS, session hijack, …) have **no** skills.

| Skill | When |
|---|---|
| `pma-static-triage` | Static first-move on an authorized PE |
| `pma-packing-signals` | Packing as inferred, never unpack |
| `pma-dynamic-evidence` | Label sandbox logs the operator already has |
| `eilam-reversing-foundations` | Cheap reversing before decompile |
| `eilam-windows-formats` | PE layout from inventory JSON |
| `eilam-own-app-audit` | Own-app bug hunt via static inventory |
| `goppit-pe-layout` | Map inventory onto PE structure; unknown fields stay unknown |
| `pe-iat-capability-map` | Imports as capability buckets, not observed calls |
| `cookbook-static-first` | Cheapest static probes |
| `cookbook-format-tricks` | Magic-byte identify |
| `rce-process` | Observe / hypothesize / verify |
| `rce-artifacts` | Session artifacts, slice disasm dumps |
| `program-understanding-map` | Structure of an authorized program |
| `program-understanding-questions` | Scope the question (2–4 tool calls) |
| `memory-static-indicators` | ASLR/NX vs runtime addresses |
| `memory-evidence-labels` | Grade memory claims |
| `packer-detection` | Packed? inferred from inventory |
| `packer-honesty-limits` | Do not invent entropy |
| `authorized-scope-ethics` | Permission before analysis |
| `ceh-malware-static` | Static malware-suspect classification |
| `secplus-observe-vs-assume` | Claims need evidence |
| `crypto-inventory-static` | Crypto APIs/strings only |

Use with `reveng-debug` (`doctor`, `identify`, `inventory`, `slice`, optional `ghidra` / `app-re`).
