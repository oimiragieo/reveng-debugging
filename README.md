# reveng-debug

Evidence-first **debugging / software-archaeology** toolkit for binaries and apps you are authorized to inspect.

It is a thin Python orchestrator: Windows-first PE + ELF/Mach-O + JS/Electron inventory, website clone (static HTML or gotcontext-chrome capture), a TUI, a thin MCP, and agent skills. It is **not** a dump of REA, leanrea, or REVENG, and it does **not** generate exploits.

## Install

```powershell
python -m pip install -e ".[dev,lief]"
reveng-debug --help
reveng-debug doctor
```

Python 3.11+. `pefile` is the PE fallback and reports reduced coverage. LIEF is preferred for PE/ELF/Mach-O. BYO Ghidra (`analyzeHeadless` on PATH or `GHIDRA_INSTALL_DIR`) and BYO `reveng` (`reverse-engineer-app` only) are opt-in; they are never vendored.

## Commands

| Command | Purpose |
|---|---|
| `reveng-debug doctor` | Tool probes + support matrix (`unknown` ≠ absent) |
| `reveng-debug identify PATH` | Magic-byte / extension kind |
| `reveng-debug inventory PATH` | Copy into `%TEMP%\reveng-debug\<session>\`, emit evidence |
| `reveng-debug slice PATH NEEDLE` | Bounded static slice |
| `reveng-debug clone-website TARGET` | HTML file, capture JSON, or static http(s) snapshot |
| `reveng-debug ghidra PATH` | Opt-in BYO Ghidra headless on the session copy |
| `reveng-debug app-re PATH` | Opt-in BYO reverse-engineer-app on the session copy |
| `reveng-debug tui` | Interactive loop; attach omega-vision at `http://127.0.0.1:8092/attach` |
| `reveng-debug session show ID` | Session + ledger |
| `reveng-debug mcp` | Thin MCP stdio (includes `ghidra` and `app_re`) |

Live website DOM/tokens/assets: follow `skills/reveng-debug/SKILL.md` gotcontext-chrome sequence, then `clone-website capture.json`. Native targets are never executed by default. Live native attach remains `unsupported`.

This host's omega-vision attach URL is `http://127.0.0.1:8092/attach` (README default elsewhere is `:8090`).

## Skills

Router: [`skills/reveng-debug/SKILL.md`](skills/reveng-debug/SKILL.md). Full catalog: [`skills/README.md`](skills/README.md).

Original methodology distillations from local gitignored PDFs (`references/courseware/`). They do **not** copy book text and they do **not** teach exploits. CEH attack modules have no skills.

| Skill | When |
|---|---|
| [`authorized-scope-ethics`](skills/authorized-scope-ethics/SKILL.md) | Permission before analysis |
| [`pma-static-triage`](skills/pma-static-triage/SKILL.md) | Static first-move on an authorized PE |
| [`pma-packing-signals`](skills/pma-packing-signals/SKILL.md) | Packing as inferred, never unpack |
| [`pma-dynamic-evidence`](skills/pma-dynamic-evidence/SKILL.md) | Label sandbox logs the operator already has |
| [`eilam-reversing-foundations`](skills/eilam-reversing-foundations/SKILL.md) | Cheap reversing before decompile |
| [`eilam-windows-formats`](skills/eilam-windows-formats/SKILL.md) | PE layout from inventory JSON |
| [`eilam-own-app-audit`](skills/eilam-own-app-audit/SKILL.md) | Own-app bug hunt via static inventory |
| [`goppit-pe-layout`](skills/goppit-pe-layout/SKILL.md) | Map inventory onto PE structure |
| [`pe-iat-capability-map`](skills/pe-iat-capability-map/SKILL.md) | Imports as capability buckets, not observed calls |
| [`cookbook-static-first`](skills/cookbook-static-first/SKILL.md) | Cheapest static probes |
| [`cookbook-format-tricks`](skills/cookbook-format-tricks/SKILL.md) | Magic-byte identify |
| [`rce-process`](skills/rce-process/SKILL.md) | Observe / hypothesize / verify |
| [`rce-artifacts`](skills/rce-artifacts/SKILL.md) | Session artifacts, slice disasm dumps |
| [`program-understanding-map`](skills/program-understanding-map/SKILL.md) | Structure of an authorized program |
| [`program-understanding-questions`](skills/program-understanding-questions/SKILL.md) | Scope the question (2–4 tool calls) |
| [`memory-static-indicators`](skills/memory-static-indicators/SKILL.md) | ASLR/NX vs runtime addresses |
| [`memory-evidence-labels`](skills/memory-evidence-labels/SKILL.md) | Grade memory claims |
| [`packer-detection`](skills/packer-detection/SKILL.md) | Packed? inferred from inventory |
| [`packer-honesty-limits`](skills/packer-honesty-limits/SKILL.md) | Do not invent entropy |
| [`ceh-malware-static`](skills/ceh-malware-static/SKILL.md) | Static malware-suspect classification |
| [`secplus-observe-vs-assume`](skills/secplus-observe-vs-assume/SKILL.md) | Claims need evidence |
| [`crypto-inventory-static`](skills/crypto-inventory-static/SKILL.md) | Crypto APIs/strings only |

Own-app investigation stubs: [`bug-hunt`](skills/investigations/bug-hunt.md), [`performance-checkup`](skills/investigations/performance-checkup.md), [`security-leak-check`](skills/investigations/security-leak-check.md), [`clone-website`](skills/investigations/clone-website.md).

## Specs

- [SPEC-RD-000 design](docs/superpowers/specs/2026-10-25-reveng-debug-design.md)
- [Architecture](docs/explanation/architecture-overview.md)
- [Support matrix](docs/support/support-matrix.md)
- [CLI](docs/reference/cli.md)
- [MCP](docs/reference/mcp-tools.md)

## License

MIT. See [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md) for REA, leanrea, and REVENG attribution.
