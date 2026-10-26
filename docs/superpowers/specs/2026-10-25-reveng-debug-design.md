# SPEC-RD-000 — reveng-debug design

**Spec ID:** SPEC-RD-000  
**PRD:** Authorized software-archaeology / debugging studio for binaries and apps the operator owns or is allowed to inspect.  
**Status:** Approved plan 2026-10-25 (operator); thinktank advisory before code.  
**Product:** `reveng-debug` at `C:\dev\projects\reveng-debugging-main`

## 1. Problem

Three existing trees contain complementary reverse-engineering / debugging capability:

| Source | Role | Must not dump |
|---|---|---|
| leanrea (`aicodeking/leanrea`, MIT) | 8 KB agent skill; Windows-first command router | Mach-O-only first-move as the product CLI |
| REA `rea-agents` 6.7.0 (morluto, MIT) | Evidence vocabulary, investigation flow, adapters | 2,216 TS files, 207 MCP tools, CTF showcase, native `.node` |
| REVENG 4.0.0 (`oimiragieo/reveng-main`, MIT) | GA app-RE adapters, result contracts, honesty matrix | `exploits/`, malware samples, reconstructed proprietary trees, ML weights |

Goal: a **thin Python orchestrator** that keeps leanrea’s cost profile and REA/REVENG evidence honesty without vendoring those trees.

## 2. Non-goals

- Exploit generation, ROP, payload delivery, malware weaponization
- Reconstructing third-party products (Obsidian/Notion clone prompts)
- Copying courseware PDFs or opening untrusted executables
- 207-tool MCP catalog
- Default execution / live attach of targets
- Claiming missing optional engines as present

## 3. Architecture

Surfaces → router → (workspace + evidence ledger) → first-party adapters.

Always-on adapters: PE inventory (LIEF, optional dumpbin / llvm-objdump), JS/Electron (asar extract into `%TEMP%\reveng-debug\<session>\`).

BYO (not vendored): installed `reveng` GA `reverse-engineer-app` only; `rea` PATH passthrough; local Ghidra headless.

Thin MCP: `doctor`, `identify`, `inventory`, `slice`, `session_show`, `evidence_get`, `clone_website`, `ghidra`, `app_re`.

## 4. Evidence contract (SPEC-RD-001)

Thinktank 2026-10-25 (`tt-bb8fc99cce52472cbd5e1e2ab27d755a`): agy APPROVE, codex ADVISE. Folds applied below.

Every claim is `seen` | `inferred` | `unknown`. Capability outcomes are distinct from claims:

| Capability status | Meaning |
|---|---|
| `present` | Tool/engine was found and used |
| `unsupported` | Optional engine not available in this environment (e.g. Ghidra missing, dynamic attach) |
| `failed` | Engine was present but the probe errored; keep partial results |
| `unknown` | Presence not yet probed |

Missing optional tool → `unsupported` or `unknown` plus doctor hint — never “absent”. `pefile` fallback must declare reduced coverage versus LIEF.

Ledger **models** live in contracts (CL1). Ledger **persistence** lives in storage (CL2). Adapters emit evidence immediately; later ledger CL adds retrieval/presentation.

Fields: `schema_version`, `authority`, `tool`, `command`, `limitations`, location (path/offset/symbol), `session_id`.

## 5. Workspace (SPEC-RD-002)

Never mutate the original target. Copy into `%TEMP%\reveng-debug\<session_id>\`. Session JSON + artifact index.

ASAR extract (Python reader or bounded `asar` CLI) **must** reject `..`, drive-root, absolute, and symlink/junction members. All extracted paths stay inside the session directory. BYO `rea` / `reveng` passthrough is **opt-in**, receives copy-workspace paths only, and defaults to static/non-executing flags. Ghidra is opt-in Wave 2 (`reveng-debug ghidra`); missing analyzeHeadless returns `unsupported`.

## 6. CLI (SPEC-RD-003+)

`reveng-debug doctor|identify|inventory|slice|session|ghidra|app-re|tui`

Runtime default: do not execute the target. `dynamic_attach` flag is present and **unsupported**.

## 7. CL sequence

CL0 repo skeleton → CL1 contracts → CL2 storage → CL3a doctor/router → CL3b PE → CL3c JS/Electron → CL3d ledger/prompts → CL4 CLI → CL4b skill+MCP → CL5 CI/docs.

## 8. Stack

Python >=3.11, pydantic v2, typer, lief, pefile fallback. pytest, ruff, mypy. No angr/z3/pytorch in MVP.

## 9. License

MIT. NOTICE attributes morluto/REA, AICodeKing/leanrea, oimiragieo/REVENG.

## 10. Website clone (SPEC-RD-007)

Shipped after MVP: REA-style "Clone this website" without REA CDP. Static HTML/JSON in-process; live DOM via **gotcontext-chrome** (`tabs_context_mcp`, `navigate`, `get_page_text`, `extract_design_tokens`, `tab_page_assets`, `decompose_dom_components`, `javascript_tool`, `capture_visual_frame`).

## 11. Wave 2 (shipped)

- Ghidra BYO headless: `reveng-debug ghidra PATH` (analyzeHeadless / `GHIDRA_INSTALL_DIR`; project paths without `.`-prefixed segments).
- ELF/Mach-O inventory via LIEF.
- TUI: `reveng-debug tui`, omega-vision attach `http://127.0.0.1:8092/attach` (README default `:8090`).
- Opt-in `reveng-debug app-re` wrapping installed `reveng` GA `reverse-engineer-app` only, copy-workspace paths, non-executing.

Native `dynamic_attach` stays unsupported.
