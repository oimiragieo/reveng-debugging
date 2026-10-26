---
name: reveng-debug
description: Evidence-first debugging of shipped software you are authorized to inspect. Windows-first PE, ELF/Mach-O, JS, Electron, website clone via reveng-debug CLI plus gotcontext-chrome live capture, optional BYO Ghidra and reverse-engineer-app. Use to explain how a feature works, inventory imports/exports, slice bundles, or clone a website's visible structure. Do not execute native targets unless the operator explicitly opts in.
---

# reveng-debug: fast path (Windows)

Derived from leanrea (MIT, AICodeKing) with a Windows-first first-move.
Original: `third_party/leanrea/SKILL.md`.

## Rules
- Local methodology PDFs (gitignored): `references/courseware/`. Read for PE/IAT/static-vs-dynamic ideas. Do not paste book text. Do not implement exploits from CEH/unpacking papers.
- Work on a copy. `reveng-debug inventory PATH` copies into `%TEMP%\reveng-debug\<session>\`. Never mutate the original.
- Route by magic bytes first (`reveng-debug identify PATH`). Cheapest inventory next. Do not decompile unless the operator opts into `reveng-debug ghidra`.
- Search extracted trees including hidden bundler dirs (`.webpack/`, `.vite/`). Prefer `tg` in this repo; on extracted trees include ignored/hidden files.
- Never dump a whole minified file. Use `reveng-debug slice PATH NEEDLE`.
- Mark every claim **seen**, **inferred**, or **unknown**. Missing is not absent. Static reading is not observed execution.
- A missing optional tool is `unknown` or `unsupported`. Run `reveng-debug doctor`. Do not invent dumpbin/Ghidra results.
- Do not execute native targets. Dynamic attach is unsupported.
- BYO Ghidra is opt-in: `reveng-debug ghidra PATH`. If analyzeHeadless is missing, the adapter returns `unsupported` — never fake functions.
- BYO `reveng` / `rea` is opt-in (`reveng-debug app-re PATH`) and must be pointed at the session copy, not the original. GA `reverse-engineer-app` only. Never call generate-exploit.
- Website clone is for **authorized** sites. Capture visible structure only. Do not steal backends, auth cookies, or paywalled content. Static `clone-website https://...` does not run page JS.

## First move
```powershell
reveng-debug doctor
reveng-debug identify .\target
reveng-debug inventory .\target
```

PE (if doctor shows dumpbin present; otherwise trust LIEF/pefile inventory JSON):
```powershell
dumpbin /HEADERS /IMPORTS /EXPORTS /SUMMARY .\copy.exe
```

Electron ASAR:
```powershell
reveng-debug inventory .\app.asar
# extraction is path-safe; traversal/symlink members are refused
```

Website (static snapshot):
```powershell
reveng-debug clone-website .\page.html
reveng-debug clone-website https://example.test/  # HTML only; no JS runtime
```

Website (live DOM — **gotcontext-chrome**, REA's inspect-web-page role):
1. `tabs_context_mcp` with `createIfEmpty: true` (mandatory first call).
2. `tabs_create_mcp` — new tab, do not reuse the operator's existing tabs.
3. `navigate` to the authorized URL (`tabId` from create).
4. Capture in parallel where the MCP allows:
   - `get_page_text`
   - `extract_design_tokens` (`include_tailwind: true`)
   - `tab_page_assets` (`mode: "performance"` then `native_scripts` if needed)
   - `decompose_dom_components` (root selector, `include_props_interface: true`)
   - `javascript_tool` with `document.documentElement.outerHTML`
   - `capture_visual_frame` for a visual receipt
5. Write `capture.json` with `kind: "website-capture"` and `backend: "gotcontext-chrome"`.
6. `reveng-debug clone-website .\capture.json` — emits `index.html`, `tokens.json`, `assets.json`, `components.json`, `reconstruction.md` under the session clone dir.

Do not use claude-in-chrome for this flow; this host's live browser seat is gotcontext-chrome.

## TUI / omega-vision
```powershell
reveng-debug tui
```
Attach visually at **http://127.0.0.1:8092/attach** (this host). omega-vision README default is `:8090` if the operator's daemon uses that port.

## Router
| Target | Fastest path |
|---|---|
| PE (`MZ`) | `reveng-debug inventory` (LIEF or pefile fallback with declared coverage) |
| ELF (`\\x7fELF`) / Mach-O | `reveng-debug inventory` (LIEF); opt-in `reveng-debug ghidra` for function names |
| JS / package.json | `reveng-debug inventory` then `slice` for IPC / sourceMappingURL |
| Electron `.asar` | `reveng-debug inventory` (Python ASAR reader, workspace containment) |
| Website HTML / capture JSON | `reveng-debug clone-website` |
| Live website DOM | gotcontext-chrome capture sequence, then `clone-website` on the JSON |
| Installed `reveng` GA | opt-in `reveng-debug app-re` on the session copy |
| Running native process | `unsupported` |

## Courseware methodology skills
Original distillations (not copied book text) live next to this file. Start at
[`../README.md`](../README.md). Use `authorized-scope-ethics` first. Use
`pma-static-triage` / `goppit-pe-layout` / `pe-iat-capability-map` for PE work.
Never apply CEH attack modules; those have no skills.

## MCP (thin catalog, not REA's 207)
`doctor` `identify` `inventory` `slice` `session_show` `evidence_get` `clone_website` `ghidra` `app_re`

```powershell
reveng-debug mcp
```
