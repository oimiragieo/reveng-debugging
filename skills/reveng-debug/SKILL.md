---
name: reveng-debug
description: Evidence-first debugging of shipped software you are authorized to inspect. Windows-first PE, JS, and Electron inventory via reveng-debug CLI. Use to explain how a feature works, inventory imports/exports, or slice bundles. Do not execute the target unless the operator explicitly opts in (unsupported in MVP).
---

# reveng-debug: fast path (Windows)

Derived from leanrea (MIT, AICodeKing) with a Windows-first first-move.
Original: `third_party/leanrea/SKILL.md`.

## Rules
- Work on a copy. `reveng-debug inventory PATH` copies into `%TEMP%\reveng-debug\<session>\`. Never mutate the original.
- Route by magic bytes first (`reveng-debug identify PATH`). Cheapest inventory next. Do not decompile in MVP.
- Search extracted trees including hidden bundler dirs (`.webpack/`, `.vite/`). Prefer `tg` in this repo; on extracted trees include ignored/hidden files.
- Never dump a whole minified file. Use `reveng-debug slice PATH NEEDLE`.
- Mark every claim **seen**, **inferred**, or **unknown**. Missing is not absent. Static reading is not observed execution.
- A missing optional tool is `unknown` or `unsupported`. Run `reveng-debug doctor`. Do not invent dumpbin/Ghidra results.
- Do not execute the target. Dynamic attach is unsupported. Ghidra is Wave 2 (doctor may show PATH only).
- BYO `rea` / `reveng` is opt-in and must be pointed at the session copy, not the original.

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

## Router
| Target | Fastest path |
|---|---|
| PE (`MZ`) | `reveng-debug inventory` (LIEF or pefile fallback with declared coverage) |
| JS / package.json | `reveng-debug inventory` then `slice` for IPC / sourceMappingURL |
| Electron `.asar` | `reveng-debug inventory` (Python ASAR reader, workspace containment) |
| ELF / Mach-O | identify only; inventory returns `unsupported` (Wave 2) |
| Running process | `unsupported` in MVP |

## MCP (six tools, not 207)
`doctor` `identify` `inventory` `slice` `session_show` `evidence_get`

```powershell
reveng-debug mcp
```
