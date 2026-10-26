# reveng-debug

Evidence-first **debugging / software-archaeology** toolkit for binaries and apps you are authorized to inspect.

It is a thin Python orchestrator: Windows-first PE + ELF/Mach-O + JS/Electron inventory, website clone (static HTML or gotcontext-chrome capture), a TUI, a thin MCP, and an agent skill. It is **not** a dump of REA, leanrea, or REVENG, and it does **not** generate exploits.

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

## Specs

- [SPEC-RD-000 design](docs/superpowers/specs/2026-10-25-reveng-debug-design.md)
- [Architecture](docs/explanation/architecture-overview.md)
- [Support matrix](docs/support/support-matrix.md)
- [CLI](docs/reference/cli.md)
- [MCP](docs/reference/mcp-tools.md)

## License

MIT. See [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md) for REA, leanrea, and REVENG attribution.
