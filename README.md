# reveng-debug

Evidence-first **debugging / software-archaeology** toolkit for binaries and apps you are authorized to inspect.

It is a thin Python orchestrator: Windows-first PE + JS/Electron inventory, a six-tool MCP, and an agent skill. It is **not** a dump of REA, leanrea, or REVENG, and it does **not** generate exploits.

## Install

```powershell
python -m pip install -e ".[dev]"
reveng-debug --help
reveng-debug doctor
```

Python 3.11+. Optional: `pip install -e ".[lief]"` for the preferred PE engine (`pefile` is the fallback and reports reduced coverage).

## Commands

| Command | Purpose |
|---|---|
| `reveng-debug doctor` | Tool probes + support matrix (`unknown` ≠ absent) |
| `reveng-debug identify PATH` | Magic-byte / extension kind |
| `reveng-debug inventory PATH` | Copy into `%TEMP%\reveng-debug\<session>\`, emit evidence |
| `reveng-debug slice PATH NEEDLE` | Bounded static slice |
| `reveng-debug session show ID` | Session + ledger |
| `reveng-debug mcp` | Six-tool MCP stdio |

Targets are never executed by default. Ghidra and live attach are Wave 2 (`unsupported`).

## Specs

- [SPEC-RD-000 design](docs/superpowers/specs/2026-10-25-reveng-debug-design.md)
- [Architecture](docs/explanation/architecture-overview.md)
- [Support matrix](docs/support/support-matrix.md)
- [CLI](docs/reference/cli.md)
- [MCP](docs/reference/mcp-tools.md)

## License

MIT. See [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md) for REA, leanrea, and REVENG attribution.
