# Gates: reveng-debug Wave 2

Scope: Public Python debugging toolkit with contracts, workspace, PE/ELF/Mach-O/JS inventory, website clone, TUI, opt-in BYO Ghidra and reverse-engineer-app, CLI, thin MCP, CI, and GitHub remote.

- [x] G1: Package imports and CLI help
  CHECK: python -m reveng_debug --help
  EXPECT: doctor
  EVIDENCE: help lists doctor, identify, inventory, slice, mcp, session, ghidra, app-re, tui

- [x] G2: Hermetic unit tests
  CHECK: python -m pytest -q
  EXPECT: passed
  EVIDENCE: Wave 2 suite (native, ghidra, tui, reveng extra)

- [x] G3: Lint
  CHECK: python -m ruff check src tests
  EXPECT: All checks passed

- [x] G4: Format
  CHECK: python -m ruff format --check src tests
  EXPECT: already formatted

- [x] G5: Types
  CHECK: python -m mypy src
  EXPECT: Success

- [x] G6: Public git remote exists
  CHECK: git remote -v
  EXPECT: github.com
  EVIDENCE: origin https://github.com/oimiragieo/reveng-debugging.git PUBLIC

- [x] G7: Exclusions honored (no exploits package, no courseware PDFs in git, no reconstructed trees)
  CHECK: git check-ignore references/courseware/*.pdf ; git ls-files "*.pdf"
  EXPECT: PDFs ignored; none tracked
  EVIDENCE: `*.pdf` and `references/courseware/**` gitignored; local copies for agents only

- [x] G8: Wave 2 surfaces
  CHECK: ELF/Mach-O inventory, `reveng-debug ghidra`, `reveng-debug app-re`, `reveng-debug tui`
  EXPECT: missing BYO engines return unsupported; LIEF inventory present; attach URL 8092
  EVIDENCE: tests/test_native.py tests/test_ghidra.py tests/test_reveng_extra.py tests/test_tui.py
