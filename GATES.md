# Gates: reveng-debug MVP

Scope: Public Python debugging toolkit with contracts, workspace, PE/JS inventory, CLI, thin MCP, CI, and GitHub remote.

- [x] G1: Package imports and CLI help
  CHECK: python -m reveng_debug --help
  EXPECT: doctor
  EVIDENCE: help lists doctor, identify, inventory, slice, mcp, session

- [x] G2: Hermetic unit tests
  CHECK: python -m pytest -q
  EXPECT: passed
  EVIDENCE: 17 passed

- [x] G3: Lint
  CHECK: python -m ruff check src tests
  EXPECT: All checks passed
  EVIDENCE: All checks passed!

- [x] G4: Format
  CHECK: python -m ruff format --check src tests
  EXPECT: already formatted
  EVIDENCE: 29 files already formatted

- [x] G5: Types
  CHECK: python -m mypy src
  EXPECT: Success
  EVIDENCE: Success: no issues found in 19 source files

- [x] G6: Public git remote exists
  CHECK: git remote -v
  EXPECT: github.com
  EVIDENCE: origin https://github.com/oimiragieo/reveng-debugging.git PUBLIC

- [x] G7: Exclusions honored (no exploits package, no courseware PDFs, no reconstructed trees)
  CHECK: python -c "..."
  EXPECT: clean
  EVIDENCE: clean (no generate-exploit files outside docs)
