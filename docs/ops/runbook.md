# Operator runbook

**Spec ID:** CL5 / Wave 2

- State root: `$env:REVENG_DEBUG_STATE_ROOT` (default `%TEMP%\reveng-debug`).
- CI: `.github/workflows/ci.yml` (ruff, mypy, pytest) headless.
- Thinktank design receipt: `docs/superpowers/audits/2026-10-25-thinktank-design.md`.
- Public repo: `gh repo create` / `git push -u origin main`.
- Cleanup: delete local feature branches and `%TEMP%\reveng-debug-tt` after merge. Leftovers go to `_archive/`.
- TUI attach: omega-vision `http://127.0.0.1:8092/attach` (this host). README default elsewhere is `:8090`.
- Ghidra project dirs must not contain `.`-prefixed path segments.
- `reveng-debug app-re` must receive the session copy, never the original, and must not invoke generate-exploit.
