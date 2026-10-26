# Analyst: install and triage

**Spec ID:** SPEC-RD-003

1. `python -m pip install -e ".[dev,lief]"`
2. `reveng-debug doctor` — record which tools are `present` vs `unknown`.
3. `reveng-debug identify PATH`
4. `reveng-debug inventory PATH` — work happens on the session copy.
5. Read `evidence` in the JSON: every statement is seen, inferred, or unknown.

If identify says `elf` or `macho`, inventory uses LIEF. If LIEF cannot parse the file, status is `failed` or `unknown`, never a fake success.

Opt-in decompile: `reveng-debug ghidra PATH` (BYO analyzeHeadless). Missing Ghidra → `unsupported`.

Opt-in app reverse-engineering: `reveng-debug app-re PATH` (BYO `reveng` GA only).

TUI: `reveng-debug tui` then attach omega-vision at `http://127.0.0.1:8092/attach`.

For a website: save HTML or a gotcontext-chrome `capture.json`, then `reveng-debug clone-website PATH`.
