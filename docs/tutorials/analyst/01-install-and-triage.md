# Analyst: install and triage

**Spec ID:** SPEC-RD-003

1. `python -m pip install -e ".[dev]"`
2. `reveng-debug doctor` — record which tools are `present` vs `unknown`.
3. `reveng-debug identify PATH`
4. `reveng-debug inventory PATH` — work happens on the session copy.
5. Read `evidence` in the JSON: every statement is seen, inferred, or unknown.

If identify says `elf` or `macho`, inventory will return `unsupported` (Wave 2).

For a website: save HTML or a gotcontext-chrome `capture.json`, then `reveng-debug clone-website PATH`.
