# Thinktank design gate — SPEC-RD-000

**Run:** `tt-bb8fc99cce52472cbd5e1e2ab27d755a`  
**Out dir:** `%TEMP%\reveng-debug-tt\tt-bb8fc99cce52472cbd5e1e2ab27d755a`  
**Seats:** codex (native gpt-6-astra, ADVISE), agy (Gemini 4 Argon High, APPROVE)  
**Artifact hash gate:** none (advisory). Runner `approval=false` as expected.

## Folds applied before CL0

1. Evidence models in contracts; persistence in storage; adapters emit evidence immediately.
2. Distinguish `unsupported` / `failed` / `unknown` / `present`; pefile fallback reports coverage.
3. Safe ASAR extraction (no traversal / symlink escape).
4. BYO passthrough opt-in, copy-workspace paths, non-executing defaults.
5. Ghidra invocation deferred to Wave 2.
