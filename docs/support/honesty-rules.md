# Honesty rules

**Spec ID:** SPEC-RD-001

1. `seen` / `inferred` / `unknown` on every claim. Missing evidence is unknown, not absent.
2. Capability status is `present` | `unsupported` | `failed` | `unknown`. Do not collapse these.
3. `pefile` fallback must advertise reduced coverage versus LIEF.
4. Doctor must not print “absent”.
5. Do not vendor exploits, malware, reconstructed proprietary trees, or courseware PDFs.
6. Do not execute the target unless a future flag is supported and the operator opts in.
