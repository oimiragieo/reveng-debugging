# Honesty rules

**Spec ID:** SPEC-RD-001

1. `seen` / `inferred` / `unknown` on every claim. Missing evidence is unknown, not absent.
2. Capability status is `present` | `unsupported` | `failed` | `unknown`. Do not collapse these.
3. `pefile` fallback must advertise reduced coverage versus LIEF.
4. Doctor must not print “absent”.
5. Do not vendor exploits, malware, reconstructed proprietary trees, or courseware PDFs. Local gitignored copies may live in `references/courseware/` for agent reading; never commit or paste book text.
6. Do not execute native targets unless a future flag is supported and the operator opts in.
7. Website clone captures visible structure only. Static fetch ≠ live DOM. Live tokens/assets require a gotcontext-chrome capture JSON.
