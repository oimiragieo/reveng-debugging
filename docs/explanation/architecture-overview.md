# Architecture overview

**Spec ID:** SPEC-RD-000  
**PRD:** Thin orchestrator, not a dump of REA/REVENG.

```
CLI / skill / 6-tool MCP
        │
     service.py
        │
   identify + doctor
        │
 SessionStore (copy under %TEMP%\reveng-debug\<id>\)
        │
  PE | JS | Electron adapters → Ledger (JSONL)
```

Dependencies flow inward: `contracts` has no storage/adapter imports. Adapters emit `EvidenceItem` immediately. Persistence is `SessionStore.append_evidence`.

Website clone (SPEC-RD-007): static HTML/JSON in `adapters/website.py`; live
DOM/tokens/assets via the operator's **gotcontext-chrome** MCP, documented in
`skills/reveng-debug/SKILL.md`. This replaces REA's `inspect-web-page` /
`analyze-web-bundle` / "Clone this website" path without vendoring REA CDP.

Wave 2 still deferred: ELF/Mach-O inventory, Ghidra invocation, TUI via
omega-vision `http://127.0.0.1:8092/attach`.
