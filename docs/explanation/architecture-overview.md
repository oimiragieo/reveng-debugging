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

Wave 2 (documented, not built): ELF/Mach-O inventory, Ghidra BYO invocation, TUI via omega-vision `http://127.0.0.1:8092/attach`, gotcontext-chrome website adapter.
