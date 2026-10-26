# Add an adapter

**Spec ID:** SPEC-RD-000 engineer track

1. Add a `TargetKind` only if identify can prove it from magic bytes.
2. Put result types in `contracts/models.py` (CL1).
3. Admit a copy via `SessionStore.admit` (CL2).
4. Emit `EvidenceItem` through `Ledger.record` as you parse.
5. Wire `service.inventory` and a unit test with a generated fixture.
6. Update `SupportMatrix` in the same change. Unsupported stays explicit.

Do not add exploit generation, live attach, or Ghidra invocation in MVP.
