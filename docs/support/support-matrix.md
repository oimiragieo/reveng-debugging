# Support matrix

**Spec ID:** SPEC-RD-001  
Source of truth: `reveng_debug.contracts.models.SupportMatrix`.

| Workflow | Status | Notes |
|---|---|---|
| pe_inventory | present | LIEF preferred; pefile fallback with declared coverage |
| javascript_inventory | present | package.json, sourceMappingURL, IPC regex |
| electron_asar | present | Path-safe Python extract |
| website_clone | present | Static HTML/JSON clone; live DOM via gotcontext-chrome skill |
| dynamic_attach | unsupported | MVP never executes the target |
| ghidra_headless | unsupported | Wave 2; doctor may report PATH |
| reveng_extra | unsupported until import | Opt-in, copy-workspace paths only |
| rea_passthrough | unsupported until PATH | Opt-in, never auto-launches |
| elf/macho inventory | unsupported | Identify only |

`unknown` means not yet probed. It is not “absent”.
