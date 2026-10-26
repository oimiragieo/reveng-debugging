# Support matrix

**Spec ID:** SPEC-RD-001  
Source of truth: `reveng_debug.contracts.models.SupportMatrix`.

| Workflow | Status | Notes |
|---|---|---|
| pe_inventory | present | LIEF preferred; pefile fallback with declared coverage |
| elf_inventory | present | LIEF ELF headers, sections, needed libs, dynamic symbols, strings |
| macho_inventory | present | LIEF Mach-O headers, sections, dylibs, exports, strings |
| javascript_inventory | present | package.json, sourceMappingURL, IPC regex |
| electron_asar | present | Path-safe Python extract |
| website_clone | present | Static HTML/JSON clone; live DOM via gotcontext-chrome skill |
| ghidra_headless | present (adapter) | Opt-in BYO; runtime `unsupported` if analyzeHeadless missing |
| reveng_extra | present (adapter) | Opt-in `app-re`; runtime `unsupported` if `reveng` missing |
| tui_attach | present | `reveng-debug tui`; omega-vision `http://127.0.0.1:8092/attach` |
| dynamic_attach | unsupported | This build never executes the target |
| rea_passthrough | unsupported until PATH | Opt-in, never auto-launches |

`unknown` means not yet probed. It is not “absent”.
