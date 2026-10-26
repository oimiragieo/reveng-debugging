# CLI reference

**Spec ID:** SPEC-RD-003+

```
reveng-debug doctor
reveng-debug identify PATH
reveng-debug inventory PATH [--session-id ID]
reveng-debug slice PATH NEEDLE [--session-id ID]
reveng-debug clone-website TARGET [--session-id ID]
reveng-debug ghidra PATH [--session-id ID]
reveng-debug app-re PATH [--session-id ID]
reveng-debug tui
reveng-debug session show ID
reveng-debug mcp
```

Workspace root: `%TEMP%\reveng-debug\` or `$env:REVENG_DEBUG_STATE_ROOT`.
Original files are copied, never overwritten.

`ghidra` and `app-re` are opt-in BYO. Missing engines return `unsupported`, never invented results.
TUI attach URL printed at start: `http://127.0.0.1:8092/attach` (omega-vision README default `:8090`).
