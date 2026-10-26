# CLI reference

**Spec ID:** SPEC-RD-003+

```
reveng-debug doctor
reveng-debug identify PATH
reveng-debug inventory PATH [--session-id ID]
reveng-debug slice PATH NEEDLE [--session-id ID]
reveng-debug session show ID
reveng-debug mcp
```

Workspace root: `%TEMP%\reveng-debug\` or `$env:REVENG_DEBUG_STATE_ROOT`.
Original files are copied, never overwritten.
