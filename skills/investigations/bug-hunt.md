# Own-app bug hunt (SPEC-RD-006)

Adapted from the REA “pricing bug hunt” prompt. Use only on an app you operate.

Do not change code. Do not execute binaries through reveng-debug.

```
Review the operator-owned app and compare observed behavior of the named feature
with the expected behavior. For mismatches, retrace from the user action to the
failure. Label each finding seen, inferred, or unknown. Do not read this as
authorization to reverse a third-party product.
```

Prefer `reveng-debug inventory` / `slice` on the shipped bundle copy, then
gotcontext-chrome against localhost if the operator already has the app running.
