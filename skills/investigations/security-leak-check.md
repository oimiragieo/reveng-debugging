# Own-app leak check (SPEC-RD-006)

Adapted from the REA leak-check prompt. Defensive review of an app you own.

```
Inspect this operator-owned app for leaked credentials, tokens, private keys,
and sensitive data that would be dangerous if disclosed. Static inventory first
(`reveng-debug inventory` / `slice`). Do not exploit, do not bypass auth, do
not attack third parties.
```
