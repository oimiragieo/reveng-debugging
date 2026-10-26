---
name: program-understanding-map
description: >-
  Use when you must explain how an authorized program is structured from
  static evidence. DO NOT USE to reconstruct third-party products for cloning.
---

# program-understanding-map

Question-scoped static blueprint of a program the operator is allowed to
inspect. Ideas only from local courseware
`references/courseware/reversing/Reverse Engineering and Program Understanding.pdf`
(do not paste that text). Probe with `reveng-debug`; do not invent surfaces.

## Hard rules

| Do | Never |
|----|-------|
| Confirm authorization, then work on the `inventory` session copy | Mutate the original; analyze a third-party product to clone it |
| Seed the map at public edges: PE exports / entry, JS `main`, asar main/preload | Start in a random inner module or a full decompile |
| Follow **imports** and **IPC names** one hop at a time | Dump a whole minified file; brute-walk every branch |
| **Stop** when a **seen** fact answers the asked question | Keep mapping "for completeness" after the question is settled |
| Label every claim **seen**, **inferred**, or **unknown** | Treat missing as absent; treat IAT/import lists as observed calls |
| Static inventory + `slice` only | Execute native targets; attach a debugger; write exploits or patches |

A mental map is a **small graph** (entry → few hops → answer), not a
whole-program dump. Deeper modules are longer paths from a public edge;
do not go there unless the question still lacks evidence.

## Workflow

1. **Need a question.** If the operator has not named a feature, file, IPC
   channel, or "how does X get in?", hand off to
   `program-understanding-questions`. Mapping without a question is a dump.

2. **Cheapest identity.**
   ```powershell
   reveng-debug doctor
   reveng-debug identify .\target
   reveng-debug inventory .\target
   ```
   Route by magic bytes. Copy lives under `%TEMP%\reveng-debug\<session>\`.
   Opt-in `ghidra` only if this graph cannot answer and the operator asked.

3. **Seed entry points (seen only).**

   | Kind | Where the map starts |
   |---|---|
   | PE (`MZ`) | `AddressOfEntryPoint`; export names in inventory JSON |
   | JS / Node | `package.json` `main` / `exports` / `bin`, then that file |
   | Electron `.asar` | inventory paths for main, preload, renderer entry (path-safe extract) |

   Import/export **names** are structure. They are not proof the code ran.

4. **Walk one hop.** From each seed, follow only:
   - static imports (`import` / `require` / PE IAT names)
   - IPC (`ipcMain` / `ipcRenderer` / `contextBridge` / `invoke` / `on`) via
     `reveng-debug slice PATH NEEDLE`
   Record `from → via → to`. Then go to step 5 before taking another hop.

5. **Stop test.** Does a **seen** location, import, or IPC name answer the
   question? If yes, freeze. If no, take **one** unread neighbor that could.
   Do not explore both sides of a branch unless the question names both.

6. **Runtime stays unknown.** Native attach is `unsupported`. A log the
   operator already captured may be labeled **seen**; guessed live behavior
   is **inferred** or **unknown**. Static structure ≠ observed control flow.

## Output contract

```
question: <feature / edge / "how does X get in?">
entry_points:
  - { kind: pe-export|pe-entry|js-main|asar-main|asar-preload|other, location, evidence: seen }
edges:
  - { from, via: import|iat|ipc, to, evidence: seen|inferred }
answer: <one paragraph, or unknown>
not_walked: [<neighbors left unknown — missing is not absent>]
limitations: [session copy only, no native exec, IAT≠call, slice≠full file]
```

Every node and edge carries `seen` | `inferred` | `unknown`. A missing
optional tool is `unsupported` (run `doctor`) — never fake dumpbin/Ghidra.

## Siblings

- `program-understanding-questions` — pin the question in 2–4 tool calls first
- `reveng-debug` — `identify` / `inventory` / `slice`
- `pe-iat-capability-map` — import names as capability buckets, not calls
- `cookbook-static-first` — cheapest static probes
- `authorized-scope-ethics` — permission before analysis
- `clone-website` — visible site structure; not a program map
