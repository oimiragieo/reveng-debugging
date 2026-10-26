---
name: eilam-reversing-foundations
description: >-
  Use when deciding how to reverse an authorized binary without wasting
  decompiler time. DO NOT USE for cracking, DRM bypass, or exploit development.
---

# eilam-reversing-foundations

Decide **whether** to open a decompiler, and **what cheaper evidence already answers**.

Ideas only from Eldad Eilam, *Reversing: Secrets of Reverse Engineering* (Wiley):
foundations, legitimate motives, and how compilers/OS loaders leave a readable
surface. Do not paste the PDF. Later chapters on cracking, copy protection, and
anti-reversing are **out of scope** — refuse them.

Sibling for commands: `skills/reveng-debug/SKILL.md`.

## Hard rules

| Do | Never |
|----|-------|
| Work only on software the operator owns, ships, or is explicitly authorized to inspect | Reverse a competitor, pirate build, or “just this one DRM check” |
| Copy via `reveng-debug inventory`; never mutate the original | Patch, unpack-as-attack, or write a loader |
| Route `identify` → `inventory` → `slice`; stop when the question is answered | Open Ghidra “to look around” |
| Treat imports, exports, headers, resources, and strings as the first design map | Decompile until those fail to answer the asked question |
| Label every claim **seen**, **inferred**, or **unknown** | Invent symbols, PEB walks, or anti-debug bypasses |
| If Ghidra/`analyzeHeadless` is missing, report `unsupported` | Fake a decompilation |
| Static read of the session copy | Execute the native target; dynamic attach is unsupported |

## Why reverse (this product’s slice)

Reversing here means recovering **intent from a shipped artifact** when source,
docs, or a vendor diagram are missing. Legitimate motives on **owned** software:

1. **What actually shipped** — compiler output, stripped names, leftover
   resources. The binary is the contract with production, not the last git tag.
2. **Interoperability you are licensed for** — an undocumented but permitted
   API, file layout, or IPC surface inside your own stack.
3. **Audit of your own attack surface** — which libraries and syscalls the
   binary *declares*, not a hunt for a 0-day to weaponize.
4. **Lost documentation** — reconstruct enough of a module you operate to
   debug or replace it.

Refuse: cracking, serial fishing, DRM circumvention, malware construction,
exploit development, and any recipe that disables a debugger check.

If authority is unclear, stop. Ask. Do not “proceed statically anyway.”

## Low-level ideas that change the first move

A compiler is a pipeline (front end → IR → optimizer → back end). Names, types,
and structured control flow are **optional leftovers**. What usually survives
without a decompiler:

- **Identity of the artifact** — magic bytes, machine, subsystem. That is the
  execution environment (native PE/ELF/Mach-O vs bytecode/VM vs a JS bundle).
- **Capability map** — imported libraries and ordinals/names. This is the OS
  and runtime contract: networking, crypto, UI, process APIs. Often this *is*
  the answer to “what does it do?”
- **Public surface** — exports, COM/type libraries, resources. Cheaper than
  reconstructing every function.
- **Data before code** — tables, string pools, error catalogs, and embedded
  configs encode structure (records, lists, dispatch keys) that a CFG guess
  will only rediscover slowly.
- **Control flow is flags + branches** — loops and `if` are not gone, but they
  are expensive to read. Do not start there.
- **Listing / symbols if present** — debug leftovers beat pseudocode. Inventory
  first; do not assume stripped.

Decompilation is a **lossy reconstruction** of that pipeline’s back end. It is
justified only when the asked behavior is not visible in the inventory.

## Workflow (cheapest evidence first)

1. **Authority.** Named owner/operator and a specific question (“which DLLs
   does our service load?”, “where is the IPC channel string?”). No question →
   no session.
2. **Doctor.** `reveng-debug doctor`. Missing dumpbin/Ghidra is
   `unsupported` / `unknown`, not “absent.”
3. **Identify.** `reveng-debug identify PATH`. Route by magic. Wrong
   environment (treating a bundle as a PE, or the reverse) wastes the rest.
4. **Inventory.** `reveng-debug inventory PATH`. Work on the session copy under
   `%TEMP%\reveng-debug\<session>\` (or `$env:REVENG_DEBUG_STATE_ROOT`). Read
   headers, imports, exports, section/summary facts, package metadata.
5. **Answer or slice.** If the question is already answered, **stop**. Else
   `reveng-debug slice PATH NEEDLE` for one string/symbol. Never dump a whole
   minified file or listing.
6. **Ghidra is opt-in and last.** Only if inventory + slice cannot answer, and
   the operator wants function-level reconstruction: `reveng-debug ghidra PATH`.
   Point it at the **copy**. If the adapter returns `unsupported`, stop there.
7. **Do not execute.** No run, no attach, no “just to see the packer unpack.”
   Packer/obfuscator *presence* may be inferred from inventory entropy/sections;
   bypassing it is out of scope.

```powershell
reveng-debug doctor
reveng-debug identify .\target
reveng-debug inventory .\target
# only if the question is still open:
reveng-debug slice .\target NEEDLE
# only if inventory/slice failed to answer, operator opted in:
reveng-debug ghidra .\target
```

## Stop tests (do not decompile yet)

| Asked | Enough evidence |
|-------|-----------------|
| What kind of file is this? | `identify` magic + machine |
| What can it call? | Inventory imports / NEEDED / `package.json` |
| What does it expose? | Inventory exports / resources / main entry |
| Where is feature X named? | `slice` hit with file:offset |
| Did this build include Y.dll / crate / module? | Inventory, not a CFG |
| How does this one function decide Z? | Ghidra opt-in **after** the rows above miss |

If a row is satisfied, write the answer. Extra tools are waste.

## Output contract

- One sentence: **question**, **authority**, **stop-layer** (`identify` /
  `inventory` / `slice` / `ghidra` / refused).
- Claims tagged **seen** (path, offset, or symbol), **inferred**, or **unknown**.
- Capability status separate: `present` | `unsupported` | `failed` | `unknown`.
- If you did not open Ghidra, say so. That is success when inventory answered.
- Missing is **unknown**, not absent. Static is not observed execution.

## Refuse in one short sentence

- Cracking, keygens, license checks, DRM, “remove the nag.”
- Anti-debug, anti-tamper, or packer-unpack recipes.
- Exploit, ROP, shellcode, or malware-lab reproduction.
- Circumvention framed as research, CTF, or “our own copy protection.”

Point the operator at `reveng-debug` for authorized inventory, or stop.
