---
name: memory-evidence-labels
description: >-
  Use when someone claims a runtime memory fact and you must grade confidence.
  DO NOT USE to produce memory-corruption exploits.
---

# Memory evidence labels

Grade claims about **heap**, **stack**, and **modules**. This toolkit never
attaches to a process, never executes the target, and never writes memory.
Live address-space facts that would need a debugger stay `unknown`.

Courseware idea (local PDF, do not quote): process memory is a *running*
address space. On-disk sections and import names are a different evidence
class. Type guesses from patterns are elimination, not proof.

## Hard rules

| Do | Never |
|---|---|
| Label every atomic claim `seen`, `inferred`, or `unknown` | Collapse “no dump” into “there is no heap/stack/module” |
| Keep **claim** labels separate from **capability** status (`unsupported` attach ≠ `unknown` fact) | Treat `dynamic_attach: unsupported` as proof of absence |
| Treat inventory JSON as the shipped file, not the live VA space | Equate PE/ELF section names with mapped regions *now* |
| Treat operator-pasted dumps as evidence *of that paste only* | Reproduce attach APIs, heap walks, stack writes, or module-injection steps |
| Stop when the next step would be attach or mutation | Invent addresses, allocation sizes, loaded-module lists, or ROP/write primitives |

Missing live view is `unknown`, not absent. Preferred image base is not the
load address. An import DLL name is not a loaded module. A `.data` section
on disk is not a live global.

## What can be true here

`reveng-debug` sees the **copy** under `%TEMP%\reveng-debug\<session>\` via
`identify` / `inventory` / `slice` (optional `ghidra` names). It does not
open another process.

| Region | `seen` | `inferred` | `unknown` |
|---|---|---|---|
| **Modules** | DLL / `DT_NEEDED` / dylib **names** in inventory; section names and sizes on the file | “These names will be mapped if this image loads” | Which modules are mapped *now*, ASLR slide, injected images, live `/maps` or PEB lists |
| **Heap** | Import *names* such as allocator APIs in the IAT / needed-libs | “This binary is written as if it allocates” | Chunk base, size, in-use list, live pointers, heap cookie/state |
| **Stack** | Architecture / calling-convention *hints* from machine + symbols (file) | “Locals of this function would live on a stack if it ran” | RSP/ESP, frames, return addresses, live stack bytes |
| **Image sections** | `.text` / `.data` / `.bss` / `rodata` **file** records (name, virtual size, raw size) | “A global *might* land in `.data` after load” | Current VA of any object, BSS contents at runtime |
| **Pointers / types** | Bytes **in** an operator-supplied dump or a file slice, quoted with offset | Field is “probably an int / string / pointer” from alignment or printable bytes | Pointer *validity* in a live space; structure size without a documented dump |

Operator dump exception: if the operator already pasted a crash dump or
debugger excerpt, the **bytes in that paste** are `seen` as contents of the
paste. Mapping those bytes to “heap vs stack vs module of process X right
now” is `inferred` unless the dump’s own header already names the region —
and this toolkit still did not capture it.

## Workflow

1. **Quote the claim** in one sentence. Name the region: heap, stack, module
   (or section / pointer if that is what they meant).
2. **Name the evidence class** actually in hand:
   - shipped-artifact inventory / slice / Ghidra names
   - operator-supplied dump (they already have it)
   - live attach (this product: **not available**)
3. **Split compounds.** “`kernel32.dll` is imported and loaded at `0x…`”
   is two claims: import name vs live base.
4. **Grade each atom** with the table above. If the only way to promote
   `unknown` → `seen` is attach, leave it `unknown` and stop.
5. **Offer the next *legal* probe** only: `doctor`, `inventory`, `slice`,
   or “ask the operator for a dump they already captured.” Do not describe
   how to attach.

## Output contract

```
claim: <one sentence>
region: heap | stack | module | section | pointer
evidence_class: shipped-artifact | operator-dump | live-attach-unavailable
label: seen | inferred | unknown
why: <one line; cite inventory field, dump line, or missing live view>
next_legal_probe: doctor | inventory | slice | operator-dump | stop
```

Repeat one block per atom. Do not emit addresses you did not read from
inventory, a named dump, or the operator.

## Anti-patterns

- “No heap allocations found” after a static inventory (you did not look).
- Reporting a preferred ImageBase as the runtime load address.
- Promoting a repeating pattern in a file to a live array without a dump.
- Walking from a known string to a live linked list (attach + search).
- Any write to process memory, game-state edit, or memory-corruption recipe.

## Siblings

- `memory-static-indicators` — ASLR/NX **flags** on the file vs runtime VA
- `reveng-debug` — CLI router; attach stays `unsupported`
- `secplus-observe-vs-assume` — claims need evidence
- `rce-process` — observe / hypothesize / verify without live attach
- `pe-iat-capability-map` — import names as capability buckets, not calls
