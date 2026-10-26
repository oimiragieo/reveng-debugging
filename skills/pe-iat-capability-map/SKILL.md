---
name: pe-iat-capability-map
description: Use when turning PE import/export lists into a capability map with honest confidence labels. DO NOT USE to infer observed execution from static imports.
---

# pe-iat-capability-map

Turn a PE **import/export name list** into a **capability map**. Names the parser printed are **seen**. Buckets you group them into are **inferred**. Whether any of those names ran is **unknown**.

Source ideas (paraphrase only, never paste): local gitignored PE courseware under `references/courseware/pe/` — Goppit, *PE Format — A Reverse Engineer View* (CodeBreakers Magazine 1.2, 2006); the French PE-format notes (`Le_format_PE.pdf`); corkami `pe-headers` data-directory slots; short PE-layout notes (`pe.pdf`, `PE Format.pdf`). Keep the loader-table picture. Drop every patching, “add an import,” virus, and IAT-rewrite procedure those papers also contain.

This skill reads `reveng-debug inventory` JSON. It does not execute the target, does not snap thunks, and does not watch a process.

## Hard rules

| Do | Never |
|---|---|
| Start from `findings.imports` / `findings.exports` on the session copy | Claim an API was **called**, **reached**, or **observed** because it is imported |
| Copy DLL + function strings **verbatim** and mark them **seen** | Invent names, ordinals, delay-load DLLs, or forwarders the JSON omitted |
| Group **seen** names into **inferred** buckets (network, crypto, process, …) | Treat the bucket as a fact about runtime behavior |
| Treat a 200-name cap, a missing `imp.name`, and unparsed directories as **unknown** | Treat a gap as “this binary has no such API” / “absent” |
| Cite `engine`, `coverage`, `limitations` | Fill gaps with dumpbin/Ghidra output you did not run |
| Stop at a labeled map | Patch the IAT, add descriptors, hook thunks, unpack, or write a call tracer |

Static IAT/EAT reading is a **declaration map**. The on-disk tables say what the linker asked the loader to resolve, and what this module publishes. They are not a trace.

## First move

```powershell
reveng-debug doctor
reveng-debug identify .\target
reveng-debug inventory .\target
```

`identify` must report PE (`MZ`). Otherwise this skill does not apply — ELF/Mach-O have their own symbol lists.

Then read, in order: `status`, `engine`, `coverage`, `limitations`, `workspace_path`, `findings.imports`, `findings.exports`. Work only on `workspace_path`. If `status` is not `present`, the map is **unknown**.

`pefile` coverage is thinner than LIEF and already says so. Neither engine parses Authenticode, bound-import, or delay-load directories. `limitations` includes `static parse only; target was not executed` — keep that sentence in the report.

Optional, only when `doctor` shows dumpbin **present**:

```powershell
dumpbin /IMPORTS /EXPORTS .\copy.exe
```

Use it to corroborate names already in JSON. Dumpbin is still a static parse. Missing dumpbin stays **unsupported** / **unknown**.

## What the tables actually are (ideas, not a hex walk)

A PE optional header lists a small array of data directories (corkami: `NumberOfRvaAndSizes` slots). Two of those slots point at **imports** and **exports**. Inventory does **not** emit the RVAs or sizes. You cannot prove a directory is empty just because a JSON key is `[]`.

**Imports (IAT idea).** Each imported DLL has a descriptor. In the format there are two parallel thunk arrays: one keeps the lookup (name, or an ordinal when the high bit is set) so the file still documents the request; the other is the slot the Windows loader overwrites with a real address once the image is mapped. Courseware calls that overwritten array the Import Address Table. `reveng-debug` never watches that overwrite. The adapter walks the import directory and emits `{dll, names}` — the **declared** names, capped at **200 per DLL**. Calls in code (when they exist) go through those slots, often via a small jump thunk; this JSON has no call sites.

**Hint field.** A named import may carry a 16-bit hint into the providing DLL’s export table. That is a loader speed hint. It is not a call count.

**Ordinal-only thunks.** A thunk can store an ordinal instead of a name. Both LIEF and pefile adapters **drop** entries with no `imp.name`. Those imports are **unknown**, not absent. Do not reconstruct ordinal numbers.

**Delay-load and bound-import directories.** Separate data-directory slots exist. Bound values on disk can already look like addresses; delay-load names can live outside the regular import directory. This inventory does not emit either table. Names that only live there are **unknown**. Bound or delay-load is still not a runtime trace.

**Exports (EAT idea).** A providing module publishes an export address table: a vector of RVAs, a name array, and an ordinal array. Names let a search find a slot; ordinals index the address table. `NumberOfNames` can be smaller than `NumberOfFunctions` when some exports have no name. Some EAT slots are **forwarders**: the “address” is actually a string `other.dll.Func` inside the export section — this module is a relay, not the implementation. Inventory gives **up to 200 names** and none of the RVAs, ordinals, or forwarder flags. An export is a published entry point, not proof anyone imported it, and not proof its body ran.

**Stub / hosted IATs.** A managed host that only names `mscoree.dll`, or a stub that only names `LoadLibrary` / `GetProcAddress`, still has a capability map: it is a **loader stub**. Do not conclude “no network” because `ws2_32` is missing from that short list. A tiny IAT is an **inferred** packing or hosting signal — hand packing questions to `packer-detection`; do not unpack here.

## Inventory shape (this product)

```text
findings.imports[]  = { "dll": <string>, "names": [<up to 200 strings>] }
findings.exports    = [<up to 200 strings>]
```

`evidence[]` currently records `pe.machine` and `pe.security_flags`, not each import. Cite **findings fields**, not invented evidence rows.

| JSON | Seen | Inferred | Unknown on purpose |
|---|---|---|---|
| `imports[].dll` + `imports[].names[]` | The strings as printed | Capability **bucket** for a cluster of names | Runtime call, call-site existence, ordinal-only rows, names past the 200 cap, delay-load-only / bound-only DLLs |
| `exports[]` | Published names as printed | “library-like surface” / plugin if many names | RVAs, ordinal-only exports, forwarders, who calls them, names past the 200 cap |
| empty `imports` | Parser returned no names | Packed, .NET host, delay-load-only, or ordinal-only — pick **one** guess and label it inferred, or leave unknown | “this image calls nobody” |
| empty `exports` | Parser returned no names | Typical for many `.exe` files | “this is not a DLL” (Characteristics bit was not read) |

## Buckets (inferred only)

Group **seen** names. The DLL is a weak signal (`kernel32` is everything). Prefer function-name prefixes. One name may sit in more than one bucket; say so. Examples are **not exhaustive** — do not invent a hit that is not in the JSON.

| Bucket | Typical DLL / name cues (examples) |
|---|---|
| network | `ws2_32` `wsock32` `wininet` `winhttp` `iphlpapi` `dnsapi` `WSAStartup` `connect` `InternetOpen` |
| crypto | `advapi32` `Crypt*` `bcrypt` `ncrypt` `crypt32` `BCrypt*` — then stop and hand depth to `crypto-inventory-static` |
| process / thread / memory | `CreateProcess` `CreateThread` `OpenProcess` `VirtualAlloc` `WriteProcessMemory` `Nt*` |
| file / path | `CreateFile` `ReadFile` `WriteFile` `FindFirstFile` |
| registry | `RegOpenKey` `RegSetValue` `RegQueryValue` |
| ipc / sync | `CreateMutex` `CreatePipe` `CreateNamedPipe` `CreateFileMapping` |
| ui | `user32` `gdi32` `comctl32` `MessageBox` `CreateWindow` |
| service / scm | `OpenSCManager` `CreateService` `StartService` |
| debug / instrumentation | `IsDebuggerPresent` `CheckRemoteDebuggerPresent` `DebugActiveProcess` |
| loader / dynamic resolve | `LoadLibrary` `GetProcAddress` `Ldr*` `GetModuleHandle` |
| com / ole | `ole32` `oleaut32` `CoCreateInstance` |
| .net host | `mscoree` `_CorExeMain` `_CorDllMain` |
| other | Any DLL you cannot bucket — keep the **seen** name, bucket = `unclassified` |

`Ex` / `A` / `W` suffixes are naming noise; map to the base API when choosing a bucket, but quote the **seen** spelling in the table.

**Narrow inference only:** `WSAStartup` **seen** under `ws2_32.dll` → bucket `network` **inferred**. Do not write “the sample connected to the internet.” `CryptEncrypt` **seen** → bucket `crypto` **inferred**; algorithm and key use stay **unknown** unless `crypto-inventory-static` finds a named primitive in `strings`.

A bucket with zero **seen** names is **unknown**, not “not capable.”

## Workflow

1. **Gate.** Named path, named question, named authority. If authorization is missing, stop (`authorized-scope-ethics`).
2. **Inventory.** Run identify + inventory if the operator did not already paste JSON. Record `session_id`, `workspace_path`, `engine`, `coverage`, `limitations`.
3. **List seen names.** For each `findings.imports` row, copy `dll` and every `names[]` string. Note `len(names) == 200` as **truncated → unknown remainder**. Do the same for `findings.exports`.
4. **Bucket.** Assign each name to one or more buckets from the table. Mark the assignment **inferred**. Unclassified names stay in `other`.
5. **Export surface.** If exports exist, list them as **seen** published names. “This is the DLL’s API” is **inferred**. Forwarders / ordinal-only: **unknown**.
6. **Stub check.** If imports are only a loader or `mscoree` cluster, say **inferred** stub/host. Do not fill empty buckets from imagination. Do not unpack.
7. **Optional corroboration.** Dumpbin on the **copy** if doctor showed it. A dumpbin-only name that JSON lacked is still **seen** (cite dumpbin), but still not a call. Do not run Ghidra unless the operator opts in; even then, function names are not execution.
8. **Emit the contract.** Stop. Do not attach, do not “confirm by running,” do not rewrite thunks.

## Output contract

```text
target: <original_path>
copy: <workspace_path>  session: <id>
engine/coverage: <from inventory>
limitations: <quote inventory; include static-parse>
imports_seen: [{dll, names, truncated: yes|no}]
exports_seen: [<names>] | [] | truncated
capability_map:
  - bucket: <network|crypto|process|file|registry|ipc|ui|service|debug|loader|com|dotnet-host|other>
    confidence: inferred
    evidence_names: [<verbatim seen names>]
    runtime: unknown
gaps: [ordinal-only dropped | delay-load unparsed | bound-import unparsed | 200-cap | empty-IAT meaning unknown]
stance: declaration map only — not a call trace
next: stop | crypto-inventory-static | packer-detection | operator dumpbin | wait for ghidra opt-in
```

Cap at the inventory you have. Do not re-inventory to “find more imports.” Do not launch the binary to see which names fire.

## Siblings

- `reveng-debug` — command router (`doctor`, `identify`, `inventory`, optional dumpbin on the copy)
- `authorized-scope-ethics` — permission before the first parse
- `goppit-pe-layout` — map inventory onto PE structure; unknown directories stay unknown
- `eilam-windows-formats` — PE layout from the same JSON
- `pma-static-triage` — broader static first-move; this skill is the import/export map it points at
- `crypto-inventory-static` — crypto family labels once this map flags the crypto bucket
- `packer-detection` / `packer-honesty-limits` — tiny IAT as a packing signal; do not unpack
- `rce-process` — observe / hypothesize / verify; an IAT name is observe, not verify
- `docs/support/honesty-rules.md` — seen / inferred / unknown
