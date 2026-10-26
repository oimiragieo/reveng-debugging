---
name: goppit-pe-layout
description: Use when mapping a PE inventory JSON onto PE file layout for an authorized binary. DO NOT USE to craft malicious PE files.
---

# goppit-pe-layout

Walk an authorized PE in **on-disk order** and pin each stop to a `reveng-debug inventory` key, or to **unknown**. This is a reading skill. It does not assemble, patch, inject, or unpack an image.

Source ideas (paraphrase only; never paste tables, offsets, or samples): Goppit, *Portable Executable File Format – A Reverse Engineer View* (CodeBreakers Magazine 1.2, 2006); Ero Carrera’s 2005 PE layout poster (`PE Format.pdf`); Yinrong Huang’s 2003 disk-vs-RAM notes (`pe.pdf`). Keep Goppit chapters 2–7 and 17 (structure + RVA idea). Drop chapters 12–15 (adding code, adding imports, packers, infection) and Huang’s embedding / “cook” sections. `eilam-windows-formats` owns the mapped-image story and the four `DllCharacteristics` bits. This skill owns the **byte-order walk** and the **unknown field census**.

## Hard rules

| Do | Never |
|---|---|
| Start from inventory JSON (`engine`, `coverage`, `findings`, `evidence`, `limitations`) | Hex-edit, rebuild an IAT, add a section, or “fix” headers |
| Mark every claim **seen**, **inferred**, or **unknown** | Treat a missing JSON key as “this file has none of that” |
| Count `findings.sections` and named imports/exports you actually received | Invent `e_lfanew`, entry point, image base, or directory RVAs |
| Compare `virtual_size` vs `sizeof_raw_data` as two **seen** integers | Turn a size gap into overlay, packing family, or a place to hide bytes |
| Stop after a layout map | Follow Goppit’s add-code / add-import labs, Huang’s gap fill, or any virus/packer recipe |

`identify` seeing `MZ` is not a verified `PE\0\0`. Coverage text saying `pe-headers` is not a dump of every header field. `dynamic_attach` is **unsupported**. Do not execute the target.

## What inventory emits today

`reveng-debug inventory PATH` copies the file under `%TEMP%\reveng-debug\<session>\` (or `$env:REVENG_DEBUG_STATE_ROOT`) and prints `InventoryResult` JSON.

Envelope (always read first): `schema_version`, `session_id`, `target_kind` (`pe`), `original_path`, `workspace_path`, `status`, `engine` (`lief` preferred, `pefile` fallback), `coverage`, `findings`, `evidence`, `limitations` (static parse; target was not executed).

`findings` keys **only**:

| Key | Shape | Cap / quirk |
|---|---|---|
| `machine` | LIEF: engine string of `IMAGE_FILE_HEADER.Machine`. pefile: hex word (`0x14c`, …) | Formats are not interchangeable. Do not guess ARM vs Itanium from a hex you are unsure of. |
| `sections[]` | `{name, virtual_size, sizeof_raw_data}` | Names are labels the OS ignores. No RVA, no file pointer, no characteristics. |
| `imports[]` | `{dll, names[]}` | Named imports only; ordinal-only rows are dropped. **200 names per DLL.** |
| `exports` | list of names | Named exports only. **200 names total.** |
| `security_flags` | `{ASLR, NX_COMPAT, GUARD_CF, HIGH_ENTROPY_VA}` → bool | Four optional-header bits. Not Authenticode. Meanings: `eilam-windows-formats`. |
| `strings` | ASCII runs, length ≥ 4, **first 200**, whole-file bytes | Not PE-aware. Stub text, overlay bytes, and resources can all appear here without being parsed. |

`evidence[]` kinds today: `pe.machine` (location `offset=0` is the file start, **not** `e_lfanew`) and `pe.security_flags`. Nothing else is ledgered.

pefile `coverage` already says `no authenticode`. LIEF `coverage` lists `pe-headers,imports,exports,sections,dll-characteristics,strings` and still does **not** emit a certificate table. Neither engine’s coverage string is a field list.

## On-disk walk → JSON

Goppit’s picture, in file order. Carrera’s poster is the same skeleton with more structs overlaid. At each stop: what the toolkit **saw**, what it **used internally and threw away**, what stays **unknown**.

### 1. DOS header (first 64 bytes) and DOS stub

Identify: `header[:64]` starts with `MZ` → `kind: pe`. That is **seen** magic, not a parsed `IMAGE_DOS_HEADER`.

Inventory does not emit `e_magic`, the reserved DOS words, `e_lfanew` (the file offset of the NT headers), the stub program, or the Microsoft “Rich” linker overlay that sometimes sits between stub and `PE`. A `strings` hit like `This program cannot be run in DOS mode` is **seen** text, not a stub parse.

If identify routed on `.exe` / `.dll` / `.sys` **without** `MZ` in those 64 bytes, say so; do not pretend the DOS header was walked.

### 2. PE signature

The loader skips the stub using `e_lfanew` and checks `PE\0\0`. Inventory never prints the signature. A successful parse **infers** the parser accepted some NT signature; it does **not** distinguish PE from older NE / LE / LX marks. Those remain **unknown**. Do not claim “valid PE signature” as a **seen** field.

### 3. COFF file header (`IMAGE_FILE_HEADER`)

| Field | Inventory |
|---|---|
| `Machine` | **seen** as `findings.machine` (+ evidence `pe.machine`) |
| `NumberOfSections` | **not emitted**. `len(findings.sections)` is a **seen** count of headers the parser returned, which is not the same as reading the COFF word |
| `TimeDateStamp` | **unknown** |
| `PointerToSymbolTable`, `NumberOfSymbols` | **unknown** |
| `SizeOfOptionalHeader` | **unknown** |
| `Characteristics` (EXE vs DLL, relocs stripped, …) | **unknown**. Do not infer “this is a DLL” from `exports` alone without saying so |

### 4. Optional header

Goppit: logical layout (entry, preferred base, two alignments, size of image, data directory). Inventory emits **none** of those numbers except four `DllCharacteristics` bits.

**Unknown** (do not invent): `Magic` (PE32 vs PE32+), linker major/minor, `SizeOfCode` / initialized / uninitialized, `AddressOfEntryPoint`, `BaseOfCode`, `BaseOfData` (PE32 only), `ImageBase`, `SectionAlignment`, `FileAlignment`, OS / image / subsystem versions, `Win32VersionValue`, `SizeOfImage`, `SizeOfHeaders`, `CheckSum`, `Subsystem` (GUI / CUI / native), remaining `DllCharacteristics` bits, stack and heap reserve/commit, `LoaderFlags`, `NumberOfRvaAndSizes`.

Without `Magic`, `ImageBase`, alignments, and entry point you cannot reconstruct load address, disk↔RAM padding, or where execution would start. Leave them **unknown**. Historical “most EXEs prefer `0x400000`” folklore is not this file.

`security_flags` **seen** bits: `ASLR` 0x0040, `NX_COMPAT` 0x0100, `GUARD_CF` 0x4000, `HIGH_ENTROPY_VA` 0x0020. `false` means the bit was clear in the optional header, **seen** — not “the OS will skip that mitigation.”

### 5. Data directory (sixteen RVA+size slots)

Carrera/Goppit: export, import, resource, exception, security (Authenticode), basereloc, debug, architecture, globalptr, TLS, load config, bound import, IAT, delay import, COM/.NET, reserved.

The adapter **walks import and export directories internally** to harvest names, then discards RVAs and sizes. Inventory does **not** emit any directory slot.

| Slot | What you may say |
|---|---|
| Import | Names in `findings.imports` are **seen**. Descriptor fields (`OriginalFirstThunk`, `TimeDateStamp`, `ForwarderChain`, name RVA, `FirstThunk`), INT vs IAT, bound vs unbound, delay-load table: **unknown** |
| Export | Names in `findings.exports` are **seen**. Module internal name, ordinal base, EAT/ENT/EOT RVAs, forwarded exports, ordinal-only exports: **unknown** |
| Security / Authenticode | **unknown**. `security_flags` is the wrong structure. pefile coverage already warns `no authenticode` |
| Resource, exception, reloc, debug, TLS, load config, bound import, IAT-as-directory, delay import, COM descriptor | **unknown** |

Empty `imports` / `exports` is **seen: parser returned no names**, not “this image links nothing.” Packed or delay-loaded files often look empty here (`packer-detection`, `pe-iat-capability-map`).

### 6. Section table, then section bodies

Each inventory row is three fields. Map them honestly:

| JSON | PE meaning | Stop here |
|---|---|---|
| `name` | Eight-byte label (not a path, not a guarantee of contents) | `.text` / `CODE` / `.rsrc` are conventions. The loader does not care. |
| `virtual_size` | Bytes the loader backs in memory (unrounded VirtualSize) | |
| `sizeof_raw_data` | Bytes on disk, rounded to file alignment by the linker | |

**Unknown** per section: `VirtualAddress`, `PointerToRawData`, reloc/linenumber pointers and counts, `Characteristics` (code / init data / r/w/x). You **cannot** convert RVA ↔ file offset from this JSON.

Huang/Goppit observation you *may* make: if `virtual_size` > `sizeof_raw_data`, the mapped page is larger than the file bytes — **seen** integers, **inferred** “BSS-like or packed workspace,” **unknown** as a hide-site. If `sizeof_raw_data` > `virtual_size`, extra file bytes exist relative to the virtual size — **seen** integers, not a license to talk about slack injection. File vs section alignment values are **unknown**, so disk gaps and RAM page gaps cannot be measured.

Common body names (code, data, rsrc, edata, idata, reloc, debug, tls) are **inferred** from the label only. Contents of `.rsrc` (version info, dialogs, manifests) are **unknown**. Overlay past the last section is **unknown**: inventory never compares file length to `SizeOfHeaders` + raw section span.

### 7. RVA idea (Goppit ch. 17) — one sentence

An RVA is an offset from the **preferred mapped base**, not from byte 0 of the file. This toolkit never prints an RVA. Do not add `ImageBase` you do not have.

## Numbered workflow

1. **Authorize.** Named path, named owner. If the ask is to craft, infect, unpack-to-run, or stealth-patch a PE, refuse.
2. **Identify.** `reveng-debug identify PATH` must be PE. Record whether that was `MZ` in the first 64 bytes or suffix fallback.
3. **Inventory.** `reveng-debug inventory PATH`. Copy `engine` and `coverage`. Work only on `workspace_path`.
4. **Walk the seven stops above.** For each, cite the JSON key or write **unknown**. Quote `evidence[]` when `kind` matches.
5. **Size pair only.** Optionally note `virtual_size` vs `sizeof_raw_data` per section. Do not compute entropy, overlay, or OEP.
6. **Optional dumpbin** only if `reveng-debug doctor` shows dumpbin **present** and the operator wants corroboration of names already seen. Missing dumpbin stays **unknown**. Never invent its output.
7. **Stop.** Output the contract. Hand packing to `packer-detection`, import-as-capability to `pe-iat-capability-map`. Do not open Ghidra unless the operator opts in.

## Output contract

```markdown
## PE layout map (static)

- Identify: MZ-in-64 | suffix-fallback | not-PE
- Engine / coverage / limitations: ...
- DOS header + stub: seen(MZ only) | unknown(e_lfanew, stub, Rich)
- Signature: inferred-parser-accepted | unknown (NE/LE/LX not tested)
- COFF: machine=... (**seen**); NumberOfSections/timestamp/Characteristics=**unknown**; section-row-count=N (**seen**)
- Optional: DllCharacteristics bits ... (**seen**); Magic/entry/ImageBase/align/SizeOfImage/Subsystem=**unknown**
- Directories: import names ...; export names ...; all sixteen RVA+size slots=**unknown**
- Sections: (table: name, virtual_size, sizeof_raw_data); VA/raw-ptr/flags=**unknown**
- Strings window: (few layout-relevant hits, not the full 200)

## Inferred
- (DLL-vs-EXE, packing hint, body-from-name — each tagged)

## Unknown in this toolkit
- e_lfanew, PE signature bytes, Rich
- COFF timestamp, symbol table, SizeOfOptionalHeader, Characteristics
- Optional: Magic, entry point, ImageBase, both alignments, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, leftover DllCharacteristics, stack/heap
- Data directories: resource, exception, Authenticode, reloc, debug, TLS, load config, bound import, IAT directory, delay import, COM
- Per section: VirtualAddress, PointerToRawData, Characteristics
- Overlay, checksum verify, runtime IAT values
```

Every bullet carries **seen** / **inferred** / **unknown**. Missing evidence is unknown, not absent. Static layout is not observed execution.

## Siblings

- `reveng-debug` — `identify` / `inventory` / `doctor` / session copy
- `eilam-windows-formats` — mapped-image explanation + the four security bits
- `pe-iat-capability-map` — import names as capability buckets, not calls
- `packer-detection` — packed-looking from this same JSON
- `authorized-scope-ethics` — permission before analysis
- `docs/support/honesty-rules.md` — seen / inferred / unknown
