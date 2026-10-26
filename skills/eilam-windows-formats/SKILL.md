---
name: eilam-windows-formats
description: Use when explaining a Windows PE file layout from a reveng-debug inventory. DO NOT USE for patching binaries or forging signatures.
---

# eilam-windows-formats

Read a Windows PE from a `reveng-debug inventory` JSON. Teach the on-disk layout in original words. Do not reconstruct the book. Do not patch, unpack, or mint signatures.

Source ideas (paraphrase only, never paste): Eilam, *Reversing: Secrets of Reverse Engineering* (Wiley, 2005), Chapter 3 “Windows Fundamentals” (executable formats) and Chapter 6 “Deciphering File Formats” (how to map a layout from what a parser actually exposes). Chapter 4’s DUMPBIN notes are optional corroboration when `doctor` shows dumpbin **present**.

## Hard rules

| Do | Never |
|---|---|
| Explain `findings` keys that exist: `machine`, `sections`, `imports`, `exports`, `security_flags`, `strings` | Invent PE directories, version resources, certificates, or trailing blobs |
| Mark every claim **seen**, **inferred**, or **unknown** | Treat a missing key as “this binary has none” |
| Treat `security_flags` as `DllCharacteristics` bits | Call those bits Authenticode, a catalog signature, or “signed/unsigned” |
| Work on the session copy the CLI already made | Mutate the original file, rewrite the IAT, or hex-edit sections |
| List toolkit gaps as **unknown** | Fill gaps with dumpbin/Ghidra/WinDbg output you did not run |
| Stop at a static layout reading | Crack, unpack, forge certificates, bypass checks, or “fix” a binary |

A format reading is interoperability of *understanding*: name the tables this parser surfaced. Generating a compatible or patched PE is out of scope.

## First move

If the operator did not already paste inventory JSON:

```powershell
reveng-debug identify .\target
reveng-debug inventory .\target
```

`identify` must report PE (`MZ`). If it does not, this skill does not apply.

Then read, in order: `engine`, `coverage`, `limitations`, `findings`, `evidence`. `pefile` coverage is reduced versus LIEF and already says `no authenticode`. LIEF coverage does not parse Authenticode either. Neither engine fills the unknown list below.

Optional, only when `reveng-debug doctor` shows dumpbin **present**:

```powershell
dumpbin /HEADERS /IMPORTS /EXPORTS /SUMMARY .\copy.exe
```

Use dumpbin to corroborate names you already saw. If doctor did not show dumpbin, do not pretend you ran it.

## What a PE is (layout, not folklore)

A PE is a *mapped image*, not a sequential blob you can index with file offsets as if they were runtime addresses.

1. **DOS stub** — bytes start with `MZ`. A tiny 16-bit program exists so a real DOS loader fails politely. Inventory does not dump the stub. The ASCII scrape in `strings` may include the familiar “cannot be run in DOS mode” line; that is **seen** as a string, not a parsed stub.
2. **NT headers** — a file offset in the DOS header (`e_lfanew`) points at `PE\0\0`, then the file header and optional header. Inventory does not emit `e_lfanew`, `ImageBase`, entry point, subsystem, or timestamp. Those are **unknown** unless a field below happens to imply them.
3. **Machine** — `findings.machine` is the file-header CPU id. LIEF usually stringifies the enum (`I386`, `AMD64`, …). `pefile` may emit a hex word (`0x14c`). **Seen**. Do not translate a hex value you are not sure of; say **unknown** rather than guess Itanium vs ARM.
4. **Sections** — the image is sliced so the loader can apply different page rights. Each inventory section has `name`, `virtual_size` (in-memory), `sizeof_raw_data` (on disk). Those two sizes are *not* interchangeable: in-memory alignment is typically a page; on-disk alignment is smaller. An RVA is relative to the mapped image, not to the file. This toolkit does **not** convert RVAs to file offsets and does **not** emit section characteristics (readable / writable / executable). Rights per section: **unknown**.
5. **Imports** — static linking: a list of other modules this image asked the loader to map, plus function names (or, when a name is missing, nothing — ordinals are not a separate field here). Each entry is `{dll, names}` with names capped at 200. This is the compile-time import table the loader will satisfy by filling an Import Address Table. Runtime `LoadLibrary` / `GetProcAddress` linking is **not** visible in this list. Empty `imports` is **seen** as “parser returned no import names,” not “this image calls nobody.”
6. **Exports** — names this module publishes (capped at 200). Typical for a DLL; an `.exe` may still export. Presence of exports is **seen**. “This is a DLL” from exports alone is **inferred**, and only if you also say the file header Characteristics bit was **not** read (it was not).
7. **Optional directories Eilam enumerates that this JSON omits** — resources, relocations, debug, TLS, load-config body, bound imports, delay-load, the IAT as its own table. Name them as **unknown**. Do not reconstruct Table 3.1 from memory as if inventory printed it.

Chapter 6’s method, applied here: first watch what the *parser in front of you* actually returns; then map those fields onto the on-disk story. Do not run the target. Do not treat Cryptex-style archive crypto, password recovery, or brute force as part of this skill.

## Inventory field map

Walk `findings` in this order. Cite `evidence[]` when a matching `kind` exists (`pe.machine`, `pe.security_flags`).

| JSON key | PE meaning | How to talk about it |
|---|---|---|
| `machine` | `IMAGE_FILE_HEADER.Machine` | Architecture the linker targeted. **Seen**. |
| `sections[]` | Section table names + sizes | `virtual_size` = mapped; `sizeof_raw_data` = file. Do not sum them into “image size” or “overlay starts at…”. |
| `imports[]` | Import directory names | Capability map: which DLLs, which APIs. Cap is 200 names per DLL. Ordinals, bound addresses, delay-load: **unknown**. |
| `exports[]` | Export directory names | Published surface. RVAs of export functions: **unknown**. Forwarders: **unknown**. |
| `security_flags` | Four `DllCharacteristics` bits | See next section. Not a certificate. |
| `strings` | First 200 ASCII runs, length ≥ 4, whole file bytes | A scrape, not a string table. Unicode, resources, and overlay contents are not classified. |

`limitations` always includes static parse only. Static layout is not observed execution.

### `security_flags` (DllCharacteristics, not Authenticode)

The adapter masks four bits and nothing else:

| Flag | Bit | Honest reading |
|---|---|---|
| `ASLR` | 0x0040 | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` — loader *may* rebase. Does not prove the reloc directory exists or that rebase succeeded. |
| `HIGH_ENTROPY_VA` | 0x0020 | 64-bit high-entropy ASLR hint. On a 32-bit `machine` value, still report the bit **seen**; do not invent “this is PE32+”. |
| `NX_COMPAT` | 0x0100 | Data Execution Prevention compatible. Does not prove NX is enforced at runtime. |
| `GUARD_CF` | 0x4000 | Control Flow Guard marked. Inventory does not read the load-config function table. CFG coverage: **unknown**. |

`false` means the bit was clear in the optional header, **seen**. It does not mean the process will lack that mitigation (policy, older OS, or a packed stub can diverge). It is not a signature verdict.

## Unknown in this toolkit — do not invent

These three are **required** in every write-up, even when strings look suggestive:

| Surface | Why it is unknown here |
|---|---|
| **resources** | No `IMAGE_RESOURCE_DIRECTORY`. Icons, dialogs, version info, manifests, message tables: not walked. An ASCII hit that *looks* like `VS_VERSION_INFO` is still only a string. |
| **authenticode** | No certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY`), no PKCS#7 blob, no catalog, no hash check. `pefile` coverage text already says `no authenticode`. `security_flags` are unrelated bits. Signed vs unsigned: **unknown**. |
| **overlay** | No comparison of `SizeOfImage` / last section `PointerToRawData + SizeOfRawData` against file length. Extra bytes after the last section (installers, packed payloads, appended zip) are **unknown**. Strings from those bytes may appear in the 200-cap scrape; that does not locate an overlay. |

Also **unknown** unless a future inventory key appears: entry point, image base, subsystem (GUI/CUI/native), file checksum, relocations, TLS, delay-load, bound imports, IAT slots, export RVAs, section flags, Rich header, debug directory, `.pdata` / exception unwind.

If `imports` or `exports` is an empty list, say **seen: parser returned none**, not **absent from the file**. Packed or delay-loaded images often look empty here.

## Numbered workflow

1. Confirm `target_kind` / magic is PE.
2. Record `engine` (`lief` or `pefile`) and `coverage`. Note the pefile Authenticode disclaimer; do not imply LIEF verified a signature either.
3. Report `machine` (**seen**).
4. Tabulate `sections`: name, `virtual_size`, `sizeof_raw_data`. Flag names that look non-standard (`.upx*`, `.themida`, single section) as **inferred** packing *hints* only — packing is **unknown** without more parsers.
5. Group `imports` by `dll`. Summarize capability families (file, net, crypto, UI) as **inferred** from names. Do not claim those APIs ran.
6. List `exports` or state the parser returned none.
7. Quote `security_flags` booleans as **seen** bits. Restate: this is not Authenticode.
8. Sample `strings` that support the layout story (DOS message, PDB path-looking text, URL). Cap discussion; do not dump all 200.
9. Emit the unknown block: **resources**, **authenticode**, **overlay**, plus any other PE field you almost claimed.
10. Stop. No patch, no signature forge, no unpacker, no “next you should nop…”.

## Output contract

```markdown
## PE layout (static)

- Engine / coverage: ...
- Machine: ... (**seen**)
- Sections: (table: name, virtual_size, sizeof_raw_data)
- Imports: (dll → names or cap warning)
- Exports: ...
- DllCharacteristics bits: ASLR=... NX_COMPAT=... GUARD_CF=... HIGH_ENTROPY_VA=...
  These are not a signature.

## Inferred
- ... (capability families from import names, DLL-vs-EXE guess, packing hints)

## Unknown in this toolkit
- resources: not parsed
- authenticode: not parsed (do not use security_flags as a stand-in)
- overlay: not measured
- (any other PE directory you did not see)
```

Every bullet carries **seen** / **inferred** / **unknown**. Missing evidence is unknown, not absent.

## Siblings

- `reveng-debug` — identify / inventory / doctor / session copy rules
- Courseware PDFs stay gitignored; do not paste Eilam or MSDN listings into answers
