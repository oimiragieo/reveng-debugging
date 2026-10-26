---
name: packer-honesty-limits
description: >-
  Use when a packing claim is about to be overstated from incomplete inventory.
  DO NOT USE to fill gaps with fake entropy or unpack recipes.
---

# Packer honesty limits

Gate for packing language on an authorized binary. Courseware describes many
wrapper families (compress, encrypt, protect, virtualize, bundle) and many
unlabeled ones. This CLI does not measure most of those signals. **Missing is
unknown.** Interpretation of a field you did quote is **inferred**. Never
promote either into a named packer, an entropy figure, or an unpacked body.

Read local packer methodology PDFs under `references/courseware/reversing/`
(`packers*.pdf`, `unpackers.pdf` detection discussion only). Do not paste them.
Do not follow unpacker/debug/dump procedures.

## Hard rules

| Do | Never |
|---|---|
| Quote inventory fields, then label the claim `seen` / `inferred` / `unknown` | Invent entropy, Shannon scores, or “high/low entropy” |
| Keep packing as `inferred` when the shape is only packing-adjacent | Name a packer as fact from a section label or a string |
| Leave unmeasured literature signals `unknown` | Compute side-channel stats and pretend they came from inventory |
| Stop at on-disk inventory (`reveng-debug inventory`) | Unpack, dump, hunt OEP, rebuild IAT, attach, single-step, or W-X intercept |
| Say `unsupported` if the operator asks to recover a runtime image | Treat a thin IAT or a single section as proof of a family |

## What this inventory actually has

PE (`adapters/pe.py`): `machine`, per-section `name` / `virtual_size` /
`sizeof_raw_data`, import DLLs and names (capped), exports (capped),
`security_flags`, bounded `strings`, plus a `coverage` string. pefile fallback
must keep its reduced-coverage note.

ELF/Mach-O: section `name` and `size` only. No virtual-vs-raw pair.

**Not a field today (always `unknown`, do not invent):** entropy, entry-point
bytes, overlay, section characteristics / RWX, checksum, packer database hit,
runtime image, write-then-execute, reconstructed imports after resolve.

## Paper signal → honest bucket

| Literature hint | If inventory shows it | Ceiling |
|---|---|---|
| Sparse / empty mapped section | `virtual_size` ≫ `sizeof_raw_data` | `inferred` packing-adjacent |
| Section merge | one section row | `inferred` packing-adjacent |
| Compact / stub imports | few DLLs, often load/get-proc style names | `inferred` packing-adjacent |
| Family name in strings or section titles | exact quoted text | `seen` text; family identity stays `inferred` (spoofed stubs exist) |
| Unusual section names | exact quoted names | `seen` names; packing stays `inferred` |
| Entropy / “compressed blob” | no field | `unknown` |
| Entry-point stub match | no EP bytes | `unknown` |
| Overlay / appended payload | no overlay | `unknown` |
| Unpacked original code | no dump, no execute | `unknown` |
| Virtualized / p-code body | no VM trace | `unknown` |
| Bundler drop / inject / API redirect | runtime only | `unknown` |
| “Not packed” because it did not match a known stub | polymorphism + unlabeled families | `unknown`, not a negative |

Non-PE kinds: PE packer literature does not apply. Packing verdict is
`unknown` unless a sibling skill for that format supplies its own fields.

## Workflow

1. **Freeze coverage.** Run `reveng-debug doctor` then `identify` then
   `inventory` on the session copy. Copy the `coverage` string. If identify is
   not PE, stop: packing verdict `unknown`.
2. **List packing-adjacent facts you can quote.** Section names, count,
   `virtual_size` vs `sizeof_raw_data`, import DLL/name lists, matching
   strings. Each quoted field is `seen`.
3. **Separate interpretation.** Any sentence that uses those facts to mean
   “likely wrapped / compressed / protected” is `inferred`. Do not upgrade it.
4. **Downgrade gaps.** Entropy, EP bytes, overlay, permissions, named family,
   unpacked payload, runtime import rewrite, virtualizer: `unknown`. Do not
   fill them from memory of other tools.
5. **Refuse unpack.** Detection papers recover layout by executing or dumping.
   This toolkit’s dynamic attach is unsupported. Do not offer dump, OEP, IAT
   rebuild, debugger, emulator, or page-guard recipes. If asked, one sentence:
   unsupported; packing remains inferred or unknown.
6. **Emit the card** below. A packing-adjacent shape may stay on the card as
   `inferred`. It must not become a family name, an entropy number, or
   “unpacked.”

## Output contract

```text
packing_honesty:
  kind: <identify>
  coverage: <quoted inventory coverage>
  seen: [<field=value citations>]
  inferred: [<packing-adjacent readings, each tied to a seen field>]
  unknown: [entropy, entry_point_bytes, overlay, section_flags, runtime_image, named_family, unpacked_payload, …]
  packing_verdict: packing-adjacent-inferred | not-indicated | unknown
  unpack: unsupported
```

`not-indicated` means the quoted PE shape does not look packing-adjacent.
It is **not** “unpacked” and **not** “entropy is low.”

## Red flags

| About to say | Write instead |
|---|---|
| “Entropy is high/low” | `unknown` — no entropy field |
| “This is UPX/Themida/…” | quoted string/section is `seen`; identity is `inferred` or `unknown` |
| “Not packed” | `not-indicated` or `unknown` |
| “Here is the original code” | `unknown`; unpack unsupported |
| Side-computed entropy in the report | omit it; it is not inventory |
| Unpack / dump / OEP steps | refuse; this skill does not teach them |

## Siblings

- `packer-detection` — whether inventory is packing-adjacent (`inferred`)
- `pma-packing-signals` — same ceiling, PMA-flavored static hints
- `reveng-debug` — doctor / identify / inventory only
- `authorized-scope-ethics` — permission before analysis
