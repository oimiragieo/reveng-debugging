---
name: secplus-observe-vs-assume
description: Use when a claim about a binary or app is about to be stated as fact without evidence. DO NOT USE as a Security+ exam dump or attack guide.
---

# Observe vs assume

Ideas from the local SY0-401 review guide (CIA, detective controls, logs, false alarms, evidence handling). Original wording. Do not paste book text. Do not teach attacks.

A sentence about a binary or app is a **security claim**. Treat it the way that guide treats a control: it is only as strong as the sensor that recorded it.

## Hard rules

| Do | Never |
|---|---|
| Label every claim `seen`, `inferred`, or `unknown` | State an app/binary fact with no sensor behind it |
| Cite tool, command, and path/offset/symbol for `seen` | Call a missing field **absent** |
| Keep claim confidence separate from capability status | Collapse `unsupported` / `failed` / `unknown` into one bucket |
| Treat static inventory as a snapshot, not runtime | Treat imports, strings, or names as observed execution |
| Work on the session copy; leave the original intact | Mutate the target or invent Ghidra/dumpbin output |
| Stay in detective mode (observe, label, stop) | Attack steps, exploit paths, or exam-dump Q&A |

`reveng-debug doctor` before trusting an optional engine. A missing engine is `unsupported` or `unknown`, not proof the target lacks a feature.

## CIA → claim grades

| Goal | In this workflow | Maps to |
|---|---|---|
| **Confidentiality** | Do not promote a guess into a public fact. Unobserved internals stay unobserved. Over-claiming is unauthorized disclosure of certainty. | `inferred` and `unknown` must stay labeled. Do not leak them as `seen`. |
| **Integrity** | A fact is reliable only if the evidence trail is intact: session copy, tool, command, location. A gap in that trail is a broken chain. | `seen` requires a cite. Unlabeled mixing of guess and observation corrupts the ledger. |
| **Availability** | If the observation channel is down, the fact is unavailable *to you*. That is not the same as the property being missing from the target. | Sensor down or not yet run → `unknown` / `unsupported`. One failed probe is not “feature absent”. |

Safety of the analysis: do not execute native targets unless the operator opts into a supported dynamic path. This skill does not add one.

## Observability → sensors

Security+ monitoring ideas (event / audit / security / access logs, baselines, continuous watch, detective vs preventive) map onto **what you actually ran**.

| Sensor class | What it can support as `seen` | What it cannot |
|---|---|---|
| Magic / identify | File kind, header signature | Behavior |
| Inventory (IAT, exports, sections, package.json) | Names and layout that the parser printed | That a symbol was called |
| Slice / strings | Substring at a location | Meaning, reachability, runtime use |
| Doctor / support matrix | Whether *your* tools were `present` | Anything about the target’s internals |
| Operator-supplied log or screenshot | What that artifact shows, with its limits | Events outside the capture window |
| Opt-in Ghidra / app-re | What that engine emitted, with `limitations` | Functions it did not list |

No sensor ran → **unknown**. Static reading is a baseline snapshot, not continuous monitoring. Detective inventory discovers; it does not fill gaps. Preventive “lock it down” thinking does not authorize declaring the gap closed.

Identification is not authentication is not authorization:

1. **Identify** — a name appeared (string, import, symbol).
2. **Authenticate** — the same name is bound to a cite (tool output, hash, offset) you could re-check.
3. **Authorize** — only then may the report treat it as `seen`. A name alone is not a fact.

Implicit deny: if evidence did not specifically grant `seen`, the claim is denied that grade.

## False alarm vs missed alarm

| Pattern | Grade | Why |
|---|---|---|
| Import or string looks like a capability, so you report the capability as used | False certainty (`seen` abused) | Detection without verification. Label `seen` for the name, `inferred` for the capability, `unknown` for use. |
| You did not find a name, so you report the capability as missing | Missed coverage (`absent` invented) | Weak or unrun sensors. That is a **false negative** of observation: harm to honesty while you think you are done. |
| Optional tool missing, so you narrate what it “would have” shown | Fabrication | Capability is `unsupported`. Claim about the target is `unknown`. |

Least privilege of speech: assert only what the evidence grants. Separation of duties: **confidence** (`seen` / `inferred` / `unknown`) never substitutes for **capability** (`present` / `unsupported` / `failed` / `unknown`).

## Volatility and custody

Order of volatility, in this product: process memory and live traffic are more fragile than the on-disk copy. Default tools see the copy. Do not upgrade on-disk layout into “in use” or “in transit” claims.

Chain of custody analogue: copy into `%TEMP%\reveng-debug\<session>\`, record `session_id`, keep hashes/commands on evidence items. Analyzing a mutated original breaks integrity of every later `seen`.

Data **at rest** (the file) can be inventoried. Data **in transit** and **in use** need sensors this CLI does not run by default → `unknown`.

## Workflow

1. **Freeze the sentence.** Whatever you were about to state as fact, write it as a candidate claim. Do not emit it yet.
2. **Name the sensor.** Which command or JSON field could have observed it? If none ran, emit `unknown` and stop (or run the cheapest honest probe: `doctor` → `identify` → `inventory` → `slice`).
3. **Grade.**
   - `seen` — the sensor output contains the fact; cite location.
   - `inferred` — a reading of `seen` material; say the leap.
   - `unknown` — uncovered, failed, or too weak. Not absent.
4. **CIA check.** Confidentiality: not promoting a guess. Integrity: cite intact. Availability: missing sensor ≠ missing feature.
5. **Emit and stop.** Do not “verify” by attacking, executing, or dumping exam lore.

Cap recon. Two to four tool calls, then answer with labels. Do not re-prove what you already cited.

## Output contract

Every claim in the answer:

```
[seen] statement — tool, command, path or offset or symbol
[inferred] statement — because <seen material>; leap: <what was not observed>
[unknown] statement — sensor missing, failed, or out of coverage
```

Capability lines stay separate: `present` | `unsupported` | `failed` | `unknown`.

Do not write “there is no X” unless a sensor that *would have had to record X* ran and returned an empty, trusted result — and even then prefer “not seen in this inventory” over “absent”.

## Siblings

- `reveng-debug` — CLI that emits these labels
- `authorized-scope-ethics` — permission before looking
- `rce-process` — observe / hypothesize / verify *after* labels are honest
- `memory-evidence-labels` — grading memory-shaped claims
- `crypto-inventory-static` — crypto names as inventory, not proof of use
