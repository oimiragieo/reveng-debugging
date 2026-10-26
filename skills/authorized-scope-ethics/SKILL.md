---
name: authorized-scope-ethics
description: Use before any reverse-engineering or malware-analysis work to confirm authorization and evidence rules. DO NOT USE as a pentest or hacking playbook.
---

# authorized-scope-ethics

Gate, not a lab. Confirm **who owns the artifact**, **what is in writing**, and **how claims will be labeled** before `identify` / `inventory`. If any of those three is missing, stop.

Source idea: local gitignored PDF `references/courseware/ceh-ebooks/CEHv9_Module_01_Introduction_to_Ethical_Hacking.pdf`. That module mixes consent, written limits, and confidentiality with attack-simulation chapters. Keep the consent fence. Drop every attack method, phase, tool list, and “think like an intruder” procedure. Original wording only — do not quote or reconstruct the PDF. CEH attack modules have no skills.

This product is authorized software archaeology. It is not a penetration test. Written permission here licenses **static inspection of a named, operator-owned or operator-authorized copy**. It does not license scanning, access-gaining, privilege play, payload work, or live attach.

## Hard rules

| Do | Never |
|---|---|
| Restrict work to software the operator owns, or a target they can show **written** permission to inspect | Inspect third-party products, stolen samples, pirate courseware binaries, or “the neighbor’s box” |
| Require a named path, named question, and named authority **before** the first tool | Infer permission from curiosity, good intent, a job title, or a courseware slide |
| Stay inside the written fence: artifact, question, time window, static-only | Widen to adjacent files, other hosts, credentials, paywalled pages, or “just this one extra binary” |
| Copy-then-read: `reveng-debug inventory PATH` writes under `%TEMP%\reveng-debug\<session>\` | Mutate the original; execute or attach; unpack as a weapon |
| Label every claim **seen**, **inferred**, or **unknown** | Treat a missing field as absent; treat imports as observed calls; invent dumpbin/Ghidra output |
| Keep session copies, slices, and findings with the operator | Paste book text, leak inventory, or ship reconstructed proprietary trees |
| Refuse exploit, bypass, crash, malware-run, and pentest asks | Follow Module 01 (or later CEH modules) as a how-to-hack script |

Consent is the whole distinction. Skill without permission is still unauthorized access. Good intent does not fill a missing signature.

## What “written permission” means here

Operator-owned is enough when the path is theirs (their build, their installed app, their site). Otherwise the operator must point at a document that names:

1. **Artifact** — file, tree, URL, or session copy; not “the company network.”
2. **Question** — the feature or defect under study; not “see what we can break.”
3. **Allow / forbid** — static inventory and slice are the default allow. Native run, attach, unpack, credential use, and backend theft are forbid unless a future product flag exists **and** the writing says yes.
4. **Window** — if the writing has start/stop times, honor them. If it does not, ask; do not assume forever.
5. **Confidentiality** — findings stay with the operator. Do not disclose customer data, health data, or trade-secret strings found in the copy.

Verbal “go ahead” is **unknown**, not a yes. If the writing is not in the session, record authority as **unknown** and stop.

## Mapping

| Module 01 idea (ethics only) | What it means on this host |
|---|---|
| Work only with the owner’s consent | `Authority: owned` (operator’s software) or `authorized` (writing names this path). Else `refused` |
| Do not start until express permission exists | No `identify` / `inventory` / `ghidra` / `app-re` / `clone-website` until the gate passes |
| Stay inside agreed limits | Named PATH + named question. Adjacent disks, other URLs, and “related malware” are out of scope |
| Confidentiality / NDA | Do not dump the session tree into chat; `slice` a needle. Do not commit courseware PDFs or customer artifacts |
| Confidentiality, integrity, availability as *defensive* duties | Do not leak the copy; do not mutate the original; do not take the target down. This host does not execute, so availability harm is not a method — it is a reason to stay static |
| Tester ≠ attacker (intent + permission, not toolkit) | Same CLI used without a yes is still refuse. Do not “simulate an attack” to prove a point |
| Rules of engagement as a **fence**, not a menu | The fence is static-first on the session copy. It is not a list of techniques to try |

`reveng-debug doctor` probes *this machine’s* tools. It is not permission to touch a target.

| Tool | Allowed after the gate | Still forbidden |
|---|---|---|
| `doctor` | Always (host health only) | Using its output as authority over a binary |
| `identify PATH` | Named authorized path | Guessing a system file “to practice” |
| `inventory PATH` | Session copy; coverage notes are **seen** | Treating omitted PE fields as “not there” |
| `slice PATH NEEDLE` | Needles for the named question | Whole-file dumps; crash recipes |
| `clone-website` | Operator-authorized URL or local HTML; visible structure | Auth cookies, paywalls, backend APIs, running page JS on the static path |
| `ghidra` / `app-re` | Operator opt-in, session copy only | Default decompile; `generate-exploit`; missing engine faked as present |
| native run / `dynamic_attach` | — | **unsupported**. Do not collect runtime by launching the target |

Missing optional engines → **unsupported** or **unknown**. Run `doctor`. Do not print “absent.” Static reading is not observed execution.

## Workflow

1. **Name the target.** Path or URL, plus the one question. If the operator did not name both, ask once, then stop.
2. **Name the authority.** `owned` (they built or licensed it and can inspect it) or `authorized` (writing covers this artifact). Screenshots of a lab VM you do not own, random malware from the internet, and other people’s websites are `refused`.
3. **Read the fence.** Confirm static-only, session-copy-only, question-only. If they ask for a pentest, exploit, bypass, unpack-to-run, or live attach, refuse in one short sentence. Do not offer a substitute attack.
4. **Honesty contract.** Before tools: every later claim is **seen** (copied from inventory/slice/Ghidra JSON you actually received), **inferred** (a story about unseen behavior), or **unknown** (not in the evidence). Missing evidence stays **unknown**.
5. **Hand off.** Only after 1–4 pass: `reveng-debug doctor` if the host is unproven, then `identify` and `inventory` on the named path. Further method lives in `reveng-debug` and siblings. This skill does not continue into analysis.

Website extra: live DOM capture is still authorized-scope. New tab, that URL, visible structure. Do not reuse the operator’s logged-in tabs to steal a session.

Malware-suspect extra: only a sample the operator already holds and may inspect. Static labels only. Do not fetch, run, or weaponize.

## Output contract

```
Target: <path or URL>
Question: <one sentence>
Authority: owned | authorized | unknown | refused
Writing: <what names the artifact, allow/forbid, window> | none
Fence: static-session-copy | violated
Evidence rule: seen | inferred | unknown (missing ≠ absent)
Next: identify+inventory | stop
```

If `Authority` is `unknown` or `refused`, or `Fence` is `violated`, `Next` is `stop`. Do not run target tools.

## Siblings

- `reveng-debug` — command router after this gate
- `rce-process` — observe / hypothesize / verify on an already-authorized copy
- `cookbook-static-first` — cheapest static probes
- `ceh-malware-static` — static labels on an authorized suspect sample
- `secplus-observe-vs-assume` — claims still need evidence
- `docs/support/honesty-rules.md` — seen / inferred / unknown; do not vendor exploits or courseware PDFs
