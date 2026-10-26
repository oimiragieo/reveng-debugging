---
name: pma-dynamic-evidence
description: Use when the operator already has sandbox/procmon logs and you must label runtime claims honestly. DO NOT USE to launch malware or attach a debugger to untrusted binaries.
---

# pma-dynamic-evidence

Methodology ideas (not labs) from Practical Malware Analysis basic-dynamic chapters: sandbox reports, process-monitor rows, process trees, registry diffs, and packet/DNS logs. This product never executes the target. `dynamic_attach` is **unsupported**. If the operator already captured a run elsewhere, you only **read those files** and map them into the evidence ledger language.

## Hard rules

| Do | Never |
|---|---|
| Static inventory first (`reveng-debug identify` / `inventory`) | Run, debug, dump, or “just launch in a VM” |
| Treat operator logs as `historical-reference` | Call a log row `controlled-replay` or claim this CLI observed execution |
| Mark every runtime sentence `seen` / `inferred` / `unknown` | Treat a quiet sandbox as “no behavior” |
| Cite log path + row/field for `seen` | Invent Procmon/Wireshark/INetSim output |
| Cross-check log names against IAT/strings from inventory | Teach unpacking, attach, or fake-network setup |
| Keep capability `unsupported` distinct from claim `unknown` | Collapse “we cannot attach” into “the sample does nothing” |

Do not paste courseware. Do not reproduce lab steps. Do not start Procmon, Regshot, INetSim, ApateDNS, OllyDbg, or WinDbg.

## What counts as which confidence

A **seen** claim is a concrete record you can point at. Two different seens:

- **Shipped artifact (this session):** inventory JSON — imports, sections, strings. Authority `shipped-artifact`. This is not runtime.
- **Operator log (already captured):** one event row or report field (operation, path, result, PID, DNS name, TCP tuple). Authority `historical-reference`. You saw the **log**, not a live process in `reveng-debug`.

**Inferred** (`analyst-inference`): you combined two sources or named a motive the log does not state. Examples: IAT has `URLDownloadToFileW` **and** a Procmon `WriteFile` to a new `.exe` → “likely dropper” is inferred; a Run-key `SetValue` → “persistence” is inferred.

**Unknown:** the log does not cover that question. Empty sandbox, over-filtered Procmon, no PID-to-flow map on a pcap, delayed/trigger-gated samples, anti-VM silence, or a fake-network appliance answering HTTP. Missing is not absent.

**Capability (not a claim):** `reveng-debug doctor` shows `dynamic_attach` = `unsupported`. Record that as support-matrix status. Do not emit a `seen` execution item from this tool.

## Artifact → ledger map

Phrase each finding as an `EvidenceItem`: `confidence`, `authority`, `kind`, `statement`, `tool`, `command`, `limitations`, `location`, `session_id`. Adapters write `ledger.jsonl`; you usually **report** matching rows. Do not invent an `evidence-add` CLI.

| Operator file (already exists) | `kind` | `seen` | `inferred` | `unknown` | `authority` |
|---|---|---|---|---|---|
| Procmon CSV/XML/TXT | `runtime.file` `runtime.reg` `runtime.process` | PID + image + operation + path + result on a cited line | “installer/persistence” from the path class | Filtered-out PID; `NAME NOT FOUND` ≠ never retried; duration shorter than the delay | `historical-reference` |
| Sandbox HTML/JSON | `runtime.net` `runtime.file` | Named indicator with timestamp in the report | Family/role labels the report guessed | “No network” while the box was isolated, or the sample waited for a click | `historical-reference` |
| pcap / DNS log | `runtime.dns` `runtime.tcp` | Query, SNI, or HTTP host in the capture | “C2” without protocol proof | Which process, if the capture has no PID map | `historical-reference` |
| Fake-DNS / INetSim-style log | `runtime.net` | The sample issued that request | What a real responder would return | Production C2 content; TLS to a sinkhole | `historical-reference` + limitation **simulator** |
| Regshot-style diff | `runtime.reg` | Key/value present in snap B not A | The target binary wrote it | Which process; host noise in the window | `historical-reference` |
| Process-tree export | `runtime.process` | Child PID and image name | Injection because a child looks unrelated | Modules not listed; signature “verify” failures | `historical-reference` |
| No log / screenshot only | — | Nothing runtime | — | All runtime behavior | leave `unknown`; screenshot: extra limitation `truncated` |

Always add `limitations`: `not-generated-by-reveng-debug`, `dynamic_attach unsupported`, plus filter/VM/simulator notes that apply.

## Workflow

1. **Refuse execution.** If the operator asks you to run the sample or attach a debugger, stop. Point at this skill and `dynamic_attach: unsupported`. Ask for an existing log path instead.
2. **Static first.** Copy-safe inventory only:

```powershell
reveng-debug doctor
reveng-debug identify .\target
reveng-debug inventory .\target
```

Read `imports`, `sections`, `strings`. Those claims are `seen` + `shipped-artifact`. They do not prove a call happened.

3. **Confirm the log is a file, not a plan.** Need a path to CSV/JSON/HTML/pcap/txt the operator already produced. If they only describe “I ran it and it connected,” that description is `unknown` until a file exists.
4. **Read the log as text.** Do not launch the sample, the sandbox UI, or a debugger to “refresh” the capture. Quote the row you use.
5. **Align names.** For each runtime `seen`, search inventory for the API, DLL, URL, mutex, or path string (`reveng-debug slice` on the session copy). Match = still two items (static `seen` + log `seen`). Role words (“downloader”, “keylogger”) stay `inferred`.
6. **Mismatches stay honest.**
   - Log shows `CreateRemoteThread` but IAT lacks it → `inferred` dynamic resolve / packing; do not unpack.
   - IAT shows network APIs but sandbox is quiet → `unknown` (isolation, delay, anti-VM), not “benign”.
   - Fake-network 200 OK → `seen` request, `unknown` real C2 body.
7. **Emit the table.** Include static and historical rows. Pull session static items with `reveng-debug` MCP `evidence_get` / `session_show` when a session exists. Do not merge operator logs into `ledger.jsonl` unless a shipped adapter wrote them (none do today).

## Output contract

One table, then a short gap list.

```
| confidence | authority | kind | statement | tool | limitations | location |
| seen | shipped-artifact | pe.imports | IAT lists wininet!InternetOpenA | lief | static parse only; target was not executed | work\sample.exe |
| seen | historical-reference | runtime.dns | Procmon/pcap row: DNS query example.test | operator-pcap | not-generated-by-reveng-debug; no PID map | logs\capture.pcap:frame 18 |
| inferred | analyst-inference | runtime.role | DNS + IAT wininet → likely HTTP client | — | role not stated by either source | — |
| unknown | historical-reference | runtime.file | whether files survived reboot | operator-procmon | capture shorter than reboot | — |
```

End with: runtime claims this session **cannot** make (`dynamic_attach` unsupported) versus claims the **log omitted**. Those are different unknowns.

## Siblings

- `reveng-debug` — doctor/identify/inventory/slice; required before labeling runtime
- `pma-static-triage` — operator has no sandbox log; stay on shipped artifacts
- `docs/support/honesty-rules.md` — `seen` / `inferred` / `unknown` and capability statuses
