# Third-party material

| Work | License | How we use it | What we do not copy |
|---|---|---|---|
| [morluto/rea](https://github.com/morluto/rea) (`rea-agents`) | MIT | Evidence vocabulary, investigation flow, adapter ideas | 207 MCP tools, TypeScript tree, CTF `solve.py`, native `.node` |
| [aicodeking/leanrea](https://github.com/aicodeking/leanrea) | MIT | `third_party/leanrea/SKILL.md` plus Windows-first skill | Benchmark targets / Electron app copies |
| [oimiragieo/reveng-main](https://github.com/oimiragieo/reveng-main) | MIT | Result-contract / honesty patterns | `exploits/`, malware samples, reconstructed source, GA dumps |

Optional BYO engines (Ghidra, dumpbin, llvm-objdump, `@electron/asar`, `rea`, `reveng`) remain the user's install. This package never vendors them.

Courseware under `F:\Course Ware\` is **not** redistributed. Local gitignored copies for agents live in `references/courseware/` (see that README). Methodology only: static vs dynamic split, PE/IAT inventory, provenance, default non-execution. Never commit PDFs.
