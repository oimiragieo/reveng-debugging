"""Tool presence probes. Missing tools stay unknown/unsupported — never 'absent'."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

from reveng_debug.contracts.models import CapabilityStatus, ToolProbe

CANDIDATES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("dumpbin", ("dumpbin", "dumpbin.exe"), "optional PE dumper"),
    ("llvm-objdump", ("llvm-objdump", "llvm-objdump.exe"), "optional object dumper"),
    ("npx", ("npx", "npx.cmd"), "optional @electron/asar launcher"),
    ("rea", ("rea", "rea.cmd"), "optional BYO REA CLI"),
    ("reveng", ("reveng", "reveng.exe"), "optional BYO REVENG CLI"),
    ("ghidra", ("ghidraRun", "analyzeHeadless", "ghidra"), "Wave 2; presence only"),
)


def probe_tools() -> list[ToolProbe]:
    probes = [_probe_lief(), _probe_pefile(), _probe_reveng_module(), _probe_gotcontext()]
    for name, binaries, note in CANDIDATES:
        found = _which_any(binaries)
        if found:
            status = CapabilityStatus.UNSUPPORTED if name == "ghidra" else CapabilityStatus.PRESENT
            detail = f"{found}; {note}"
            if name == "ghidra":
                detail = f"{found}; Wave 2 — doctor reports PATH only, MVP does not invoke Ghidra"
            probes.append(ToolProbe(name=name, status=status, detail=detail))
        else:
            probes.append(
                ToolProbe(
                    name=name,
                    status=CapabilityStatus.UNKNOWN,
                    detail=f"not probed beyond PATH; {note}",
                )
            )
    return probes


def _probe_lief() -> ToolProbe:
    if importlib.util.find_spec("lief") is None:
        return ToolProbe(
            name="lief",
            status=CapabilityStatus.UNKNOWN,
            detail="optional extra not imported",
            coverage=None,
        )
    return ToolProbe(
        name="lief",
        status=CapabilityStatus.PRESENT,
        detail="importable",
        coverage="pe-headers,imports,exports,sections,dll-characteristics",
    )


def _probe_pefile() -> ToolProbe:
    if importlib.util.find_spec("pefile") is None:
        return ToolProbe(
            name="pefile",
            status=CapabilityStatus.UNKNOWN,
            detail="dependency missing from this environment",
            coverage=None,
        )
    return ToolProbe(
        name="pefile",
        status=CapabilityStatus.PRESENT,
        detail="importable fallback",
        coverage="pe-headers,imports,exports,sections,dll-characteristics; no authenticode",
    )


def _probe_reveng_module() -> ToolProbe:
    if importlib.util.find_spec("reveng") is None:
        return ToolProbe(
            name="reveng_module",
            status=CapabilityStatus.UNKNOWN,
            detail="optional extra; importlib did not find reveng",
        )
    return ToolProbe(
        name="reveng_module",
        status=CapabilityStatus.PRESENT,
        detail="importable; passthrough remains opt-in and copy-workspace only",
    )


def _probe_gotcontext() -> ToolProbe:
    return ToolProbe(
        name="gotcontext_chrome",
        status=CapabilityStatus.UNKNOWN,
        detail=(
            "live website clone backend; presence is the operator MCP session, "
            "not PATH. Follow skills/reveng-debug/SKILL.md capture sequence"
        ),
        coverage=(
            "tabs_context_mcp,tabs_create_mcp,navigate,get_page_text,"
            "extract_design_tokens,tab_page_assets,decompose_dom_components,"
            "javascript_tool,capture_visual_frame"
        ),
    )


def _which_any(names: tuple[str, ...]) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return str(Path(path))
    return None
