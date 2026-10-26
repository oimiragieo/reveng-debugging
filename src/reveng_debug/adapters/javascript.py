"""JavaScript inventory: package.json, source maps, IPC-ish surface, bounded slices."""

from __future__ import annotations

import json
import re
from pathlib import Path

from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    InventoryResult,
    Location,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger

SOURCEMAP = re.compile(r"sourceMappingURL=(\S+)")
IPC = re.compile(
    r"ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|contextBridge\.exposeInMainWorld"
)


def inventory_javascript(path: Path, ledger: Ledger) -> InventoryResult:
    root = path if path.is_dir() else path.parent
    files = _js_files(path)
    package = None
    pkg_path = root / "package.json" if path.is_dir() else path.parent / "package.json"
    if pkg_path.exists():
        package = json.loads(pkg_path.read_text(encoding="utf-8"))
        ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="js.package",
            statement=f"package.json name={package.get('name')} main={package.get('main')}",
            tool="json",
            command=f"read {pkg_path.name}",
            location=Location(path=str(pkg_path)),
        )
    maps: list[str] = []
    ipc_hits: list[str] = []
    for file in files[:80]:
        text = file.read_text(encoding="utf-8", errors="replace")
        for match in SOURCEMAP.finditer(text):
            maps.append(f"{file.name}:{match.group(1)}")
        if IPC.search(text):
            ipc_hits.append(str(file))
    if maps:
        ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="js.sourcemap",
            statement=f"sourceMappingURL hits={len(maps)}",
            tool="slice",
            metadata={"maps": maps[:20]},
        )
    else:
        ledger.record(
            confidence=ClaimConfidence.UNKNOWN,
            kind="js.sourcemap",
            statement="no sourceMappingURL seen in sampled files",
            tool="slice",
            limitations=["sampled first 80 JS files only"],
        )
    if ipc_hits:
        ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="js.ipc_surface",
            statement=f"IPC/contextBridge surface in {len(ipc_hits)} files",
            tool="slice",
            metadata={"files": ipc_hits[:20]},
        )
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=TargetKind.JAVASCRIPT,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.PRESENT,
        engine="javascript-static",
        coverage="package.json,sourceMappingURL,ipc-regex,file-list",
        findings={
            "package": package,
            "files": [str(f) for f in files[:80]],
            "sourcemaps": maps[:20],
            "ipc_hits": ipc_hits[:20],
        },
        evidence=ledger.all(),
        limitations=["static read only; hidden bundler dirs are included"],
    )


def slice_text(path: Path, needle: str, window: int = 200, limit: int = 20) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    hits: list[str] = []
    start = 0
    while len(hits) < limit:
        idx = text.find(needle, start)
        if idx < 0:
            break
        lo = max(0, idx - window)
        hi = min(len(text), idx + len(needle) + window)
        hits.append(text[lo:hi].replace("\n", " "))
        start = idx + len(needle)
    return hits


def _js_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files: list[Path] = []
    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        if "node_modules" in candidate.parts:
            continue
        if candidate.suffix.lower() in {".js", ".mjs", ".cjs", ".ts", ".json"}:
            files.append(candidate)
    return files
