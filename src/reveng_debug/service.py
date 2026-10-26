"""Shared operations for CLI and MCP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reveng_debug.adapters.electron import inventory_electron
from reveng_debug.adapters.ghidra import run_ghidra_headless
from reveng_debug.adapters.javascript import inventory_javascript, slice_text
from reveng_debug.adapters.native import inventory_elf, inventory_macho
from reveng_debug.adapters.pe import inventory_pe
from reveng_debug.adapters.website import clone_website as clone_capture
from reveng_debug.adapters.website import fetch_url
from reveng_debug.contracts.models import (
    CapabilityStatus,
    InventoryResult,
    SupportMatrix,
    TargetKind,
)
from reveng_debug.extras.reveng_app import run_reveng_app_re
from reveng_debug.ledger.service import Ledger
from reveng_debug.router.doctor import probe_tools
from reveng_debug.router.identify import identify_target
from reveng_debug.storage.workspace import SessionStore

OMEGA_VISION_ATTACH = "http://127.0.0.1:8092/attach"
OMEGA_VISION_ATTACH_DEFAULT_PORT = "http://127.0.0.1:8090/attach"


def doctor() -> dict[str, Any]:
    matrix = SupportMatrix()
    return {
        "schema_version": matrix.schema_version,
        "support_matrix": matrix.model_dump(),
        "tools": [p.model_dump() for p in probe_tools()],
        "omega_vision_attach": OMEGA_VISION_ATTACH,
        "omega_vision_attach_readme_default": OMEGA_VISION_ATTACH_DEFAULT_PORT,
    }


def open_session(session_id: str | None, source: Path) -> tuple[SessionStore, Path]:
    store = SessionStore(session_id=session_id)
    admitted = store.admit(source)
    return store, admitted


def identify(path: Path) -> dict[str, Any]:
    kind = identify_target(path)
    return {"path": str(path), "kind": kind.value}


def inventory(path: Path, session_id: str | None = None) -> InventoryResult:
    store, admitted = open_session(session_id, path)
    ledger = Ledger(store)
    kind = identify_target(admitted)
    if kind is TargetKind.PE:
        result = inventory_pe(admitted, ledger)
    elif kind is TargetKind.JAVASCRIPT:
        result = inventory_javascript(admitted, ledger)
    elif kind is TargetKind.ELECTRON:
        result = inventory_electron(admitted, ledger)
    elif kind is TargetKind.WEBSITE:
        result = clone_capture(admitted, ledger)
    elif kind is TargetKind.ELF:
        result = inventory_elf(admitted, ledger)
    elif kind is TargetKind.MACHO:
        result = inventory_macho(admitted, ledger)
    else:
        result = InventoryResult(
            session_id=store.session_id,
            target_kind=TargetKind.UNKNOWN,
            original_path=str(path),
            workspace_path=str(admitted),
            status=CapabilityStatus.UNKNOWN,
            engine="none",
            coverage="none",
            findings={},
            limitations=["kind unknown; no adapter ran"],
        )
    result.original_path = str(path.resolve())
    if result.target_kind is not TargetKind.WEBSITE:
        result.workspace_path = str(admitted)
    return result


def ghidra_headless(path: Path, session_id: str | None = None) -> InventoryResult:
    """Opt-in BYO Ghidra headless on a session copy. Does not execute the target."""
    store, admitted = open_session(session_id, path)
    ledger = Ledger(store)
    result = run_ghidra_headless(
        admitted,
        ledger,
        project_dir=store.artifacts / "ghidra_project",
    )
    result.original_path = str(path.resolve())
    if not result.workspace_path:
        result.workspace_path = str(admitted)
    return result


def app_re(path: Path, session_id: str | None = None) -> InventoryResult:
    """Opt-in BYO reverse-engineer-app on a session copy. Does not execute the target."""
    store, admitted = open_session(session_id, path)
    ledger = Ledger(store)
    result = run_reveng_app_re(admitted, ledger)
    result.original_path = str(path.resolve())
    if not result.workspace_path:
        result.workspace_path = str(admitted)
    return result


def slice_file(path: Path, needle: str, session_id: str | None = None) -> dict[str, Any]:
    store, admitted = open_session(session_id, path)
    target = admitted if admitted.is_file() else _first_file(admitted, path.name)
    if not target.is_file():
        return {
            "session_id": store.session_id,
            "path": str(admitted),
            "needle": needle,
            "hits": [],
            "confidence": "unknown",
            "limitations": [f"slice needs a file, got directory {admitted}"],
        }
    hits = slice_text(target, needle)
    return {
        "session_id": store.session_id,
        "path": str(admitted),
        "needle": needle,
        "hits": hits,
        "confidence": "seen" if hits else "unknown",
    }


def session_show(session_id: str) -> dict[str, Any]:
    store = SessionStore(session_id=session_id, create=False)
    data = store.show()
    data["evidence"] = [item.model_dump() for item in store.read_evidence()]
    data["corrupt_ledger_lines"] = store.skipped_ledger_lines
    return data


def clone_website(target: str, session_id: str | None = None) -> InventoryResult:
    """Clone a local HTML/capture JSON file or a static http(s) snapshot."""
    if target.startswith(("http://", "https://")):
        store = SessionStore(session_id=session_id)
        capture = fetch_url(target)
        return clone_capture(capture, Ledger(store))
    path = Path(target)
    store, admitted = open_session(session_id, path)
    return clone_capture(admitted, Ledger(store))


def evidence_get(session_id: str) -> list[dict[str, Any]]:
    store = SessionStore(session_id=session_id, create=False)
    return [item.model_dump() for item in store.read_evidence()]


def _first_file(admitted: Path, name: str) -> Path:
    candidate = admitted / name
    if candidate.exists():
        return candidate
    return admitted
