"""Shared operations for CLI and MCP."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reveng_debug.adapters.electron import inventory_electron
from reveng_debug.adapters.javascript import inventory_javascript, slice_text
from reveng_debug.adapters.pe import inventory_pe
from reveng_debug.contracts.models import (
    CapabilityStatus,
    InventoryResult,
    SupportMatrix,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger
from reveng_debug.router.doctor import probe_tools
from reveng_debug.router.identify import identify_target
from reveng_debug.storage.workspace import SessionStore

ELF_MACHO_LIMIT = "ELF/Mach-O inventory is Wave 2; identify reports kind only"


def doctor() -> dict[str, Any]:
    matrix = SupportMatrix()
    return {
        "schema_version": matrix.schema_version,
        "support_matrix": matrix.model_dump(),
        "tools": [p.model_dump() for p in probe_tools()],
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
    elif kind in {TargetKind.ELF, TargetKind.MACHO}:
        result = InventoryResult(
            session_id=store.session_id,
            target_kind=kind,
            original_path=str(path),
            workspace_path=str(admitted),
            status=CapabilityStatus.UNSUPPORTED,
            engine="none",
            coverage="identify-only",
            findings={},
            limitations=[ELF_MACHO_LIMIT],
        )
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
    result.workspace_path = str(admitted)
    return result


def slice_file(path: Path, needle: str, session_id: str | None = None) -> dict[str, Any]:
    store, admitted = open_session(session_id, path)
    hits = slice_text(admitted if admitted.is_file() else _first_file(admitted, path.name), needle)
    return {
        "session_id": store.session_id,
        "path": str(admitted),
        "needle": needle,
        "hits": hits,
        "confidence": "seen" if hits else "unknown",
    }


def session_show(session_id: str) -> dict[str, Any]:
    store = SessionStore(session_id=session_id)
    data = store.show()
    data["evidence"] = [item.model_dump() for item in store.read_evidence()]
    return data


def evidence_get(session_id: str) -> list[dict[str, Any]]:
    store = SessionStore(session_id=session_id)
    return [item.model_dump() for item in store.read_evidence()]


def _first_file(admitted: Path, name: str) -> Path:
    candidate = admitted / name
    if candidate.exists():
        return candidate
    return admitted
