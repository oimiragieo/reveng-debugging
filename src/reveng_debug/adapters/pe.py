"""PE inventory: LIEF preferred, pefile fallback with declared coverage."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    EvidenceItem,
    InventoryResult,
    Location,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger

IMAGE_DLL_CHARACTERISTICS = {
    "ASLR": 0x0040,
    "NX_COMPAT": 0x0100,
    "GUARD_CF": 0x4000,
    "HIGH_ENTROPY_VA": 0x0020,
}


def inventory_pe(path: Path, ledger: Ledger) -> InventoryResult:
    try:
        lief = importlib.import_module("lief")
        findings = _from_lief(lief, path)
        engine = "lief"
        coverage = "pe-headers,imports,exports,sections,dll-characteristics,strings"
    except Exception:
        findings = _from_pefile(path)
        engine = "pefile"
        coverage = (
            "pe-headers,imports,exports,sections,dll-characteristics,strings; no authenticode"
        )

    evidence: list[EvidenceItem] = []
    machine = findings.get("machine")
    if machine is not None:
        evidence.append(
            ledger.record(
                confidence=ClaimConfidence.SEEN,
                kind="pe.machine",
                statement=f"PE machine={machine}",
                tool=engine,
                command=f"{engine} parse {path.name}",
                location=Location(path=str(path), offset=0),
            )
        )
    flags = findings.get("security_flags") or {}
    evidence.append(
        ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="pe.security_flags",
            statement=f"dll characteristics {flags}",
            tool=engine,
            command=f"{engine} optional_header.dll_characteristics",
        )
    )
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=TargetKind.PE,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.PRESENT,
        engine=engine,
        coverage=coverage,
        findings=findings,
        evidence=evidence,
        limitations=["static parse only; target was not executed"],
    )


def _from_lief(lief: Any, path: Path) -> dict[str, Any]:
    binary = lief.PE.parse(str(path))
    if binary is None:
        raise ValueError("lief returned None")
    imports: list[dict[str, Any]] = []
    for entry in getattr(binary, "imports", []) or []:
        names = [imp.name for imp in entry.entries if getattr(imp, "name", None)]
        imports.append({"dll": entry.name, "names": names[:200]})
    exports = []
    export_obj = getattr(binary, "get_export", lambda: None)()
    if export_obj is not None:
        exports = [e.name for e in export_obj.entries if getattr(e, "name", None)][:200]
    sections = [
        {
            "name": s.name,
            "virtual_size": int(s.virtual_size),
            "sizeof_raw_data": int(s.size),
        }
        for s in binary.sections
    ]
    chars = int(binary.optional_header.dll_characteristics)
    return {
        "machine": str(binary.header.machine),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "security_flags": _flags(chars),
        "strings": _strings(path.read_bytes()),
    }


def _from_pefile(path: Path) -> dict[str, Any]:
    pefile = importlib.import_module("pefile")
    pe = pefile.PE(str(path), fast_load=False)
    imports: list[dict[str, Any]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = _ascii(entry.dll)
        names: list[str] = []
        for imp in entry.imports:
            if imp.name:
                names.append(_ascii(imp.name))
        imports.append({"dll": dll, "names": names[:200]})
    exports: list[str] = []
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is not None:
        for exp in directory.symbols:
            if exp.name:
                exports.append(_ascii(exp.name))
    sections = [
        {
            "name": s.Name.decode("ascii", "replace").strip("\x00"),
            "virtual_size": s.Misc_VirtualSize,
            "sizeof_raw_data": s.SizeOfRawData,
        }
        for s in pe.sections
    ]
    chars = int(pe.OPTIONAL_HEADER.DllCharacteristics)
    machine = hex(int(pe.FILE_HEADER.Machine))
    pe.close()
    return {
        "machine": machine,
        "sections": sections,
        "imports": imports,
        "exports": exports[:200],
        "security_flags": _flags(chars),
        "strings": _strings(path.read_bytes()),
    }


def _ascii(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii", "replace")
    return str(value)


def _flags(chars: int) -> dict[str, bool]:
    return {name: bool(chars & bit) for name, bit in IMAGE_DLL_CHARACTERISTICS.items()}


def _strings(blob: bytes, min_len: int = 4, limit: int = 200) -> list[str]:
    out: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= min_len:
            out.append(current.decode("ascii"))
            if len(out) >= limit:
                return out
        current.clear()
    if len(current) >= min_len and len(out) < limit:
        out.append(current.decode("ascii"))
    return out
