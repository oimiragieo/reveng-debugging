"""ELF and Mach-O inventory: LIEF preferred; honest UNKNOWN/FAILED if missing."""

from __future__ import annotations

import importlib
import warnings
from collections.abc import Callable
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

ELF_COVERAGE = "elf-headers,sections,imported-libraries,exported-symbols,dynamic-symbols,strings"
MACHO_COVERAGE = (
    "macho-headers,sections,imported-libraries,exported-symbols,dynamic-symbols,strings"
)
SYMBOL_CAP = 200
STATIC_LIMIT = "static parse only; target was not executed"
ELF_MAGIC = b"\x7fELF"


def inventory_elf(path: Path, ledger: Ledger) -> InventoryResult:
    return _inventory(
        path,
        ledger,
        kind=TargetKind.ELF,
        parser=_from_lief_elf,
        coverage=ELF_COVERAGE,
    )


def inventory_macho(path: Path, ledger: Ledger) -> InventoryResult:
    return _inventory(
        path,
        ledger,
        kind=TargetKind.MACHO,
        parser=_from_lief_macho,
        coverage=MACHO_COVERAGE,
    )


def _inventory(
    path: Path,
    ledger: Ledger,
    *,
    kind: TargetKind,
    parser: Callable[[Any, Path], dict[str, Any]],
    coverage: str,
) -> InventoryResult:
    try:
        lief = importlib.import_module("lief")
    except Exception:
        return _unavailable(path, ledger, kind)
    try:
        findings = parser(lief, path)
    except Exception as exc:
        return _parse_failed(path, ledger, kind, exc)
    evidence: list[EvidenceItem] = []
    machine = findings.get("machine")
    if machine is not None:
        evidence.append(
            ledger.record(
                confidence=ClaimConfidence.SEEN,
                kind=f"{kind.value}.machine",
                statement=f"{kind.value.upper()} machine={machine}",
                tool="lief",
                command=f"lief parse {path.name}",
                location=Location(path=str(path), offset=0),
            )
        )
    fmt = findings.get("format")
    if fmt is not None:
        evidence.append(
            ledger.record(
                confidence=ClaimConfidence.SEEN,
                kind=f"{kind.value}.format",
                statement=f"format={fmt}",
                tool="lief",
                command=f"lief parse {path.name}",
            )
        )
    limitations = [STATIC_LIMIT]
    if findings.get("fat"):
        limitations.append("fat binary: inventory used first slice")
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=kind,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.PRESENT,
        engine="lief",
        coverage=coverage,
        findings=findings,
        evidence=evidence,
        limitations=limitations,
    )


def _unavailable(path: Path, ledger: Ledger, kind: TargetKind) -> InventoryResult:
    evidence = [
        ledger.record(
            confidence=ClaimConfidence.UNKNOWN,
            kind=f"{kind.value}.engine",
            statement="lief extra not importable; inventory not run",
            tool="none",
            limitations=["optional extra not importable in this environment", STATIC_LIMIT],
        )
    ]
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=kind,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.UNKNOWN,
        engine="none",
        coverage="none; lief not importable",
        findings={"error": "lief extra not importable"},
        evidence=evidence,
        limitations=["lief extra not importable", STATIC_LIMIT],
    )


def _parse_failed(
    path: Path,
    ledger: Ledger,
    kind: TargetKind,
    exc: Exception,
) -> InventoryResult:
    evidence = [
        ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind=f"{kind.value}.parse",
            statement=f"lief parse failed: {exc}",
            tool="lief",
            command=f"lief parse {path.name}",
            limitations=[STATIC_LIMIT],
        )
    ]
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=kind,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.FAILED,
        engine="lief",
        coverage="none",
        findings={"error": str(exc)},
        evidence=evidence,
        limitations=[f"lief parse failed: {exc}", STATIC_LIMIT],
    )


def _from_lief_elf(lief: Any, path: Path) -> dict[str, Any]:
    binary = lief.ELF.parse(str(path))
    if binary is None:
        raise ValueError("lief returned None")
    _require_elf_identity(binary)
    header = getattr(binary, "header", None)
    machine_raw = getattr(header, "machine_type", None) if header is not None else None
    machine = str(machine_raw) if machine_raw is not None else None
    return {
        "format": "elf",
        "machine": machine,
        "arch": machine,
        "sections": _sections(binary),
        "imported_libraries": _library_names(binary),
        "exported_symbols": _symbol_names(getattr(binary, "exported_symbols", None)),
        "dynamic_symbols": _symbol_names(getattr(binary, "dynamic_symbols", None)),
        "strings": _strings(path.read_bytes()),
    }


def _from_lief_macho(lief: Any, path: Path) -> dict[str, Any]:
    if path.stat().st_size < 32:
        raise ValueError("Mach-O file shorter than mach_header_64")
    parsed = lief.MachO.parse(str(path))
    if parsed is None:
        raise ValueError("lief returned None")
    binaries = _macho_binaries(parsed)
    if not binaries:
        raise ValueError("lief returned no Mach-O slices")
    primary = binaries[0]
    _require_macho_header(primary)
    header = getattr(primary, "header", None)
    machine_raw = getattr(header, "cpu_type", None) if header is not None else None
    machine = str(machine_raw) if machine_raw is not None else None
    slices: list[str] = []
    for binary in binaries:
        slice_header = getattr(binary, "header", None)
        cpu = getattr(slice_header, "cpu_type", None) if slice_header is not None else None
        slices.append(str(cpu) if cpu is not None else "unknown")
    dynamic = getattr(primary, "dynamic_symbols", None)
    if dynamic is None:
        dynamic = getattr(primary, "symbols", None)
    return {
        "format": "macho",
        "machine": machine,
        "arch": machine,
        "fat": len(binaries) > 1,
        "slices": slices,
        "sections": _sections(primary),
        "imported_libraries": _library_names(primary),
        "exported_symbols": _symbol_names(getattr(primary, "exported_symbols", None)),
        "dynamic_symbols": _symbol_names(dynamic),
        "strings": _strings(path.read_bytes()),
    }


def _require_elf_identity(binary: Any) -> None:
    header = getattr(binary, "header", None)
    if header is None:
        raise ValueError("lief returned ELF without header")
    identity = getattr(header, "identity", None)
    try:
        raw = bytes(identity)[:4] if identity is not None else b""
    except (TypeError, ValueError):
        raw = b""
    if raw != ELF_MAGIC:
        raise ValueError("lief could not parse ELF identity")


def _require_macho_header(binary: Any) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        header = getattr(binary, "header", None)
        if header is None:
            raise ValueError("lief returned Mach-O without header")
        magic = getattr(header, "magic", None)
        try:
            magic_int = int(magic) if magic is not None else 0
        except (TypeError, ValueError):
            magic_int = 0
    if magic_int == 0:
        raise ValueError("lief could not parse Mach-O magic")


def _macho_binaries(parsed: Any) -> list[Any]:
    if getattr(parsed, "header", None) is not None:
        return [parsed]
    if hasattr(parsed, "at") and hasattr(parsed, "size"):
        return [parsed.at(index) for index in range(int(parsed.size))]
    try:
        return list(parsed)
    except TypeError as exc:
        raise ValueError("lief Mach-O parse was not iterable") from exc


def _sections(binary: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for section in getattr(binary, "sections", None) or []:
        name = getattr(section, "name", "")
        size = getattr(section, "size", 0)
        out.append({"name": str(name), "size": int(size)})
    return out


def _library_names(binary: Any) -> list[str]:
    names = _as_names(getattr(binary, "libraries", None))
    if names:
        return names
    return _as_names(getattr(binary, "imported_libraries", None))


def _symbol_names(symbols: Any) -> list[str]:
    return _as_names(symbols)


def _as_names(items: Any) -> list[str]:
    names: list[str] = []
    if items is None:
        return names
    for item in items:
        if len(names) >= SYMBOL_CAP:
            break
        if isinstance(item, str):
            if item:
                names.append(item)
            continue
        name = getattr(item, "name", None)
        if name:
            names.append(str(name))
    return names


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
