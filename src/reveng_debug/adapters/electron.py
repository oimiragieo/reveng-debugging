"""Electron/ASAR inventory via path-safe extract."""

from __future__ import annotations

from pathlib import Path

from reveng_debug.adapters.javascript import inventory_javascript
from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    InventoryResult,
    Location,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger
from reveng_debug.storage.asar import AsarError, extract_asar


def inventory_electron(path: Path, ledger: Ledger) -> InventoryResult:
    extracted = path
    unpacked: list[str] = []
    asar_item = None
    if path.is_file() and path.suffix.lower() == ".asar":
        dest = ledger.store.artifacts / "asar"
        try:
            extracted, unpacked = extract_asar(path, dest)
        except (AsarError, OSError) as exc:
            evidence = [
                ledger.record(
                    confidence=ClaimConfidence.SEEN,
                    kind="electron.asar",
                    statement=f"asar extract refused: {exc}",
                    tool="asar-python",
                    limitations=["unsafe or malformed archive"],
                )
            ]
            return InventoryResult(
                session_id=ledger.store.session_id,
                target_kind=TargetKind.ELECTRON,
                original_path=str(path),
                workspace_path=str(path),
                status=CapabilityStatus.FAILED,
                engine="asar-python",
                coverage="none",
                findings={"error": str(exc)},
                evidence=evidence,
                limitations=[str(exc)],
            )
        asar_item = ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="electron.asar",
            statement=f"extracted asar into {extracted}",
            tool="asar-python",
            command=f"extract_asar {path.name}",
            location=Location(path=str(extracted)),
        )
    inner = inventory_javascript(extracted, ledger)
    inner.target_kind = TargetKind.ELECTRON
    inner.engine = "asar-python+javascript-static"
    inner.original_path = str(path)
    if asar_item is not None:
        inner.evidence = [asar_item, *inner.evidence]
    if unpacked:
        inner.limitations = [
            *inner.limitations,
            (
                f"{len(unpacked)} unpacked members not extracted "
                "(app.asar.unpacked); extract separately with @electron/asar"
            ),
        ]
    return inner
