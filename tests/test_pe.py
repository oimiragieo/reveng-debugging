from __future__ import annotations

from pathlib import Path

import pytest

from reveng_debug.adapters.pe import inventory_pe
from reveng_debug.ledger.service import Ledger
from reveng_debug.storage.workspace import SessionStore
from tests.helpers import build_minimal_pe32


def test_pe_inventory_emits_seen_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    pe_path = tmp_path / "tiny.bin"
    pe_path.write_bytes(build_minimal_pe32())
    store = SessionStore()
    admitted = store.admit(pe_path)
    result = inventory_pe(admitted, Ledger(store))
    assert result.engine in {"lief", "pefile"}
    assert "pe-headers" in result.coverage
    assert result.findings["security_flags"]["ASLR"] is True
    assert result.findings["security_flags"]["NX_COMPAT"] is True
    confidences = {item.confidence.value for item in result.evidence}
    assert "seen" in confidences
    assert any("REVENG" in s for s in result.findings["strings"])
