from __future__ import annotations

from pathlib import Path

import pytest

from reveng_debug.contracts.models import CapabilityStatus, TargetKind
from reveng_debug.service import inventory


def test_elf_is_unsupported_not_fake_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    elf = tmp_path / "sample.elf"
    elf.write_bytes(b"\x7fELF\x02\x01\x01")
    result = inventory(elf)
    assert result.target_kind is TargetKind.ELF
    assert result.status is CapabilityStatus.UNSUPPORTED
    assert "Wave 2" in result.limitations[0]


def test_unknown_kind_stays_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    blob = tmp_path / "notes.txt"
    blob.write_text("hello", encoding="utf-8")
    result = inventory(blob)
    assert result.status is CapabilityStatus.UNKNOWN
    assert result.target_kind is TargetKind.UNKNOWN
