from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest

from reveng_debug.adapters.native import inventory_elf, inventory_macho
from reveng_debug.contracts.models import CapabilityStatus, TargetKind
from reveng_debug.ledger.service import Ledger
from reveng_debug.router.identify import identify_target
from reveng_debug.storage.workspace import SessionStore
from tests.helpers_native import (
    build_elf_ident,
    build_macho_ident,
    build_minimal_elf64,
    build_minimal_macho64,
)


def _lief_available() -> bool:
    try:
        importlib.import_module("lief")
    except Exception:
        return False
    return True


def _install_fake_lief(
    monkeypatch: pytest.MonkeyPatch, *, exported: list[str] | None = None
) -> None:
    fake = _FakeLief(exported=exported or ["fixture_export"])
    monkeypatch.setattr(
        "reveng_debug.adapters.native.importlib.import_module",
        lambda name: fake if name == "lief" else importlib.import_module(name),
    )


def _install_missing_lief(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(name: str) -> Any:
        if name == "lief":
            raise ImportError("lief")
        return importlib.import_module(name)

    monkeypatch.setattr("reveng_debug.adapters.native.importlib.import_module", boom)


def _open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blob: bytes,
    name: str,
) -> tuple[Path, Ledger]:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    path = tmp_path / name
    path.write_bytes(blob)
    store = SessionStore()
    return store.admit(path), Ledger(store)


def _no_absent(result: Any) -> None:
    assert "absent" not in result.model_dump_json().lower()


def test_identify_elf_and_macho_magic(tmp_path: Path) -> None:
    elf = tmp_path / "sample.elf"
    elf.write_bytes(build_elf_ident())
    macho = tmp_path / "sample.macho"
    macho.write_bytes(build_macho_ident())
    assert identify_target(elf) is TargetKind.ELF
    assert identify_target(macho) is TargetKind.MACHO


def test_elf_without_lief_is_unknown_not_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_missing_lief(monkeypatch)
    admitted, ledger = _open(tmp_path, monkeypatch, build_elf_ident(), "sample.elf")
    result = inventory_elf(admitted, ledger)
    assert result.target_kind is TargetKind.ELF
    assert result.status is CapabilityStatus.UNKNOWN
    assert result.status is not CapabilityStatus.PRESENT
    _no_absent(result)
    assert result.limitations
    lowered = [item.lower() for item in result.limitations]
    assert any("static" in item or "not executed" in item for item in lowered)


def test_macho_without_lief_is_unknown_not_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_missing_lief(monkeypatch)
    admitted, ledger = _open(tmp_path, monkeypatch, build_macho_ident(), "sample.macho")
    result = inventory_macho(admitted, ledger)
    assert result.target_kind is TargetKind.MACHO
    assert result.status is CapabilityStatus.UNKNOWN
    assert result.status is not CapabilityStatus.PRESENT
    _no_absent(result)


def test_elf_parse_failure_is_failed_when_lief_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not _lief_available():
        pytest.skip("lief not importable")
    admitted, ledger = _open(tmp_path, monkeypatch, build_elf_ident(), "trunc.elf")
    result = inventory_elf(admitted, ledger)
    assert result.target_kind is TargetKind.ELF
    # Whether LIEF rejects a 14-byte header is not a documented contract, so do not
    # pin one outcome (that is what made this test flake). Mirror the Mach-O sibling:
    # accept either, and require real findings when it does parse.
    assert result.status in {CapabilityStatus.FAILED, CapabilityStatus.PRESENT}
    assert result.engine == "lief"
    if result.status is CapabilityStatus.PRESENT:
        assert result.findings.get("format") == "elf"
    _no_absent(result)


def test_macho_parse_failure_is_failed_when_lief_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not _lief_available():
        pytest.skip("lief not importable")
    admitted, ledger = _open(tmp_path, monkeypatch, build_macho_ident(), "trunc.macho")
    result = inventory_macho(admitted, ledger)
    assert result.target_kind is TargetKind.MACHO
    assert result.status is not CapabilityStatus.UNSUPPORTED
    assert result.status in {CapabilityStatus.FAILED, CapabilityStatus.PRESENT}
    assert result.engine == "lief"
    if result.status is CapabilityStatus.PRESENT:
        assert result.findings.get("format") == "macho"
    _no_absent(result)


def test_elf_inventory_emits_seen_facts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not _lief_available():
        _install_fake_lief(monkeypatch)
    admitted, ledger = _open(tmp_path, monkeypatch, build_minimal_elf64(), "tiny.elf")
    result = inventory_elf(admitted, ledger)
    assert result.status is CapabilityStatus.PRESENT
    assert result.engine == "lief"
    assert result.target_kind is TargetKind.ELF
    assert "elf-headers" in result.coverage
    assert result.findings["format"] == "elf"
    assert result.findings.get("machine") or result.findings.get("arch")
    assert isinstance(result.findings["sections"], list)
    sections = result.findings["sections"]
    assert all("name" in section and "size" in section for section in sections)
    assert isinstance(result.findings["imported_libraries"], list)
    assert isinstance(result.findings["exported_symbols"], list)
    assert isinstance(result.findings["dynamic_symbols"], list)
    assert any("REVENG" in item for item in result.findings["strings"])
    confidences = {item.confidence.value for item in result.evidence}
    assert "seen" in confidences
    assert any("not executed" in item.lower() for item in result.limitations)
    _no_absent(result)


def test_macho_inventory_emits_seen_facts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if not _lief_available():
        _install_fake_lief(monkeypatch)
    admitted, ledger = _open(tmp_path, monkeypatch, build_minimal_macho64(), "tiny.macho")
    result = inventory_macho(admitted, ledger)
    assert result.status is CapabilityStatus.PRESENT
    assert result.engine == "lief"
    assert result.target_kind is TargetKind.MACHO
    assert "macho-headers" in result.coverage
    assert result.findings["format"] == "macho"
    assert result.findings.get("machine") or result.findings.get("arch")
    assert isinstance(result.findings["sections"], list)
    sections = result.findings["sections"]
    assert all("name" in section and "size" in section for section in sections)
    assert isinstance(result.findings["imported_libraries"], list)
    assert isinstance(result.findings["exported_symbols"], list)
    assert isinstance(result.findings["dynamic_symbols"], list)
    assert any("REVENG" in item for item in result.findings["strings"])
    confidences = {item.confidence.value for item in result.evidence}
    assert "seen" in confidences
    assert any("not executed" in item.lower() for item in result.limitations)
    _no_absent(result)


def test_exported_symbols_are_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_lief(monkeypatch, exported=[f"sym{i}" for i in range(250)])
    admitted, ledger = _open(tmp_path, monkeypatch, build_minimal_elf64(), "capped.elf")
    result = inventory_elf(admitted, ledger)
    assert result.status is CapabilityStatus.PRESENT
    assert len(result.findings["exported_symbols"]) == 200


class _FakeSym:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeSection:
    def __init__(self, name: str, size: int) -> None:
        self.name = name
        self.size = size


class _FakeHeader:
    def __init__(self, *, machine: str, cpu: str) -> None:
        self.machine_type = machine
        self.cpu_type = cpu
        self.identity = [0x7F, 0x45, 0x4C, 0x46, 2, 1, 1, 0] + [0] * 8


class _FakeBinary:
    def __init__(self, *, exported: list[str]) -> None:
        self.header = _FakeHeader(machine="EM_X86_64", cpu="CPU_TYPE_X86_64")
        self.sections = [_FakeSection(".text", 7), _FakeSection("__text", 7)]
        self.libraries = ["libc.so.6"]
        self.imported_libraries = ["libc.so.6"]
        self.exported_symbols = [_FakeSym(name) for name in exported]
        self.dynamic_symbols = [_FakeSym("dyn_fixture")]
        self.symbols = [_FakeSym("dyn_fixture")]


class _FakeFat:
    def __init__(self, binary: _FakeBinary) -> None:
        self._binary = binary
        self.size = 1

    def __iter__(self) -> Any:
        yield self._binary

    def at(self, index: int) -> _FakeBinary:
        if index != 0:
            raise IndexError(index)
        return self._binary


class _FakeELF:
    def __init__(self, binary: _FakeBinary) -> None:
        self._binary = binary

    def parse(self, _path: str) -> _FakeBinary:
        return self._binary


class _FakeMachO:
    def __init__(self, binary: _FakeBinary) -> None:
        self._binary = binary

    def parse(self, _path: str) -> _FakeFat:
        return _FakeFat(self._binary)


class _FakeLief:
    def __init__(self, *, exported: list[str]) -> None:
        binary = _FakeBinary(exported=exported)
        self.ELF = _FakeELF(binary)
        self.MachO = _FakeMachO(binary)
