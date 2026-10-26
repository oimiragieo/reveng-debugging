from __future__ import annotations

import json
from pathlib import Path

import pytest

from reveng_debug.adapters.ghidra import (
    ENGINE,
    HEADLESS_TIMEOUT_SEC,
    UNSUPPORTED_HINT,
    HeadlessRun,
    discover_analyze_headless,
    run_ghidra_headless,
)
from reveng_debug.contracts.models import CapabilityStatus, TargetKind
from reveng_debug.ledger.service import Ledger
from reveng_debug.storage.workspace import SessionStore
from tests.helpers import build_minimal_pe32

FUNCTIONS_JSON = json.dumps(
    [{"name": "entry", "entry": "00401000"}, {"name": "FUN_00401100", "entry": "00401100"}]
)


def _session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Ledger]:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    pe_path = tmp_path / "tiny.bin"
    pe_path.write_bytes(build_minimal_pe32())
    store = SessionStore()
    admitted = store.admit(pe_path)
    return admitted, Ledger(store)


def test_ghidra_missing_is_unsupported_never_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("reveng_debug.adapters.ghidra.discover_analyze_headless", lambda: None)
    admitted, ledger = _session(tmp_path, monkeypatch)
    result = run_ghidra_headless(admitted, ledger)
    assert result.status is CapabilityStatus.UNSUPPORTED
    assert result.engine == "none"
    assert result.coverage == "none"
    blob = json.dumps(result.model_dump()).lower()
    assert "absent" not in blob
    assert "ghidra_install_dir" in result.limitations[0].lower()
    assert "ghidra_home" in result.limitations[0].lower()
    assert result.limitations[0] == UNSUPPORTED_HINT
    assert result.evidence[0].confidence.value == "unknown"


def test_ghidra_fake_runner_parses_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_bin = tmp_path / "analyzeHeadless.bat"
    fake_bin.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr("reveng_debug.adapters.ghidra.discover_analyze_headless", lambda: fake_bin)
    captured: dict[str, object] = {}

    def fake_invoke(command: list[str], *, timeout: float = 0.0) -> HeadlessRun:
        captured["command"] = command
        captured["timeout"] = timeout
        json_out = Path(command[-1])
        json_out.write_text(FUNCTIONS_JSON, encoding="utf-8")
        return HeadlessRun(returncode=0, stdout="ok", stderr="", timed_out=False)

    monkeypatch.setattr("reveng_debug.adapters.ghidra.invoke_headless", fake_invoke)
    admitted, ledger = _session(tmp_path, monkeypatch)
    result = run_ghidra_headless(admitted, ledger)
    assert result.status is CapabilityStatus.PRESENT
    assert result.engine == ENGINE
    assert result.target_kind is TargetKind.PE
    assert result.findings["function_count"] == 2
    assert result.findings["functions"][0] == {"name": "entry", "entry": "00401000"}
    assert "static analysis only" in result.limitations[0]
    command = captured["command"]
    assert isinstance(command, list)
    assert "-import" in command
    assert str(admitted) in command
    assert "-deleteProject" in command
    assert captured["timeout"] == HEADLESS_TIMEOUT_SEC
    assert "-postScript" in command
    assert "ExportFunctions.java" in command
    project_dir = Path(command[command.index("-import") - 2])
    assert not any(part.startswith(".") for part in project_dir.parts)
    assert project_dir.name == "ghidra_project"
    assert "absent" not in json.dumps(result.model_dump()).lower()


def test_discover_none_without_path_or_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr("reveng_debug.adapters.ghidra.shutil.which", lambda _name: None)
    assert discover_analyze_headless() is None


def test_discover_from_ghidra_install_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reveng_debug.adapters.ghidra.shutil.which", lambda _name: None)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    install = tmp_path / "ghidra_11"
    support = install / "support"
    support.mkdir(parents=True)
    bat = support / "analyzeHeadless.bat"
    bat.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(install))
    assert discover_analyze_headless() == bat


def test_discover_from_ghidra_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reveng_debug.adapters.ghidra.shutil.which", lambda _name: None)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    home = tmp_path / "NSA" / "ghidra"
    bat = home / "support" / "analyzeHeadless.bat"
    bat.parent.mkdir(parents=True)
    bat.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    assert discover_analyze_headless() == bat


def test_timeout_is_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_bin = tmp_path / "analyzeHeadless.bat"
    fake_bin.write_text("", encoding="utf-8")
    monkeypatch.setattr("reveng_debug.adapters.ghidra.discover_analyze_headless", lambda: fake_bin)

    def fake_invoke(_command: list[str], *, timeout: float = 0.0) -> HeadlessRun:
        return HeadlessRun(
            returncode=None,
            stdout="still analyzing",
            stderr="",
            timed_out=True,
        )

    monkeypatch.setattr("reveng_debug.adapters.ghidra.invoke_headless", fake_invoke)
    admitted, ledger = _session(tmp_path, monkeypatch)
    result = run_ghidra_headless(admitted, ledger)
    assert result.status is CapabilityStatus.FAILED
    assert result.engine == ENGINE
    assert result.findings["timed_out"] is True
    assert "timed out" in result.limitations[0]
    assert "absent" not in json.dumps(result.model_dump()).lower()


def test_dot_component_project_dir_relocated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "analyzeHeadless.bat"
    fake_bin.write_text("", encoding="utf-8")
    monkeypatch.setattr("reveng_debug.adapters.ghidra.discover_analyze_headless", lambda: fake_bin)
    captured: dict[str, list[str]] = {}

    def fake_invoke(command: list[str], *, timeout: float = 0.0) -> HeadlessRun:
        captured["command"] = command
        return HeadlessRun(returncode=0, stdout="[]", stderr="", timed_out=False)

    monkeypatch.setattr("reveng_debug.adapters.ghidra.invoke_headless", fake_invoke)
    admitted, ledger = _session(tmp_path, monkeypatch)
    unsafe = tmp_path / ".reveng" / "ghidra_project"
    result = run_ghidra_headless(admitted, ledger, project_dir=unsafe)
    assert result.status is CapabilityStatus.PRESENT
    command = captured["command"]
    project_dir = Path(command[command.index("-import") - 2])
    assert ".reveng" not in project_dir.parts
    assert not any(part.startswith(".") for part in project_dir.parts)
    assert "ghidra-safe" in " ".join(result.limitations).lower()
