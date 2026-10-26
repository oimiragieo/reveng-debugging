from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from reveng_debug.cli import app
from tests.helpers import build_minimal_pe32, write_js_app

runner = CliRunner()


def test_help_lists_doctor() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "clone-website" in result.stdout


def test_doctor_identify_inventory_slice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    doctor = runner.invoke(app, ["doctor"])
    assert doctor.exit_code == 0
    assert "support_matrix" in doctor.stdout
    assert "absent" not in doctor.stdout

    pe = tmp_path / "tiny.bin"
    pe.write_bytes(build_minimal_pe32())
    identified = runner.invoke(app, ["identify", str(pe)])
    assert identified.exit_code == 0
    assert '"kind": "pe"' in identified.stdout

    inventoried = runner.invoke(app, ["inventory", str(pe)])
    assert inventoried.exit_code == 0
    assert "session_id" in inventoried.stdout
    assert "security_flags" in inventoried.stdout

    app_dir = write_js_app(tmp_path / "jsapp")
    sliced = runner.invoke(app, ["slice", str(app_dir / "main.js"), "ipcMain"])
    assert sliced.exit_code == 0
    assert "hits" in sliced.stdout

    html = tmp_path / "site.html"
    html.write_text(
        "<!doctype html><title>Demo</title><script src='a.js'></script>",
        encoding="utf-8",
    )
    cloned = runner.invoke(app, ["clone-website", str(html)])
    assert cloned.exit_code == 0, cloned.stdout
    assert "website" in cloned.stdout
    assert "clone_dir" in cloned.stdout
