from __future__ import annotations

from pathlib import Path

import pytest

from reveng_debug.adapters.electron import inventory_electron
from reveng_debug.adapters.javascript import inventory_javascript, slice_text
from reveng_debug.ledger.service import Ledger
from reveng_debug.storage.workspace import SessionStore
from tests.helpers import build_asar, write_js_app


def test_javascript_inventory_and_slice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    app = write_js_app(tmp_path / "app")
    store = SessionStore()
    admitted = store.admit(app)
    result = inventory_javascript(admitted, Ledger(store))
    assert result.findings["package"]["name"] == "fixture-app"
    assert result.findings["sourcemaps"]
    assert result.findings["ipc_hits"]
    hits = slice_text(admitted / "main.js", "ipcMain")
    assert hits
    kinds = {item.kind for item in store.read_evidence()}
    assert "js.package" in kinds
    assert "js.sourcemap" in kinds


def test_electron_asar_inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    archive = tmp_path / "app.asar"
    archive.write_bytes(
        build_asar(
            {
                "package.json": b'{"name":"asar-app","main":"index.js"}',
                "index.js": b"contextBridge.exposeInMainWorld('api', {})\n",
            }
        )
    )
    store = SessionStore()
    admitted = store.admit(archive)
    result = inventory_electron(admitted, Ledger(store))
    assert result.target_kind.value == "electron"
    assert result.status.value == "present"
    assert result.findings["package"]["name"] == "asar-app"
