from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

ATTACH_URL = "http://127.0.0.1:8092/attach"


class _FakeResult:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.session_id = str(payload["session_id"])
        self._payload = payload

    def model_dump(self) -> dict[str, Any]:
        return self._payload


class _FakeService:
    OMEGA_VISION_ATTACH = ATTACH_URL
    OMEGA_VISION_ATTACH_DEFAULT_PORT = "http://127.0.0.1:8090/attach"

    def doctor(self) -> dict[str, Any]:
        return {"support_matrix": {"rows": [{"workflow": "pe_inventory", "status": "present"}]}}

    def identify(self, path: Path) -> dict[str, Any]:
        return {"path": str(path), "kind": "pe"}

    def inventory(self, path: Path, session_id: str | None = None) -> _FakeResult:
        return _FakeResult(
            {
                "session_id": session_id or "sess-1",
                "path": str(path),
                "target_kind": "pe",
            }
        )

    def slice_file(self, path: Path, needle: str, session_id: str | None = None) -> dict[str, Any]:
        return {"path": str(path), "needle": needle, "hits": [{"line": 1}]}

    def clone_website(self, target: str, session_id: str | None = None) -> _FakeResult:
        return _FakeResult(
            {
                "session_id": session_id or "sess-2",
                "target_kind": "website",
                "findings": {"clone_dir": "clone"},
            }
        )

    def session_show(self, session_id: str) -> dict[str, Any]:
        return {"session_id": session_id, "evidence": [{"kind": "pe_inventory"}]}


def _feed(monkeypatch: pytest.MonkeyPatch, lines: Iterable[str]) -> None:
    remaining = iter(lines)

    def fake_input(_prompt: str = "") -> str:
        try:
            return next(remaining)
        except StopIteration as exc:
            raise EOFError from exc

    monkeypatch.setattr("builtins.input", fake_input)


def _stub_service(monkeypatch: pytest.MonkeyPatch) -> _FakeService:
    fake = _FakeService()
    monkeypatch.setattr("reveng_debug.tui._svc", lambda: fake)
    return fake


def test_tui_doctor_then_quit(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.tui import run_tui

    _feed(monkeypatch, ["doctor", "quit"])
    run_tui()
    out = capsys.readouterr().out
    assert ATTACH_URL in out
    assert "support_matrix" in out or "pe_inventory" in out


def test_tui_identify_inventory_prints_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reveng_debug.tui import run_tui

    _stub_service(monkeypatch)
    pe = tmp_path / "tiny.bin"
    pe.write_text("not-executed", encoding="utf-8")
    _feed(monkeypatch, [f"identify {pe}", f"inventory {pe}", "quit"])
    run_tui()
    out = capsys.readouterr().out
    assert ATTACH_URL in out
    assert '"kind": "pe"' in out
    assert "session_id" in out
    assert "evidence" in out


def test_tui_slice_and_clone_website(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reveng_debug.tui import run_tui

    _stub_service(monkeypatch)
    js = tmp_path / "main.js"
    js.write_text("ipcMain.handle('ping')", encoding="utf-8")
    html = tmp_path / "site.html"
    html.write_text("<!doctype html><title>Demo</title>", encoding="utf-8")
    _feed(
        monkeypatch,
        [
            f"slice {js} ipcMain",
            f"clone-website {html}",
            "quit",
        ],
    )
    run_tui()
    out = capsys.readouterr().out
    assert "hits" in out
    assert "website" in out
    assert "clone_dir" in out or "session_id" in out


def test_tui_eof_quits_without_command(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.tui import run_tui

    _feed(monkeypatch, [])
    run_tui()
    out = capsys.readouterr().out
    assert ATTACH_URL in out
    assert "pe_inventory" in out
