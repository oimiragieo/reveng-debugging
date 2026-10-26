from __future__ import annotations

from pathlib import Path

import pytest

from reveng_debug.storage.asar import AsarError, _assert_safe_name, _safe_join, extract_asar
from reveng_debug.storage.workspace import SessionStore
from tests.helpers import build_asar


def test_admit_does_not_mutate_original(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    original = tmp_path / "sample.txt"
    original.write_text("hello", encoding="utf-8")
    store = SessionStore()
    admitted = store.admit(original)
    original.write_text("changed", encoding="utf-8")
    assert admitted.read_text(encoding="utf-8") == "hello"
    assert original.read_text(encoding="utf-8") == "changed"
    assert store.contained(admitted)


def test_asar_extracts_and_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "app.asar"
    archive.write_bytes(build_asar({"hello.js": b"console.log(1)"}))
    dest = tmp_path / "out"
    extract_asar(archive, dest)
    assert (dest / "hello.js").read_bytes() == b"console.log(1)"

    with pytest.raises(AsarError):
        _assert_safe_name("..")
    with pytest.raises(AsarError):
        _assert_safe_name("C:foo")
    with pytest.raises(AsarError):
        _safe_join(dest.resolve(), "../escape")
