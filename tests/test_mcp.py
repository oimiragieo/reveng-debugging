from __future__ import annotations

from pathlib import Path

import pytest

from reveng_debug.mcp import TOOLS, dispatch, handle
from tests.helpers import build_minimal_pe32


def test_tools_catalog_includes_clone_website() -> None:
    names = [t["name"] for t in TOOLS]
    assert names == [
        "doctor",
        "identify",
        "inventory",
        "slice",
        "session_show",
        "evidence_get",
        "clone_website",
    ]


def test_handle_initialize_and_list() -> None:
    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init is not None
    assert init["result"]["serverInfo"]["name"] == "reveng-debug"
    listed = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed is not None
    assert len(listed["result"]["tools"]) == 7


def test_dispatch_identify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    pe = tmp_path / "tiny.bin"
    pe.write_bytes(build_minimal_pe32())
    result = dispatch("identify", {"path": str(pe)})
    assert "pe" in result["content"][0]["text"]
