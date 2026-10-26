from __future__ import annotations

import json
from pathlib import Path

import pytest

from reveng_debug.contracts.models import CapabilityStatus, TargetKind
from reveng_debug.router.identify import identify_target
from reveng_debug.service import clone_website, inventory

FIXTURE_HTML = """<!doctype html>
<html>
<head>
  <title>Notes Lab</title>
  <link rel="stylesheet" href="/app.css">
  <script src="/export.js"></script>
</head>
<body>
  <img src="/logo.png" alt="logo">
  <button>Export notes</button>
</body>
</html>
"""


def test_identify_and_inventory_html(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    page = tmp_path / "index.html"
    page.write_text(FIXTURE_HTML, encoding="utf-8")
    assert identify_target(page) is TargetKind.WEBSITE
    result = inventory(page)
    assert result.target_kind is TargetKind.WEBSITE
    assert result.status is CapabilityStatus.PRESENT
    assert any(s.endswith("/export.js") or s == "/export.js" for s in result.findings["scripts"])
    assert (Path(result.workspace_path) / "reconstruction.md").exists()
    kinds = {item.kind for item in result.evidence}
    assert "website.clone" in kinds
    assert "website.tokens" in kinds


def test_clone_gotcontext_capture_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    capture = {
        "schema_version": "1.0",
        "kind": "website-capture",
        "backend": "gotcontext-chrome",
        "url": "https://example.test/notes",
        "html": FIXTURE_HTML,
        "text": "Export notes",
        "tokens": {"--bg": "#fff", "font-sans": "Inter"},
        "components": [{"name": "ExportButton"}],
        "assets": [{"url": "/logo.png"}],
    }
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture), encoding="utf-8")
    assert identify_target(path) is TargetKind.WEBSITE
    result = clone_website(str(path))
    assert result.engine == "gotcontext-chrome"
    assert result.findings["title"] == "Notes Lab"
    assert "--bg" in result.findings["token_keys"]
    assert result.findings["component_count"] == 1
    clone_dir = Path(result.workspace_path)
    assert (clone_dir / "tokens.json").read_text(encoding="utf-8")
    assert "gotcontext-chrome" in (clone_dir / "reconstruction.md").read_text(encoding="utf-8")
