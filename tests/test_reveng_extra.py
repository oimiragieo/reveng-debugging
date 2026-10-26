from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from reveng_debug.contracts.models import CapabilityStatus
from reveng_debug.ledger.service import Ledger
from reveng_debug.storage.workspace import SessionStore


def _ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Ledger:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    return Ledger(SessionStore())


def _target(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.js"
    path.write_text("console.log('fixture');\n", encoding="utf-8")
    return path


def test_missing_reveng_is_unsupported_never_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: None)
    ledger = _ledger(tmp_path, monkeypatch)
    result = reveng_app.run_reveng_app_re(_target(tmp_path), ledger)
    assert result.status is CapabilityStatus.UNSUPPORTED
    blob = json.dumps(result.model_dump()).lower()
    assert "absent" not in blob
    joined = " ".join(result.limitations).lower()
    assert "reveng" in joined
    assert "extra" in joined or "path" in joined
    assert result.engine == "reveng"


def test_present_fake_runner_records_output_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    seen: dict[str, Path] = {}

    def fake_runner(admitted: Path, output_dir: Path) -> dict[str, object]:
        seen["admitted"] = admitted
        seen["output_dir"] = output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        marker = output_dir / "fake.json"
        marker.write_text("{}", encoding="utf-8")
        return {"marker": str(marker)}

    monkeypatch.setattr(reveng_app, "invoke_ga_app_re", fake_runner)
    ledger = _ledger(tmp_path, monkeypatch)
    source = _target(tmp_path)
    result = reveng_app.run_reveng_app_re(source, ledger)
    assert result.status is CapabilityStatus.PRESENT
    output_dir = Path(str(result.findings["output_dir"]))
    assert output_dir.name == "app-re"
    assert output_dir.parent.name == "artifacts"
    assert (output_dir / "fake.json").is_file()
    assert ledger.store.contained(seen["admitted"])
    assert ledger.store.contained(output_dir)
    assert "absent" not in json.dumps(result.model_dump()).lower()


def test_already_admitted_path_is_not_recopied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    monkeypatch.setattr(
        reveng_app,
        "invoke_ga_app_re",
        lambda admitted, output_dir: {"admitted": str(admitted), "output_dir": str(output_dir)},
    )
    ledger = _ledger(tmp_path, monkeypatch)
    admitted = ledger.store.admit(_target(tmp_path))
    calls: list[Path] = []
    original_admit = ledger.store.admit

    def wrapped(source: Path) -> Path:
        calls.append(source)
        return original_admit(source)

    monkeypatch.setattr(ledger.store, "admit", wrapped)
    result = reveng_app.run_reveng_app_re(admitted, ledger)
    assert calls == []
    assert Path(result.workspace_path).resolve() == admitted.resolve()
    assert result.status is CapabilityStatus.PRESENT


def test_subprocess_fallback_is_ga_surface_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    monkeypatch.setattr(reveng_app, "_try_python_api", lambda *_a, **_k: None)
    monkeypatch.setattr(reveng_app.shutil, "which", lambda _name: "reveng")

    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(reveng_app.subprocess, "run", fake_run)
    ledger = _ledger(tmp_path, monkeypatch)
    result = reveng_app.run_reveng_app_re(_target(tmp_path), ledger)
    cmd = [str(part) for part in captured["cmd"]]  # type: ignore[union-attr]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs.get("shell") in {None, False}
    assert kwargs.get("timeout") is not None
    assert "reverse-engineer-app" in cmd
    assert "--output-dir" in cmd
    joined = " ".join(cmd).lower()
    assert "generate-exploit" not in joined
    assert "malware" not in joined
    assert result.status is CapabilityStatus.PRESENT
    assert Path(str(result.findings["output_dir"])).name == "app-re"


def test_python_api_uses_static_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    seen: dict[str, object] = {}

    class _Framework:
        def reverse_engineer(self, input_path: str, output_dir: str, **kwargs: object) -> object:
            seen["input_path"] = input_path
            seen["output_dir"] = output_dir
            seen["kwargs"] = kwargs
            return SimpleNamespace(
                language="javascript",
                adapter_name="javascript",
                source_count=1,
                validation_grade="packaging_only",
            )

    monkeypatch.setattr(
        reveng_app,
        "_load_app_re_framework",
        lambda: _Framework(),
    )
    ledger = _ledger(tmp_path, monkeypatch)
    result = reveng_app.run_reveng_app_re(_target(tmp_path), ledger)
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs.get("run_deobfuscator") is False
    assert ledger.store.contained(Path(str(seen["input_path"])))
    assert result.status is CapabilityStatus.PRESENT
    assert result.findings.get("via") == "python-api"
