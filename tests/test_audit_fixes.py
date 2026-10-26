"""Regression tests for the 2026-10-26 code audit findings."""

from __future__ import annotations

import importlib
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from reveng_debug.adapters.electron import inventory_electron
from reveng_debug.adapters.ghidra import HeadlessRun, _extract_json_array, run_ghidra_headless
from reveng_debug.adapters.javascript import inventory_javascript
from reveng_debug.adapters.pe import inventory_pe
from reveng_debug.adapters.website import clone_website
from reveng_debug.contracts.models import (
    SCHEMA_VERSION,
    CapabilityStatus,
    EvidenceItem,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger
from reveng_debug.mcp import handle, main
from reveng_debug.router.identify import identify_target
from reveng_debug.service import session_show, slice_file
from reveng_debug.storage.asar import AsarError, extract_asar
from reveng_debug.storage.workspace import SessionStore
from tests.helpers import build_asar, build_minimal_pe32, write_js_app


def _ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Ledger:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    return Ledger(SessionStore())


def test_mcp_newline_delimited_initialize_roundtrip() -> None:
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
    stdin = io.BytesIO(request.encode("utf-8"))
    stdout = io.BytesIO()
    main(stdin=stdin, stdout=stdout)
    raw = stdout.getvalue()
    assert raw.endswith(b"\n")
    assert b"Content-Length" not in raw
    lines = [line for line in raw.split(b"\n") if line]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["id"] == 1
    assert payload["result"]["serverInfo"]["name"] == "reveng-debug"


def test_mcp_malformed_line_returns_parse_error_and_continues() -> None:
    init = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}})
    stdin = io.BytesIO(b"not-json\n" + init.encode("utf-8") + b"\n")
    stdout = io.BytesIO()
    main(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().split(b"\n") if line]
    assert lines[0]["error"]["code"] == -32700
    assert lines[0]["id"] is None
    assert lines[1]["id"] == 2
    assert "protocolVersion" in lines[1]["result"]


def test_mcp_ping_returns_empty_result() -> None:
    reply = handle({"jsonrpc": "2.0", "id": 7, "method": "ping"})
    assert reply == {"jsonrpc": "2.0", "id": 7, "result": {}}


def test_asar_unpacked_member_does_not_abort_extract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    archive = tmp_path / "app.asar"
    archive.write_bytes(
        build_asar(
            {
                "package.json": b'{"name":"asar-app","main":"index.js"}',
                "index.js": b"contextBridge.exposeInMainWorld('api', {})\n",
            },
            unpacked={"native.node": 12},
        )
    )
    dest, unpacked = extract_asar(archive, tmp_path / "out")
    assert (dest / "index.js").is_file()
    assert unpacked == ["native.node"]
    assert not (dest / "native.node").exists()

    store = SessionStore()
    admitted = store.admit(archive)
    result = inventory_electron(admitted, Ledger(store))
    assert result.status is CapabilityStatus.PRESENT
    assert result.findings["package"]["name"] == "asar-app"
    assert any("unpacked" in note.lower() for note in result.limitations)


def test_asar_link_member_still_refused(tmp_path: Path) -> None:
    archive = tmp_path / "app.asar"
    archive.write_bytes(build_asar({"ok.js": b"1"}, links={"escape": "../x"}))
    with pytest.raises(AsarError, match="link"):
        extract_asar(archive, tmp_path / "out")


def test_identify_does_not_slurp_whole_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "huge.bin"
    target.write_bytes(b"MZ" + b"\x00" * 4096)

    def boom(self: Path) -> bytes:
        raise AssertionError("identify must not Path.read_bytes the whole target")

    monkeypatch.setattr(Path, "read_bytes", boom)
    assert identify_target(target) is TargetKind.PE


def test_lief_parse_failure_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = importlib.import_module

    class FakeLief:
        class PE:
            @staticmethod
            def parse(_path: str) -> None:
                raise RuntimeError("malformed optional header")

    def fake_import(name: str, package: str | None = None) -> object:
        if name == "lief":
            return FakeLief
        return real_import(name, package)

    monkeypatch.setattr("reveng_debug.adapters.pe.importlib.import_module", fake_import)
    ledger = _ledger(tmp_path, monkeypatch)
    pe_path = tmp_path / "tiny.bin"
    pe_path.write_bytes(build_minimal_pe32())
    admitted = ledger.store.admit(pe_path)
    result = inventory_pe(admitted, ledger)
    assert result.engine == "pefile"
    assert result.status is CapabilityStatus.PRESENT
    blob = " ".join(result.limitations).lower()
    assert "lief parse failed" in blob
    assert "malformed optional header" in blob
    assert any(item.kind == "pe.engine" for item in result.evidence)


def test_pe_machine_is_int_with_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger(tmp_path, monkeypatch)
    pe_path = tmp_path / "tiny.bin"
    pe_path.write_bytes(build_minimal_pe32())
    result = inventory_pe(ledger.store.admit(pe_path), ledger)
    assert isinstance(result.findings["machine"], int)
    assert result.findings["machine"] == 0x14C
    assert "machine_name" in result.findings


def test_ghidra_failed_rerun_does_not_report_stale_functions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_bin = tmp_path / "analyzeHeadless.bat"
    fake_bin.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr("reveng_debug.adapters.ghidra.discover_analyze_headless", lambda: fake_bin)
    calls = {"n": 0}

    def fake_invoke(command: list[str], *, timeout: float = 0.0) -> HeadlessRun:
        calls["n"] += 1
        json_out = Path(command[-1])
        if calls["n"] == 1:
            json_out.write_text(
                json.dumps([{"name": "stale_from_run_1", "entry": "0x1000"}]),
                encoding="utf-8",
            )
            return HeadlessRun(returncode=0, stdout="ok", stderr="", timed_out=False)
        return HeadlessRun(returncode=7, stdout="boom", stderr="fail", timed_out=False)

    monkeypatch.setattr("reveng_debug.adapters.ghidra.invoke_headless", fake_invoke)
    ledger = _ledger(tmp_path, monkeypatch)
    pe_path = tmp_path / "tiny.bin"
    pe_path.write_bytes(build_minimal_pe32())
    admitted = ledger.store.admit(pe_path)
    first = run_ghidra_headless(admitted, ledger)
    assert first.status is CapabilityStatus.PRESENT
    assert first.findings["function_count"] == 1
    second = run_ghidra_headless(admitted, ledger)
    assert second.status is CapabilityStatus.FAILED
    assert second.findings["functions"] == []
    assert second.findings["function_count"] == 0


def test_ghidra_stdout_fallback_skips_log_brackets() -> None:
    text = '[INFO] Analyzing /tmp/sample [main]\n[{"name": "main", "entry": "0x401000"}]'
    extracted = _extract_json_array(text)
    assert extracted is not None
    assert json.loads(extracted) == [{"name": "main", "entry": "0x401000"}]


def test_session_id_cannot_escape_state_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state2"
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(root))
    with pytest.raises(ValueError, match="illegal session id"):
        SessionStore(session_id="../../../escaped-session", root=root)
    assert not (tmp_path / "escaped-session").exists()


def test_partial_ledger_line_does_not_brick_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    store = SessionStore()
    good = EvidenceItem(
        session_id=store.session_id,
        confidence="seen",  # type: ignore[arg-type]
        kind="pe.machine",
        statement="ok",
        tool="test",
    )
    store.append_evidence(good)
    with store.ledger_path.open("a", encoding="utf-8") as handle:
        handle.write('{"partial": \n')
    items = store.read_evidence()
    assert len(items) == 1
    assert items[0].kind == "pe.machine"
    assert store.skipped_ledger_lines == 1
    shown = session_show(store.session_id)
    assert shown["corrupt_ledger_lines"] == 1
    assert len(shown["evidence"]) == 1


def test_same_basename_admissions_do_not_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    a = one / "target.bin"
    b = two / "target.bin"
    a.write_bytes(b"FIRST-CONTENT")
    b.write_bytes(b"SECOND-CONTENT")
    store = SessionStore()
    d1 = store.admit(a)
    d2 = store.admit(b)
    assert d1 != d2
    assert d1.read_bytes() == b"FIRST-CONTENT"
    assert d2.read_bytes() == b"SECOND-CONTENT"


def test_unknown_session_does_not_invent_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    missing = "0" * 32
    with pytest.raises(FileNotFoundError, match="no such session"):
        session_show(missing)
    assert not (tmp_path / "state" / missing).exists()


def test_app_re_allows_malware_in_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    monkeypatch.setattr(reveng_app, "_try_python_api", lambda *_a, **_k: None)
    monkeypatch.setattr(reveng_app.shutil, "which", lambda _name: "reveng")

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(reveng_app.subprocess, "run", fake_run)
    samples = tmp_path / "malware-samples"
    samples.mkdir()
    target = samples / "fixture.js"
    target.write_text("console.log(1);\n", encoding="utf-8")
    result = reveng_app.run_reveng_app_re(target, Ledger(SessionStore()))
    assert result.status is CapabilityStatus.PRESENT


def test_app_re_typeerror_is_not_retried_as_signature_mismatch() -> None:
    from reveng_debug.extras import reveng_app

    calls = {"n": 0}

    def reverse(_a: str, _b: str, **_kwargs: object) -> object:
        calls["n"] += 1
        raise TypeError("cannot unpack None")

    with pytest.raises(TypeError, match="cannot unpack"):
        reveng_app._call_reverse(reverse, Path("a"), Path("b"))
    assert calls["n"] == 1


def test_app_re_subprocess_decodes_utf8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reveng_debug.extras import reveng_app

    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    monkeypatch.setattr(reveng_app, "_try_python_api", lambda *_a, **_k: None)
    monkeypatch.setattr(reveng_app.shutil, "which", lambda _name: "reveng")
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(reveng_app.subprocess, "run", fake_run)
    target = tmp_path / "fixture.js"
    target.write_text("x\n", encoding="utf-8")
    reveng_app.run_reveng_app_re(target, Ledger(SessionStore()))
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs.get("encoding") == "utf-8"
    assert kwargs.get("errors") == "replace"


def test_slice_directory_is_unknown_not_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    adir = tmp_path / "adir"
    adir.mkdir()
    (adir / "notes.txt").write_text("hello needle\n", encoding="utf-8")
    payload = slice_file(adir, "needle")
    assert payload["hits"] == []
    assert payload["confidence"] == "unknown"
    assert any("directory" in note.lower() for note in payload["limitations"])


def test_javascript_evidence_is_this_run_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    app = write_js_app(tmp_path / "app")
    store = SessionStore()
    admitted = store.admit(app)
    ledger = Ledger(store)
    first = inventory_javascript(admitted, ledger)
    second = inventory_javascript(admitted, ledger)
    assert len(second.evidence) == len(first.evidence)
    assert len(ledger.all()) == len(first.evidence) * 2


def test_website_evidence_is_this_run_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    page = tmp_path / "index.html"
    page.write_text("<!doctype html><title>x</title>", encoding="utf-8")
    store = SessionStore()
    ledger = Ledger(store)
    first = clone_website(page, ledger)
    second = clone_website(page, ledger)
    assert len(second.evidence) == len(first.evidence)
    assert len(ledger.all()) == len(first.evidence) * 2


def test_schema_version_major_mismatch_rejected() -> None:
    with pytest.raises(ValidationError, match="unsupported schema_version"):
        EvidenceItem(
            schema_version="99.0-future",
            session_id="s",
            confidence="seen",  # type: ignore[arg-type]
            kind="pe.machine",
            statement="x",
            tool="t",
        )
    ok = EvidenceItem(
        schema_version=SCHEMA_VERSION,
        session_id="s",
        confidence="seen",  # type: ignore[arg-type]
        kind="pe.machine",
        statement="x",
        tool="t",
    )
    assert ok.schema_version == SCHEMA_VERSION


def test_asar_clears_dest_before_extract(tmp_path: Path) -> None:
    dest = tmp_path / "collision-out"
    dest.mkdir()
    (dest / "c").write_bytes(b"file")
    archive = tmp_path / "app.asar"
    archive.write_bytes(build_asar({"c/nested.js": b"ok"}))
    extract_asar(archive, dest)
    assert (dest / "c" / "nested.js").read_bytes() == b"ok"


def _capture_app_re_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from reveng_debug.extras import reveng_app

    monkeypatch.setenv("REVENG_DEBUG_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setattr(reveng_app, "find_spec", lambda _name: object())
    monkeypatch.setattr(reveng_app, "_try_python_api", lambda *_a, **_k: None)
    monkeypatch.setattr(reveng_app.shutil, "which", lambda _name: "reveng")
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = list(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(reveng_app.subprocess, "run", fake_run)
    target = tmp_path / "fixture.js"
    target.write_text("x\n", encoding="utf-8")
    reveng_app.run_reveng_app_re(target, Ledger(SessionStore()))
    return captured["cmd"]


def test_app_re_cli_argv_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Global options must precede the subcommand, and the subcommand takes none of them."""
    cmd = _capture_app_re_argv(tmp_path, monkeypatch)
    assert cmd[0] == "reveng"
    assert cmd[1] == "--output-dir"
    assert cmd.index("--output-dir") < cmd.index("reverse-engineer-app")
    assert cmd[3] == "reverse-engineer-app"


def test_app_re_cli_argv_is_accepted_by_real_reveng(tmp_path: Path) -> None:
    """Exercise the real CLI contract, not a monkeypatched subprocess.run."""
    binary = shutil.which("reveng") or shutil.which("reveng.exe")
    if binary is None:
        pytest.skip("reveng CLI not on PATH")
    proc = subprocess.run(
        [
            binary,
            "--output-dir",
            tempfile.mkdtemp(),
            "reverse-engineer-app",
            "--help",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    combined = f"{proc.stdout or ''}{proc.stderr or ''}"
    assert "unrecognized arguments" not in combined
    assert proc.returncode == 0
