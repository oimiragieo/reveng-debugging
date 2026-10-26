"""Opt-in BYO REVENG extra: GA reverse-engineer-app only, copy-workspace paths."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import shutil
import subprocess
from collections.abc import Awaitable, Callable
from importlib.util import find_spec
from pathlib import Path
from typing import Any, cast

from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    InventoryResult,
    Location,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger
from reveng_debug.router.identify import identify_target
from reveng_debug.storage.workspace import SessionStore

GA_SURFACE = "reverse-engineer-app"
APP_RE_TIMEOUT_SECONDS = 180
UNSUPPORTED_HINT = (
    "Install the reveng extra or put the reveng CLI on PATH. "
    "Optional BYO reverse-engineer-app is unsupported in this environment."
)
_STATIC_KWARGS: dict[str, Any] = {
    "language": "auto",
    "run_deobfuscator": False,
    "run_js_behavior_probe": False,
    "run_js_npm_lifecycle_probe": False,
}


def run_reveng_app_re(path: Path, ledger: Ledger) -> InventoryResult:
    """Run opt-in reverse-engineer-app on a session copy. Never executes the target."""
    store = _store_for(ledger)
    if find_spec("reveng") is None:
        return _unsupported(path, store, ledger)
    admitted = _admit_if_needed(path, store)
    output_dir = store.artifacts / "app-re"
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        payload = invoke_ga_app_re(admitted, output_dir)
    except Exception as exc:
        return _failed(path, admitted, store, ledger, output_dir, exc)
    findings: dict[str, Any] = dict(payload) if isinstance(payload, dict) else {}
    findings["output_dir"] = str(output_dir)
    evidence = ledger.record(
        confidence=ClaimConfidence.SEEN,
        kind="reveng.app_re",
        statement=f"reverse-engineer-app wrote {output_dir}",
        tool="reveng",
        command=f"reveng --output-dir {output_dir} {GA_SURFACE} {admitted}",
        location=Location(path=str(admitted)),
        limitations=[
            "opt-in BYO; copy-workspace paths only",
            "static/non-executing defaults; target was not executed",
            "GA surface reverse-engineer-app only",
        ],
        metadata={"output_dir": str(output_dir)},
    )
    return InventoryResult(
        session_id=store.session_id,
        target_kind=_kind(admitted),
        original_path=str(path),
        workspace_path=str(admitted),
        status=CapabilityStatus.PRESENT,
        engine="reveng.reverse-engineer-app",
        coverage="reverse-engineer-app; copy-workspace; static/non-executing",
        findings=findings,
        evidence=[evidence],
        limitations=[
            "opt-in BYO; copy-workspace paths only",
            "static/non-executing defaults; target was not executed",
        ],
    )


def invoke_ga_app_re(admitted: Path, output_dir: Path) -> dict[str, Any]:
    """Call the GA Python API when present; otherwise the reverse-engineer-app CLI."""
    python = _try_python_api(admitted, output_dir)
    if python is not None:
        return python
    return _run_subprocess(admitted, output_dir)


def _try_python_api(admitted: Path, output_dir: Path) -> dict[str, Any] | None:
    framework = _load_app_re_framework()
    if framework is None:
        return None
    reverse = getattr(framework, "reverse_engineer", None)
    if not callable(reverse):
        return None
    call = cast("Callable[..., Any]", reverse)
    result = _call_reverse(call, admitted, output_dir)
    if inspect.isawaitable(result):
        result = asyncio.run(_await_timeout(cast("Awaitable[object]", result)))
    return _serialize_python_result(result, output_dir)


def _load_app_re_framework() -> object | None:
    """Import reveng.app_reverse_engineering only — never exploit or malware modules."""
    try:
        module = importlib.import_module("reveng.app_reverse_engineering")
    except ImportError:
        return None
    create = getattr(module, "create_default_framework", None)
    if not callable(create):
        return None
    try:
        created = create()
    except Exception:
        return None
    return None if created is None else cast("object", created)


def _call_reverse(reverse: Callable[..., Any], admitted: Path, output_dir: Path) -> object:
    kwargs = _static_call_kwargs(reverse)
    return reverse(str(admitted), str(output_dir), **kwargs)


def _static_call_kwargs(reverse: Callable[..., Any]) -> dict[str, Any]:
    try:
        params = inspect.signature(reverse).parameters
    except (TypeError, ValueError):
        return {"run_deobfuscator": False}
    accepts_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    if accepts_var_kw:
        return dict(_STATIC_KWARGS)
    return {name: value for name, value in _STATIC_KWARGS.items() if name in params}


def _serialize_python_result(result: object, output_dir: Path) -> dict[str, Any]:
    payload: dict[str, Any] = {"output_dir": str(output_dir), "via": "python-api"}
    if isinstance(result, dict):
        payload.update(result)
        payload["output_dir"] = str(output_dir)
        payload["via"] = "python-api"
        return payload
    for attr in ("language", "adapter_name", "source_count", "validation_grade"):
        value = getattr(result, attr, None)
        if value is not None:
            payload[attr] = str(value) if isinstance(value, Path) else value
    return payload


def _run_subprocess(admitted: Path, output_dir: Path) -> dict[str, Any]:
    binary = shutil.which("reveng") or shutil.which("reveng.exe") or "reveng"
    # `reveng` requires global options BEFORE the subcommand, and its
    # `reverse-engineer-app` subcommand has no --output-dir of its own
    # (`reveng reverse-engineer-app --help` lists only --language, --input-root,
    # --skip-pattern, --max-snippets, --snippet-context, --run-deobfuscator).
    # Putting the flag after the subcommand fails with rc=2 "unrecognized arguments".
    # Only GA_SURFACE is ever placed here; that constraint is held by construction
    # and locked by test_app_re_cli_argv_shape.
    cmd = [binary, "--output-dir", str(output_dir), GA_SURFACE, str(admitted)]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=APP_RE_TIMEOUT_SECONDS,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "")[-1000:]
        raise RuntimeError(f"reveng {GA_SURFACE} failed rc={completed.returncode}: {detail}")
    return {"output_dir": str(output_dir), "via": "cli", "returncode": completed.returncode}


async def _await_timeout(awaitable: Awaitable[object]) -> object:
    return await asyncio.wait_for(awaitable, timeout=APP_RE_TIMEOUT_SECONDS)


def _store_for(ledger: Ledger) -> SessionStore:
    store = getattr(ledger, "store", None)
    if isinstance(store, SessionStore):
        return store
    return SessionStore()


def _admit_if_needed(path: Path, store: SessionStore) -> Path:
    resolved = path.resolve()
    if store.contained(resolved):
        return resolved
    return store.admit(resolved)


def _kind(path: Path) -> TargetKind:
    try:
        return identify_target(path)
    except OSError:
        return TargetKind.UNKNOWN


def _unsupported(path: Path, store: SessionStore, ledger: Ledger) -> InventoryResult:
    evidence = ledger.record(
        confidence=ClaimConfidence.UNKNOWN,
        kind="reveng.app_re",
        statement=UNSUPPORTED_HINT,
        tool="reveng",
        limitations=[UNSUPPORTED_HINT],
    )
    return InventoryResult(
        session_id=store.session_id,
        target_kind=_kind(path),
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.UNSUPPORTED,
        engine="reveng",
        coverage="none",
        findings={},
        evidence=[evidence],
        limitations=[UNSUPPORTED_HINT],
    )


def _failed(
    original: Path,
    admitted: Path,
    store: SessionStore,
    ledger: Ledger,
    output_dir: Path,
    exc: Exception,
) -> InventoryResult:
    statement = f"reverse-engineer-app failed: {exc}"
    evidence = ledger.record(
        confidence=ClaimConfidence.SEEN,
        kind="reveng.app_re",
        statement=statement,
        tool="reveng",
        command=f"reveng --output-dir {output_dir} {GA_SURFACE} {admitted}",
        location=Location(path=str(admitted)),
        limitations=[statement, "target was not executed"],
    )
    return InventoryResult(
        session_id=store.session_id,
        target_kind=_kind(admitted),
        original_path=str(original),
        workspace_path=str(admitted),
        status=CapabilityStatus.FAILED,
        engine="reveng.reverse-engineer-app",
        coverage="none",
        findings={"output_dir": str(output_dir), "error": str(exc)},
        evidence=[evidence],
        limitations=[statement, "target was not executed"],
    )
