"""BYO Ghidra headless adapter (Wave 2). Never downloads Ghidra; never executes the target."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reveng_debug.contracts.models import (
    CapabilityStatus,
    ClaimConfidence,
    InventoryResult,
    Location,
    TargetKind,
)
from reveng_debug.ledger.service import Ledger
from reveng_debug.router.identify import identify_target

ENGINE = "ghidra-headless"
PROJECT_NAME = "reveng"
HEADLESS_TIMEOUT_SEC = 120
CAPTURE_LIMIT = 32_768
MAX_FUNCTIONS = 500
EXPORT_SCRIPT_NAME = "ExportFunctions.java"
OUTPUT_JSON_NAME = "ghidra_functions.json"

UNSUPPORTED_HINT = (
    "analyzeHeadless not on PATH; set GHIDRA_INSTALL_DIR or GHIDRA_HOME "
    "to a local install (Wave 2 BYO). This adapter does not download Ghidra."
)

_HEADLESS_NAMES_NT = ("analyzeHeadless.bat", "analyzeHeadless")
_HEADLESS_NAMES_POSIX = ("analyzeHeadless", "analyzeHeadless.bat")
_ENV_DIRS = ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME")

__all__ = [
    "ENGINE",
    "HEADLESS_TIMEOUT_SEC",
    "HeadlessRun",
    "UNSUPPORTED_HINT",
    "discover_analyze_headless",
    "invoke_headless",
    "run_ghidra_headless",
]


@dataclass(frozen=True)
class HeadlessRun:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def discover_analyze_headless() -> Path | None:
    """Locate analyzeHeadless via PATH, then GHIDRA_INSTALL_DIR / GHIDRA_HOME."""
    names = _headless_names()
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    for env in _ENV_DIRS:
        raw = os.environ.get(env)
        if not raw:
            continue
        root = Path(raw)
        for name in names:
            for candidate in (root / "support" / name, root / name):
                if candidate.is_file():
                    return candidate
    return None


def invoke_headless(
    command: list[str],
    *,
    timeout: float = HEADLESS_TIMEOUT_SEC,
) -> HeadlessRun:
    """Run a prepared analyzeHeadless command. Tests monkeypatch this."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        return HeadlessRun(
            returncode=None,
            stdout=_clip(exc.stdout),
            stderr=_clip(exc.stderr),
            timed_out=True,
        )
    except OSError as exc:
        return HeadlessRun(
            returncode=None,
            stdout="",
            stderr=_clip(str(exc)),
            timed_out=False,
        )
    return HeadlessRun(
        returncode=completed.returncode,
        stdout=_clip(completed.stdout),
        stderr=_clip(completed.stderr),
        timed_out=False,
    )


def run_ghidra_headless(
    path: Path,
    ledger: Ledger,
    *,
    project_dir: Path | None = None,
) -> InventoryResult:
    """Static headless inventory of a session-workspace copy. Opt-in BYO only."""
    target = path
    kind = identify_target(target) if target.exists() else TargetKind.UNKNOWN
    headless = discover_analyze_headless()
    if headless is None:
        return _unsupported(target, ledger, kind)

    safe_project = _resolve_project_dir(project_dir, ledger)
    json_out = ledger.store.artifacts / OUTPUT_JSON_NAME
    script = _materialize_export_script(ledger.store.artifacts / "ghidra_scripts")
    command = _build_command(
        headless=headless,
        project_dir=safe_project,
        target=target,
        script=script,
        output_json=json_out,
    )
    safe_project.mkdir(parents=True, exist_ok=True)
    json_out.parent.mkdir(parents=True, exist_ok=True)

    run = invoke_headless(command, timeout=HEADLESS_TIMEOUT_SEC)
    functions = _load_functions(json_out, run.stdout)
    display_cmd = " ".join(command)
    static_limit = "static analysis only; target was not executed"

    if run.timed_out or run.returncode != 0:
        if run.timed_out:
            statement = f"analyzeHeadless timed out after {HEADLESS_TIMEOUT_SEC}s"
            fail_limits = [
                statement,
                static_limit,
                "stdout/stderr captured with a size cap",
            ]
        elif run.returncode is None:
            statement = "analyzeHeadless did not start"
            fail_limits = [statement, static_limit, run.stderr or UNSUPPORTED_HINT]
        else:
            statement = f"analyzeHeadless exited {run.returncode}"
            fail_limits = [statement, static_limit]
        evidence = ledger.record(
            confidence=ClaimConfidence.SEEN,
            kind="ghidra.headless",
            statement=statement,
            tool=ENGINE,
            command=display_cmd,
            limitations=fail_limits,
            location=Location(path=str(target)),
            metadata={"timed_out": run.timed_out, "returncode": run.returncode},
        )
        return InventoryResult(
            session_id=ledger.store.session_id,
            target_kind=kind,
            original_path=str(target),
            workspace_path=str(target),
            status=CapabilityStatus.FAILED,
            engine=ENGINE,
            coverage="functions",
            findings={
                "functions": functions,
                "function_count": len(functions),
                "headless": str(headless),
                "project_dir": str(safe_project),
                "returncode": run.returncode,
                "timed_out": run.timed_out,
                "stdout": run.stdout,
                "stderr": run.stderr,
            },
            evidence=[evidence],
            limitations=fail_limits,
        )

    statement = f"headless listed {len(functions)} functions"
    evidence = ledger.record(
        confidence=ClaimConfidence.SEEN if functions else ClaimConfidence.UNKNOWN,
        kind="ghidra.functions",
        statement=statement,
        tool=ENGINE,
        command=display_cmd,
        limitations=[static_limit],
        location=Location(path=str(target)),
        metadata={"function_count": len(functions)},
    )
    limits = [static_limit]
    if not functions:
        limits.append("no function JSON produced")
    if project_dir is not None and _has_dot_component(project_dir):
        limits.append("requested project dir had a '.' path element; used a Ghidra-safe directory")
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=kind,
        original_path=str(target),
        workspace_path=str(target),
        status=CapabilityStatus.PRESENT,
        engine=ENGINE,
        coverage="functions",
        findings={
            "functions": functions,
            "function_count": len(functions),
            "headless": str(headless),
            "project_dir": str(safe_project),
        },
        evidence=[evidence],
        limitations=limits,
    )


def _unsupported(
    path: Path,
    ledger: Ledger,
    kind: TargetKind,
) -> InventoryResult:
    evidence = ledger.record(
        confidence=ClaimConfidence.UNKNOWN,
        kind="ghidra.headless",
        statement="analyzeHeadless not on PATH or GHIDRA_INSTALL_DIR/GHIDRA_HOME",
        tool=ENGINE,
        limitations=[UNSUPPORTED_HINT],
        location=Location(path=str(path)),
    )
    return InventoryResult(
        session_id=ledger.store.session_id,
        target_kind=kind,
        original_path=str(path),
        workspace_path=str(path),
        status=CapabilityStatus.UNSUPPORTED,
        engine="none",
        coverage="none",
        findings={},
        evidence=[evidence],
        limitations=[UNSUPPORTED_HINT],
    )


def _headless_names() -> tuple[str, ...]:
    if os.name == "nt":
        return _HEADLESS_NAMES_NT
    return _HEADLESS_NAMES_POSIX


def _build_command(
    *,
    headless: Path,
    project_dir: Path,
    target: Path,
    script: Path | None,
    output_json: Path,
) -> list[str]:
    command = [
        *_command_prefix(headless),
        str(project_dir),
        PROJECT_NAME,
        "-import",
        str(target),
        "-deleteProject",
    ]
    if script is not None:
        command.extend(
            [
                "-scriptPath",
                str(script.parent),
                "-postScript",
                script.name,
                str(output_json),
            ]
        )
    return command


def _command_prefix(headless: Path) -> list[str]:
    if headless.suffix.lower() in {".bat", ".cmd"}:
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        return [comspec, "/c", str(headless)]
    return [str(headless)]


def _resolve_project_dir(preferred: Path | None, ledger: Ledger) -> Path:
    """Ghidra rejects project paths whose components start with '.'."""
    candidate = preferred or (ledger.store.artifacts / "ghidra_project")
    if not _has_dot_component(candidate):
        return candidate
    fallback = (
        Path(tempfile.gettempdir()) / "reveng-debug" / "ghidra_project" / ledger.store.session_id
    )
    if not _has_dot_component(fallback):
        return fallback
    return candidate


def _has_dot_component(path: Path) -> bool:
    try:
        parts = path.resolve().parts
    except OSError:
        parts = path.parts
    return any(part.startswith(".") for part in parts)


def _materialize_export_script(dest_dir: Path) -> Path | None:
    src = Path(__file__).resolve().parent / "ghidra_scripts" / EXPORT_SCRIPT_NAME
    if not src.is_file():
        return None
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / EXPORT_SCRIPT_NAME
    payload = src.read_bytes()
    if not dest.is_file() or dest.read_bytes() != payload:
        dest.write_bytes(payload)
    return dest


def _load_functions(output_json: Path, stdout: str) -> list[dict[str, str]]:
    if output_json.is_file():
        try:
            return _parse_functions(output_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    extracted = _extract_json_array(stdout)
    if extracted is None:
        return []
    try:
        return _parse_functions(extracted)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []


def _parse_functions(raw: str) -> list[dict[str, str]]:
    text = raw.strip()
    if not text:
        return []
    data: Any = json.loads(text)
    if not isinstance(data, list):
        return []
    out: list[dict[str, str]] = []
    for item in data[:MAX_FUNCTIONS]:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        entry = item.get("entry")
        if name is None or entry is None:
            continue
        out.append({"name": str(name), "entry": str(entry)})
    return out


def _extract_json_array(text: str) -> str | None:
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return None


def _clip(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    if len(text) <= CAPTURE_LIMIT:
        return text
    return text[:CAPTURE_LIMIT] + "\n...[truncated]"
