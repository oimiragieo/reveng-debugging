"""Interactive stdlib TUI for omega-vision attach (Wave 2).

Never executes target binaries. Drive this from a real terminal or via
omega-vision: this host prints http://127.0.0.1:8092/attach (README default 8090).
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

ATTACH_URL = "http://127.0.0.1:8092/attach"
README_ATTACH_URL = "http://127.0.0.1:8090/attach"
PROMPT = "reveng-debug (identify PATH | inventory PATH | session show)> "


def run_tui() -> None:
    """Run the interactive command loop until quit or EOF."""
    _print_banner()
    _print_doctor_summary()
    last_session: str | None = None
    while True:
        try:
            raw = input(PROMPT)
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print()
            return
        line = raw.strip()
        if not line:
            continue
        should_quit, last_session = _handle(line, last_session)
        if should_quit:
            print("quit")
            return


def _svc() -> Any:
    from reveng_debug import service as svc

    return svc


def _attach_urls() -> tuple[str, str]:
    try:
        svc = _svc()
    except ModuleNotFoundError:
        return ATTACH_URL, README_ATTACH_URL
    return (
        str(getattr(svc, "OMEGA_VISION_ATTACH", ATTACH_URL)),
        str(getattr(svc, "OMEGA_VISION_ATTACH_DEFAULT_PORT", README_ATTACH_URL)),
    )


def _doctor() -> dict[str, Any]:
    try:
        payload = _svc().doctor()
        if isinstance(payload, dict):
            return payload
    except ModuleNotFoundError:
        pass
    from reveng_debug.contracts.models import SupportMatrix
    from reveng_debug.router.doctor import probe_tools

    matrix = SupportMatrix()
    return {
        "schema_version": matrix.schema_version,
        "support_matrix": matrix.model_dump(),
        "tools": [p.model_dump() for p in probe_tools()],
        "omega_vision_attach": ATTACH_URL,
        "omega_vision_attach_readme_default": README_ATTACH_URL,
    }


def _print_banner() -> None:
    attach, readme = _attach_urls()
    print("reveng-debug TUI (Wave 2) — never executes target binaries.")
    print(f"Attach at {attach} (omega-vision) to visually drive this TUI.")
    print(f"omega-vision README default is {readme}; this host uses 8092.")
    print("Commands: doctor | identify PATH | inventory PATH |")
    print("          slice PATH NEEDLE | clone-website TARGET | session show ID | quit")


def _print_doctor_summary() -> None:
    payload = _doctor()
    matrix = payload.get("support_matrix") or {}
    rows = matrix.get("rows") or []
    bits: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            workflow = str(row.get("workflow", ""))
            status = str(row.get("status", ""))
            if workflow:
                bits.append(f"{workflow}={status}")
    if bits:
        print("doctor summary: " + ", ".join(bits))
    else:
        print("doctor summary: (empty)")


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _tokenize(line: str) -> list[str]:
    posix = os.name != "nt"
    try:
        return shlex.split(line, posix=posix)
    except ValueError:
        return line.split()


def _handle(line: str, last_session: str | None) -> tuple[bool, str | None]:
    tokens = _tokenize(line)
    if not tokens:
        return False, last_session
    cmd = tokens[0].lower()
    rest = tokens[1:]
    try:
        return _dispatch(cmd, rest, last_session)
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}")
        return False, last_session


def _dispatch(cmd: str, rest: list[str], last_session: str | None) -> tuple[bool, str | None]:
    if cmd in {"quit", "exit", "q"}:
        return True, last_session
    if cmd in {"help", "?"}:
        _print_banner()
        return False, last_session
    if cmd == "doctor":
        _emit(_doctor())
        return False, last_session
    if cmd == "identify":
        path = _require_path(rest, "identify PATH")
        if path is None:
            return False, last_session
        _emit(_svc().identify(path))
        return False, last_session
    if cmd == "inventory":
        path = _require_path(rest, "inventory PATH")
        if path is None:
            return False, last_session
        result = _svc().inventory(path)
        _emit(result.model_dump())
        _emit(_svc().session_show(result.session_id))
        return False, result.session_id
    if cmd == "slice":
        if len(rest) < 2:
            print("usage: slice PATH NEEDLE")
            return False, last_session
        path = Path(rest[0])
        needle = " ".join(rest[1:])
        _emit(_svc().slice_file(path, needle))
        return False, last_session
    if cmd == "clone-website":
        if not rest:
            print("usage: clone-website TARGET")
            return False, last_session
        result = _svc().clone_website(" ".join(rest))
        _emit(result.model_dump())
        _emit(_svc().session_show(result.session_id))
        return False, result.session_id
    if cmd == "session":
        return False, _session_show(rest, last_session)
    print(f"unknown command: {cmd} (try help)")
    return False, last_session


def _require_path(rest: list[str], usage: str) -> Path | None:
    if not rest:
        print(f"usage: {usage}")
        return None
    return Path(" ".join(rest))


def _session_show(rest: list[str], last_session: str | None) -> str | None:
    sid = last_session
    if rest and rest[0].lower() == "show":
        if len(rest) >= 2:
            sid = rest[1]
    elif rest:
        sid = rest[0]
    if not sid:
        print("usage: session show SESSION_ID")
        return last_session
    _emit(_svc().session_show(sid))
    return sid
