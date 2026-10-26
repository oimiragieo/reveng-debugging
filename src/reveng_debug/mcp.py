"""Thin MCP stdio server. Not the 207-tool REA catalog."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from reveng_debug import service

PROTOCOL_VERSION = "2024-11-05"
TOOLS = (
    {
        "name": "doctor",
        "description": "Report tool probes and the support matrix.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "identify",
        "description": "Classify a filesystem target by magic bytes.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "inventory",
        "description": "Admit a copy and inventory PE/ELF/Mach-O/JS/Electron/website targets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "slice",
        "description": "Bounded static text slice around a needle.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "needle": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["path", "needle"],
        },
    },
    {
        "name": "session_show",
        "description": "Show a session and its evidence ledger.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "evidence_get",
        "description": "Return evidence items for a session.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "clone_website",
        "description": (
            "Clone a local HTML/capture JSON or static http(s) snapshot. "
            "Live DOM/tokens come from a gotcontext-chrome capture JSON."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ghidra",
        "description": (
            "Opt-in BYO Ghidra analyzeHeadless on a session copy. "
            "Returns unsupported if Ghidra is not installed. Does not execute the target."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "app_re",
        "description": (
            "Opt-in BYO reverse-engineer-app on a session copy. "
            "Returns unsupported if reveng is not importable. Does not execute the target."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "session_id": {"type": "string"},
            },
            "required": ["path"],
        },
    },
)


def _result(payload: Any) -> dict[str, Any]:
    text = json.dumps(payload, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}]}


def dispatch(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "doctor":
        return _result(service.doctor())
    if name == "identify":
        return _result(service.identify(Path(str(arguments["path"]))))
    if name == "inventory":
        result = service.inventory(
            Path(str(arguments["path"])),
            session_id=arguments.get("session_id"),
        )
        return _result(result.model_dump())
    if name == "slice":
        return _result(
            service.slice_file(
                Path(str(arguments["path"])),
                str(arguments["needle"]),
                session_id=arguments.get("session_id"),
            )
        )
    if name == "session_show":
        return _result(service.session_show(str(arguments["session_id"])))
    if name == "evidence_get":
        return _result(service.evidence_get(str(arguments["session_id"])))
    if name == "clone_website":
        result = service.clone_website(
            str(arguments["target"]),
            session_id=arguments.get("session_id"),
        )
        return _result(result.model_dump())
    if name == "ghidra":
        result = service.ghidra_headless(
            Path(str(arguments["path"])),
            session_id=arguments.get("session_id"),
        )
        return _result(result.model_dump())
    if name == "app_re":
        result = service.app_re(
            Path(str(arguments["path"])),
            session_id=arguments.get("session_id"),
        )
        return _result(result.model_dump())
    raise ValueError(f"unknown tool {name}")


def _read_message() -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("utf-8").partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    body = sys.stdin.buffer.read(length)
    payload: dict[str, Any] = json.loads(body.decode("utf-8"))
    return payload


def _write_message(payload: dict[str, Any]) -> None:
    blob = json.dumps(payload).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(blob)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(blob)
    sys.stdout.buffer.flush()


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    msg_id = message.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "reveng-debug", "version": "0.1.0"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": list(TOOLS)}}
    if method == "tools/call":
        params = message.get("params") or {}
        try:
            result = dispatch(str(params.get("name")), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except Exception as exc:  # noqa: BLE001 — surface to MCP client
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": str(exc)}],
                },
            }
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"unknown method {method}"},
        }
    return None


def main() -> None:
    while True:
        message = _read_message()
        if message is None:
            return
        reply = handle(message)
        if reply is not None:
            _write_message(reply)


if __name__ == "__main__":
    main()
