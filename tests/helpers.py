"""Hermetic fixture builders. No malware, no third-party binaries."""

from __future__ import annotations

import json
import struct
from pathlib import Path


def build_minimal_pe32() -> bytes:
    """Tiny PE32 that pefile can parse; not a runnable sample."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    pe = 0x80
    buf[pe : pe + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, pe + 4, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = pe + 24
    struct.pack_into("<H", buf, opt, 0x10B)
    struct.pack_into("<I", buf, opt + 16, 0x1000)
    struct.pack_into("<I", buf, opt + 20, 0x1000)
    struct.pack_into("<I", buf, opt + 28, 0x400000)
    struct.pack_into("<I", buf, opt + 32, 0x1000)
    struct.pack_into("<I", buf, opt + 36, 0x200)
    struct.pack_into("<HH", buf, opt + 40, 4, 0)
    struct.pack_into("<HH", buf, opt + 48, 4, 0)
    struct.pack_into("<I", buf, opt + 56, 0x2000)
    struct.pack_into("<I", buf, opt + 60, 0x200)
    struct.pack_into("<HH", buf, opt + 68, 3, 0x0140)  # console + ASLR/NX
    struct.pack_into("<I", buf, opt + 72, 0x100000)
    struct.pack_into("<I", buf, opt + 76, 0x1000)
    struct.pack_into("<I", buf, opt + 80, 0x100000)
    struct.pack_into("<I", buf, opt + 84, 0x1000)
    struct.pack_into("<I", buf, opt + 92, 16)
    sect = opt + 0xE0
    buf[sect : sect + 5] = b".text"
    struct.pack_into("<I", buf, sect + 8, 0x200)
    struct.pack_into("<I", buf, sect + 12, 0x1000)
    struct.pack_into("<I", buf, sect + 16, 0x200)
    struct.pack_into("<I", buf, sect + 20, 0x200)
    struct.pack_into("<I", buf, sect + 36, 0x60000020)
    buf[0x200:0x208] = b"REVENG\x00"
    return bytes(buf)


def build_asar(
    members: dict[str, bytes],
    *,
    unpacked: dict[str, int] | None = None,
    links: dict[str, str] | None = None,
) -> bytes:
    files: dict[str, object] = {}
    blobs = bytearray()
    for name, content in members.items():
        _insert_asar_entry(files, name, {"offset": str(len(blobs)), "size": len(content)})
        blobs.extend(content)
    for name, size in (unpacked or {}).items():
        _insert_asar_entry(files, name, {"size": size, "unpacked": True})
    for name, target in (links or {}).items():
        _insert_asar_entry(files, name, {"link": target})
    header = json.dumps({"files": files}, separators=(",", ":")).encode("utf-8")
    pickle = struct.pack("<II", 4, len(header)) + header
    if len(pickle) % 4:
        pickle += b"\x00" * (4 - len(pickle) % 4)
    return pickle + bytes(blobs)


def _insert_asar_entry(files: dict[str, object], name: str, spec: dict[str, object]) -> None:
    parts = [part for part in name.replace("\\", "/").split("/") if part]
    node: dict[str, object] = files
    for part in parts[:-1]:
        entry = node.get(part)
        if not isinstance(entry, dict):
            entry = {}
            node[part] = entry
        nested = entry.get("files")
        if not isinstance(nested, dict):
            nested = {}
            entry["files"] = nested
        node = nested
    node[parts[-1]] = spec


def write_js_app(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "fixture-app", "main": "main.js", "version": "0.0.1"}),
        encoding="utf-8",
    )
    (root / "main.js").write_text(
        'ipcMain.handle("ping", () => 1);\n//# sourceMappingURL=main.js.map\n',
        encoding="utf-8",
    )
    return root
