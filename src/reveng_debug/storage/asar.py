"""Path-safe ASAR reader. Rejects traversal, absolute paths, and link entries."""

from __future__ import annotations

import json
import os
import stat
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any


class AsarError(ValueError):
    """Malformed or unsafe ASAR archive."""


def iter_asar_entries(archive: Path) -> Iterator[tuple[str, bytes]]:
    data = archive.read_bytes()
    if len(data) < 16:
        raise AsarError("asar too small")
    # pickle uint32 size-of-size (4) + uint32 json size + json + files
    size_of_size, header_size = struct.unpack_from("<II", data, 0)
    if size_of_size != 4:
        raise AsarError("unexpected asar pickle size")
    header_start = 8
    header_json = data[header_start : header_start + header_size]
    try:
        header = json.loads(header_json.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AsarError("asar header is not JSON") from exc
    aligned = header_start + header_size
    if aligned % 4:
        aligned += 4 - (aligned % 4)
    files = header.get("files")
    if not isinstance(files, dict):
        raise AsarError("asar header missing files")
    yield from _walk(files, "", data, aligned)


def extract_asar(archive: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    for rel, blob in iter_asar_entries(archive):
        target = _safe_join(dest_resolved, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        # Refuse to keep a symlink if the OS somehow created one.
        if target.is_symlink() or stat.S_ISLNK(target.lstat().st_mode):
            target.unlink()
            raise AsarError(f"refusing symlink member {rel}")
    return dest


def _walk(
    node: dict[str, Any], prefix: str, data: bytes, files_offset: int
) -> Iterator[tuple[str, bytes]]:
    for name, spec in node.items():
        _assert_safe_name(name)
        rel = f"{prefix}/{name}" if prefix else name
        if not isinstance(spec, dict):
            raise AsarError(f"bad asar entry {rel}")
        if spec.get("link") or spec.get("unpacked"):
            raise AsarError(f"refusing link/unpacked member {rel}")
        nested = spec.get("files")
        if isinstance(nested, dict):
            yield from _walk(nested, rel, data, files_offset)
            continue
        offset_s = spec.get("offset")
        size = spec.get("size")
        if offset_s is None or size is None:
            continue
        start = files_offset + int(offset_s)
        end = start + int(size)
        if start < files_offset or end > len(data) or end < start:
            raise AsarError(f"asar slice out of range for {rel}")
        yield rel.replace("\\", "/"), data[start:end]


def _assert_safe_name(name: str) -> None:
    if not name or name in {".", ".."}:
        raise AsarError(f"illegal asar name {name!r}")
    if "/" in name or "\\" in name:
        raise AsarError(f"illegal asar name {name!r}")
    if os.path.isabs(name) or (len(name) >= 2 and name[1] == ":"):
        raise AsarError(f"absolute asar name {name!r}")


def _safe_join(root: Path, rel: str) -> Path:
    if rel.startswith("/") or rel.startswith("\\") or (len(rel) >= 2 and rel[1] == ":"):
        raise AsarError(f"absolute asar path {rel!r}")
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    if any(p in {".", ".."} for p in parts):
        raise AsarError(f"traversal in asar path {rel!r}")
    target = root.joinpath(*parts).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise AsarError(f"asar path escaped workspace: {rel}") from exc
    return target
