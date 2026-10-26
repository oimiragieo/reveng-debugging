"""Magic-byte and extension routing (SPEC-RD-003)."""

from __future__ import annotations

from pathlib import Path

from reveng_debug.contracts.models import TargetKind

ELF = b"\x7fELF"
MACHO_BE = b"\xca\xfe\xba\xbe"
MACHO_64_LE = b"\xcf\xfa\xed\xfe"
MACHO_64_BE = b"\xce\xfa\xed\xfe"


def identify_target(path: Path) -> TargetKind:
    if not path.exists():
        return TargetKind.UNKNOWN
    if path.is_dir():
        if (path / "package.json").exists():
            text = (path / "package.json").read_text(encoding="utf-8", errors="replace")
            if "electron" in text.lower():
                return TargetKind.ELECTRON
            return TargetKind.JAVASCRIPT
        return TargetKind.UNKNOWN
    suffix = path.suffix.lower()
    if suffix == ".asar":
        return TargetKind.ELECTRON
    if suffix in {".js", ".mjs", ".cjs", ".ts"}:
        return TargetKind.JAVASCRIPT
    header = path.read_bytes()[:16]
    if header.startswith(b"MZ"):
        return TargetKind.PE
    if header.startswith(ELF):
        return TargetKind.ELF
    macho = (MACHO_BE, MACHO_64_LE, MACHO_64_BE, b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
    if header.startswith(macho):
        return TargetKind.MACHO
    if suffix in {".exe", ".dll", ".sys"}:
        return TargetKind.PE
    return TargetKind.UNKNOWN
