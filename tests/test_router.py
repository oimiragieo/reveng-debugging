from __future__ import annotations

from pathlib import Path

from reveng_debug.contracts.models import CapabilityStatus, TargetKind
from reveng_debug.router.doctor import probe_tools
from reveng_debug.router.identify import identify_target
from tests.helpers import build_minimal_pe32, write_js_app


def test_identify_pe_js_asar(tmp_path: Path) -> None:
    pe = tmp_path / "a.bin"
    pe.write_bytes(build_minimal_pe32())
    assert identify_target(pe) is TargetKind.PE
    js_dir = write_js_app(tmp_path / "app")
    assert identify_target(js_dir) is TargetKind.JAVASCRIPT
    asar = tmp_path / "app.asar"
    asar.write_bytes(b"not-really")
    asar.write_bytes(b"x")
    asar = tmp_path / "packed.asar"
    asar.write_bytes(b"xxxx")
    assert identify_target(asar) is TargetKind.ELECTRON
    elf = tmp_path / "elf.bin"
    elf.write_bytes(b"\x7fELF\x02\x01")
    assert identify_target(elf) is TargetKind.ELF


def test_doctor_never_says_absent() -> None:
    probes = probe_tools()
    names = {p.name for p in probes}
    assert "pefile" in names
    assert "ghidra" in names
    ghidra = next(p for p in probes if p.name == "ghidra")
    assert ghidra.status in {
        CapabilityStatus.UNKNOWN,
        CapabilityStatus.UNSUPPORTED,
        CapabilityStatus.PRESENT,
    }
    blob = " ".join(f"{p.status} {p.detail}" for p in probes)
    assert "absent" not in blob
