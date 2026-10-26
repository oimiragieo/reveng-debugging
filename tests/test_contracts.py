from __future__ import annotations

from reveng_debug.contracts.models import (
    SCHEMA_VERSION,
    CapabilityStatus,
    ClaimConfidence,
    EvidenceItem,
    FeatureFlags,
    SupportMatrix,
)


def test_evidence_roundtrip() -> None:
    item = EvidenceItem(
        session_id="abc",
        confidence=ClaimConfidence.SEEN,
        kind="pe.machine",
        statement="PE machine=I386",
        tool="pefile",
        command="pefile parse",
        limitations=["static"],
    )
    raw = item.model_dump_json()
    again = EvidenceItem.model_validate_json(raw)
    assert again.schema_version == SCHEMA_VERSION
    assert again.confidence is ClaimConfidence.SEEN
    assert again.session_id == "abc"


def test_support_matrix_wave2_and_dynamic_attach() -> None:
    matrix = SupportMatrix()
    by_name = {row.workflow: row.status for row in matrix.rows}
    assert by_name["dynamic_attach"] is CapabilityStatus.UNSUPPORTED
    assert by_name["ghidra_headless"] is CapabilityStatus.PRESENT
    assert by_name["elf_inventory"] is CapabilityStatus.PRESENT
    assert by_name["macho_inventory"] is CapabilityStatus.PRESENT
    assert by_name["reveng_extra"] is CapabilityStatus.PRESENT
    assert by_name["tui_attach"] is CapabilityStatus.PRESENT
    assert by_name["pe_inventory"] is CapabilityStatus.PRESENT
    assert by_name["website_clone"] is CapabilityStatus.PRESENT
    assert matrix.flags == FeatureFlags()
    assert matrix.flags.gotcontext_chrome is True
    assert matrix.flags.ghidra_byo is True
    assert matrix.flags.reveng_extra is True
    assert matrix.flags.dynamic_attach is False


def test_missing_is_not_absent_in_schema() -> None:
    item = EvidenceItem(
        session_id="s",
        confidence=ClaimConfidence.UNKNOWN,
        kind="js.sourcemap",
        statement="no sourceMappingURL seen",
        tool="slice",
    )
    dumped = item.model_dump()
    assert dumped["confidence"] == "unknown"
    assert "absent" not in dumped["statement"]
