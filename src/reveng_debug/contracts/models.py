"""Versioned evidence and capability contracts (SPEC-RD-001)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from reveng_debug import SCHEMA_VERSION as PACKAGE_SCHEMA

SCHEMA_VERSION = PACKAGE_SCHEMA


class TargetKind(StrEnum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    JAVASCRIPT = "javascript"
    ELECTRON = "electron"
    WEBSITE = "website"
    UNKNOWN = "unknown"


class ClaimConfidence(StrEnum):
    SEEN = "seen"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class CapabilityStatus(StrEnum):
    PRESENT = "present"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    UNKNOWN = "unknown"


class EvidenceAuthority(StrEnum):
    SHIPPED_ARTIFACT = "shipped-artifact"
    CONTROLLED_REPLAY = "controlled-replay"
    HISTORICAL_REFERENCE = "historical-reference"
    ANALYST_INFERENCE = "analyst-inference"


class Location(BaseModel):
    path: str | None = None
    offset: int | None = None
    symbol: str | None = None


class EvidenceItem(BaseModel):
    schema_version: str = SCHEMA_VERSION
    session_id: str
    confidence: ClaimConfidence
    authority: EvidenceAuthority = EvidenceAuthority.SHIPPED_ARTIFACT
    kind: str
    statement: str
    tool: str
    command: str | None = None
    limitations: list[str] = Field(default_factory=list)
    location: Location | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FeatureFlags(BaseModel):
    dynamic_attach: bool = False
    ghidra_byo: bool = False
    reveng_extra: bool = False
    rea_passthrough: bool = False
    gotcontext_chrome: bool = True


class SupportRow(BaseModel):
    workflow: str
    status: CapabilityStatus
    notes: str


class SupportMatrix(BaseModel):
    schema_version: str = SCHEMA_VERSION
    flags: FeatureFlags = Field(default_factory=FeatureFlags)
    rows: list[SupportRow] = Field(
        default_factory=lambda: [
            SupportRow(
                workflow="pe_inventory",
                status=CapabilityStatus.PRESENT,
                notes="LIEF preferred; pefile fallback with reduced coverage",
            ),
            SupportRow(
                workflow="javascript_inventory",
                status=CapabilityStatus.PRESENT,
                notes="package.json, sourceMappingURL, bounded slices",
            ),
            SupportRow(
                workflow="electron_asar",
                status=CapabilityStatus.PRESENT,
                notes="Path-safe extract into session workspace",
            ),
            SupportRow(
                workflow="website_clone",
                status=CapabilityStatus.PRESENT,
                notes=(
                    "Static HTML/capture JSON clone package; live DOM/tokens/assets "
                    "via gotcontext-chrome skill (not REA CDP)"
                ),
            ),
            SupportRow(
                workflow="dynamic_attach",
                status=CapabilityStatus.UNSUPPORTED,
                notes="Flag exists; MVP never executes the target",
            ),
            SupportRow(
                workflow="ghidra_headless",
                status=CapabilityStatus.UNSUPPORTED,
                notes="Wave 2: doctor may report PATH presence only",
            ),
            SupportRow(
                workflow="reveng_extra",
                status=CapabilityStatus.UNSUPPORTED,
                notes="Opt-in BYO if import reveng succeeds; copy-workspace paths only",
            ),
            SupportRow(
                workflow="rea_passthrough",
                status=CapabilityStatus.UNSUPPORTED,
                notes="Opt-in BYO; never auto-launches targets",
            ),
        ]
    )


class ToolProbe(BaseModel):
    name: str
    status: CapabilityStatus
    detail: str | None = None
    coverage: str | None = None


class WebsiteCapture(BaseModel):
    """Normalized capture from static HTML or a gotcontext-chrome session dump."""

    schema_version: str = SCHEMA_VERSION
    kind: str = "website-capture"
    backend: str = "static-html"
    url: str | None = None
    title: str | None = None
    html: str | None = None
    text: str | None = None
    tokens: dict[str, Any] = Field(default_factory=dict)
    assets: list[Any] = Field(default_factory=list)
    components: list[Any] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    stylesheets: list[str] = Field(default_factory=list)
    images: list[str] = Field(default_factory=list)


class InventoryResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    session_id: str
    target_kind: TargetKind
    original_path: str
    workspace_path: str
    status: CapabilityStatus = CapabilityStatus.PRESENT
    engine: str
    coverage: str
    findings: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
