"""Evidence ledger persistence (models live in contracts)."""

from __future__ import annotations

from reveng_debug.contracts.models import (
    ClaimConfidence,
    EvidenceAuthority,
    EvidenceItem,
    Location,
)
from reveng_debug.storage.workspace import SessionStore


class Ledger:
    def __init__(self, store: SessionStore) -> None:
        self.store = store

    def record(
        self,
        *,
        confidence: ClaimConfidence,
        kind: str,
        statement: str,
        tool: str,
        command: str | None = None,
        limitations: list[str] | None = None,
        location: Location | None = None,
        authority: EvidenceAuthority = EvidenceAuthority.SHIPPED_ARTIFACT,
        metadata: dict[str, object] | None = None,
    ) -> EvidenceItem:
        item = EvidenceItem(
            session_id=self.store.session_id,
            confidence=confidence,
            authority=authority,
            kind=kind,
            statement=statement,
            tool=tool,
            command=command,
            limitations=limitations or [],
            location=location,
            metadata=metadata or {},
        )
        self.store.append_evidence(item)
        return item

    def all(self) -> list[EvidenceItem]:
        return self.store.read_evidence()
