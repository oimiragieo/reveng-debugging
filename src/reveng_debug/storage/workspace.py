"""Copy-on-write session workspace (SPEC-RD-002). Never mutates the original."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reveng_debug.contracts.models import EvidenceItem

ENV_ROOT = "REVENG_DEBUG_STATE_ROOT"


def new_session_id() -> str:
    return uuid.uuid4().hex


def default_root() -> Path:
    configured = os.environ.get(ENV_ROOT)
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "reveng-debug"


class SessionStore:
    def __init__(self, session_id: str | None = None, root: Path | None = None) -> None:
        self.session_id = session_id or new_session_id()
        self.root = root or default_root()
        self.dir = self.root / self.session_id
        self.work = self.dir / "work"
        self.artifacts = self.dir / "artifacts"
        self.session_path = self.dir / "session.json"
        self.ledger_path = self.dir / "ledger.jsonl"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(exist_ok=True)
        self.artifacts.mkdir(exist_ok=True)
        if not self.session_path.exists():
            self._write_session({"session_id": self.session_id, "artifacts": [], "created": _now()})

    def admit(self, source: Path) -> Path:
        source = source.resolve()
        if not source.exists():
            raise FileNotFoundError(source)
        dest = self.work / source.name
        if source.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(source, dest, symlinks=False)
        else:
            shutil.copy2(source, dest)
        self._index_artifact(str(source), str(dest))
        return dest

    def contained(self, candidate: Path) -> bool:
        try:
            candidate.resolve().relative_to(self.dir.resolve())
            return True
        except ValueError:
            return False

    def append_evidence(self, item: EvidenceItem) -> None:
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(item.model_dump_json() + "\n")

    def read_evidence(self) -> list[EvidenceItem]:
        if not self.ledger_path.exists():
            return []
        items: list[EvidenceItem] = []
        for line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(EvidenceItem.model_validate_json(line))
        return items

    def show(self) -> dict[str, Any]:
        payload: dict[str, Any] = json.loads(self.session_path.read_text(encoding="utf-8"))
        return payload

    def _index_artifact(self, original: str, workspace: str) -> None:
        data = self.show()
        data.setdefault("artifacts", []).append(
            {"original": original, "workspace": workspace, "admitted": _now()}
        )
        self._write_session(data)

    def _write_session(self, data: dict[str, Any]) -> None:
        self.session_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _now() -> str:
    return datetime.now(UTC).isoformat()
